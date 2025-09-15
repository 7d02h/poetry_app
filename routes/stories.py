from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, jsonify
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os

from models import db, Story, StoryView, StoryLike, User, Follower, Notification
from notification_utils import send_notification

stories_bp = Blueprint("stories", __name__)

ALLOWED_EXTENSIONS = {"png","jpg","jpeg","gif","pdf","mp4","webm","txt"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# 📌 رفع ستوري
@stories_bp.route('/upload_story', methods=['GET', 'POST'])
@login_required
def upload_story():
    if request.method == 'POST':
        file = request.files.get('file')

        if not file or file.filename.strip() == "":
            flash("⚠️ الرجاء اختيار ملف قبل الرفع", "error")
            return redirect(url_for('stories.upload_story'))

        if not allowed_file(file.filename):
            flash("⚠️ صيغة الملف غير مدعومة", "error")
            return redirect(url_for('stories.upload_story'))

        filename = secure_filename(file.filename)
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        filename = f"{current_user.username}_{timestamp}_{filename}"

        upload_path = os.path.join(os.getcwd(), 'static', 'uploads', 'stories')
        os.makedirs(upload_path, exist_ok=True)

        file_path = os.path.join(upload_path, filename)
        file.save(file_path)

        ext = filename.rsplit('.', 1)[-1].lower()
        media_type = 'video' if ext in ['mp4', 'mov', 'avi', 'mkv'] else 'image'

        new_story = Story(
            user_id=current_user.id,
            media_path=f"uploads/stories/{filename}",
            media_type=media_type,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )
        db.session.add(new_story)
        db.session.commit()

        flash("✅ تم رفع الستوري بنجاح", "success")
        return redirect(url_for('stories.my_stories'))

    return render_template('upload_story.html')


# 📌 مشاهدة ستوري
@stories_bp.route('/story/<int:story_id>')
@login_required
def view_story(story_id):
    story = Story.query.get_or_404(story_id)

    following_users = Follower.query.filter_by(username=current_user.username).all()
    following_list = [f.followed_username for f in following_users]
    allowed_users = following_list + [current_user.username]

    story_owner = User.query.get(story.user_id)
    if story_owner.username not in allowed_users:
        abort(403)

    if current_user.id != story.user_id:
        with db.session.no_autoflush:
            existing_view = StoryView.query.filter_by(
                story_id=story.id,
                viewer_id=current_user.id
            ).first()
        if not existing_view:
            new_view = StoryView(story_id=story.id, viewer_id=current_user.id)
            db.session.add(new_view)
            db.session.commit()

    user_stories = (
        Story.query.filter_by(user_id=story.user_id, is_active=True)
        .filter(Story.expires_at > datetime.utcnow())
        .order_by(Story.created_at.asc())
        .all()
    )

    story_ids = [s.id for s in user_stories]
    current_index = story_ids.index(story.id)

    return render_template(
        "view_story.html",
        stories=user_stories,
        current_index=current_index
    )


# 📌 ستورياتي
@stories_bp.route("/my_stories")
@login_required
def my_stories():
    stories = (
        Story.query
        .filter(
            Story.user_id == current_user.id,
            Story.is_active == True,
            Story.is_archived == False,
            Story.expires_at > datetime.utcnow()
        )
        .order_by(Story.created_at.asc())
        .all()
    )

    stories_data = []
    for story in stories:
        views = (
            StoryView.query
            .filter_by(story_id=story.id)
            .join(User, StoryView.viewer_id == User.id)
            .add_columns(
                User.username.label("viewer_username"),
                User.profile_image.label("viewer_profile_image"),
                StoryView.viewed_at
            )
            .all()
        )

        views_data = []
        for view in views:
            has_liked = StoryLike.query.filter_by(
                story_id=story.id,
                username=view.viewer_username
            ).first() is not None

            views_data.append({
                "username": view.viewer_username,
                "profile_image": view.viewer_profile_image,
                "viewed_at": view.viewed_at,
                "has_liked": has_liked
            })

        is_viewed = StoryView.query.filter_by(
            story_id=story.id,
            viewer_id=current_user.id
        ).first() is not None

        is_liked = StoryLike.query.filter_by(
            story_id=story.id,
            username=current_user.username
        ).first() is not None

        stories_data.append({
            "story": story,
            "views": views_data,
            "likes_count": StoryLike.query.filter_by(story_id=story.id).count(),
            "is_viewed": is_viewed,
            "is_liked": is_liked
        })

    return render_template(
        "my_story.html",
        stories_data=stories_data
    )


# 📌 حفظ ستوري
@stories_bp.route("/save_story/<int:story_id>")
@login_required
def save_story(story_id):
    story = Story.query.get_or_404(story_id)

    if story.user_id != current_user.id:
        abort(403)

    # تقدر تضيف كود الحفظ/التحميل هنا
    return redirect(url_for("stories.my_stories"))


# 📌 لايك للستوري
@stories_bp.route('/like_story/<int:story_id>', methods=['POST'])
@login_required
def like_story(story_id):
    story = Story.query.get_or_404(story_id)
    username = current_user.username

    if story.expires_at < datetime.utcnow():
        return jsonify({'success': False, 'message': 'انتهت صلاحية الستوري'})

    existing_like = StoryLike.query.filter_by(username=username, story_id=story_id).first()

    if existing_like:
        db.session.delete(existing_like)
    else:
        new_like = StoryLike(username=username, story_id=story_id)
        db.session.add(new_like)

        if story.user.username != username:
            notification = Notification(
                recipient=story.user.username,
                sender=username,
                type="like_story",
                content=f"{username} أعجب قصتك! ❤️"
            )
            db.session.add(notification)
            send_notification(story.user.username, f"{username} أعجب قصتك! ❤️")

    db.session.commit()
    total_likes = StoryLike.query.filter_by(story_id=story_id).count()

    return jsonify({'success': True, 'likes': total_likes})