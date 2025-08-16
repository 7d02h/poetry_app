from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, has_request_context
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_babel import Babel
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room
from flask_migrate import Migrate
from models import Story, StoryView, Block
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from models import StoryLike
from sqlalchemy import or_, and_, desc

from datetime import datetime, timedelta
import os
import json
import eventlet
import humanize
import re
import stripe

# استيراد الموديلات
from models import (
    db, User, Ban, Notification, Message, MessageReport, ContactMessage,
    Poem, Settings, Follower, Story, Block, Like, Report, FollowRequest
)

# استيراد الدوال من user_utils.py
from user_utils import (
    verify_user, get_user_by_username, get_all_users, delete_user,
    unverify_user_by_id, increase_followers_by_id, valid_username
)

# استيراد دوال الإشعارات
from notification_utils import send_notification


eventlet.monkey_patch()
# ----------------------------- إعداد التطبيق -----------------------------
app = Flask(__name__)

CORS(app)
@app.template_filter('short_number')
def short_number_filter(value):
    try:
        value = int(value)
        if value >= 1_000_000:
            return f"{value / 1_000_000:.1f}M"
        elif value >= 1_000:
            return f"{value / 1_000:.1f}K"
        else:
            return str(value)
    except:
        return value

app.secret_key = "s3cr3t_2025_kjfh73hdf983hf"
basedir = os.path.abspath(os.path.dirname(__file__))

app.config['BABEL_DEFAULT_LOCALE'] = 'ar'
app.config['BABEL_TRANSLATION_DIRECTORIES'] = 'translations'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'poetry.db')
app.config["UPLOAD_FOLDER"] = "static/profile_pics"
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2MB
app.config["UPLOAD_FOLDER"] = os.path.join("static", "profile_pics")
# ----------------------------- قاعدة البيانات -----------------------------
db.init_app(app)
migrate = Migrate(app, db)

stripe.api_key = "sk_test_your_secret_key_here"
STRIPE_PUBLIC_KEY = "pk_test_your_public_key_here"


# ----------------------------- اللغة -----------------------------
babel = Babel(app)

@babel.localeselector
def get_locale():
    return session.get('lang', request.accept_languages.best_match(['ar', 'en']))

# ----------------------------- SocketIO -----------------------------
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

@socketio.on('connect')
def handle_connect():
    print(f"✅ مستخدم متصل عبر SocketIO")

@socketio.on('join')
def handle_join(data):
    room = data.get('room')
    if room:
        join_room(room)
        print(f"✅ انضم المستخدم للغرفة: {room}")

# السماح فقط بالصور والفيديوهات
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi'}
UPLOAD_FOLDER = 'static/stories'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS




def send_notification(to_username, message, notif_type='general'):
    # إرسال الإشعار اللحظي باستخدام SocketIO
    socketio.emit('new_notification', {
        'type': notif_type,
        'message': message
    }, room=to_username)
# ----------------------------- تسجيل الدخول -----------------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class SimpleUser(UserMixin):
    def __init__(self, user):
        self.id = user.id
        self.username = user.username
        self.email = user.email
        self.is_admin = user.is_admin
        self.verified = user.verified

    def get_id(self):
        return str(self.id)

    @property
    def is_active(self):
        return True


ALLOWED_EXTENSIONS = {"png","jpg","jpeg","gif","pdf","mp4","webm","txt"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def time_ago_format(timestamp):
    diff = datetime.now() - timestamp
    seconds = diff.total_seconds()
    if seconds < 60:
        return "الآن"
    elif seconds < 3600:
        return f"{int(seconds//60)} دقيقة"
    elif seconds < 86400:
        return f"{int(seconds//3600)} ساعة"
    else:
        return f"{int(seconds//86400)} يوم"

@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    if user:
        return SimpleUser(user)
    return None

# ----------------------------- السياق العام -----------------------------
@app.context_processor
def inject_user():
    return dict(current_user=current_user)

def inject_blocked_users():
    if not has_request_context() or 'username' not in session:
        return {}
    blocked_entries = Block.query.filter_by(blocker=session['username']).all()
    blocked_usernames = [entry.blocked for entry in blocked_entries]
    return {'blocked_users_sidebar': blocked_usernames}


@app.context_processor
def inject_counts():
    if not has_request_context() or not current_user.is_authenticated:
        return {
            'notifications': [],
            'has_unread_notifications': False,
            'unread_messages_count': 0
        }

    username = current_user.username

    try:
        # ✅ حساب عدد المحادثات غير المقروءة (distinct senders)
        unread_messages_count = (
            db.session.query(Message.sender)
            .filter(Message.receiver == username, Message.is_read == False)
            .distinct()
            .count()
        )

        unread_notifications = Notification.query.filter_by(
            recipient=username,
            is_read=False
        ).order_by(Notification.timestamp.desc()).all()

        return {
            'notifications': unread_notifications,
            'has_unread_notifications': len(unread_notifications) > 0,
            'unread_messages_count': unread_messages_count
        }

    except Exception as e:
        print("❌ خطأ أثناء جلب الإشعارات أو الرسائل:", e)
        return {
            'notifications': [],
            'has_unread_notifications': False,
            'unread_messages_count': 0
        }
# ----------------------------- تنسيق التاريخ -----------------------------
@app.template_filter('format_ar_date')
def format_ar_date(value):
    months_ar = [
        "يناير", "فبراير", "مارس", "أبريل", "مايو", "يونيو",
        "يوليو", "أغسطس", "سبتمبر", "أكتوبر", "نوفمبر", "ديسمبر"
    ]
    try:
        dt = datetime.strptime(value, "%d/%m/%Y %H:%M")
        return f"{dt.day} {months_ar[dt.month - 1]} {dt.year} - {dt.strftime('%I:%M %p').replace('AM', 'صباحًا').replace('PM', 'مساءً')}"
    except:
        return value

def time_ago(timestamp):
    return humanize.naturaltime(datetime.now() - timestamp)

# ----------------------------- الاتفاقيات -----------------------------
@app.before_request
def require_terms_agreement():
    allowed_endpoints = ['accept_terms', 'static', 'login', 'register']
    if request.endpoint not in allowed_endpoints:
        if not session.get('accepted_terms'):
            return redirect(url_for('accept_terms'))

# ----------------------------- التحقق من الحظر -----------------------------
def is_user_banned(user_id):
    now = datetime.now()
    ban = Ban.query.filter(Ban.user_id == user_id, Ban.ends_at > now)\
        .order_by(Ban.ends_at.desc()).first()
    return ban

@app.before_request
def check_user_ban():
    allowed_endpoints = ['login', 'static', 'accept_terms', 'register']
    if request.endpoint in allowed_endpoints:
        return

    if has_request_context():
        try:
            if current_user.is_authenticated and current_user.username != "admin":
                ban = is_user_banned(current_user.id)
                if ban:
                    logout_user()
                    session.pop('username', None)
                    ends_at = ban.ends_at.strftime('%Y-%m-%d %H:%M') if ban.ends_at else "غير محدد"
                    flash(f"🔒 حسابك محظور حتى {ends_at}", "danger")
                    return redirect(url_for('login'))
        except Exception as e:
            print("خطأ أثناء التحقق من الحظر:", e)
            pass

@app.route('/')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))

    current_username = session['username']

    # جلب أفضل 3 أبيات حسب الإعجابات
    top_poems_raw = (
        db.session.query(Poem, User)
        .join(User, Poem.username == User.username)
        .order_by(Poem.likes.desc())
        .limit(3)
        .all()
    )

    # فلترة الأبيات من المحظورين
    filtered_top = []
    for poem, author in top_poems_raw:
        blocked = Block.query.filter(
            or_(
                (Block.blocker == current_username) & (Block.blocked == author.username),
                (Block.blocker == author.username) & (Block.blocked == current_username)
            )
        ).first()
        if not blocked:
            filtered_top.append((poem, author))

    # تنسيق التاريخ
    top_poems = []
    for poem, author in filtered_top:
        time_ago = humanize.naturaltime(datetime.now() - poem.created_at)
        top_poems.append({
            "id": poem.id,
            "text": poem.text,
            "likes": poem.likes,
            "views": poem.views,
            "username": author.username,
            "profile_image": author.profile_image,
            "verified": author.verified,
            "created_at": time_ago
        })

    # جميع الأبيات مع استثناء المحظورين
    blocked_users = [b.blocked for b in Block.query.filter_by(blocker=current_username).all()]
    all_poems_raw = (
        db.session.query(Poem, User)
        .join(User, Poem.username == User.username)
        .filter(~Poem.username.in_(blocked_users))
        .order_by(Poem.created_at.desc())
        .all()
    )

    all_poems = []
    for poem, author in all_poems_raw:
        poem.views += 1
        db.session.commit()
        time_ago = humanize.naturaltime(datetime.now() - poem.created_at)
        all_poems.append({
            "id": poem.id,
            "text": poem.text,
            "likes": poem.likes,
            "views": poem.views,
            "username": author.username,
            "profile_image": author.profile_image,
            "verified": author.verified,
            "created_at": time_ago
        })

    # الأبيات التي أعجب بها المستخدم
    liked = Like.query.filter_by(username=current_username).with_entities(Like.poem_id).all()
    user_liked = [row.poem_id for row in liked]

    # المحظورين للقائمة الجانبية
    sidebar = Block.query.filter_by(blocker=current_username).all()
    blocked_users_sidebar = [{"username": b.blocked} for b in sidebar]

    # ===================== جلب الستوريات =====================
    # جلب قائمة المتابعين (بدون إضافة المستخدم الحالي)
    following_users = db.session.query(Follower.followed_username)\
        .filter_by(username=current_username).all()
    following_list = [f.followed_username for f in following_users]

    # جلب الستوريات من المتابعين فقط والتي لم تنتهي بعد
    stories_raw = (
        db.session.query(Story, User)
        .join(User, Story.user_id == User.id)
        .filter(User.username.in_(following_list))
        .filter(Story.expires_at > datetime.utcnow())
        .order_by(Story.created_at.desc())
        .all()
    )

    # 📌 تجميع الستوريات حسب المستخدم
    stories_dict = {}
    for story, author in stories_raw:
        if author.username not in stories_dict:
            stories_dict[author.username] = {
                "username": author.username,
                "profile_image": author.profile_image,
                "stories": []
            }
        stories_dict[author.username]["stories"].append({
            "id": story.id,
            "media_path": story.media_path,
            "media_type": story.media_type,
            "created_at": story.created_at
        })

    # تحويل القاموس إلى قائمة
    stories = list(stories_dict.values())

    # ✅ إضافة ستوري المستخدم الحالي بشكل منفصل
    current_user_obj = User.query.filter_by(username=current_username).first()

    has_story_flag = Story.query.filter_by(user_id=current_user_obj.id)\
        .filter(Story.expires_at > datetime.utcnow())\
        .count() > 0

    user_story = Story.query.filter_by(user_id=current_user_obj.id)\
        .filter(Story.expires_at > datetime.utcnow())\
        .order_by(Story.created_at.desc())\
        .first()

    # 📌 تعديل my_story ليحتوي على الكائن user
    my_story = {
        "user": current_user_obj,  # الكائن User نفسه
        "id": user_story.id if user_story else None,
        "has_story": has_story_flag
    }

    has_stories = len(stories) > 0
    # ==========================================================

    return render_template('index.html',
                           username=current_username,
                           top_poems=top_poems,
                           all_poems=all_poems,
                           user_liked=user_liked,
                           blocked_users_sidebar=blocked_users_sidebar,
                           stories=stories,
                           my_story=my_story,
                           has_stories=has_stories)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash("❗ يرجى ملء جميع الحقول.", "warning")
            return render_template("login.html")

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            # التحقق من وجود حظر نشط
            now = datetime.now()
            active_ban = Ban.query.filter(
                Ban.username == username,
                Ban.ends_at != None,
                Ban.ends_at > now
            ).first()

            if active_ban:
                ends_at_str = active_ban.ends_at.strftime('%Y-%m-%d %H:%M') if active_ban.ends_at else "غير محدد"
                flash(f"🚫 حسابك محظور حتى {ends_at_str}.", "danger")
                return redirect(url_for('login'))

            # تسجيل الدخول باستخدام كائن SimpleUser
            login_user(SimpleUser(user))
            session["username"] = username
            flash("✅ تم تسجيل الدخول بنجاح", "success")
            return redirect(url_for("home"))

        flash("❌ اسم المستخدم أو كلمة المرور غير صحيحة", "danger")

    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()

        # --- ⚠️ تحديد إذا هو بريميوم (حالياً False)
        is_premium = False  # أو True لو عندك نظام تفعيل مخصص

        # --- ✅ التحقق من صلاحية اسم المستخدم حسب حالة البريميوم
        if not re.match("^[A-Za-z0-9_]+$", username):
            flash("⚠️ اسم المستخدم يجب أن يحتوي فقط على أحرف إنجليزية أو أرقام أو شرطة سفلية.")
            return render_template("signup.html")

        if len(username) < 4 and not is_premium:
            flash("⚠️ اسم المستخدم يجب أن يكون 4 أحرف على الأقل، أو اشترك بريميوم لاستخدام اسم أقصر.")
            return render_template("signup.html")

        # --- كلمة المرور
        if len(password) < 8:
            flash("⚠️ كلمة المرور يجب أن تكون 8 أحرف على الأقل.")
            return render_template("signup.html")

        # --- هل الاسم مستخدم مسبقًا؟
        existing = User.query.filter_by(username=username).first()
        if existing:
            flash("⚠️ اسم المستخدم موجود مسبقًا. اختر اسمًا آخر.")
            return render_template("signup.html")

        # --- إنشاء الحساب
        hashed_password = generate_password_hash(password)
        user = User(
            username=username,
            password=hashed_password,
            first_name=first_name,
            last_name=last_name
        )

        # ✅ تفعيل البريميوم تلقائيًا لو عندك منطق لذلك
        if is_premium:
            user.premium_until = datetime.utcnow() + timedelta(days=30)

        db.session.add(user)
        db.session.commit()

        session["username"] = username
        flash("✅ تم إنشاء الحساب بنجاح! مرحبًا بك 🌟")
        return redirect(url_for("home"))

    return render_template("signup.html")


# 📌 تسجيل الخروج
@app.route("/logout")
def logout():
    session.clear()  # 🟢 يمسح كل بيانات الجلسة (username + أي متغيرات ثانية)
    flash("تم تسجيل الخروج.")
    return redirect(url_for("login"))

@app.route("/profile/<username>", methods=["GET", "POST"])
def public_profile(username):
    current_user = session.get("username")
    if not current_user:
        return redirect(url_for("login"))

    user = User.query.filter_by(username=username).first()
    if not user:
        return "المستخدم غير موجود", 404

    is_following = Follower.query.filter_by(
        username=current_user,
        followed_username=username
    ).first() is not None

    blocked = Block.query.filter_by(
        blocker=current_user,
        blocked=username
    ).first() is not None

    # هل أرسل طلب متابعة سابقًا
    follow_request_sent = FollowRequest.query.filter_by(
        sender_username=current_user,
        receiver_username=username,
        status='pending'
    ).first() is not None

    if request.method == "POST":
        action = request.form.get("action")

        if action == "follow":
            if user.private:
                existing_request = FollowRequest.query.filter_by(
                    sender_username=current_user,
                    receiver_username=username,
                    status='pending'
                ).first()
                if not existing_request:
                    new_request = FollowRequest(
                        sender_username=current_user,
                        receiver_username=username,
                        status='pending'
                    )
                    db.session.add(new_request)

                    # إرسال إشعار لصاحب الحساب
                    notif = Notification(
                        recipient=username,
                        sender=current_user,
                        type='follow_request',
                        content=json.dumps({}),
                        timestamp=datetime.utcnow()
                    )
                    db.session.add(notif)
            else:
                exists = Follower.query.filter_by(
                    username=current_user,
                    followed_username=username
                ).first()
                if not exists:
                    db.session.add(Follower(
                        username=current_user,
                        followed_username=username
                    ))

                    # إرسال إشعار بالمتابعة
                    notif = Notification(
                        recipient=username,
                        sender=current_user,
                        type='follow',
                        content=json.dumps({}),
                        timestamp=datetime.utcnow()
                    )
                    db.session.add(notif)

        elif action == "unfollow":
            Follower.query.filter_by(
                username=current_user,
                followed_username=username
            ).delete()

        elif action == "block":
            if not Block.query.filter_by(
                blocker=current_user,
                blocked=username
            ).first():
                db.session.add(Block(
                    blocker=current_user,
                    blocked=username
                ))

        elif action == "unblock":
            Block.query.filter_by(
                blocker=current_user,
                blocked=username
            ).delete()

        db.session.commit()
        return redirect(url_for("public_profile", username=username))

    # عدد المتابعين
    followers = Follower.query.filter_by(followed_username=username).all()
    followers_count = len(followers)

    # الأبيات
    user_poems = Poem.query.filter_by(username=username).all()

    # مجموع الإعجابات
    total_likes = db.session.query(db.func.sum(Poem.likes))\
                            .filter_by(username=username).scalar() or 0

    return render_template("profile.html",
                           user=user,user_poems=user_poems,
                           total_likes=total_likes,
                           followers_count=followers_count,
                           followers=followers,
                           is_following=is_following,
                           current_user=current_user,
                           blocked=blocked,
                           follow_request_sent=follow_request_sent)

@app.route("/profile")
def my_profile():
    if "username" not in session:
        return redirect("/login")
    return redirect(url_for("public_profile", username=session["username"]))


@app.route("/edit_profile", methods=["GET", "POST"])
def edit_profile():
    if "username" not in session:
        flash("يجب تسجيل الدخول أولاً.")
        return redirect("/login")

    user = User.query.filter_by(username=session["username"]).first()
    if not user:
        flash("المستخدم غير موجود.")
        return redirect("/")

    if request.method == "POST":
        new_username = request.form.get("username", "").strip()
        full_name = request.form.get("full_name", "").strip()
        bio = request.form.get("bio", "").strip()

        # تقسيم الاسم الكامل
        first_name = ""
        last_name = ""
        if full_name:
            parts = full_name.split(" ", 1)
            first_name = parts[0]
            if len(parts) > 1:
                last_name = parts[1]

        # 🔐 تحقق خاص بأسماء أقل من 4 أحرف
        if len(new_username) < 4 and not user.is_premium():
            flash("⚠️ لا يمكن استخدام اسم مستخدم أقل من 4 أحرف إلا إذا كنت مشتركًا بريميوم.")
            return redirect(url_for("edit_profile"))

        # تحقق عام لصلاحية الاسم
        if not valid_username(new_username):
            flash("⚠️ اسم المستخدم غير صالح.")
            return redirect(url_for("edit_profile"))

        # معالجة صورة الملف الشخصي
        profile_image_file = request.files.get("profile_pic")
        profile_image_filename = user.profile_image or "default.jpg"
        if profile_image_file and profile_image_file.filename != "":
            filename = secure_filename(profile_image_file.filename)
            profile_image_filename = filename
            image_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
            profile_image_file.save(image_path)

        # محاولة التحديث
        try:
            user.username = new_username
            user.first_name = first_name
            user.last_name = last_name
            user.bio = bio
            user.profile_image = profile_image_filename
            db.session.commit()

            session["username"] = new_username
            flash("✅ تم تحديث الملف الشخصي بنجاح!")
            return redirect(url_for("public_profile", username=new_username))

        except:
            db.session.rollback()
            flash("⚠️ اسم المستخدم موجود مسبقًا.")
            return redirect(url_for("edit_profile"))

    full_name = f"{user.first_name or ''} {user.last_name or ''}".strip()
    return render_template("edit_profile.html",
                           username=user.username,
                           full_name=full_name,
                           bio=user.bio or "",
                           profile_pic=user.profile_image or "default.jpg")


# ✅ متابعة مستخدم
@app.route('/follow', methods=['POST'])
@login_required
def follow():
    target_user = request.form.get('target_user')
    current_username = current_user.username  # استخدم Flask-Login بدلًا من session مباشرة

    # التأكد من أن المستخدم لا يتابع نفسه
    if target_user and target_user != current_username:
        exists = Follower.query.filter_by(username=current_username, followed_username=target_user).first()

        if not exists:
            # إنشاء علاقة المتابعة
            follow_relation = Follower(username=current_username, followed_username=target_user)
            db.session.add(follow_relation)

            # إنشاء إشعار في قاعدة البيانات
            notification = Notification(
                recipient=target_user,
                sender=current_username,
                type="follow",
                content=f"{current_username} بدأ متابعتك!"
            )
            db.session.add(notification)

            # إرسال الإشعار اللحظي عبر Socket.IO
            send_notification(target_user, f"{current_username} بدأ متابعتك! 👥")

            db.session.commit()
            flash(f'تمت متابعة {target_user} بنجاح ✅', 'success')
        else:
            flash(f'أنت تتابع {target_user} بالفعل.', 'info')
    else:
        flash('❌ لا يمكن متابعة نفسك أو مدخل غير صالح.', 'danger')

    return redirect(request.referrer or url_for('search'))

# البحث عن مستخدمين
@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'username' not in session:
        flash('يجب تسجيل الدخول أولاً', 'warning')
        return redirect(url_for('login'))

    results = None
    keyword = ''

    if request.method == 'POST':
        keyword = request.form.get('keyword', '').strip()
        if keyword:
            results = User.query.filter(
                or_(
                    User.username.ilike(f"%{keyword}%"),
                    User.first_name.ilike(f"%{keyword}%"),
                    User.last_name.ilike(f"%{keyword}%")
                )
            ).all()

    return render_template('search.html', results=results, current_user=session.get('username'))

from flask_login import login_required, current_user

@app.route('/explore')
@login_required
def explore_page():
    current_username = current_user.username  # استخدم Flask-Login

    # ✅ الأبيات الأكثر إعجابًا (مع التحقق من حالة التوثيق)
    top_poems_query = (
        db.session.query(Poem, User.profile_image, User.verified)
        .join(User, Poem.username == User.username)
        .order_by(Poem.likes.desc())
        .limit(10)
        .all()
    )

    top_poems = []
    for poem, profile_image, verified in top_poems_query:
        top_poems.append({
            'id': poem.id,
            'text': poem.text,
            'likes': poem.likes,
            'views': poem.views,
            'username': poem.username,
            'profile_image': profile_image,
            'verified': verified,  # ✅ إضافة حالة التوثيق
            'created_ago': time_ago(poem.created_at)
        })

    # ✅ المستخدمون المقترحون (مع التحقق من حالة التوثيق)
    followed_subquery = (
        db.session.query(Follower.followed_username)
        .filter(Follower.username == current_username)
    )

    suggested_users = (
        db.session.query(User.username, User.first_name, User.last_name, User.profile_image, User.verified)
        .filter(User.username != current_username)
        .filter(~User.username.in_(followed_subquery))
        .limit(5)
        .all()
    )

    suggested_users_list = []
    for username, first_name, last_name, profile_image, verified in suggested_users:
        suggested_users_list.append({
            'username': username,
            'first_name': first_name,
            'last_name': last_name,
            'profile_image': profile_image,
            'verified': verified  # ✅ إضافة حالة التوثيق
        })

    # ✅ الأبيات التي أعجب بها المستخدم
    liked_poems_ids = (
        db.session.query(Like.poem_id)
        .filter(Like.username == current_username)
        .with_entities(Like.poem_id)
        .all()
    )
    liked_poems_ids = [poem_id for (poem_id,) in liked_poems_ids]

    return render_template(
        'explore.html',
        top_poems=top_poems,
        suggested_users=suggested_users_list,
        user_liked=liked_poems_ids
    )

# ✅ تعديل عدد اللايكات (للمسؤول فقط)
@app.route('/admin/setlike/<int:poem_id>/<int:like_count>')
def admin_set_likes(poem_id, like_count):
    if 'username' not in session or session['username'] != 'admin':
        return "ممنوع الدخول!", 403

    poem = Poem.query.get(poem_id)
    if poem:
        poem.likes = like_count
        db.session.commit()
        return f"✅ تم تعديل عدد اللايكات للمنشور رقم {poem_id} إلى {like_count}"
    return "المنشور غير موجود", 404


# ✅ زيادة عدد مشاهدات مخصص (للمسؤول فقط)
@app.route('/admin/addviews/<int:poem_id>/<int:view_count>')
def admin_add_views(poem_id, view_count):
    if 'username' not in session or session['username'] != 'admin':
        return "ممنوع الدخول!", 403

    poem = Poem.query.get(poem_id)
    if poem:
        poem.views += view_count
        db.session.commit()
        return f"👁️ تمت إضافة {view_count} مشاهدة للمنشور رقم {poem_id}. عدد المشاهدات الآن: {poem.views}"
    return "المنشور غير موجود", 404

# 🗑️ حذف بيت شعري
@app.route('/delete/<int:poem_id>')
def delete(poem_id):
    poem = Poem.query.get(poem_id)
    if poem:
        db.session.delete(poem)
        db.session.commit()
    return redirect(url_for('home'))


# ➕ إرسال بيت شعري جديد
@app.route('/submit', methods=['POST'])
def submit():
    if 'username' not in session:
        return redirect(url_for('login'))

    text = request.form.get('text')
    username = session.get('username')

    new_poem = Poem(text=text, username=username)
    db.session.add(new_poem)
    db.session.commit()

    return redirect(url_for('home'))



# 🚩 إبلاغ عن بيت شعري
@app.route('/report/<int:poem_id>')
def report_poem(poem_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    existing_report = Report.query.filter_by(poem_id=poem_id, reported_by=username).first()

    if existing_report:
        return "تم الإبلاغ مسبقًا عن هذا البيت."

    report = Report(poem_id=poem_id, reported_by=username)
    db.session.add(report)
    db.session.commit()
    return redirect(request.referrer or url_for('explore_page'))


# 🚫 حظر مستخدم
@app.route('/block_user/<username>')
def block_user(username):
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = session['username']
    if current_user == username:
        flash("❌ لا يمكنك حظر نفسك.", "danger")
        return redirect(request.referrer or url_for('explore_page'))

    block = Block.query.filter_by(blocker=current_user, blocked=username).first()
    if not block:
        db.session.add(Block(blocker=current_user, blocked=username))
        db.session.commit()

    flash(f"🚫 تم حظر {username}.", "info")
    return redirect(request.referrer or url_for('explore_page'))

# 🔓 إلغاء الحظر
@app.route('/unblock/<username>', methods=['POST'])
def unblock_user(username):
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = session['username']
    block = Block.query.filter_by(blocker=current_user, blocked=username).first()
    if block:
        db.session.delete(block)
        db.session.commit()

    return redirect(request.referrer or url_for('home'))



@app.route("/messages/<username>")
def view_messages(username):
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = session['username']  # نص، ليس كائن User
    anonymous_mode = request.args.get("anonymous", "0") == "1"

    # التحقق من الحظر بين المستخدمين
    blocked_entry = Block.query.filter(
        or_(
            and_(Block.blocker == current_user, Block.blocked == username),
            and_(Block.blocker == username, Block.blocked == current_user)
        )
    ).first()
    is_blocked = bool(blocked_entry)

    if is_blocked:
        messages = []
        display_name = "User is unavailable"
        profile_visible = False
    else:
        # جلب الرسائل
        msgs = Message.query.filter(
            and_(
                or_(
                    and_(Message.sender == current_user, Message.receiver == username),
                    and_(Message.sender == username, Message.receiver == current_user)
                ),
                Message.is_anonymous == anonymous_mode
            )
        ).order_by(Message.timestamp).all()

        messages = []
        for msg in msgs:
            show_sender = True
            if msg.is_anonymous:
                sender_user = User.query.filter_by(username=msg.sender).first()
                if sender_user and not sender_user.is_premium():
                    show_sender = False
            messages.append({'msg': msg, 'show_sender': show_sender})

        display_name = username
        profile_visible = True

    # 🛑 حساب عدد المحادثات غير المقروءة بدل الرسائل
    unread_conversations_count = (
        db.session.query(Message.sender)
        .filter(Message.receiver == current_user, Message.is_read == False)
        .distinct()
        .count()
    )

    unread_notifications_count = Notification.query.filter_by(
        recipient=current_user, is_read=False
    ).count()

    return render_template(
        "messages.html",
        messages=messages,
        is_blocked=is_blocked,
        current_user=current_user,
        anonymous_mode=anonymous_mode,
        display_name=display_name,
        profile_visible=profile_visible,
        real_username=username,  # كما طلبت
        unread_messages_count=unread_conversations_count,  # ← صار يعرض عدد المحادثات
        unread_notifications_count=unread_notifications_count,
        has_unread_messages=(unread_conversations_count > 0),
        has_unread_notifications=(unread_notifications_count > 0)
    )
# 📤 إرسال رسالة جديدة
@app.route("/send_message/<username>", methods=["POST"])
def send_message(username):
    if 'username' not in session:
        return redirect(url_for("login"))

    sender = session['username']
    content = request.form.get("content")
    file_path = None

    # التعامل مع الملف (اختياري)
    file = request.files.get("file")
    if file and file.filename != '':
        filename = secure_filename(file.filename)
        upload_folder = os.path.join('static', 'uploads')
        os.makedirs(upload_folder, exist_ok=True)
        full_path = os.path.join(upload_folder, filename)
        file.save(full_path)
        # نخزن المسار بالنسبة لـ static
        file_path = f"uploads/{filename}"

    # هل المستخدم أرسل الرسالة كمجهول؟
    anonymous = 'anonymous' in request.form

    # جلب حساب المرسل من قاعدة البيانات
    sender_user = User.query.filter_by(username=sender).first()

    # إنشاء الرسالة
    message = Message(
        sender=sender,
        receiver=username,
        content=content,
        file_path=file_path,
        is_anonymous=anonymous   # عمود واحد فقط بدون تكرار
    )
    db.session.add(message)
    db.session.commit()

    # إرسال إشعار للمستلم
    if username != sender:
        send_notification(username, "📨 وصلك رسالة جديدة!")

    # نعيد التوجيه وعرض الرسائل
    return redirect(url_for("view_messages", username=username))


# 🚨 كود البلاغ عن محادثة
@app.route("/report_conversation/<username>")
def report_conversation(username):
    if 'username' not in session:
        return redirect(url_for("login"))

    reporter = session['username']

    report = MessageReport(reported_user=username, reporter=reporter)
    db.session.add(report)
    db.session.commit()

    return f"تم الإبلاغ عن المحادثة مع {username} بنجاح!"


@app.route('/inbox')
def inbox():
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user_name = session['username']
    anonymous = request.args.get("anonymous", "0") == "1"

    # جلب جميع الرسائل الخاصة أو المجهولة المتعلقة بالمستخدم
    messages = Message.query.filter(
        ((Message.sender == current_user_name) | (Message.receiver == current_user_name)) &
        (Message.anonymous == anonymous)
    ).order_by(Message.timestamp.desc()).all()

    # إنشاء قائمة المحادثات مع كل مستخدم تم التواصل معه
    conversation_users = {}
    for msg in messages:
        other_user = msg.receiver if msg.sender == current_user_name else msg.sender
        if other_user not in conversation_users:
            conversation_users[other_user] = msg.timestamp  # نحفظ توقيت آخر رسالة

    # ترتيب المستخدمين حسب آخر رسالة
    sorted_usernames = sorted(conversation_users.items(), key=lambda x: x[1], reverse=True)

    # تجهيز بيانات المستخدمين للعرض في الواجهة
    users = []
    for username, _ in sorted_usernames:
        user = User.query.filter_by(username=username).first()
        if user:
            display_name = "مجهول" if anonymous else (user.first_name or user.username)

            # 🔹 حساب عدد الرسائل غير المقروءة من هذا المستخدم
            unread_count = Message.query.filter_by(
                sender=username,
                receiver=current_user_name,
                is_read=False,
                anonymous=anonymous
            ).count()

            users.append({
                "username": user.username,
                "display_name": display_name,
                "profile_image": user.profile_image or "default.jpg",
                "unread_count": unread_count
            })

    return render_template('inbox.html', users=users, anonymous=anonymous)

@app.route("/unfollow/<username>")
def unfollow(username):
    if "username" not in session:
        flash("يجب تسجيل الدخول أولاً.")
        return redirect("/login")

    from models import Follower
    try:
        Follower.query.filter_by(
            username=session["username"],
            followed_username=username
        ).delete()
        db.session.commit()
        flash("تم إلغاء المتابعة.")
        return redirect(url_for("public_profile", username=username))

    except Exception as e:
        db.session.rollback()
        print("Error in /unfollow route:", e)
        return "حدث خطأ في السيرفر.", 500





@app.route("/blocked_users")
def blocked_users():
    if "username" not in session:
        return redirect(url_for("login"))

    current_username = session["username"]
    blocks = Block.query.filter_by(blocker=current_username).all()

    blocked_users = []
    for entry in blocks:
        user = User.query.filter_by(username=entry.blocked).first()
        if user:
            blocked_users.append(user)

    return render_template("blocked_users.html", users=blocked_users)




from flask import (
    Flask, render_template, session, redirect, url_for,
    request, jsonify, flash
)


# ❤️ زر الإعجاب
@app.route('/like/<int:poem_id>')
def like(poem_id):
    if 'username' not in session:
        return jsonify({'success': False, 'redirect': url_for('login')})

      # ✅

    username = session['username']
    poem = Poem.query.get(poem_id)
    if not poem:
        return jsonify({'success': False, 'message': 'البيت غير موجود'})

    existing_like = Like.query.filter_by(username=username, poem_id=poem_id).first()

    if existing_like:
        db.session.delete(existing_like)
        poem.likes -= 1
    else:
        new_like = Like(username=username, poem_id=poem_id)
        db.session.add(new_like)
        poem.likes += 1

        # ✅ إشعار لحظي
        if poem.username != username:
            notification = Notification(
                recipient=poem.username,
                sender=username,
                type="like",
                content=f"{username} أعجب ببيتك!"
            )
            db.session.add(notification)

            send_notification(poem.username, f"{username} أعجب ببيتك! ❤️")

    db.session.commit()

    return jsonify({'success': True, 'likes': poem.likes})

@app.route('/handle_follow_request', methods=['POST'])
@login_required
def handle_follow_request():
    notif_id = request.form.get('notif_id')
    action = request.form.get('action')  # "accept" أو "reject"

    # جلب الإشعار
    notif = Notification.query.get_or_404(notif_id)

    # التحقق من أن نوع الإشعار هو طلب متابعة
    if notif.type != 'follow_request':
        flash('نوع الإشعار غير صالح.', 'danger')
        return redirect(url_for('notifications'))

    # إذا تم قبول الطلب
    if action == 'accept':
        # التحقق من عدم وجود علاقة متابعة مسبقة
        existing = Follower.query.filter_by(
            username=notif.sender,
            followed_username=notif.recipient
        ).first()

        if not existing:
            new_follower = Follower(
                username=notif.sender,            # المرسل
                followed_username=notif.recipient # أنت
            )
            db.session.add(new_follower)
            flash(f'✅ تم قبول طلب المتابعة من {notif.sender}.', 'success')
        else:
            flash(f'⚠️ {notif.sender} يتابعك بالفعل.', 'info')

    elif action == 'reject':
        flash(f'❌ تم رفض طلب المتابعة من {notif.sender}.', 'info')

    # حذف الإشعار في كلتا الحالتين
    db.session.delete(notif)
    db.session.commit()

    # إعادة التوجيه إلى بروفايل المرسل
    return redirect(url_for('public_profile', username=notif.sender))
# ----------------------------- حذف إشعار -----------------------------
@app.route("/delete_notification/<int:notif_id>", methods=["POST"])
def delete_notification(notif_id):
    if "username" not in session:
        return jsonify({"status": "unauthorized"}), 401

    notif = Notification.query.get_or_404(notif_id)
    if notif.recipient != session["username"]:
        return jsonify({"status": "forbidden"}), 403

    db.session.delete(notif)
    db.session.commit()
    return jsonify({"status": "deleted"}), 200


@app.route("/notifications")
@login_required
def notifications():
    notifs = Notification.query.filter_by(recipient=current_user.username)\
                .order_by(Notification.timestamp.desc()).all()

    notif_data = []
    for n in notifs:
        sender_user = User.query.filter_by(username=n.sender).first()
        sender_image = sender_user.profile_image if sender_user and sender_user.profile_image else "default.jpg"

        # تحديد الرابط حسب النوع
        if n.type in ["like", "comment"] and n.poem_id:
            # لو فيه line_id في content، نضيفه للرابط
            if n.content:
                link = url_for("poem", poem_id=n.poem_id) + f"#line-{n.content}"
            else:
                link = url_for("view_poem", poem_id=n.poem_id)
        elif n.type in ["follow", "follow_request"]:
            link = url_for("public_profile", username=n.sender)
        else:
            link = url_for("notifications")

        notif_data.append({
            "id": n.id,
            "sender": n.sender,
            "sender_image": sender_image,
            "type": n.type,
            "is_read": n.is_read,
            "time_ago": time_ago_format(n.timestamp),
            "link": url_for("mark_notification_read", notif_id=n.id, next_url=link)
        })

    return render_template("notifications.html", notifications=notif_data)

@app.route("/notification/read/<int:notif_id>")
@login_required
def mark_notification_read(notif_id):
    notif = Notification.query.get_or_404(notif_id)

    # التحقق من ملكية الإشعار
    if notif.recipient != current_user.username:
        return redirect(url_for("notifications"))

    # تحديث حالة القراءة
    notif.is_read = True
    db.session.commit()

    # تحديد الرابط المناسب
    if notif.type in ["like", "comment"] and notif.poem_id:
        # لو الإشعار يخص بيت معين، نضيف line_id للعنوان
        next_url = url_for("poem", poem_id=notif.poem_id, line_id=notif.content or None)  # نفترض notif.content فيه line_id
        if notif.content:
            next_url += f"#line-{notif.content}"  # عشان ينزل مباشرة للبيت
    elif notif.type in ["follow", "follow_request"]:
        next_url = url_for("public_profile", username=notif.sender)
    else:
        next_url = url_for("notifications")

    return redirect(next_url)

@app.route('/settings')
def settings():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("settings.html")


# عرض بيت شعري مفرد
@app.route("/poem/<int:poem_id>")
@login_required
def view_poem(poem_id):
    from models import Poem, User, Line  # تأكد أن الموديل Line موجود

    # جلب القصيدة
    poem = Poem.query.get_or_404(poem_id)

    # جلب كاتب القصيدة
    user = User.query.filter_by(username=poem.username).first()

    # جلب الأبيات المرتبطة وترتيبها
    lines = Line.query.filter_by(poem_id=poem.id).order_by(Line.id.asc()).all()

    # لو جاي من إشعار، ناخذ line_id من الرابط
    line_id = request.args.get("line_id", type=int)

    return render_template(
        "view_poem.html",
        poem=poem,
        user=user,
        lines=lines,
        highlight_line_id=line_id  # نرسله للقالب لو نحتاج تمييز البيت
    )

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        current_password = request.form["current_password"]
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]
        user = User.query.filter_by(username=session["username"]).first()

        if not user or not check_password_hash(user.password, current_password):
            flash("❌ كلمة المرور الحالية غير صحيحة", "danger")
            return redirect(url_for("change_password"))

        if new_password != confirm_password:
            flash("❌ كلمة المرور الجديدة غير متطابقة", "danger")
            return redirect(url_for("change_password"))

        user.password = generate_password_hash(new_password)
        db.session.commit()

        flash("✅ تم تغيير كلمة المرور بنجاح", "success")
        return redirect(url_for("settings"))

    return render_template("change_password.html")

@app.route('/confirm_delete_account')
def confirm_delete_account():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("confirm_delete_account.html")


@app.route('/delete_account', methods=['POST'])
def delete_account():
    if "username" not in session:
        return redirect(url_for("login"))

    password = request.form.get("password")
    user = User.query.filter_by(username=session["username"]).first()

    if not user or user.password != password:
        flash("❌ كلمة المرور غير صحيحة. لم يتم حذف الحساب.", "danger")
        return redirect(url_for("confirm_delete_account"))

    db.session.delete(user)
    db.session.commit()
    session.pop("username", None)
    flash("✅ تم حذف الحساب بنجاح", "success")
    return redirect(url_for("signup"))


@app.route('/settings/dark_mode')
def settings_dark_mode():
    return redirect(url_for('settings'))

@app.route('/settings/privacy', methods=['GET', 'POST'])
def settings_privacy():
    if "username" not in session:
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session["username"]).first()

    if request.method == 'POST':
        user.private = request.form.get("is_private") == "on"
        user.allow_anonymous_messages = request.form.get("allow_anonymous_messages") == "on"
        db.session.commit()
        flash("✅ تم حفظ إعدادات الخصوصية بنجاح", "success")
        return redirect(url_for("settings_privacy"))

    return render_template("privacy_settings.html", user=user)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        message = request.form.get("message")

        msg = ContactMessage(name=name, email=email, message=message)
        db.session.add(msg)
        db.session.commit()

        flash("✅ تم إرسال رسالتك بنجاح! سنقوم بالرد عليك قريبًا.", "success")
        return redirect(url_for("contact"))

    return render_template("contact.html")


@app.route('/memo')
@login_required
def memo_dashboard():
    if not current_user.is_authenticated or not current_user.is_admin:
        return redirect(url_for('home'))
    return render_template('memo_dashboard.html')


# ✅ إدارة المستخدمين
@app.route('/memo/users')
@login_required
def memo_users():
    if not current_user.is_authenticated or not current_user.is_admin:
        return redirect(url_for('home'))

    users = User.query.order_by(User.id.desc()).all()
    return render_template('memo_users.html', users=users)

# حذف مستخدم
@app.route('/memo/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
    return redirect(url_for('memo_users'))

# إضافة مستخدم
@app.route('/memo/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'], method='sha256')
        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('memo_users'))

    return render_template('memo_add_user.html')

# تعديل مستخدم
@app.route('/memo/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('memo_users'))

    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        db.session.commit()
        return redirect(url_for('memo_users'))

    return render_template('memo_edit_user.html', user=user)

# رسائل "تواصل معنا"
@app.route('/memo/contact-messages')
@login_required
def memo_contact_messages():
    if not current_user.is_admin:
        return redirect(url_for("index"))

    from models import ContactMessage  # تأكد من وجود هذا الاستيراد
    from sqlalchemy import desc        # ضروري للترتيب التنازلي

    messages = ContactMessage.query.order_by(desc(ContactMessage.sent_at)).all()
    return render_template("memo_contact_messages.html", messages=messages)
@app.route('/memo/contact-messages/delete/<int:message_id>', methods=['POST'])
@login_required
def delete_contact_message(message_id):
    if not current_user.is_admin:
        return redirect(url_for("index"))

    message = ContactMessage.query.get(message_id)
    if message:
        db.session.delete(message)
        db.session.commit()

    flash("🗑️ تم حذف الرسالة بنجاح.", "success")
    return redirect(url_for("memo_contact_messages"))

# إدارة الأبيات
@app.route('/memo/poems')
@login_required
def memo_poems():
    if not current_user.is_admin:
        return redirect(url_for('home'))

    poems = Poem.query.order_by(Poem.created_at.desc()).all()
    return render_template("memo_poems.html", poems=poems)

@app.route('/memo/delete_poem/<int:poem_id>', methods=["POST"])
@login_required
def delete_poem_admin(poem_id):
    if not current_user.is_admin:
        return redirect(url_for("home"))

    poem = Poem.query.get(poem_id)
    if poem:
        db.session.delete(poem)
        db.session.commit()
        flash("✅ تم حذف البيت بنجاح.", "success")

    return redirect(url_for("memo_poems"))

# صفحة إشعارات الإدارة
@app.route("/memo/notifications")
@login_required
def memo_notifications():
    if not current_user.username == "admin":
        return redirect(url_for("home"))
    return render_template("memo_notifications.html")
# إعدادات عامة
@app.route("/memo/settings", methods=["GET", "POST"])
@login_required
def memo_settings():
    if not current_user.is_admin:
        return redirect(url_for("home"))

    from models import Settings
    settings = Settings.query.get(1)

    # 🛠️ إذا لم توجد إعدادات، نقوم بإنشائها تلقائيًا
    if not settings:
        settings = Settings(id=1)
        db.session.add(settings)
        db.session.commit()

    def get_int_or_default(key, default):
        val = request.form.get(key, "")
        return int(val) if val.isdigit() else default

    if request.method == "POST":
        settings.site_name = request.form.get("site_name", "").strip()
        settings.site_description = request.form.get("site_description", "").strip()

        settings.allow_registration = bool(request.form.get("allow_registration"))
        settings.maintenance_mode = bool(request.form.get("maintenance_mode"))
        settings.auto_verify_users = bool(request.form.get("auto_verify_users"))

        settings.default_ban_duration_days = get_int_or_default("default_ban_duration_days", 7)
        settings.max_login_attempts = get_int_or_default("max_login_attempts", 5)
        settings.ban_duration_minutes = get_int_or_default("ban_duration_minutes", 60)

        settings.max_poem_length = get_int_or_default("max_poem_length", 250)
        settings.post_interval_seconds = get_int_or_default("post_interval_seconds", 60)

        settings.enable_likes = bool(request.form.get("enable_likes"))
        settings.enable_comments = bool(request.form.get("enable_comments"))
        settings.enable_saved = bool(request.form.get("enable_saved"))
        settings.enable_notifications = bool(request.form.get("enable_notifications"))
        settings.enable_messages = bool(request.form.get("enable_messages"))

        settings.instagram_url = request.form.get("instagram_url", "").strip()
        settings.twitter_url = request.form.get("twitter_url", "").strip()
        settings.contact_email = request.form.get("contact_email", "").strip()

        settings.admin_panel_name = request.form.get("admin_panel_name", "ميمو").strip()
        settings.dark_mode = bool(request.form.get("dark_mode"))

        settings.blocked_words = request.form.get("blocked_words", "").strip()

        db.session.commit()
        flash("✅ تم تحديث الإعدادات بنجاح", "success")

    return render_template("memo_settings.html", settings=settings)

@app.route('/test_notification')
def test_notification():
    socketio.emit("new_notification", {"message": "هذا إشعار تجريبي!"}, to="admin")
    return "تم إرسال الإشعار"

@app.route('/increase_followers/<int:user_id>', methods=['POST'])
@login_required
def increase_followers(user_id):
    from models import db, User, Follower
    import random
    import string

    user = User.query.get_or_404(user_id)
    amount = int(request.form.get('amount', 1))

    for _ in range(amount):
        # توليد اسم مستخدم وهمي فريد
        fake_username = 'fake_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        
        # إضافة متابع وهمي جديد إلى جدول Follower
        new_follower = Follower(
            username=fake_username,
            followed_username=user.username
        )
        db.session.add(new_follower)

    db.session.commit()

    # إعادة تحميل عدد المتابعين من جدول Follower مباشرة
    follower_count = Follower.query.filter_by(followed_username=user.username).count()

    return jsonify({
        'success': True,
        'followers': follower_count
    })
# توثيق المستخدم
@app.route('/verify_user/<int:user_id>', methods=['POST'])
@login_required
def verify_user_route(user_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))

    user = User.query.get(user_id)
    if user:
        user.verified = True
        db.session.commit()
    return redirect(url_for('memo_users'))

# إزالة التوثيق
@app.route('/unverify_user/<int:user_id>', methods=['POST'])
@login_required
def unverify_user_route(user_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))

    user = User.query.get(user_id)
    if user:
        user.verified = False
        db.session.commit()
    return redirect(url_for('memo_users'))



# صفحة عرض المحظورين
@app.route('/memo/bans')
@login_required
def memo_bans():
    if not current_user.is_admin:
        return redirect(url_for('home'))

    bans = Ban.query.join(User, Ban.username == User.username).add_columns(
        Ban.id,
        User.username,
        User.first_name,
        User.last_name,
        Ban.banned_at,
        Ban.duration_days,
        Ban.reason
    ).order_by(Ban.banned_at.desc()).all()

    now = datetime.now()
    bans_processed = []
    for b in bans:
        banned_at = b.banned_at
        duration_days = b.duration_days or 0
        ends_at = banned_at + timedelta(days=duration_days)
        is_active = now < ends_at
        bans_processed.append({
            "id": b.id,
            "username": b.username,
            "full_name": f"{b.first_name or ''} {b.last_name or ''}",
            "banned_at": banned_at,
            "ends_at": ends_at,
            "reason": b.reason,
            "active": is_active
        })

    return render_template('memo_bans.html', bans=bans_processed)



@app.route('/unban_user/<int:ban_id>', methods=['POST'])
@login_required
def unban_user(ban_id):
    if not hasattr(current_user, "is_admin") or not current_user.is_admin:
        flash("❌ ليس لديك صلاحيات إدارية.", "danger")
        return redirect(url_for('home'))

    ban = Ban.query.get_or_404(ban_id)

    # تحديث تاريخ الانتهاء ليتم رفع الحظر فوراً
    ban.end_date = datetime.utcnow()
    db.session.commit()

    flash("✅ تم رفع الحظر عن المستخدم بنجاح", "success")
    return redirect(url_for('memo_bans'))

@app.route('/memo/bans/add', methods=['GET', 'POST'])
@login_required
def memo_ban_form():
    if not current_user.is_admin:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username')
        duration_days = int(request.form.get('duration'))
        reason = request.form.get('reason')

        # الحصول على المستخدم
        user = User.query.filter_by(username=username).first()

        if not user:
            flash("❌ المستخدم غير موجود", "danger")
            return redirect(url_for('memo_ban_form'))

        # التحقق إذا كان محظور مسبقًا
        active_ban = Ban.query.filter(
            Ban.user_id == user.id,
            Ban.ends_at > datetime.utcnow()
        ).first()

        if active_ban:
            flash("⚠️ المستخدم محظور بالفعل", "warning")
            return redirect(url_for('memo_bans'))

        # حساب وقت انتهاء الحظر
        ends_at = datetime.utcnow() + timedelta(days=duration_days)

        new_ban = Ban(
            user_id=user.id,
            username=user.username,
            reason=reason,
            banned_at=datetime.utcnow(),
            duration_days=duration_days,
            ends_at=ends_at
        )
        db.session.add(new_ban)
        db.session.commit()

        flash(f"✅ تم حظر {username} بنجاح", "success")
        return redirect(url_for('memo_bans'))

    return render_template('memo_ban_form.html')


@app.route('/memo/ban_user/<int:user_id>', methods=['POST'])
@login_required
def ban_user_action(user_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))

    duration = request.form.get('duration')
    reason = request.form.get('reason') or "بلا سبب"

    duration_map = {
        'day': timedelta(days=1),
        'week': timedelta(days=7),
        'month': timedelta(days=30),
        'permanent': timedelta(days=365 * 100)
    }
    if duration not in duration_map:
        flash("⚠️ مدة غير صالحة", "danger")
        return redirect(url_for('memo_users'))

    user = User.query.get(user_id)
    if not user:
        flash("❌ المستخدم غير موجود", "danger")
        return redirect(url_for("memo_users"))

    banned_at = datetime.now()
    ends_at = banned_at + duration_map[duration]

    ban = Ban(user_id=user.id, username=user.username, reason=reason,
              banned_at=banned_at, ends_at=ends_at)
    db.session.add(ban)
    db.session.commit()

    flash("🚫 تم حظر المستخدم بنجاح", "success")
    return redirect(url_for('memo_users'))


@app.route("/terms", methods=["GET", "POST"])
def accept_terms():
    if request.method == "POST":
        session['accepted_terms'] = True
        return redirect(url_for("home"))
    return render_template("terms.html")

@app.route("/followers/<username>")
def followers_page(username):
    user = User.query.filter_by(username=username).first_or_404()
    followers = Follower.query.filter_by(followed_username=username).all()
    return render_template("followers_page.html", user=user, followers=followers)


@app.route("/report/<username>")
def report_user(username):
    flash(f"تم إرسال بلاغ ضد المستخدم {username}", "warning")
    return redirect(url_for("public_profile", username=username))




# لما أحد يرسل رسالة:
@socketio.on("send_message")
def handle_send_message(data):
    receiver = data.get("receiver")
    message = data.get("message")

    # تخزين الرسالة في قاعدة البيانات هنا...

    # 🔔 إرسال إشعار مباشر للطرف المستقبل:
    emit("new_message", {
        "from": data.get("sender"),
        "text": message
    }, room=receiver)






# صفحة لوحة الإحصائيات
@app.route("/memo/stats")
@login_required
def memo_stats():
    if not current_user.is_admin:
        return redirect(url_for("home"))

    from models import User, Poem, Message, Ban, Like
    total_users = User.query.count()
    total_poems = Poem.query.count()
    total_messages = Message.query.count()
    total_bans = Ban.query.count()
    total_likes = Like.query.count()

    return render_template("memo_stats.html", 
        total_users=total_users,
        total_poems=total_poems,
        total_messages=total_messages,
        total_bans=total_bans,
        total_likes=total_likes
    )


# 📌 صفحة "نسيت كلمة المرور"
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()

        if not email:
            flash("يرجى إدخال بريد إلكتروني صالح.", 'warning')
            return render_template('forgot_password.html')

        user = User.query.filter_by(email=email).first()

        if user:
            # هنا يمكنك إرسال بريد إلكتروني لإعادة تعيين كلمة المرور
            flash("📧 تم إرسال تعليمات إعادة تعيين كلمة المرور إلى بريدك الإلكتروني.", 'success')
        else:
            flash("هذا البريد الإلكتروني غير مسجل.", 'danger')

    return render_template('forgot_password.html')

@app.route("/premium")
def premium():
    # تحقق إذا المستخدم مسجل دخول
    if "username" not in session:
        flash("يجب تسجيل الدخول أولاً.")
        return redirect(url_for("login"))
    
    return render_template("premium.html")





@app.route('/premium', methods=['GET', 'POST'])
def upgrade_premium():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            # إنشاء جلسة دفع Stripe
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price_data': {
                        'currency': 'usd',
                        'product_data': {
                            'name': 'عضوية بريميوم',
                            'description': 'ترقية عضوية لتفعيل مميزات البريميوم',
                        },
                        'unit_amount': 500,  # السعر بالسنت (5 دولار)
                    },
                    'quantity': 1,
                }],
                mode='payment',
                success_url=url_for('premium_success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
                cancel_url=url_for('upgrade_premium', _external=True),
                client_reference_id=session['username'],  # نربط الدفع بالمستخدم
            )
            return redirect(checkout_session.url)
        except Exception as e:
            return str(e)

    # إذا GET نعرض صفحة الاشتراك (اللي عملتها)
    return render_template('premium.html')

@app.route('/premium/success')
def premium_success():
    session_id = request.args.get('session_id')

    if not session_id:
        return redirect(url_for('upgrade_premium'))

    # تحقق من حالة الدفع من Stripe إذا حبيت (اختياري)
    checkout_session = stripe.checkout.Session.retrieve(session_id)

    if checkout_session.payment_status == 'paid':
        # هنا حدث بيانات العضوية في قاعدة البيانات مثلاً
        # user = User.query.filter_by(username=session['username']).first()
        # user.is_premium = True
        # db.session.commit()

        return render_template('premium_success.html')

    return redirect(url_for('upgrade_premium'))


# 🟢 تحديد مجلد رفع الستوري داخل static/stories


@app.route('/upload_story', methods=['GET', 'POST'])
@login_required
def upload_story():
    if request.method == 'POST':
        file = request.files.get('file')

        # التحقق من الملف
        if not file or file.filename.strip() == "":
            flash("⚠️ الرجاء اختيار ملف قبل الرفع", "error")
            return redirect(url_for('upload_story'))

        if not allowed_file(file.filename):
            flash("⚠️ صيغة الملف غير مدعومة", "error")
            return redirect(url_for('upload_story'))

        # تجهيز اسم الملف والمسار
        filename = secure_filename(file.filename)
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        filename = f"{current_user.username}_{timestamp}_{filename}"

        upload_path = os.path.join(app.root_path, 'static', 'uploads', 'stories')
        os.makedirs(upload_path, exist_ok=True)

        file_path = os.path.join(upload_path, filename)
        file.save(file_path)

        # تحديد نوع الميديا
        ext = filename.rsplit('.', 1)[-1].lower()
        media_type = 'video' if ext in ['mp4', 'mov', 'avi', 'mkv'] else 'image'

        # حفظ البيانات في قاعدة البيانات
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
        return redirect(url_for('my_story', story_id=new_story.id))

    return render_template('upload_story.html')


@app.route('/story/<int:story_id>')
@login_required
def view_story(story_id):
    # جلب الستوري المطلوب
    story = Story.query.get_or_404(story_id)

    # جلب قائمة الأشخاص اللي المستخدم الحالي يتابعهم
    following_users = Follower.query.filter_by(username=current_user.username).all()
    following_list = [f.followed_username for f in following_users]

    # إضافة المستخدم الحالي لقائمة المسموحين
    allowed_users = following_list + [current_user.username]

    # التحقق أن صاحب الستوري مسموح عرضه
    story_owner = User.query.get(story.user_id)
    if story_owner.username not in allowed_users:
        abort(403)

    # ✅ تسجيل المشاهدة إذا لم يتم تسجيلها من قبل
    if current_user.id != story.user_id:  # ما نسجل إذا صاحب الستوري نفسه
        with db.session.no_autoflush:
            existing_view = StoryView.query.filter_by(
                story_id=story.id,
                viewer_id=current_user.id
            ).first()
        if not existing_view:
            new_view = StoryView(story_id=story.id, viewer_id=current_user.id)
            db.session.add(new_view)
            db.session.commit()

    # جلب جميع الستوريات النشطة لصاحب الستوري الحالي
    user_stories = (
        Story.query.filter_by(user_id=story.user_id, is_active=True)
        .filter(Story.expires_at > datetime.utcnow())
        .order_by(Story.created_at.asc())
        .all()
    )

    # استخراج ترتيب الستوري الحالي لتحديد السابق والتالي
    story_ids = [s.id for s in user_stories]
    current_index = story_ids.index(story.id)

    prev_story_id = story_ids[current_index - 1] if current_index > 0 else None
    next_story_id = story_ids[current_index + 1] if current_index < len(story_ids) - 1 else None

    # تمرير البيانات إلى القالب
    return render_template(
        "view_story.html",
        story=story,
        prev_story_id=prev_story_id,
        next_story_id=next_story_id,
        time_ago_format=time_ago_format
    )

@app.route("/my_story/<int:story_id>")
@login_required
def my_story(story_id):
    story = Story.query.get_or_404(story_id)

    # السماح فقط إذا الستوري للمستخدم الحالي
    if story.user_id != current_user.id:
        abort(403)

    # جلب المشاهدات مع بيانات المستخدم وصورته
    views_data = []
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

    for view in views:
        viewer_username = view.viewer_username
        viewer_profile_image = view.viewer_profile_image
        viewed_at = view.viewed_at

        # التحقق إذا المشاهد عامل لايك
        has_liked = StoryLike.query.filter_by(
            story_id=story.id,
            username=viewer_username
        ).first() is not None

        views_data.append({
            "username": viewer_username,
            "profile_image": viewer_profile_image,
            "viewed_at": viewed_at,
            "has_liked": has_liked
        })

    return render_template(
        "my_story.html",
        story=story,
        views_data=views_data,
        time_since=time_ago_format(story.created_at),
        timestamp=lambda dt: dt.strftime("%Y-%m-%d %H:%M")
    )


# حذف الستوري
@app.route("/delete_story/<int:story_id>")
@login_required
def delete_story(story_id):
    story = Story.query.get_or_404(story_id)

    if story.user_id != current_user.id:
        abort(403)

    # حذف المشاهدات المرتبطة بالستوري
    StoryView.query.filter_by(story_id=story.id).delete()

    # حذف الستوري نفسه
    db.session.delete(story)
    db.session.commit()

    return redirect(url_for("home"))


# حفظ الستوري
@app.route("/save_story/<int:story_id>")
@login_required
def save_story(story_id):
    story = Story.query.get_or_404(story_id)

    if story.user_id != current_user.id:
        abort(403)

    # هنا تحط كود الحفظ/التحميل إذا تبيه
    return redirect(url_for("my_story", story_id=story_id))

# ❤️ زر الإعجاب للستوري
@app.route('/like_story/<int:story_id>', methods=['POST'])
@login_required
def like_story(story_id):
    story = Story.query.get_or_404(story_id)
    username = current_user.username

    # تأكد أن الستوري ما انتهى
    if story.expires_at < datetime.utcnow():
        return jsonify({'success': False, 'message': 'انتهت صلاحية الستوري'})

    # تحقق من وجود الإعجاب سابقاً باستخدام جدول StoryLike
    existing_like = StoryLike.query.filter_by(username=username, story_id=story_id).first()

    if existing_like:
        db.session.delete(existing_like)
    else:
        new_like = StoryLike(username=username, story_id=story_id)
        db.session.add(new_like)

        # إشعار لحظي
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

    # حساب عدد اللايكات الحالي
    total_likes = StoryLike.query.filter_by(story_id=story_id).count()

    return jsonify({'success': True, 'likes': total_likes})

if __name__ == "__main__":
 with app.app_context():
    db.create_all()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
