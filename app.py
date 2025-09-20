import eventlet
eventlet.monkey_patch()
from mem import (
    send_new_message,
    send_new_follower,
    send_new_like
)
import os, re, json, base64, random, stripe, humanize, string, requests
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, session, redirect, url_for,
    request, jsonify, flash
)
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify, has_request_context, g
)
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user, UserMixin
)
from flask_babel import Babel
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_migrate import Migrate
from flask_mail import Mail, Message as MailMessage
from flask_wtf import CSRFProtect
from flask_talisman import Talisman
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_, and_, desc

from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from utils import format_number, time_ago_format, time_ago
from config import Config
from routes.profile import profile_bp
from routes.stories import stories_bp
from utils import format_number  # تأكد أن هذه موجودة في utils.py
from forms import (
    SignupForm, LoginForm, EditProfileForm,
    ForgotPasswordForm, EmptyForm, TermsForm
)
from models import (
    db, User, Ban, Notification, Message, MessageReport, ContactMessage,
    Poem, Settings, Follower, Story, Block, Like, Report, FollowRequest,
    StoryView, StoryLike, Offer
)
from user_utils import (
    verify_user, get_user_by_username, get_all_users, delete_user,
    unverify_user_by_id, increase_followers_by_id, valid_username
)

from routes.profile import profile_bp  # مكرّر في استيراداتك لكنه هنا كذلك (لا يحذف)
from routes.poems import poems_bp
# ----------------------------- إعداد التطبيق -----------------------------

app = Flask(__name__)  # استخدم name بدل name لتجنب أخطاء
app.config.from_object(Config)

# حماية CSRF و CORS
csrf = CSRFProtect(app)
CORS(app)

# تهيئة قاعدة البيانات، الماجريت، الإيميل، البابل، والتاليسمان
db.init_app(app)
migrate = Migrate(app, db)
mail = Mail(app)
babel = Babel(app)


def get_locale():
    return request.accept_languages.best_match(['ar', 'en'])

babel = Babel(app, locale_selector=get_locale)

# تسجيل البلوبيرنتات
app.register_blueprint(profile_bp)
app.register_blueprint(stories_bp, url_prefix="/stories")
app.register_blueprint(poems_bp)
# فلتر Jinja (format_number)
app.jinja_env.filters['format_number'] = format_number
app.jinja_env.globals['time_ago_format'] = time_ago_format
app.jinja_env.globals['time_since'] = time_ago   # alias إذا لسا القوالب بتستخدمه
# تهيئة SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# تهيئة Talisman (CSP)
csp = {
    'default-src': ["'self'"],
    'script-src': [
        "'self'",
        "https://cdn.jsdelivr.net",
        "https://code.jquery.com",
        "https://cdn.tailwindcss.com",
        "'unsafe-inline'"
    ],
    'style-src': [
        "'self'",
        "https://fonts.googleapis.com",
        "https://cdn.jsdelivr.net",
        "'unsafe-inline'"
    ],
    'font-src': [
        "'self'",
        "https://fonts.gstatic.com"
    ]
}
Talisman(app, content_security_policy=csp)

# Serializer
s = URLSafeTimedSerializer(app.secret_key if hasattr(app, "secret_key") else app.config.get("SECRET_KEY"))


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



# ----------------------------- LoginManager -----------------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "profile.login"  # إذا endpoint تسجيل الدخول في blueprint profile




@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



# ----------------------------- Context processors -----------------------------
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

@app.context_processor
def inject_user():
    # Flask-Login يجعل current_user متاح في القوالب تلقائياً عادة،
    # لكن نمرره أيضاً هنا كـ current_user لضمان وجوده.
    return dict(current_user=current_user)

@app.context_processor
def inject_blocked_users():
    # تعود قائمة المستخدمين المحظورين في sidebar إن كانت هناك جلسة
    if not has_request_context() or 'username' not in session:
        return {}
    try:
        blocked_entries = Block.query.filter_by(blocker=session['username']).all()
        blocked_usernames = [entry.blocked for entry in blocked_entries]
        return {'blocked_users_sidebar': blocked_usernames}
    except Exception:
        return {'blocked_users_sidebar': []}

@app.context_processor
def inject_counts():
    # تعود الإشعارات والرسائل غير المقروءة
    try:
        if not has_request_context() or not getattr(current_user, "is_authenticated", False):
            return {
                'notifications': [],
                'has_unread_notifications': False,
                'unread_messages_count': 0
            }
        username = current_user.username
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
        print("خطأ أثناء جلب الإشعارات أو الرسائل:", e)
        return {
            'notifications': [],
            'has_unread_notifications': False,
            'unread_messages_count': 0
        }

# ----------------------------- فلترات و دوال مساعدة -----------------------------
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

def send_notification(to_username, message, notif_type='general', sender=None, poem_id=None):
    notif = Notification(
        recipient=to_username,
        sender=sender,
        type=notif_type,
        content=message,
        poem_id=poem_id
    )
    db.session.add(notif)
    db.session.commit()

    # إرسال لحظي عبر socketio (اختياري)
    socketio.emit('new_notification', {
        'id': notif.id,
        'sender': sender,
        'message': message,
        'type': notif_type,
        'poem_id': poem_id,
        'time_ago': "الآن"
    }, room=to_username)


# ----------------------------- قبل الطلب -----------------------------
def is_user_banned(user_id):
    now = datetime.now()
    ban = Ban.query.filter(Ban.user_id == user_id, Ban.ends_at > now)\
        .order_by(Ban.ends_at.desc()).first()
    return ban

@app.before_request
def check_user_ban():
    allowed_endpoints = ['profile.login', 'profile.signup', 'static', 'accept_terms', 'register']
    if request.endpoint in allowed_endpoints:
        return

    try:
        if has_request_context() and getattr(current_user, "is_authenticated", False) and current_user.username != "admin":
            ban = is_user_banned(current_user.id)
            if ban:
                logout_user()
                session.pop('username', None)
                ends_at = ban.ends_at.strftime('%Y-%m-%d %H:%M') if ban.ends_at else "غير محدد"
                flash(f"🔒 حسابك محظور حتى {ends_at}", "danger")
                return redirect(url_for('profile.login'))
    except Exception as e:
        # لا تمنع الطلب إذا فشل الفحص لأي سبب
        print("خطأ أثناء التحقق من الحظر:", e)
        pass

# ----------------------------- SocketIO events -----------------------------
@socketio.on("send_message")
def handle_send_message(data):
    receiver = data.get("receiver")
    message = data.get("message")

    # تخزين الرسالة في قاعدة البيانات هنا (لو حاب)
    # مثال بسيط: Message(...)

    # إرسال إشعار مباشر للطرف المستقبل:
    emit("new_message", {
        "from": data.get("sender"),
        "text": message
    }, room=receiver)

# ----------------------------- ضمان إنشاء الجداول (خيارياً أثناء dev) -----------------------------
# ملاحظة: إنك تملك Alembic/Flask-Migrate فالأفضل استخدام flask db migrate / flask db upgrade.
# لكن أثناء التطوير إن أردت ضمان وجود الجداول:
with app.app_context():
    try:
        db.create_all()
    except Exception as e:
        # لا تطبع الكثير في البيئة الحية
        print("warning: create_all failed or already handled by migrations:",)

# 🔑 نسيت كلمة المرور
from flask_mail import Mail, Message as MailMessage  # ✅ استيراد بدون تعارض

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if request.method == 'POST':
        # نستعمل بيانات الفورم
        email = form.email.data.strip() if form.email.data else ''

        if not email:
            flash("⚠️ يرجى إدخال بريد إلكتروني.", 'warning')
            return render_template('forgot_password.html', form=form)

        # 🔍 التحقق من وجود المستخدم
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("❌ البريد غير مسجل.", 'danger')
            return render_template('forgot_password.html', form=form)

        # ✅ إنشاء التوكن
        token = s.dumps(email, salt='password-reset-salt')
        reset_url = url_for('reset_password', token=token, _external=True)

        try:
            # ✉️ رسالة البريد
            msg = MailMessage(
                subject="إعادة تعيين كلمة المرور",
                sender=app.config['MAIL_USERNAME'],
                recipients=[email]
            )
            msg.body = f"""
مرحباً {user.username},

اضغط الرابط التالي لإعادة تعيين كلمة المرور (صالح ساعة واحدة):
{reset_url}
"""

            mail.send(msg)  # إرسال البريد
            flash("📧 تم إرسال الرابط لبريدك.", 'success')

        except Exception as e:
            print("🚨 خطأ عند الإرسال:", e)
            flash("❌ لم يتم إرسال البريد. تحقق من الإعدادات.", 'danger')

    return render_template('forgot_password.html', form=form)


# 🔑 إعادة التعيين
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired:
        flash("⏰ انتهت صلاحية الرابط.", "danger")
        return redirect(url_for('forgot_password'))
    except BadSignature:
        flash("❌ رابط غير صالح.", "danger")
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("المستخدم غير موجود.", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        if not new_password or len(new_password) < 6:
            flash("كلمة المرور يجب أن تكون 6 أحرف على الأقل.", "warning")
            return render_template('reset_password.html')

        user.password = generate_password_hash(new_password)
        db.session.commit()
        flash("✅ تم تغيير كلمة المرور! سجل دخولك.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')


@app.route('/')
def home():
    if 'username' not in session:
        return redirect(url_for('profile.login'))

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

    # جلب الستوريات من المتابعين فقط والتي لم تنتهي بعد (مع استثناء المحظورين)
    stories_raw = (
        db.session.query(Story, User)
        .join(User, Story.user_id == User.id)
        .filter(User.username.in_(following_list))
        .filter(Story.expires_at > datetime.utcnow())
        .filter(~User.username.in_(
            db.session.query(Block.blocked).filter(Block.blocker == current_username)
        ))
        .filter(~User.username.in_(
            db.session.query(Block.blocker).filter(Block.blocked == current_username)
        ))
        .order_by(Story.created_at.desc())
        .all()
    )

    # 📌 تجميع الستوريات حسب المستخدم + حالة المشاهدة
    current_user_obj = User.query.filter_by(username=current_username).first()
    if not current_user_obj:
        return redirect(url_for("profile.login"))

    stories_dict = {}
    for story, author in stories_raw:
        viewed = StoryView.query.filter_by(
            story_id=story.id,
            viewer_id=current_user_obj.id
        ).first() is not None

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
            "created_at": story.created_at,
            "is_viewed": viewed
        })

    # تحويل القاموس إلى قائمة
    stories = list(stories_dict.values())

    # ✅ إضافة ستوري المستخدم الحالي بشكل منفصل
    has_story_flag = Story.query.filter_by(user_id=current_user_obj.id)\
        .filter(Story.expires_at > datetime.utcnow())\
        .count() > 0

    user_story = Story.query.filter_by(user_id=current_user_obj.id)\
        .filter(Story.expires_at > datetime.utcnow())\
        .order_by(Story.created_at.desc())\
        .first()

    viewed = None
    if user_story:
        viewed = StoryView.query.filter_by(
            story_id=user_story.id,
            viewer_id=current_user_obj.id
        ).first() is not None

    # 📌 تعديل my_story ليحتوي على حالة المشاهدة
    my_story = {
        "user": current_user_obj,
        "id": user_story.id if user_story else None,
        "has_story": has_story_flag,
        "is_viewed": viewed
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











@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'username' not in session:
        flash('يجب تسجيل الدخول أولاً', 'warning')
        return redirect(url_for('login'))

    current_username = session['username']
    keyword = ''
    search_type = request.args.get("type", "users")  # users / poems / all
    sort_by = request.args.get('sort', 'recent')

    # 📌 جلب المحظورين
    blocked_by_me = db.session.query(Block.blocked).filter_by(blocker=current_username).all()
    blocked_me = db.session.query(Block.blocker).filter_by(blocked=current_username).all()
    blocked_users = [u for (u,) in blocked_by_me] + [u for (u,) in blocked_me]

    results_users, results_poems = [], []

    if request.method == 'POST':
        keyword = request.form.get('keyword', '').strip()

        # 🔎 بحث في المستخدمين
        if search_type in ["users", "all"] and keyword:
            query = User.query.filter(
                or_(
                    User.username.ilike(f"%{keyword}%"),
                    User.first_name.ilike(f"%{keyword}%"),
                    User.last_name.ilike(f"%{keyword}%"),
                    User.email.ilike(f"%{keyword}%"),
                    User.bio.ilike(f"%{keyword}%")
                )
            )
            query = query.filter(
                and_(
                    User.username != current_username,
                    ~User.username.in_(blocked_users)
                )
            )

            if sort_by == "verified":
                query = query.order_by(User.verified.desc())
            elif sort_by == "oldest":
                query = query.order_by(User.id.asc())
            else:
                query = query.order_by(User.id.desc())

            for user in query.all():
                is_following = Follower.query.filter_by(
                    username=current_username,
                    followed_username=user.username
                ).first() is not None

                follow_request_sent = FollowRequest.query.filter_by(
                    sender_username=current_username,
                    receiver_username=user.username,
                    status='pending'
                ).first() is not None

                results_users.append({
                    "username": user.username,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "profile_image": user.profile_image,
                    "verified": user.verified,
                    "is_following": is_following,
                    "follow_request_sent": follow_request_sent,
                    "private": user.private,
                    "bio": user.bio,
                })

        # 🔎 بحث في الأبيات
        if search_type in ["poems", "all"] and keyword:
            query = Poem.query.join(User, Poem.username == User.username).filter(
                or_(
                    Poem.text.ilike(f"%{keyword}%"),
                    User.username.ilike(f"%{keyword}%"),
                    User.first_name.ilike(f"%{keyword}%"),
                    User.last_name.ilike(f"%{keyword}%")
                )
            )

            if sort_by == "likes":
                query = query.order_by(Poem.likes.desc())
            elif sort_by == "views":
                query = query.order_by(Poem.views.desc())
            elif sort_by == "oldest":
                query = query.order_by(Poem.created_at.asc())
            else:
                query = query.order_by(Poem.created_at.desc())

            for poem in query.all():
                results_poems.append({
                    "id": poem.id,
                    "text": poem.text,
                    "likes": poem.likes,
                    "views": poem.views,
                    "created_at": poem.created_at,
                    "username": poem.username,
                    "profile_image": poem.user.profile_image if poem.user else "default.jpg",
                    "verified": poem.user.verified if poem.user else False,
                    "category": poem.category if hasattr(poem, 'category') else None
                })

    return render_template(
        'search.html',
        results_users=results_users,
        results_poems=results_poems,
        current_user=current_username,
        blocked_users_sidebar=blocked_users,
        keyword=keyword,
        sort_by=sort_by,
        search_type=search_type
    )


@app.route('/explore')
@login_required
def explore_page():
    current_username = current_user.username  # Flask-Login

    # 📌 جيب المحظورين (أنا حاظرهم + هم حاجزيني)
    blocked_by_me = db.session.query(Block.blocked).filter_by(blocker=current_username).all()
    blocked_me = db.session.query(Block.blocker).filter_by(blocked=current_username).all()

    # حوّل الـ tuples لقائمة أسماء
    blocked_users = [u for (u,) in blocked_by_me] + [u for (u,) in blocked_me]

    # ✅ الأبيات الأكثر إعجابًا (مع التحقق من حالة التوثيق) مع فلترة المحظورين
    top_poems_query = (
        db.session.query(Poem, User.profile_image, User.verified)
        .join(User, Poem.username == User.username)
        .filter(~Poem.username.in_(blocked_users))   # 🚫 استثناء المحظورين
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
            'verified': verified,
            'created_ago': time_ago(poem.created_at)
        })

    # ✅ المستخدمون المقترحون (مع التحقق من حالة التوثيق) مع فلترة المحظورين
    followed_subquery = (
        db.session.query(Follower.followed_username)
        .filter(Follower.username == current_username)
    )

    suggested_users = (
        db.session.query(User.username, User.first_name, User.last_name, User.profile_image, User.verified)
        .filter(User.username != current_username)
        .filter(~User.username.in_(followed_subquery))
        .filter(~User.username.in_(blocked_users))   # 🚫 استثناء المحظورين
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
            'verified': verified
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
        user_liked=liked_poems_ids,
        blocked_users_sidebar=blocked_users  # 🔑 عشان كمان القالب يستعمله
    )

# ✅ زيادة عدد اللايكات (للمسؤول فقط - يتم الحفظ في جدول Like)
@app.route('/admin/addlike/<int:poem_id>/<int:like_count>')
@login_required
def admin_add_likes(poem_id, like_count):
    if not current_user.is_admin:
        return "ممنوع الدخول!", 403

    if like_count < 0:
        return "❌ غير مسموح إنقاص عدد اللايكات!", 400

    poem = Poem.query.get(poem_id)
    if poem:
        # 🔹 إضافة لايكات جديدة باسم الأدمن نفسه (موجود في users)
        for i in range(like_count):
            new_like = Like(poem_id=poem.id, username=current_user.username)
            db.session.add(new_like)

        db.session.commit()

        total_likes = Like.query.filter_by(poem_id=poem_id).count()
        return f"✅ تمت إضافة {like_count} لايكات للمنشور رقم {poem_id} (الإجمالي الآن: {total_likes})"
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

    # تحقق إذا فيه حظر سابق
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
        flash(f"✅ تم إلغاء الحظر عن {username}.", "success")

    return redirect(request.referrer or url_for('blocked_users'))

@app.route("/messages/<username>")
def view_messages(username):
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = session['username']
    current_user_obj = User.query.filter_by(username=current_user).first()

    # ✅ التحقق من الحظر بين المستخدمين
    blocked_entry = Block.query.filter(
        or_(
            and_(Block.blocker == current_user, Block.blocked == username),
            and_(Block.blocker == username, Block.blocked == current_user)
        )
    ).first()
    is_blocked = bool(blocked_entry)

    messages = []
    display_name = username
    profile_visible = not is_blocked

    if not is_blocked:
        # ✅ جلب الرسائل بين المستخدمين (فقط الخاصة)
        msgs = Message.query.filter(
            or_(
                and_(Message.sender == current_user, Message.receiver == username),
                and_(Message.sender == username, Message.receiver == current_user)
            )
        ).order_by(Message.timestamp).all()

        for msg in msgs:
            sender_user = User.query.filter_by(username=msg.sender).first()

            messages.append({
                "id": msg.id,
                "content": msg.content if msg.message_type == "text" else None,
                "file_path": msg.file_path if msg.message_type == "file" else None,
                "message_type": msg.message_type,
                "timestamp": msg.timestamp,
                "sender": msg.sender,
                "receiver": msg.receiver,
                "is_read": msg.is_read,
                "is_sender": (msg.sender == current_user),
                "status": "read" if msg.is_read else "sent",
                "sender_user": sender_user
            })

    else:
        # ✅ لو محظور
        messages = []
        display_name = "User is unavailable"

    # 🛑 عدد المحادثات غير المقروءة (زي inbox)
    unread_conversations_count = (
        db.session.query(Message.sender)
        .filter(Message.receiver == current_user, Message.is_read == False)
        .distinct()
        .count()
    )

    # 🛑 عدد الإشعارات
    unread_notifications_count = Notification.query.filter_by(
        recipient=current_user, is_read=False
    ).count()

    # ✅ ستوريات الطرف الآخر
    user_obj = User.query.filter_by(username=username).first()
    active_stories = []
    has_story = False
    has_unseen_story = False

    if user_obj:
        active_stories = Story.query.filter(
            Story.user_id == user_obj.id,
            Story.is_active == True,
            Story.expires_at > datetime.utcnow()
        ).all()

        has_story = len(active_stories) > 0

        if has_story:
            for story in active_stories:
                viewed = StoryView.query.filter_by(
                    story_id=story.id,
                    viewer_id=current_user_obj.id
                ).first()
                if not viewed:
                    has_unseen_story = True
                    break

    return render_template(
        "messages.html",
        messages=messages,
        is_blocked=is_blocked,
        current_user=current_user,
        display_name=display_name,
        profile_visible=profile_visible,
        real_username=username,
        unread_messages_count=unread_conversations_count,
        unread_notifications_count=unread_notifications_count,
        has_unread_messages=(unread_conversations_count > 0),
        has_unread_notifications=(unread_notifications_count > 0),
        # 👇 إضافات الستوري
        has_story=has_story,
        has_unseen_story=has_unseen_story,
        stories=active_stories,
        user=user_obj
    )

@app.route("/messages/anonymous/<username>")
def view_messages_anonymous(username):
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = session['username']
    current_user_obj = User.query.filter_by(username=current_user).first()

    # ✅ هنا المجهول دايمًا True
    anonymous_mode = True
    anonymous_flag = 1

    # ✅ التحقق من الحظر
    blocked_entry = Block.query.filter(
        or_(
            and_(Block.blocker == current_user, Block.blocked == username),
            and_(Block.blocker == username, Block.blocked == current_user)
        )
    ).first()
    is_blocked = bool(blocked_entry)

    messages = []
    display_name = username
    profile_visible = not is_blocked

    if not is_blocked:
        msgs = Message.query.filter(
            and_(
                or_(
                    and_(Message.sender == current_user, Message.receiver == username),
                    and_(Message.sender == username, Message.receiver == current_user)
                ),
                Message.is_anonymous == anonymous_mode
            )
        ).order_by(Message.timestamp).all()

        for msg in msgs:
            show_sender = True
            sender_user = User.query.filter_by(username=msg.sender).first() if msg.sender else None

            # ✅ في المجهول: نخفي الهوية إلا لو بريميوم
            if msg.is_anonymous:
                if sender_user and not sender_user.is_premium():
                    show_sender = False

            messages.append({
                "id": msg.id,
                "content": msg.content,
                "file_path": msg.file_path,   # 👈 الآن الصور والملفات بتبين
                "timestamp": msg.timestamp,
                "sender": msg.sender,
                "receiver": msg.receiver,
                "is_read": msg.is_read,
                "is_sender": (msg.sender == current_user),
                "show_sender": show_sender,
                "status": "read" if msg.is_read else "sent",
                "sender_user": sender_user
            })

    else:
        messages = []
        display_name = "User is unavailable"

    # 🛑 عدد المحادثات غير المقروءة
    unread_conversations_count = (
        db.session.query(Message.sender)
        .filter(Message.receiver == current_user, Message.is_read == False)
        .distinct()
        .count()
    )

    # 🛑 عدد الإشعارات
    unread_notifications_count = Notification.query.filter_by(
        recipient=current_user, is_read=False
    ).count()

    # ✅ ستوريات الطرف الآخر
    user_obj = User.query.filter_by(username=username).first()
    active_stories = []
    has_story = False
    has_unseen_story = False

    if user_obj:
        active_stories = Story.query.filter(
            Story.user_id == user_obj.id,
            Story.is_active == True,
            Story.expires_at > datetime.utcnow()
        ).all()

        has_story = len(active_stories) > 0
        if has_story:
            for story in active_stories:
                viewed = StoryView.query.filter_by(
                    story_id=story.id,
                    viewer_id=current_user_obj.id
                ).first()
                if not viewed:
                    has_unseen_story = True
                    break

    return render_template(
        "messages_anonymous.html",
        messages=messages,
        is_blocked=is_blocked,
        current_user=current_user,
        anonymous_mode=anonymous_mode,
        anonymous_flag=anonymous_flag,
        display_name=display_name,
        profile_visible=profile_visible,
        unread_conversations_count=unread_conversations_count,
        unread_notifications_count=unread_notifications_count,
        active_stories=active_stories,
        has_story=has_story,
        has_unseen_story=has_unseen_story,
        real_username=username   # 👈 هذا السطر هو المهم
    )

@app.route("/send_message/<username>", methods=["POST"])
def send_message(username):
    if 'username' not in session:
        return redirect(url_for("login"))

    sender = session['username']
    content = request.form.get("content")
    file_path = None

    # ✅ التعامل مع الملف (صورة / مرفق)
    file = request.files.get("file")
    if file and file.filename != '':
        filename = secure_filename(file.filename)

        # نخزن داخل static/uploads
        upload_folder = os.path.join(app.root_path, 'static', 'uploads')
        os.makedirs(upload_folder, exist_ok=True)

        # نحفظ الملف فعليًا
        full_path = os.path.join(upload_folder, filename)
        file.save(full_path)

        # نخزن بالقاعدة مسار نسبي من static
        file_path = f"uploads/{filename}"

    # ✅ هل المستخدم أرسل الرسالة كمجهول
    anonymous = request.args.get("anonymous", "0") == "1"

    # ✅ دايمًا نخزن المرسل الحقيقي لكن نتحكم بالعرض لاحقًا
    message = Message(
        sender=sender,
        receiver=username,
        content=content if content else None,
        file_path=file_path,
        is_anonymous=anonymous
    )
    db.session.add(message)
    db.session.commit()

    # ✅ إشعار للمستلم
    if username != sender:
        send_notification(username, "📨 وصلك رسالة جديدة!")

    # ✅ إعادة التوجيه للصفحة المناسبة
    if anonymous:
        return redirect(url_for("view_messages_anonymous", username=username))
    else:
        return redirect(url_for("view_messages", username=username, anonymous="0"))

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

    # جلب كل المستخدمين اللي في بينهم رسائل (مفلترة حسب مجهول/خاص)
    users = User.query.join(
        Message, ((Message.sender == User.username) | (Message.receiver == User.username))
    ).filter(
        ((Message.sender == current_user_name) | (Message.receiver == current_user_name)) &
        (Message.is_anonymous == anonymous)
    ).distinct().all()

    current_user_obj = User.query.filter_by(username=current_user_name).first()

    user_data = []
    for user in users:
        # آخر رسالة بين المستخدم الحالي والمستخدم الآخر
        last_message = Message.query.filter(
            (((Message.sender == current_user_name) & (Message.receiver == user.username)) |
             ((Message.sender == user.username) & (Message.receiver == current_user_name))) &
            (Message.is_anonymous == anonymous)
        ).order_by(Message.timestamp.desc()).first()

        # عدد الرسائل غير المقروءة (مفلترة برضه)
        unread_count = Message.query.filter_by(
            receiver=current_user_name,
            sender=user.username,
            is_read=False,
            is_anonymous=anonymous
        ).count()

        # 👀 ستوريات
        active_stories = Story.query.filter(
            Story.user_id == user.id,
            Story.is_active == True,
            Story.expires_at > datetime.utcnow()
        ).all()

        has_story = len(active_stories) > 0
        has_unseen_story = False

        if has_story:
            for story in active_stories:
                viewed = StoryView.query.filter_by(
                    story_id=story.id,
                    viewer_id=current_user_obj.id
                ).first()
                if not viewed:
                    has_unseen_story = True
                    break

        user_data.append({
            "username": user.username,
            "display_name": f"{user.first_name} {user.last_name}" if user.first_name else user.username,
            "profile_image": user.profile_image,
            "unread_count": unread_count,
            "has_story": has_story,
            "has_unseen_story": has_unseen_story,
            "last_message_time": last_message.timestamp.strftime("%H:%M") if last_message else None,
            "last_message": last_message.content if last_message and last_message.message_type == "text" else None,
            "last_message_type": last_message.message_type if last_message else None,
            "is_sender": last_message.sender == current_user_name if last_message else False,
            "last_message_status": (
                "read" if last_message.is_read else "sent"
            ) if last_message else None,
        })

    return render_template("inbox.html", users=user_data, anonymous=anonymous)


@app.route('/follow', methods=['POST'])
@login_required
def follow():
    target_user = request.form.get('target_user')
    current_username = current_user.username

    if target_user and target_user != current_username:
        blocked = Block.query.filter(
            or_(
                (Block.blocker == current_username) & (Block.blocked == target_user),
                (Block.blocker == target_user) & (Block.blocked == current_username)
            )
        ).first()

        if blocked:
            exists = Follower.query.filter_by(username=current_username, followed_username=target_user).first()
            if exists:
                db.session.delete(exists)
                db.session.commit()
            if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"success": False, "blocked": True})
            flash("❌ لا يمكنك متابعة هذا المستخدم (محظور).", "danger")
            return redirect(request.referrer or url_for('search'))

        exists = Follower.query.filter_by(username=current_username, followed_username=target_user).first()

        if exists:
            db.session.delete(exists)
            db.session.commit()
            if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"success": True, "following": False})
            flash(f'🚫 ألغيت متابعة {target_user}.', 'warning')
        else:
            follow_relation = Follower(username=current_username, followed_username=target_user)
            db.session.add(follow_relation)

            notification = Notification(
                recipient=target_user,
                sender=current_username,
                type="follow",
                content=f"{current_username} بدأ متابعتك!"
            )
            db.session.add(notification)

            send_notification(target_user, f"{current_username} بدأ متابعتك! ")

            db.session.commit()
            if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"success": True, "following": True})
            flash(f'تمت متابعة {target_user} بنجاح ✅', 'success')
    else:
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "error": "invalid"})
        flash('❌ لا يمكن متابعة نفسك أو مدخل غير صالح.', 'danger')

    return redirect(request.referrer or url_for('search'))

# ❤️ زر الإعجاب
@app.route('/like/<int:poem_id>', methods=['POST'])
def like(poem_id):
    if 'username' not in session:
        return jsonify({'success': False, 'redirect': url_for('profile.login')})

    username = session['username']
    poem = Poem.query.get(poem_id)
    if not poem:
        return jsonify({'success': False, 'message': 'البيت غير موجود'})

    existing_like = Like.query.filter_by(username=username, poem_id=poem_id).first()

    if existing_like:
        # حذف اللايك
        db.session.delete(existing_like)
        poem.likes = (poem.likes or 0) - 1 if poem.likes and poem.likes > 0 else 0
    else:
        # إضافة لايك جديد
        new_like = Like(username=username, poem_id=poem_id)
        db.session.add(new_like)
        poem.likes = (poem.likes or 0) + 1

        # ✅ إرسال إشعار للكاتب إذا مو هو نفس الشخص
        if poem.username != username:
            send_notification(
                to_username=poem.username,
                sender=username,  # المرسل
                message=f"{username} أعجب ببيتك!",
                notif_type="like",
                poem_id=poem.id   # البيت المرتبط
            )

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
            link = url_for("view_poem", poem_id=n.poem_id)
            # لو حابب تضيف line_id من content
            if n.content and n.content.isdigit():
                link += f"#line-{n.content}"
        elif n.type in ["follow", "follow_request"]:
            link = url_for("profile.public_profile", username=n.sender)
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
    from werkzeug.security import generate_password_hash

    # 🔹 جلب المستخدم الهدف
    user = User.query.get_or_404(user_id)

    # 🔹 العدد المطلوب إضافته
    amount = int(request.form.get('amount', 1))

    for _ in range(amount):
        # 🔹 توليد اسم مستخدم وهمي (متابع)
        fake_username = 'fake_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        fake_email = fake_username + "@fake.com"
        fake_password = generate_password_hash("12345678")  # كلمة مرور افتراضية

        # ✅ إنشاء المستخدم الوهمي إذا مش موجود
        if not User.query.filter_by(username=fake_username).first():
            fake_user = User(
                username=fake_username,
                email=fake_email,
                password=fake_password,
                verified=False  # مش ضروري يكون موثق
            )
            db.session.add(fake_user)
            db.session.flush()  # عشان ناخد الـ ID مباشرة قبل الكوميت

        # ✅ إضافة المتابع في جدول Follower
        new_follower = Follower(
            username=fake_username,           # المتابع الوهمي
            followed_username=user.username   # الشخص المستهدف
        )
        db.session.add(new_follower)

    db.session.commit()

    # 🔹 تحديث عدد المتابعين
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
    ban.ends_at = datetime.utcnow()
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






@app.route("/report/<username>")
def report_user(username):
    flash(f"تم إرسال بلاغ ضد المستخدم {username}", "warning")
    return redirect(url_for("public_profile", username=username))

@app.route("/followers/<username>")
def followers_page(username):
    user = User.query.filter_by(username=username).first_or_404()

    current_username = session.get("username")

    # جلب كل المتابعين
    followers_raw = (
        db.session.query(Follower, User)
        .join(User, Follower.username == User.username)
        .filter(Follower.followed_username == username)
        .all()
    )

    followers = []
    for follower, follower_user in followers_raw:
        blocked = Block.query.filter(
            or_(
                (Block.blocker == current_username) & (Block.blocked == follower_user.username),
                (Block.blocker == follower_user.username) & (Block.blocked == current_username)
            )
        ).first()
        if not blocked:
            followers.append(follower)

    return render_template("followers_page.html", user=user, followers=followers)


# لما أحد يرسل رسالة:

# ✅ إزالة أدمن
@app.route('/remove_admin/<username>', methods=['POST'])
@login_required
def remove_admin(username):
    if not current_user.is_admin:
        flash("❌ غير مسموح لك.", "danger")
        return redirect(url_for("home"))

    user = User.query.filter_by(username=username, is_admin=True).first()
    if user:
        if user.username != current_user.username:  # ما تزيل نفسك
            user.is_admin = False
            db.session.commit()
            flash(f"تم إزالة {username} من الأدمن ✅", "success")
        else:
            flash("❌ لا يمكنك إزالة نفسك", "danger")
    else:
        flash("❌ المستخدم غير موجود أو مش أدمن", "danger")

    return redirect(url_for("admin_list"))


# ✅ قائمة الأدمن + المشرفين
@app.route('/admin_list')
@login_required
def admin_list():
    if not current_user.is_admin:
        flash("❌ غير مسموح لك بالدخول هنا", "danger")
        return redirect(url_for("home"))

    admins = User.query.filter_by(is_admin=True).all()
    moderators = User.query.filter_by(is_moderator=True).all()

    return render_template("admin_list.html", admins=admins, moderators=moderators)


@app.route('/add_moderator', methods=['POST'])
@login_required
def add_moderator():
    if not current_user.is_admin:
        flash("❌ غير مسموح لك.", "danger")
        return redirect(url_for("home"))

    username = request.form.get("username")
    user = User.query.filter_by(username=username).first()
    if user:
        if not user.is_admin and not user.is_moderator:
            user.is_moderator = True
            db.session.commit()
            flash(f"تمت إضافة {username} كمشرف ✅", "success")
        else:
            flash("❌ هذا المستخدم أدمن أو مشرف بالفعل", "danger")
    else:
        flash("❌ المستخدم غير موجود", "danger")

    return redirect(url_for("admin_list"))


# ✅ إزالة مشرف
@app.route('/remove_moderator/<username>', methods=['POST'])
@login_required
def remove_moderator(username):
    if not current_user.is_admin:
        flash("❌ غير مسموح لك.", "danger")
        return redirect(url_for("home"))

    user = User.query.filter_by(username=username, is_moderator=True).first()
    if user:
        user.is_moderator = False
        db.session.commit()
        flash(f"تمت إزالة {username} من المشرفين ✅", "success")
    else:
        flash("❌ المستخدم غير موجود أو مش مشرف", "danger")

    return redirect(url_for("admin_list"))



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

@app.route("/admin/offers/edit/<int:offer_id>", methods=["GET", "POST"])
@login_required
def edit_offer(offer_id):
    if not current_user.is_admin:
        flash("🚫 لا تملك صلاحية", "danger")
        return redirect(url_for("memo_offers"))

    offer = Offer.query.get_or_404(offer_id)

    if request.method == "POST":
        offer.title = request.form.get("title")
        offer.description = request.form.get("description")
        offer.discount_percent = int(request.form.get("discount_percent", 0))
        offer.start_date = request.form.get("start_date") or offer.start_date
        offer.end_date = request.form.get("end_date") or offer.end_date
        offer.is_active = bool(request.form.get("is_active"))

        db.session.commit()
        flash("✅ تم تعديل العرض بنجاح", "success")
        return redirect(url_for("memo_offers"))

    return render_template("edit_offer.html", offer=offer)

@app.route("/admin/offers/delete/<int:offer_id>", methods=["POST", "GET"])
@login_required
def delete_offer(offer_id):
    if not current_user.is_admin:
        flash("🚫 لا تملك صلاحية", "danger")
        return redirect(url_for("memo_offers"))

    offer = Offer.query.get_or_404(offer_id)
    db.session.delete(offer)
    db.session.commit()

    flash("🗑 تم حذف العرض بنجاح", "success")
    return redirect(url_for("memo_offers"))

@app.route("/admin/offers")
@login_required
def memo_offers():
    if not current_user.is_admin:
        flash("🚫 لا تملك صلاحية", "danger")
        return redirect(url_for("index"))

    # جميع العروض
    offers = Offer.query.order_by(Offer.created_at.desc()).all()
    return render_template("offers.html", offers=offers)


@app.route("/admin/offers/add", methods=["GET", "POST"])
@login_required
def add_offer():
    if not current_user.is_admin:
        flash("🚫 لا تملك صلاحية", "danger")
        return redirect(url_for("index"))

    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        discount_percent = request.form.get("discount_percent", 0, type=int)
        start_date = request.form.get("start_date")
        end_date = request.form.get("end_date")
        is_active = bool(request.form.get("is_active"))

        # تحويل التاريخ من النص إلى datetime
        try:
            start_date = datetime.strptime(start_date, "%Y-%m-%dT%H:%M")
            end_date = datetime.strptime(end_date, "%Y-%m-%dT%H:%M")
        except Exception:
            flash("⚠️ صيغة التاريخ غير صحيحة", "danger")
            return redirect(url_for("add_offer"))

        # تحقق أن تاريخ النهاية بعد البداية
        if end_date <= start_date:
            flash("⚠️ تاريخ النهاية يجب أن يكون بعد تاريخ البداية", "danger")
            return redirect(url_for("add_offer"))

        # إنشاء العرض الجديد
        new_offer = Offer(
            title=title,
            description=description,
            discount_percent=discount_percent,
            start_date=start_date,
            end_date=end_date,
            is_active=is_active
        )
        db.session.add(new_offer)
        db.session.commit()

        flash("✅ تمت إضافة العرض بنجاح", "success")
        return redirect(url_for("memo_offers"))

    # صفحة إضافة عرض
    return render_template("add_offer.html")

@app.route("/admin/offers/toggle/<int:offer_id>", methods=["POST"])
@login_required
def toggle_offer(offer_id):
    if not current_user.is_admin:
        flash("🚫 لا تملك صلاحية", "danger")
        return redirect(url_for("memo_offers"))

    offer = Offer.query.get_or_404(offer_id)
    offer.is_active = not offer.is_active  # قلب الحالة
    db.session.commit()

    flash(f"تم {'تفعيل' if offer.is_active else 'إلغاء'} العرض ✅", "success")
    return redirect(url_for("memo_offers"))

@app.route("/premium", methods=["GET", "POST"])
def upgrade_premium():
    if "username" not in session:
        flash("يجب تسجيل الدخول أولاً.")
        return redirect(url_for("login"))

    if request.method == "POST":
        try:
            auth = (PAYPAL_CLIENT, PAYPAL_SECRET)
            headers = {"Content-Type": "application/json"}
            data = {
                "intent": "CAPTURE",
                "purchase_units": [{
                    "amount": {"currency_code": "USD", "value": "5.00"},
                    "description": "عضوية بريميوم"
                }],
                "application_context": {
                    "return_url": url_for("paypal_success", _external=True),
                    "cancel_url": url_for("upgrade_premium", _external=True),
                }
            }

            # إنشاء طلب دفع PayPal
            r = requests.post(f"{PAYPAL_API}/v2/checkout/orders",
                              auth=auth, headers=headers, json=data)
            order = r.json()

            # الحصول على رابط الموافقة
            for link in order.get("links", []):
                if link["rel"] == "approve":
                    return redirect(link["href"])

            return "خطأ: لم يتم العثور على رابط الموافقة"
        except Exception as e:
            return str(e)

    # GET → عرض صفحة الاشتراك
    now = datetime.utcnow()
    active_offers = Offer.query.filter(
        Offer.is_active == True,
        Offer.start_date <= now,
        Offer.end_date >= now
    ).all()
    return render_template("premium.html", offers=active_offers)


@app.route("/paypal_success")
def paypal_success():
    session["premium"] = True
    return render_template("premium_success.html")
# 🟢 تحديد مجلد رفع الستوري داخل static/stories


@app.route("/blocked_users")
@login_required
def blocked_users():
    # نجيب كل السجلات من جدول Block للمستخدم الحالي
    blocked_records = Block.query.filter_by(blocker=current_user.username).all()

    # نستخرج معلومات الأشخاص المحظورين من جدول users
    blocked_users_list = []
    for record in blocked_records:
        user = User.query.filter_by(username=record.blocked).first()
        if user:
            blocked_users_list.append(user)

    return render_template("blocked_users.html", users=blocked_users_list)

# ♻️ استرجاع بيت
@app.route("/restore/poem/<int:poem_id>", methods=["POST"])
@login_required
def restore_poem(poem_id):
    poem = Poem.query.get_or_404(poem_id)

    if poem.username != current_user.username:
        return "❌ غير مسموح", 403

    poem.is_archived = False
    poem.archived_at = None
    db.session.commit()

    return redirect(url_for("archive_page"))


# 🗑️ حذف بيت
@app.route("/delete/poem/<int:poem_id>", methods=["POST"])
@login_required
def delete_poem(poem_id):
    poem = Poem.query.get_or_404(poem_id)

    if poem.username != current_user.username:
        return "❌ غير مسموح", 403

    db.session.delete(poem)
    db.session.commit()

    return redirect(url_for("archive_page"))


# ♻️ استرجاع ستوري
@app.route("/restore/story/<int:story_id>", methods=["POST"])
@login_required
def restore_story(story_id):
    story = Story.query.get_or_404(story_id)

    if story.user_id != current_user.id:
        return "❌ غير مسموح", 403

    story.is_archived = False
    story.archived_at = None
    db.session.commit()

    return redirect(url_for("archive_page"))


# 🗑️ حذف ستوري
@app.route("/delete/story/<int:story_id>", methods=["POST"])
@login_required
def delete_story(story_id):
    story = Story.query.get_or_404(story_id)

    if story.user_id != current_user.id:
        return "❌ غير مسموح", 403

    db.session.delete(story)
    db.session.commit()

    return redirect(url_for("archive_page"))

# 📜 أرشفة بيت
@app.route("/archive/poem/<int:poem_id>", methods=["POST"])
@login_required
def archive_poem(poem_id):
    poem = Poem.query.get_or_404(poem_id)

    # التحقق إن البيت للمستخدم الحالي
    if poem.username != current_user.username:
        return "❌ غير مسموح", 403

    poem.is_archived = True
    poem.archived_at = datetime.utcnow()  # وقت الأرشفة
    db.session.commit()

    return redirect(url_for("public_profile", username=current_user.username))



@app.route("/archive/story/<int:story_id>", methods=["POST"])
@login_required
def archive_story(story_id):
    story = Story.query.get_or_404(story_id)

    if story.user_id != current_user.id:
        return "❌ غير مسموح", 403

    story.is_archived = True
    story.archived_at = datetime.utcnow()
    db.session.commit()

    return "✅ تم الأرشفة", 200

# 📦 صفحة الأرشيف
@app.route("/archive")
@login_required
def archive_page():
    # الأبيات المؤرشفة
    archived_poems = Poem.query.filter_by(
        username=current_user.username, is_archived=True
    ).all()

    # الستوري المؤرشفة
    archived_stories = Story.query.filter_by(
        user_id=current_user.id, is_archived=True
    ).all()

    return render_template(
        "archive.html",
        poems=archived_poems,
        stories=archived_stories
    )




# ✅ إضافة يوزر جديد من الرابط (للمسؤول فقط)
@app.route('/admin/adduser/<username>/<email>/<password>')
def admin_adduser(username, email, password):
    if 'username' not in session or session['username'] != 'admin':
        return "🚫 ممنوع الدخول!", 403

    # تحقق إذا موجود
    existing = User.query.filter_by(username=username).first()
    if existing:
        return f"⚠️ يوجد مستخدم بنفس الاسم: {username}"

    # تشفير الباسورد
    hashed_password = generate_password_hash(password)

    # إنشاء المستخدم
    user = User(
        username=username,
        email=email,
        password=hashed_password,
        first_name="مستخدم",
        last_name="جديد"
    )
    db.session.add(user)
    db.session.commit()

    return f"✅ تمت إضافة المستخدم: {username} | 📧 {email}"



@app.route("/create-paypal-order", methods=["POST"])
def create_paypal_order():
    if "username" not in session:
        return jsonify({"error": "يجب تسجيل الدخول أولاً"}), 403

    data = request.get_json() or {}
    plan = data.get("plan", "monthly")

    prices = {
        "monthly": "4.99",
        "yearly": "49.99"
    }
    if plan not in prices:
        return jsonify({"error": "الخطة غير صحيحة"}), 400

    access_token, err = get_paypal_access_token()
    if not access_token:
        return jsonify({"error": "PayPal OAuth failed", "details": err}), 500

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}"
    }
    body = {
        "intent": "CAPTURE",
        "purchase_units": [{
            "amount": {"currency_code": "USD", "value": prices[plan]},
            "description": f"Premium Membership - {plan}"
        }]
    }

    r = requests.post(f"{PAYPAL_API}/v2/checkout/orders", headers=headers, json=body)
    order = r.json()
    if "id" not in order:
        return jsonify({"error": "PayPal create order error", "details": order}), 500

    # (اختياري) خزّن الخطة مؤقتًا مع order_id لو بدك تربط لاحقًا
    # session[f"plan_for_{order['id']}"] = plan

    return jsonify({"id": order["id"]})


@app.route("/capture-paypal-order/<order_id>", methods=["POST"])
def capture_paypal_order(order_id):
    if "username" not in session:
        return jsonify({"error": "يجب تسجيل الدخول أولاً"}), 403

    access_token, err = get_paypal_access_token()
    if not access_token:
        return jsonify({"error": "PayPal OAuth failed", "details": err}), 500

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}"
    }
    r = requests.post(f"{PAYPAL_API}/v2/checkout/orders/{order_id}/capture", headers=headers)
    result = r.json()

    # نجاح الطلب عادةً يكون status = COMPLETED
    if result.get("status") == "COMPLETED":
        # حدّد الخطة: إمّا من السيشن أو من مبلغ الطلب
        plan = "monthly"
        try:
            purchase_units = result.get("purchase_units", [])
            amount = purchase_units[0]["payments"]["captures"][0]["amount"]["value"]
            plan = "yearly" if amount.startswith("49") else "monthly"
        except Exception:
            pass

        # فعل البريميوم في قاعدة البيانات
        user = User.query.filter_by(username=session["username"]).first()
        if user:
            now = datetime.utcnow()
            # مدّد إن كان عنده بريميوم سابق
            base = user.premium_until if user.premium_until and user.premium_until > now else now
            delta = timedelta(days=365) if plan == "yearly" else timedelta(days=30)
            user.premium_until = base + delta
            db.session.commit()

        return jsonify({"status": "success"})

    return jsonify(result), 400


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # 👇 إنشاء الحساب
        user = User(...)
        db.session.add(user)
        db.session.commit()

        # 🟢 اجبره يوافق على الشروط بعد التسجيل
        session["new_user_id"] = user.id
        return redirect(url_for("accept_terms"))

    return render_template("register.html", form=form, now=datetime.utcnow())

@app.route("/terms", methods=["GET", "POST"])
def accept_terms():
    if session.get("accepted_terms"):
        return redirect(url_for("dashboard"))  # ✅ بعد ما وافق، روح على الحساب

    form = TermsForm()
    if form.validate_on_submit():
        session["accepted_terms"] = True
        flash("✅ شكراً لموافقتك على الشروط والأحكام")

        # 🔹 سجل دخوله أو رجعه للـ dashboard
        return redirect(url_for("dashboard"))

    return render_template("terms.html", form=form)













if __name__ == "__main__":
 with app.app_context():
    db.create_all()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
