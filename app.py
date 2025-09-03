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
from flask_login import login_required, current_user
from datetime import datetime, timedelta
from flask import Flask, render_template, request, url_for, redirect, flash
from flask_mail import Mail, Message as MailMessage
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from models import db, User, Follower
from models import Offer
import requests
from flask import Flask, request, redirect, url_for, render_template, session, jsonify
import random
import string
from werkzeug.security import generate_password_hash
import random
from flask import jsonify
from werkzeug.security import generate_password_hash
from flask_babel import Babel
import os
import base64
import requests
from datetime import datetime, timedelta
from flask import jsonify, session




import json
import eventlet
import humanize
import re
import stripe
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
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


basedir = os.path.abspath(os.path.dirname(__file__))

app.config['BABEL_DEFAULT_LOCALE'] = 'ar'
app.config['BABEL_TRANSLATION_DIRECTORIES'] = 'translations'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'poetry.db')
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2MB
app.config["UPLOAD_FOLDER"] = os.path.join("static", "profile_pics")

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "ndlusioapp@gmail.com"
app.config['MAIL_PASSWORD'] = "ylma kgjg rwnd hdaz"  # بدون مسافات
app.secret_key = "s3cr3t_2025_kjfn73hdf983hr"
# PayPal Live credentials (استبدلهم باللي أخذتهم من PayPal)
PAYPAL_CLIENT = "Aaqlf_3RSD5e7RlPLA-F-V-pdfrddc5ppqjb6RdEshIjHnR837WYJoYc3LjvfXluap58xS_JavvlXvis"
PAYPAL_SECRET = "EIN-R7pBCLZqEBOg0ZCKD6w3L6MGzlRsP6WzmoZMyEfYSjmrrcT56BKtuv6HvKdUgevl7oEAWS0xois8"
PAYPAL_API = "https://api-m.paypal.com"



# ----------------------------- قاعدة البيانات -----------------------------
db.init_app(app)
migrate = Migrate(app, db)
mail = Mail(app)
stripe.api_key = "sk_test_your_secret_key_here"
STRIPE_PUBLIC_KEY = "pk_test_your_public_key_here"



# 🔑 Serializer لتوليد رابط مؤقت
s = URLSafeTimedSerializer(app.secret_key)





# ----------------------------- اللغة -----------------------------
@app.cli.command("archive_stories")
def archive_stories():
    expiration_time = datetime.utcnow() - timedelta(hours=24)
    stories = Story.query.filter(Story.created_at < expiration_time, Story.is_archived == False).all()
    for s in stories:
        s.is_archived = True
    db.session.commit()
    print("✅ تم أرشفة الستوريات المنتهية")


babel = Babel(app)


def get_locale():
    return request.accept_languages.best_match(['ar', 'en'])

babel = Babel(app, locale_selector=get_locale)

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


def get_paypal_access_token():
    auth = (PAYPAL_CLIENT, PAYPAL_SECRET)
    headers = {"Accept": "application/json", "Accept-Language": "en_US"}
    data = {"grant_type": "client_credentials"}

    r = requests.post(f"{PAYPAL_API}/v1/oauth2/token", headers=headers, data=data, auth=auth)
    j = r.json()
    if "access_token" not in j:
        return None, j
    return j["access_token"], None

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


# في ملف app.py أو حيث تسجل الفلاتر
def format_number(value):
    try:
        num = int(value)
    except (ValueError, TypeError):
        return value

    if num >= 1_000_000_000:
        return f"{num/1_000_000_000:.1f} مليار".replace(".0", "")
    elif num >= 1_000_000:
        return f"{num/1_000_000:.1f} مليون".replace(".0", "")
    elif num >= 1_000:
        return f"{num/1_000:.1f} ألف".replace(".0", "")
    return str(num)
app.jinja_env.filters['format_number'] = format_number


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
def inject_now():
    return {'now': datetime.utcnow()}
@app.context_processor
def inject_user():
    return dict(current_user=current_user)

def inject_blocked_users():
    if not has_request_context() or 'username' not in session:
        return {}
    blocked_entries = Block.query.filter_by(blocker=session['username']).all()
    blocked_usernames = [entry.blocked for entry in blocked_entries]
    return {'blocked_users_sidebar': blocked_usernames}


def is_blocked(user1, user2):
    """يتأكد إذا في حظر بين شخصين"""
    return Block.query.filter(
        ((Block.blocker == user1) & (Block.blocked == user2)) |
        ((Block.blocker == user2) & (Block.blocked == user1))
    ).first() is not None

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

# 🔑 نسيت كلمة المرور
from flask_mail import Mail, Message as MailMessage  # ✅ استيراد بدون تعارض

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            flash("⚠️ يرجى إدخال بريد إلكتروني.", 'warning')
            return render_template('forgot_password.html')

        # 🔍 التحقق من وجود المستخدم
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("❌ البريد غير مسجل.", 'danger')
            return render_template('forgot_password.html')

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

    return render_template('forgot_password.html')

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
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()

        # --- ⚠️ تحديد إذا هو بريميوم (افتراضيًا False)
        is_premium = False  

        # --- ✅ التحقق من اسم المستخدم
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

        # --- هل الاسم أو البريد مستخدم مسبقًا؟
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing_user:
            flash("⚠️ اسم المستخدم أو البريد الإلكتروني مستخدم مسبقًا.")
            return render_template("signup.html")

        # --- إنشاء الحساب
        hashed_password = generate_password_hash(password)
        user = User(
            username=username,
            email=email,
            password=hashed_password,
            first_name=first_name,
            last_name=last_name
        )

        # ✅ تفعيل البريميوم إذا عندك منطق
        if is_premium:
            user.premium_until = datetime.utcnow() + timedelta(days=30)

        db.session.add(user)
        db.session.commit()

        # --- ✅ تسجيل دخول مباشر بعد إنشاء الحساب
        session.clear()
        login_user(SimpleUser(user))   # <-- نفس آلية login
        session["username"] = username
        session.permanent = True

        flash("✅ تم إنشاء الحساب وتسجيل دخولك بنجاح! مرحبًا بك 🌟")
        return redirect(url_for("home"))

    # 🔹 مهم: لو كانت GET أو ما انطبق أي شرط، نرجع القالب
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

    # ===================== جلب ستوري المستخدم =====================
    current_user_obj = User.query.filter_by(username=username).first()
    profile_story_obj = Story.query.filter_by(user_id=current_user_obj.id)\
                                   .filter(Story.expires_at > datetime.utcnow())\
                                   .order_by(Story.created_at.desc())\
                                   .first()
    has_story = profile_story_obj is not None

    return render_template("profile.html",
                           user=user,
                           user_poems=user_poems,
                           total_likes=total_likes,
                           followers_count=followers_count,
                           followers=followers,
                           is_following=is_following,
                           current_user=current_user,
                           blocked=blocked,
                           follow_request_sent=follow_request_sent,
                           has_story=has_story,
                           profile_story=profile_story_obj)

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





# البحث عن مستخدمين
@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'username' not in session:
        flash('يجب تسجيل الدخول أولاً', 'warning')
        return redirect(url_for('login'))

    current_username = session['username']
    results = None
    keyword = ''

    # 📌 جيب المحظورين
    blocked_by_me = db.session.query(Block.blocked).filter_by(blocker=current_username).all()
    blocked_me = db.session.query(Block.blocker).filter_by(blocked=current_username).all()
    blocked_users = [u for (u,) in blocked_by_me] + [u for (u,) in blocked_me]

    if request.method == 'POST':
        keyword = request.form.get('keyword', '').strip()
        if keyword:
            results = User.query.filter(
                or_(
                    User.username.ilike(f"%{keyword}%"),
                    User.first_name.ilike(f"%{keyword}%"),
                    User.last_name.ilike(f"%{keyword}%")
                )
            ).filter(~User.username.in_(blocked_users))  # 🚫 استثناء المحظورين
            results = results.all()

            # ✅ أضف is_following لكل مستخدم
            final_results = []
            for user in results:
                is_following = Follower.query.filter_by(
                    username=current_username,
                    followed_username=user.username
                ).first() is not None

                final_results.append({
                    "username": user.username,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "profile_image": user.profile_image,
                    "verified": user.verified,
                    "is_following": is_following
                })
            results = final_results

    return render_template(
        'search.html',
        results=results,
        current_user=current_username,
        blocked_users_sidebar=blocked_users
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

            send_notification(target_user, f"{current_username} بدأ متابعتك! 👥")

            db.session.commit()
            if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"success": True, "following": True})
            flash(f'تمت متابعة {target_user} بنجاح ✅', 'success')
    else:
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "error": "invalid"})
        flash('❌ لا يمكن متابعة نفسك أو مدخل غير صالح.', 'danger')

    return redirect(request.referrer or url_for('search'))










from flask import (
    Flask, render_template, session, redirect, url_for,
    request, jsonify, flash
)


# ❤️ زر الإعجاب
@app.route('/like/<int:poem_id>', methods=['POST'])
def like(poem_id):
    if 'username' not in session:
        return jsonify({'success': False, 'redirect': url_for('login')})

    username = session['username']
    poem = Poem.query.get(poem_id)
    if not poem:
        return jsonify({'success': False, 'message': 'البيت غير موجود'})

    existing_like = Like.query.filter_by(username=username, poem_id=poem_id).first()

    if existing_like:
        db.session.delete(existing_like)
        poem.likes = poem.likes - 1 if poem.likes > 0 else 0
    else:
        new_like = Like(username=username, poem_id=poem_id)
        db.session.add(new_like)
        poem.likes = poem.likes + 1

        # ✅ إشعار لحظي
        if poem.username != username:
            notification = Notification(
                recipient=poem.username,
                sender=username,
                type="like",
                content=f"{username} أعجب ببيتك!"
            )
            db.session.add(notification)

            try:
                send_notification(poem.username, f"{username} أعجب ببيتك! ❤️")
            except NameError:
                print("⚠️ send_notification غير معرف، تخطيت الإرسال.")

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

    # 🔹 جلب المستخدم الهدف
    user = User.query.get_or_404(user_id)

    # 🔹 العدد المطلوب إضافته
    amount = int(request.form.get('amount', 1))

    for _ in range(amount):
        # 🔹 توليد اسم مستخدم وهمي (متابع)
        fake_username = 'fake_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

        # 🔹 إضافة المتابع في جدول Follower فقط
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
        return redirect(url_for('my_stories', story_id=new_story.id))

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

    # استخراج ترتيب الستوري الحالي
    story_ids = [s.id for s in user_stories]
    current_index = story_ids.index(story.id)

    return render_template(
        "view_story.html",
        stories=user_stories,   # ✅ بدال story واحد، نرسل كل ستورياته
        current_index=current_index,  # عشان يبدأ من الستوري اللي اختاره
        time_ago_format=time_ago_format
    )

@app.route("/my_stories")
@login_required
def my_stories():
    # فلترة: ستوري غير منتهية + فعالة + مش مؤرشفة
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
        # كل المشاهدين
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

        # 👇 إضافة فلاغ هل المستخدم الحالي شاف أو عمل لايك على الستوري
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
            "is_viewed": is_viewed,   # ✅ جديد
            "is_liked": is_liked      # ✅ جديد
        })

    return render_template(
        "my_story.html",
        stories_data=stories_data,
        time_since=time_ago_format
    )

    # ✅ إرسال للقالب
    return render_template(
        "my_story.html",
        stories_data=stories_data,
        time_since=time_ago_format
    )

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



if __name__ == "__main__":
 with app.app_context():
    db.create_all()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
