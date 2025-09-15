from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from flask_login import login_user
from datetime import datetime, timedelta
import os, json

from models import db, User, Poem, Story, Follower, Block, Ban, FollowRequest, Notification
from forms import LoginForm, EditProfileForm, EmptyForm
from utils import valid_username

profile_bp = Blueprint("profile", __name__)

# 📌 تسجيل الدخول
@profile_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():  # ✅ يتحقق من CSRF + الفالديشن
        username = form.username.data.strip()
        password = form.password.data

        if not username or not password:
            flash("❗ يرجى ملء جميع الحقول.", "warning")
            return render_template("login.html", form=form)

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            now = datetime.now()
            active_ban = Ban.query.filter(
                Ban.username == username,
                Ban.ends_at != None,
                Ban.ends_at > now
            ).first()

            if active_ban:
                ends_at_str = active_ban.ends_at.strftime('%Y-%m-%d %H:%M') if active_ban.ends_at else "غير محدد"
                flash(f"🚫 حسابك محظور حتى {ends_at_str}.", "danger")
                return redirect(url_for('profile.login'))

            login_user(user)
            session["username"] = username
            flash("✅ تم تسجيل الدخول بنجاح", "success")
            return redirect(url_for("home"))

        flash("❌ اسم المستخدم أو كلمة المرور غير صحيحة", "danger")

    # ✅ مهم جدًا: نمرر form للـ template
    return render_template("login.html", form=form)


# 📌 إنشاء حساب
@profile_bp.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()

        # --- التحقق من الموافقة على الشروط
        if not request.form.get("accept_terms"):
            flash("⚠️ يجب الموافقة على الشروط والأحكام قبل إنشاء الحساب.")
            return render_template("signup.html", now=datetime.utcnow())

        # --- تاريخ الميلاد
        birthdate = None
        birth_day = request.form.get("birth_day")
        birth_month = request.form.get("birth_month")
        birth_year = request.form.get("birth_year")

        if birth_day and birth_month and birth_year:
            try:
                birthdate = datetime(
                    int(birth_year), int(birth_month), int(birth_day)
                ).date()
            except ValueError:
                flash("⚠️ تاريخ الميلاد غير صالح.")
                return render_template("signup.html", now=datetime.utcnow())

        # --- التأكد من أن الاسم أو البريد غير مستخدم مسبقًا
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing_user:
            flash("⚠️ اسم المستخدم أو البريد الإلكتروني مستخدم مسبقًا.")
            return render_template("signup.html", now=datetime.utcnow())

        # --- التحقق من كلمة المرور
        if len(password) < 8:
            flash("⚠️ كلمة المرور يجب أن تكون 8 أحرف على الأقل.")
            return render_template("signup.html", now=datetime.utcnow())

        # --- إنشاء الحساب
        hashed_password = generate_password_hash(password)
        user = User(
            username=username,
            email=email,
            password=hashed_password,
            first_name=first_name,
            last_name=last_name,
            birthdate=birthdate
        )

        db.session.add(user)
        db.session.commit()

        # --- تسجيل دخول مباشر
        login_user(user)
        session["username"] = username
        session.permanent = True

        flash("✅ تم إنشاء الحساب وتسجيل دخولك بنجاح! مرحبًا بك 🌟")
        return redirect(url_for("home"))

    # إذا GET
    return render_template("signup.html", now=datetime.utcnow())


# 📌 تسجيل الخروج
@profile_bp.route("/logout")
def logout():
    session.clear()  # 🟢 يمسح كل بيانات الجلسة (username + أي متغيرات ثانية)
    flash("تم تسجيل الخروج.")
    return redirect(url_for("profile.login"))


# 📌 البروفايل العام
@profile_bp.route("/profile/<username>", methods=["GET", "POST"])
def public_profile(username):
    current_user = session.get("username")
    if not current_user:
        return redirect(url_for("profile.login"))

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

    # ✅ إضافة الفورم
    form = EmptyForm()

    if request.method == "POST" and form.validate_on_submit():
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
        return redirect(url_for("profile.public_profile", username=username))

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
                           profile_story=profile_story_obj,
                           form=form)


# 📌 اختصار لبروفايلي
@profile_bp.route("/profile")
def my_profile():
    if "username" not in session:
        return redirect(url_for("profile.login"))
    return redirect(url_for("profile.public_profile", username=session["username"]))


# 📌 تعديل البروفايل
@profile_bp.route("/edit_profile", methods=["GET", "POST"])
def edit_profile():
    if "username" not in session:
        flash("يجب تسجيل الدخول أولاً.")
        return redirect(url_for("profile.login"))

    user = User.query.filter_by(username=session["username"]).first()
    if not user:
        flash("المستخدم غير موجود.")
        return redirect("/")

    form = EditProfileForm()  # ✅ تعريف الفورم

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
            return redirect(url_for("profile.edit_profile"))

        # تحقق عام لصلاحية الاسم
        if not valid_username(new_username):
            flash("⚠️ اسم المستخدم غير صالح.")
            return redirect(url_for("profile.edit_profile"))

        # معالجة صورة الملف الشخصي
        profile_image_file = request.files.get("profile_pic")
        profile_image_filename = user.profile_image or "default.jpg"
        if profile_image_file and profile_image_file.filename != "":
            filename = secure_filename(profile_image_file.filename)
            profile_image_filename = filename
            image_path = os.path.join("static/uploads/profiles", filename)
            os.makedirs("static/uploads/profiles", exist_ok=True)
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
            return redirect(url_for("profile.public_profile", username=new_username))

        except:
            db.session.rollback()
            flash("⚠️ اسم المستخدم موجود مسبقًا.")
            return redirect(url_for("profile.edit_profile"))

    full_name = f"{user.first_name or ''} {user.last_name or ''}".strip()
    return render_template("edit_profile.html",
                           form=form,
                           username=user.username,
                           full_name=full_name,
                           bio=user.bio or "",
                           profile_pic=user.profile_image or "default.jpg")