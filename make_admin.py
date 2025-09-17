from app import app, db
from models import User, Follower, Notification
from werkzeug.security import generate_password_hash

username = "admin"
email = "admin@example.com"
password = "12345678"

with app.app_context():  # ✅ فتح الـ context
    existing = User.query.filter_by(username=username).first()
    if existing:
        print("⚠️ المستخدم موجود مسبقاً - جاري حذف العلاقات ثم المستخدم...")

        # 🗑️ حذف العلاقات followers
        Follower.query.filter_by(username=existing.username).delete()
        Follower.query.filter_by(followed_username=existing.username).delete()

        # 🗑️ حذف الإشعارات المرتبطة فيه (كمرسل أو كمستقبل)
        Notification.query.filter_by(sender=existing.username).delete()
        Notification.query.filter_by(recipient=existing.username).delete()

        # 🗑️ حذف المستخدم
        db.session.delete(existing)
        db.session.commit()

    # 🔐 إنشاء مستخدم أدمن جديد
    hashed_pw = generate_password_hash(password)
    user = User(
        username=username,
        email=email,
        password=hashed_pw,
        verified=True,
        is_admin=True  # ✅ تعيينه كأدمن
    )
    db.session.add(user)
    db.session.commit()

    print("✅ تم إنشاء المستخدم الأدمن بنجاح:")
    print(f"   Username: {username}")
    print(f"   Password: {password}")
