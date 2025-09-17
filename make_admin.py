from app import app, db
from models import User, Follower, Notification, Poem
from werkzeug.security import generate_password_hash

username = "admin"
email = "admin@example.com"
password = "12345678"

with app.app_context():
    existing = User.query.filter_by(username=username).first()
    if existing:
        print("⚠️ المستخدم موجود مسبقاً - جاري تحديث بياناته...")

        existing.email = email
        existing.password = generate_password_hash(password)
        existing.verified = True
        existing.is_admin = True

        db.session.commit()
    else:
        print("ℹ️ ما في مستخدم admin - جاري إنشاؤه...")
        hashed_pw = generate_password_hash(password)
        user = User(
            username=username,
            email=email,
            password=hashed_pw,
            verified=True,
            is_admin=True
        )
        db.session.add(user)
        db.session.commit()

    print("✅ الأدمن جاهز:")
    print(f"   Username: {username}")
    print(f"   Password: {password}")