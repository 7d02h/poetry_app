# استيراد قاعدة البيانات والموديلات المطلوبة
from models import db, User, Follower, Notification
import re

# ✅ جلب مستخدم حسب الاسم
def get_user_by_username(username):
    return User.query.filter_by(username=username).first()

# ✅ جلب مستخدم حسب ID
def get_user_by_id(user_id):
    return User.query.get(user_id)

# ✅ إنشاء مستخدم جديد
def create_user(username, password_hash, email=None, first_name=None, last_name=None):
    user = User(
        username=username,
        password=password_hash,
        email=email,
        first_name=first_name,
        last_name=last_name
    )
    db.session.add(user)
    db.session.commit()

# ✅ ترقية مستخدم إلى مدير
def promote_to_admin(username):
    user = get_user_by_username(username)
    if user:
        user.is_admin = True
        db.session.commit()

# ✅ جلب كل المستخدمين
def get_all_users():
    return User.query.all()

# ✅ حذف مستخدم حسب ID
def delete_user(user_id):
    user = get_user_by_id(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()

# ✅ توثيق مستخدم
def verify_user(user_id):
    user = get_user_by_id(user_id)
    if user:
        user.verified = True
        db.session.commit()

# ✅ إزالة التوثيق
def unverify_user_by_id(user_id):
    user = get_user_by_id(user_id)
    if user:
        user.verified = False
        db.session.commit()

# ✅ زيادة عدد المتابعين (بإضافة متابعين وهميين + إشعارات)
def increase_followers_by_id(user_id, amount=1):
    user = get_user_by_id(user_id)
    if user:
        for i in range(amount):
            fake_username = f"fake_user_{user_id}_{i}"

            # إضافة المتابع
            fake_follower = Follower(username=fake_username, followed_username=user.username)
            db.session.add(fake_follower)

            # إضافة الإشعار
            notif = Notification(
                recipient=user.username,
                sender=fake_username,
                type="follow",
                content=f"{fake_username} بدأ متابعتك!"
            )
            db.session.add(notif)

        # تحديث عدد المتابعين (اختياري إذا عندك خاصية followers داخل User)
        user.followers = (user.followers or 0) + amount

        db.session.commit()


def valid_username(username):
    return re.match("^[A-Za-z0-9_أ-ي]+$", username)

        
