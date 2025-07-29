# make_admin.py

from app import app
from models import db, User

def make_admin():
    with app.app_context():
        username = "admin"
        user = User.query.filter_by(username=username).first()
        if user:
            user.is_admin = True
            db.session.commit()
            print(f"✅ تم تفعيل لوحة admin للمستخدم: {username}")
        else:
            print(f"❌ المستخدم {username} غير موجود في قاعدة البيانات.")

if __name__ == "__main__":
    make_admin()