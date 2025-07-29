# test_notifications.py
from app import app, db
from models import Notification
from datetime import datetime

# إنشاء إشعار متابعة
notif = Notification(
    recipient='admin',  # المستخدم الذي يتم متابعته
    sender='test_sender',  # المستخدم الذي قام بالمتابعة
    type='follow',
    content='test_sender بدأ متابعتك!',
    timestamp=datetime.utcnow()
)

# إرسال داخل سياق التطبيق
with app.app_context():
    db.session.add(notif)
    db.session.commit()
    print("✅ تم إرسال إشعار متابعة تجريبي إلى admin.")