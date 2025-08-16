# add_test_story.py

from app import app
from models import db, Story, User
from datetime import datetime

def add_test_story():
    with app.app_context():
        username = "admin"  # غيّرها لاسم المستخدم تبعك
        user = User.query.filter_by(username=username).first()

        if not user:
            print(f"❌ المستخدم {username} غير موجود.")
            return

        story = Story(
            user_id=user.id,
            media_type="image",
            media_path="test.jpg",  # غيّرها لاسم صورة موجودة في مجلد uploads/stories
            created_at=datetime.utcnow()
        )

        db.session.add(story)
        db.session.commit()
        print(f"✅ تم إضافة ستوري تجريبية للمستخدم {username}")

if __name__ == "__main__":
    add_test_story()