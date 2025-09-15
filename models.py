from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):  # ✅ يرث من UserMixin
    __tablename__ = 'users'       # ✅ لازم شرطتين

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)
    first_name = db.Column(db.String(64))
    last_name = db.Column(db.String(64))
    email = db.Column(db.String(120))
    bio = db.Column(db.Text)
    profile_image = db.Column(db.String(128), default='default.jpg')
    private = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    verified = db.Column(db.Boolean, default=False)
    allow_anonymous_messages = db.Column(db.Boolean, default=False)
    is_moderator = db.Column(db.Boolean, default=False)
    premium_until = db.Column(db.DateTime, nullable=True)
    birthdate = db.Column(db.Date, nullable=True)
    def is_premium(self):
        return self.premium_until is not None and self.premium_until > datetime.utcnow()

    followers = db.relationship(
        'Follower',
        foreign_keys='Follower.followed_username',
        primaryjoin='User.username == Follower.followed_username',
        lazy='dynamic'
    )


class Poem(db.Model):
    __tablename__ = 'poems'   # ⚠️ خليها شرطتين مو وحدة
    
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    likes = db.Column(db.Integer, default=0)
    views = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.now)
    timestamp = db.Column(db.DateTime, default=datetime.now)

    username = db.Column(db.String(64), db.ForeignKey('users.username'), nullable=False)
    is_archived = db.Column(db.Boolean, default=False)
    archived_at = db.Column(db.DateTime)

    # 🔹 علاقة مع المستخدم
    user = db.relationship("User", backref="poems", lazy=True)

    # 🔹 حذفنا likes_rel من هنا (عشان ما يتعارض مع Like)

class Follower(db.Model):
    __tablename__ = 'followers'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), db.ForeignKey('users.username'), nullable=False)
    followed_username = db.Column(db.String(64), db.ForeignKey('users.username'), nullable=False)

    user = db.relationship("User", foreign_keys=[username])

class StoryLike(db.Model):
    __tablename__ = 'story_likes'
    id = db.Column(db.Integer, primary_key=True)
    story_id = db.Column(db.Integer, db.ForeignKey('stories.id'), nullable=False)
    username = db.Column(db.String(150), db.ForeignKey('users.username'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    story = db.relationship('Story', backref='likes', lazy=True)
    user = db.relationship('User', lazy=True)


class Like(db.Model):
    __tablename__ = 'likes'

    id = db.Column(db.Integer, primary_key=True)

    # 🔹 مفتاح أجنبي للقصيدة مع ON DELETE CASCADE
    poem_id = db.Column(
        db.Integer,
        db.ForeignKey('poems.id', ondelete="CASCADE"),
        nullable=False
    )

    # 🔹 مفتاح أجنبي للمستخدم مع ON DELETE CASCADE
    username = db.Column(
        db.String(64),
        db.ForeignKey('users.username', ondelete="CASCADE"),
        nullable=False
    )

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # 🔹 علاقات ORM
    poem = db.relationship(
        "Poem",
        backref=db.backref("likes_rel", cascade="all, delete-orphan", passive_deletes=True)
    )
    user = db.relationship(
        "User",
        backref=db.backref("likes", cascade="all, delete-orphan", passive_deletes=True)
    )

    # 🔹 منع تكرار اللايك لنفس المستخدم على نفس القصيدة
    table_args = (
        db.UniqueConstraint("poem_id", "username", name="unique_user_poem_like"),
    )

    

class SavedPoem(db.Model):
    __tablename__ = 'saved_poems'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), db.ForeignKey('users.username'), nullable=False)
    poem_id = db.Column(db.Integer, db.ForeignKey('poems.id'), nullable=False)


class Report(db.Model):
    __tablename__ = 'reports'
    id = db.Column(db.Integer, primary_key=True)
    poem_id = db.Column(db.Integer, db.ForeignKey('poems.id'), nullable=False)
    reported_by = db.Column(db.String(64), db.ForeignKey('users.username'), nullable=False)
    reason = db.Column(db.Text)
    report_date = db.Column(db.DateTime, default=datetime.now)


class Block(db.Model):
    __tablename__ = 'blocks'
    id = db.Column(db.Integer, primary_key=True)
    blocker = db.Column(db.String(64), db.ForeignKey('users.username'), nullable=False)
    blocked = db.Column(db.String(64), db.ForeignKey('users.username'), nullable=False)
    block_date = db.Column(db.DateTime, default=datetime.now)


class Ban(db.Model):
    __tablename__ = 'bans'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    username = db.Column(db.String(64), db.ForeignKey('users.username'), nullable=False)
    reason = db.Column(db.Text)
    banned_at = db.Column(db.DateTime, default=datetime.now)
    duration_days = db.Column(db.Integer)
    ends_at = db.Column(db.DateTime)


class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(64), db.ForeignKey('users.username'), nullable=True)
    receiver = db.Column(db.String(64), db.ForeignKey('users.username'), nullable=False)
    content = db.Column(db.Text)
    file_path = db.Column(db.String(256))
    message_type = db.Column(db.String(32), default='text')
    timestamp = db.Column(db.DateTime, default=datetime.now)
    is_read = db.Column(db.Boolean, default=False)
    is_anonymous = db.Column(db.Boolean, default=False)
    anonymous = db.Column(db.Boolean, default=False)


class MessageReport(db.Model):
    __tablename__ = 'message_reports'
    id = db.Column(db.Integer, primary_key=True)
    reporter = db.Column(db.String(64), db.ForeignKey('users.username'), nullable=False)
    reported_username = db.Column(db.String(64), db.ForeignKey('users.username'), nullable=False)
    message_id = db.Column(db.Integer, db.ForeignKey('messages.id'))
    reason = db.Column(db.Text)
    report_date = db.Column(db.DateTime, default=datetime.now)


class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    recipient = db.Column(db.String(64), db.ForeignKey('users.username'), nullable=False)
    sender = db.Column(db.String(64), db.ForeignKey('users.username'))
    type = db.Column(db.String(64), nullable=False)
    content = db.Column(db.Text)
    poem_id = db.Column(db.Integer, db.ForeignKey('poems.id'))
    is_read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)


class ContactMessage(db.Model):
    __tablename__ = 'contact_messages'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    message = db.Column(db.Text, nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.now)


class Settings(db.Model):
    __tablename__ = 'settings'
    id = db.Column(db.Integer, primary_key=True)

    site_name = db.Column(db.String(100), default='موقع الشعر')
    site_description = db.Column(db.Text, default='منصة لمشاركة الأبيات الشعرية.')
    created_at = db.Column(db.DateTime, default=datetime.now)

    maintenance_mode = db.Column(db.Boolean, default=False)
    allow_registration = db.Column(db.Boolean, default=True)
    auto_verify_users = db.Column(db.Boolean, default=False)

    default_ban_duration_days = db.Column(db.Integer, default=7)
    max_login_attempts = db.Column(db.Integer, default=5)
    ban_duration_minutes = db.Column(db.Integer, default=60)

    max_poem_length = db.Column(db.Integer, default=250)
    post_interval_seconds = db.Column(db.Integer, default=60)

    enable_likes = db.Column(db.Boolean, default=True)
    enable_comments = db.Column(db.Boolean, default=True)
    enable_saved = db.Column(db.Boolean, default=True)

    enable_notifications = db.Column(db.Boolean, default=True)
    enable_messages = db.Column(db.Boolean, default=True)

    instagram_url = db.Column(db.String(255))
    twitter_url = db.Column(db.String(255))
    contact_email = db.Column(db.String(255))

    admin_panel_name = db.Column(db.String(100), default="admin")
    dark_mode = db.Column(db.Boolean, default=False)
    blocked_words = db.Column(db.Text, default="")


class FollowRequest(db.Model):
    __tablename__ = 'follow_requests'
    id = db.Column(db.Integer, primary_key=True)
    sender_username = db.Column(db.String(100), db.ForeignKey('users.username'), nullable=False)
    receiver_username = db.Column(db.String(100), db.ForeignKey('users.username'), nullable=False)
    status = db.Column(db.String(20), default='pending')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# 🔹 جدول الستوري
class Story(db.Model):
    __tablename__ = 'stories'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    media_path = db.Column(db.String(255), nullable=False)  # صورة أو فيديو
    media_type = db.Column(db.String(10), default='image')  # image / video
    caption = db.Column(db.String(255))  # نص قصير اختياري
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=24))
    is_active = db.Column(db.Boolean, default=True)
    is_archived = db.Column(db.Boolean, default=False)  # ✅ جديد
    archived_at = db.Column(db.DateTime)
    user = db.relationship('User', backref='stories', lazy=True)


# 🔹 جدول مشاهدات الستوري
class StoryView(db.Model):
    __tablename__ = 'story_views'
    id = db.Column(db.Integer, primary_key=True)
    story_id = db.Column(db.Integer, db.ForeignKey('stories.id'), nullable=False)
    viewer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    viewed_at = db.Column(db.DateTime, default=datetime.utcnow)

    story = db.relationship('Story', backref='views', lazy=True)
    viewer = db.relationship('User', lazy=True)

class Offer(db.Model):
    __tablename__ = 'offers'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)  # عنوان العرض
    description = db.Column(db.Text, nullable=False)   # وصف العرض
    discount_percent = db.Column(db.Integer, default=0)  # نسبة الخصم %
    start_date = db.Column(db.DateTime, default=datetime.utcnow)  # بداية العرض
    end_date = db.Column(db.DateTime, nullable=False)  # نهاية العرض
    is_active = db.Column(db.Boolean, default=True)    # هل العرض مفعّل؟

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def is_valid(self):
        """يتأكد إذا العرض مازال صالح"""
        now = datetime.utcnow()
        return self.is_active and self.start_date <= now <= self.end_date