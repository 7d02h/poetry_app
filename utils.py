# utils.py
import re
import humanize
from datetime import datetime, timedelta
from flask import session, has_request_context, request, redirect, url_for, flash
from flask_login import current_user, logout_user
from models import db, User, Story, Message, Notification, Block, Ban
from models import db, Notification
from datetime import datetime

# 📌 فلاتر Jinja
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


# 📌 صلاحيات الحظر
def is_user_banned(user_id):
    now = datetime.now()
    ban = Ban.query.filter(Ban.user_id == user_id, Ban.ends_at > now) \
        .order_by(Ban.ends_at.desc()).first()
    return ban


def check_user_ban():
    allowed_endpoints = ['profile.login', 'profile.signup', 'static', 'accept_terms']
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
                    return redirect(url_for('profile.login'))
        except Exception as e:
            print("خطأ أثناء التحقق من الحظر:", e)
            pass


# 📌 الدوال المساعدة
def inject_now():
    return {'now': datetime.utcnow()}


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


def inject_counts():
    if not has_request_context() or not current_user.is_authenticated:
        return {
            'notifications': [],
            'has_unread_notifications': False,
            'unread_messages_count': 0
        }

    username = current_user.username

    try:
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


def valid_username(username):
    return re.match("^[A-Za-z0-9_أ-ي]+$", username)


