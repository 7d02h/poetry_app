# notification_utils.py
from models import db, Notification


def send_new_message(socketio, to_username, from_username, text):
    socketio.emit(
        "new_message",
        {"from": from_username, "text": text},
        room=to_username
    )


def send_new_follower(socketio, to_username, follower_username):
    socketio.emit(
        "new_notification",
        {"message": f"{follower_username} بدأ بمتابعتك 🎉"},
        room=to_username
    )


def send_new_like(socketio, to_username, liker_username, poem_id=None):
    socketio.emit(
        "new_notification",
        {"message": f"{liker_username} أعجب بالقصيدة 📖❤️", "poem_id": poem_id},
        room=to_username
    )