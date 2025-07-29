from extensions import socketio

def send_notification(username, message):
    socketio.emit("new_notification", {"message": message}, room=username)