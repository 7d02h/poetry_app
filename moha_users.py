import sqlite3

DATABASE = "poetry.db"

# الاتصال بقاعدة البيانات
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# ✅ دالة للحصول على مستخدم حسب اسم المستخدم
def get_user_by_username(username):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return user

# ✅ دالة للحصول على مستخدم حسب ID (مطلوبة لـ Flask-Login)
def get_user_by_id(user_id):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return user

# ✅ دالة لإنشاء مستخدم جديد
def create_user(username, password_hash, email=None, first_name=None, last_name=None):
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO users (username, password, email, first_name, last_name)
        VALUES (?, ?, ?, ?, ?)
    """, (username, password_hash, email, first_name, last_name))
    conn.commit()
    conn.close()

# ✅ دالة لترقية مستخدم إلى مدير
def promote_to_admin(username):
    conn = get_db_connection()
    conn.execute("UPDATE users SET is_admin = 1 WHERE username = ?", (username,))
    conn.commit()
    conn.close()

# ✅ دالة لجلب كل المستخدمين
def get_all_users():
    conn = get_db_connection()
    users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return users

# ✅ دالة لحذف مستخدم
def delete_user(user_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()