import sqlite3

conn = sqlite3.connect("poetry.db")  # تأكد أن اسم الملف هو نفسه المُستخدم في مشروعك
cursor = conn.cursor()

# إضافة مستخدم جديد
cursor.execute("""
INSERT INTO users (username, password, email)
VALUES (?, ?, ?)
""", ("mohannad", "password123", "mohannad@example.com"))

conn.commit()
conn.close()

print("User 'mohannad' added successfully.")