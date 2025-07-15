import sqlite3

# الاتصال بقاعدة البيانات
conn = sqlite3.connect("poetry.db")
cursor = conn.cursor()

# عرض أسماء الجداول الموجودة
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()

print("🧾 الجداول الموجودة في قاعدة البيانات:")
for table in tables:
    print("-", table[0])

# فحص بيانات جدول المستخدمين إذا موجود
if ('users',) in tables:
    cursor.execute("SELECT username FROM users")
    users = cursor.fetchall()

    if users:
        print("\n👤 أسماء المستخدمين:")
        for user in users:
            print("-", user[0])
    else:
        print("\n⚠️ لا يوجد مستخدمين في الجدول.")
else:
    print("\n❌ جدول 'users' غير موجود في القاعدة.")

conn.close()