import sqlite3

# الاتصال بقاعدة البيانات
conn = sqlite3.connect("poetry.db")

# تنفيذ أمر لإحضار أسماء كل الجداول
cursor = conn.cursor()
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()

# طباعة أسماء الجداول
print("الجداول الموجودة في قاعدة البيانات:")
for table in tables:
    print(f"- {table[0]}")

conn.close()