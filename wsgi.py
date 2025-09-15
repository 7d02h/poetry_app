from app import app, db
from flask_migrate import Migrate

migrate = Migrate(app, db)

# هذا الملف مخصص لإدارة قاعدة البيانات (migrations)