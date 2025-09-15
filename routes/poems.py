# routes/poems.py
from flask import Blueprint, jsonify, render_template
from flask_login import login_required, current_user
from models import db, SavedPoem, Poem

poems_bp = Blueprint("poems", __name__)  # ✅ لازم name

# 🔹 حفظ/إلغاء الحفظ
@poems_bp.route("/save_poem/<int:poem_id>", methods=["POST"])
@login_required
def save_poem(poem_id):
    saved = SavedPoem.query.filter_by(
        username=current_user.username, poem_id=poem_id
    ).first()

    if saved:
        db.session.delete(saved)
        db.session.commit()
        return jsonify({"status": "unsaved"})
    else:
        new_saved = SavedPoem(username=current_user.username, poem_id=poem_id)
        db.session.add(new_saved)
        db.session.commit()
        return jsonify({"status": "saved"})


# 🔹 عرض الأبيات المحفوظة
@poems_bp.route("/saved_poems")
@login_required
def saved_poems():
    saved = (
        db.session.query(Poem)
        .join(SavedPoem, SavedPoem.poem_id == Poem.id)
        .filter(SavedPoem.username == current_user.username)
        .order_by(Poem.created_at.desc())
        .all()
    )
    return render_template("saved_poems.html", poems=saved)