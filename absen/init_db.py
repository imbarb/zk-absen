from app import app, db, Admin
from werkzeug.security import generate_password_hash

with app.app_context():
    db.create_all()
    # Cek jika admin belum ada
    if not Admin.query.filter_by(username='admin').first():
        hashed_pw = generate_password_hash('password123', method='pbkdf2:sha256')
        new_admin = Admin(username='admin', password_hash=hashed_pw)
        db.session.add(new_admin)
        db.session.commit()
        print("Admin user created: admin / password123")
