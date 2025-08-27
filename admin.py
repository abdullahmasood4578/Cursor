from app import app, db ,User # Adjust 'app' to match your Flask app's module name # Adjust 'models' to match your models' module name
from werkzeug.security import generate_password_hash
from datetime import datetime

def add_admin_user():
    with app.app_context():  # Ensure the app context is active for database operations
        # Check if admin user already exists
        existing_admin = User.query.filter_by(email="admin@example.com").first()
        if existing_admin:
            print("Admin user with email 'admin@example.com' already exists.")
            return

        # Create new admin user
        admin = User(
            username="imabd",
            email="iamabd873@gmail.com",
            password_hash=generate_password_hash("admin123", method='pbkdf2:sha256'),  # Use password_hash
            is_verified=True,  # Set to True for admin to bypass OTP verification
            is_active=True,
            created_at=datetime.utcnow(),
            is_admin=True
        )

        try:
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully!")
            print("Email: admin@example.com")
            print("Password: admin123")
        except Exception as e:
            db.session.rollback()
            print(f"Error creating admin user: {str(e)}")

if __name__ == "__main__":
    add_admin_user()