# reset_db.py
import os
from app import app, db

with app.app_context():
    # Delete existing database
    db_path = os.path.join(os.path.dirname(__file__), 'database.db')
    if os.path.exists(db_path):
        os.remove(db_path)
        print("Old database deleted")
    
    # Create new database with updated schema
    db.create_all()
    print("New database created with updated schema")