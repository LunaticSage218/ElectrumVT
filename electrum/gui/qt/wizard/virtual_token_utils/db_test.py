import os
from db_manager import SQLiteDBManager

db_dir = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(db_dir, "enrollments.db")

try:
    db = SQLiteDBManager(db_path)
    print("Connected successfully!")
except Exception as e:
    print(f"Connection failed: {e}")
