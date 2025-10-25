"""
Database Migration Script for Aegis v1.1
Adds password expiry and security update fields to User model
Run this BEFORE starting the application after code updates
"""

import sqlite3
import os
import sys
from datetime import datetime

def migrate_database():
    """Add new columns to existing database"""
    # Use the same path as app.py
    APP_NAME = "AegisScanner"
    if sys.platform == "win32":
        USER_DATA_DIR = os.path.join(os.environ['LOCALAPPDATA'], APP_NAME)
    else:
        USER_DATA_DIR = os.path.join(os.path.expanduser('~'), f'.{APP_NAME.lower()}')

    db_path = os.path.join(USER_DATA_DIR, 'app.db')

    print(f"[INFO] Looking for database at: {db_path}")

    if not os.path.exists(db_path):
        print(f"[ERROR] Database not found: {db_path}")
        print("   The database will be created automatically when you start the application.")
        return

    print("[INFO] Database found! Starting migration...")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    migrations_applied = 0

    # Add password_changed_date column
    try:
        cursor.execute("""
            ALTER TABLE user ADD COLUMN password_changed_date TIMESTAMP
        """)
        # Set default value for existing rows
        cursor.execute("""
            UPDATE user SET password_changed_date = CURRENT_TIMESTAMP WHERE password_changed_date IS NULL
        """)
        print("[SUCCESS] Added password_changed_date column")
        migrations_applied += 1
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e).lower():
            print("[SKIP] password_changed_date column already exists - skipping")
        else:
            print(f"[ERROR] Error adding password_changed_date: {e}")

    # Add last_security_info_update column
    try:
        cursor.execute("""
            ALTER TABLE user ADD COLUMN last_security_info_update TIMESTAMP
        """)
        # Set default value for existing rows
        cursor.execute("""
            UPDATE user SET last_security_info_update = CURRENT_TIMESTAMP WHERE last_security_info_update IS NULL
        """)
        print("[SUCCESS] Added last_security_info_update column")
        migrations_applied += 1
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e).lower():
            print("[SKIP] last_security_info_update column already exists - skipping")
        else:
            print(f"[ERROR] Error adding last_security_info_update: {e}")

    # Add security_info_email_confirmed column
    try:
        cursor.execute("""
            ALTER TABLE user ADD COLUMN security_info_email_confirmed BOOLEAN DEFAULT 0
        """)
        print("[SUCCESS] Added security_info_email_confirmed column")
        migrations_applied += 1
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e).lower():
            print("[SKIP] security_info_email_confirmed column already exists - skipping")
        else:
            print(f"[ERROR] Error adding security_info_email_confirmed: {e}")

    # Commit changes
    try:
        conn.commit()
        print(f"\n[SUCCESS] Database migration completed successfully!")
        print(f"   Applied {migrations_applied} new migration(s)")
    except Exception as e:
        conn.rollback()
        print(f"\n[ERROR] Migration failed: {e}")
    finally:
        conn.close()

    print("\n[NEXT STEPS]")
    print("   1. Restart the Aegis application")
    print("   2. New features will be automatically available")

if __name__ == '__main__':
    print("=" * 60)
    print("  Aegis Cloud Scanner - Database Migration v1.1")
    print("=" * 60)
    print()

    migrate_database()

    print()
    print("=" * 60)
