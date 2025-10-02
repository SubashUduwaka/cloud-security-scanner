#!/usr/bin/env python3
"""
Database migration script for adding Basic/Pro user functionality
This script adds the new fields to existing users in the database
"""

import os
import sys
from datetime import datetime, timezone
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Create Flask app and configure database
app = Flask(__name__)
app.config['SECRET_KEY'] = 'migration-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

def run_migration():
    """Run the database migration to add new user fields"""
    print("Starting database migration for Basic/Pro user functionality...")

    with app.app_context():
        try:
            # First, try to add the new columns if they don't exist
            with db.engine.connect() as conn:
                # Check if columns exist
                from sqlalchemy import text
                result = conn.execute(text("PRAGMA table_info(user)"))
                columns = [row[1] for row in result]

                migrations_needed = []

                if 'user_type' not in columns:
                    migrations_needed.append("ALTER TABLE user ADD COLUMN user_type VARCHAR(10) DEFAULT 'BASIC'")

                if 'monthly_scans_used' not in columns:
                    migrations_needed.append("ALTER TABLE user ADD COLUMN monthly_scans_used INTEGER DEFAULT 0")

                if 'last_scan_reset' not in columns:
                    migrations_needed.append("ALTER TABLE user ADD COLUMN last_scan_reset DATETIME")

                if 'allowed_monthly_scans' not in columns:
                    migrations_needed.append("ALTER TABLE user ADD COLUMN allowed_monthly_scans INTEGER DEFAULT 5")

                # Execute migrations
                for migration in migrations_needed:
                    print(f"Executing: {migration}")
                    conn.execute(text(migration))

                # Update existing users to have proper defaults
                if migrations_needed:
                    print("Setting default values for existing users...")
                    now = datetime.now(timezone.utc).isoformat()

                    # Set default values for all existing users
                    conn.execute(text(f"""
                        UPDATE user
                        SET
                            user_type = 'BASIC',
                            monthly_scans_used = 0,
                            last_scan_reset = '{now}',
                            allowed_monthly_scans = 5
                        WHERE user_type IS NULL OR user_type = ''
                    """))

                    print("Migration completed successfully!")
                    print("Updated existing users to Basic plan with 5 scans per month")
                else:
                    print("Database is already up to date - no migrations needed")

        except Exception as e:
            print(f"Migration failed: {e}")
            return False

    return True

def verify_migration():
    """Verify that the migration was successful"""
    print("\nVerifying migration...")

    with app.app_context():
        try:
            with db.engine.connect() as conn:
                # Check table structure
                from sqlalchemy import text
                result = conn.execute(text("PRAGMA table_info(user)"))
                columns = [row[1] for row in result]

                required_columns = ['user_type', 'monthly_scans_used', 'last_scan_reset', 'allowed_monthly_scans']
                missing_columns = [col for col in required_columns if col not in columns]

                if missing_columns:
                    print(f"Missing columns: {missing_columns}")
                    return False

                # Check user data
                result = conn.execute(text("SELECT COUNT(*) as count FROM user WHERE user_type = 'BASIC'"))
                basic_users = result.fetchone()[0]

                print(f"All required columns present")
                print(f"{basic_users} users set to BASIC plan")

                return True

        except Exception as e:
            print(f"Verification failed: {e}")
            return False

if __name__ == "__main__":
    print("=== Aegis Scanner Database Migration ===")
    print("Adding Basic/Pro user functionality...\n")

    if run_migration():
        if verify_migration():
            print("\nMigration completed successfully!")
            print("Your application is now ready with Basic/Pro user functionality.")
        else:
            print("\nMigration completed but verification failed.")
    else:
        print("\nMigration failed. Please check the error messages above.")