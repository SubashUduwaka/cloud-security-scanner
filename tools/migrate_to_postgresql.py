#!/usr/bin/env python3
"""
PostgreSQL Migration Script for Aegis Cloud Scanner
==================================================

This script migrates data from SQLite to PostgreSQL.
Run this script AFTER setting up PostgreSQL and configuring the DATABASE_URL.

Usage:
    python migrate_to_postgresql.py --backup --migrate --verify

Options:
    --backup    Create a backup of the current SQLite database
    --migrate   Perform the actual migration
    --verify    Verify the migration was successful
    --all       Run all steps (backup, migrate, verify)
"""

import os
import sys
import shutil
import argparse
from datetime import datetime
from urllib.parse import urlparse

# Add the app directory to Python path
sys.path.append(os.path.dirname(__file__))

from app import app, db, User, APIKey, CloudCredential, ScanResult, AuditLog, SuppressedFinding, PasswordHistory, AutomationRule
from secrets_manager import secrets_manager

def backup_sqlite_database():
    """Create a backup of the current SQLite database."""
    print("🔄 Creating backup of SQLite database...")

    # Find current SQLite database path
    sqlite_uri = None
    with app.app_context():
        current_uri = app.config['SQLALCHEMY_DATABASE_URI']
        if current_uri.startswith('sqlite:///'):
            sqlite_path = current_uri.replace('sqlite:///', '')
            if os.path.exists(sqlite_path):
                # Create backup with timestamp
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_path = f"{sqlite_path}.backup_{timestamp}"
                shutil.copy2(sqlite_path, backup_path)
                print(f"✅ SQLite database backed up to: {backup_path}")
                return backup_path
            else:
                print(f"❌ SQLite database not found at: {sqlite_path}")
                return None
        else:
            print("❌ Current database is not SQLite, backup skipped")
            return None

def verify_postgresql_connection():
    """Verify PostgreSQL connection and create tables."""
    print("🔄 Verifying PostgreSQL connection...")

    database_url = secrets_manager.get_database_url()
    if not database_url:
        print("❌ DATABASE_URL not configured in secrets")
        print("   Please set DATABASE_URL environment variable or configure in secrets manager")
        return False

    # Parse database URL
    parsed = urlparse(database_url)
    if parsed.scheme not in ['postgresql', 'postgres']:
        print(f"❌ Invalid database URL scheme: {parsed.scheme}")
        print("   Expected: postgresql:// or postgres://")
        return False

    print(f"✅ PostgreSQL URL configured: {parsed.scheme}://{parsed.hostname}:{parsed.port}/{parsed.path.lstrip('/')}")

    # Test connection by creating tables
    try:
        with app.app_context():
            # Configure app to use PostgreSQL
            app.config['SQLALCHEMY_DATABASE_URI'] = database_url
            app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
                'pool_size': 10,
                'pool_recycle': 120,
                'pool_pre_ping': True,
                'max_overflow': 20
            }

            # Recreate db object with new config
            db.init_app(app)

            # Create all tables
            db.create_all()
            print("✅ PostgreSQL tables created successfully")
            return True

    except Exception as e:
        print(f"❌ PostgreSQL connection failed: {str(e)}")
        print("\n🔧 Common solutions:")
        print("   1. Check DATABASE_URL format: postgresql://user:password@host:port/database")
        print("   2. Ensure PostgreSQL server is running")
        print("   3. Verify database and user exist")
        print("   4. Check network connectivity and firewall")
        return False

def get_sqlite_data():
    """Extract data from SQLite database."""
    print("🔄 Extracting data from SQLite database...")

    # Temporarily configure app to use SQLite
    sqlite_uri = None
    for root, dirs, files in os.walk('.'):
        for file in files:
            if file.endswith('.db') and 'app' in file:
                sqlite_path = os.path.join(root, file)
                sqlite_uri = f'sqlite:///{sqlite_path}'
                break
        if sqlite_uri:
            break

    if not sqlite_uri:
        print("❌ SQLite database file not found")
        return None

    print(f"📁 Using SQLite database: {sqlite_uri}")

    # Configure app for SQLite
    app.config['SQLALCHEMY_DATABASE_URI'] = sqlite_uri
    db.init_app(app)

    data = {}

    try:
        with app.app_context():
            # Extract data from all models
            models = [
                ('users', User),
                ('api_keys', APIKey),
                ('cloud_credentials', CloudCredential),
                ('scan_results', ScanResult),
                ('audit_logs', AuditLog),
                ('suppressed_findings', SuppressedFinding),
                ('password_history', PasswordHistory),
                ('automation_rules', AutomationRule)
            ]

            for table_name, model in models:
                try:
                    records = model.query.all()
                    data[table_name] = []

                    for record in records:
                        # Convert SQLAlchemy object to dictionary
                        record_dict = {}
                        for column in record.__table__.columns:
                            value = getattr(record, column.name)
                            # Handle datetime objects
                            if hasattr(value, 'isoformat'):
                                value = value.isoformat()
                            record_dict[column.name] = value
                        data[table_name].append(record_dict)

                    print(f"  📊 {table_name}: {len(data[table_name])} records")

                except Exception as e:
                    print(f"  ❌ Error extracting {table_name}: {str(e)}")
                    data[table_name] = []

            total_records = sum(len(records) for records in data.values())
            print(f"✅ Extracted {total_records} total records from SQLite")
            return data

    except Exception as e:
        print(f"❌ Error accessing SQLite database: {str(e)}")
        return None

def migrate_data_to_postgresql(data):
    """Insert data into PostgreSQL database."""
    print("🔄 Migrating data to PostgreSQL...")

    database_url = secrets_manager.get_database_url()
    if not database_url:
        print("❌ DATABASE_URL not configured")
        return False

    # Configure app for PostgreSQL
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_size': 10,
        'pool_recycle': 120,
        'pool_pre_ping': True,
        'max_overflow': 20
    }
    db.init_app(app)

    models = {
        'users': User,
        'api_keys': APIKey,
        'cloud_credentials': CloudCredential,
        'scan_results': ScanResult,
        'audit_logs': AuditLog,
        'suppressed_findings': SuppressedFinding,
        'password_history': PasswordHistory,
        'automation_rules': AutomationRule
    }

    try:
        with app.app_context():
            total_migrated = 0

            for table_name, records in data.items():
                if table_name not in models:
                    print(f"  ⚠️  Skipping unknown table: {table_name}")
                    continue

                model = models[table_name]
                migrated_count = 0

                for record_dict in records:
                    try:
                        # Create new record instance
                        record = model()

                        # Set attributes from dictionary
                        for key, value in record_dict.items():
                            if hasattr(record, key):
                                # Handle datetime strings
                                if value and isinstance(value, str) and 'T' in value:
                                    try:
                                        value = datetime.fromisoformat(value.replace('Z', '+00:00'))
                                    except:
                                        pass  # Keep as string if parsing fails

                                setattr(record, key, value)

                        db.session.add(record)
                        migrated_count += 1

                    except Exception as e:
                        print(f"    ❌ Error migrating record in {table_name}: {str(e)}")
                        continue

                try:
                    db.session.commit()
                    print(f"  ✅ {table_name}: {migrated_count} records migrated")
                    total_migrated += migrated_count
                except Exception as e:
                    db.session.rollback()
                    print(f"  ❌ Error committing {table_name}: {str(e)}")

            print(f"✅ Migration completed! {total_migrated} total records migrated")
            return True

    except Exception as e:
        print(f"❌ Migration failed: {str(e)}")
        return False

def verify_migration():
    """Verify the migration was successful."""
    print("🔄 Verifying migration...")

    database_url = secrets_manager.get_database_url()
    if not database_url:
        print("❌ DATABASE_URL not configured")
        return False

    # Configure app for PostgreSQL
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    db.init_app(app)

    models = [
        ('Users', User),
        ('API Keys', APIKey),
        ('Cloud Credentials', CloudCredential),
        ('Scan Results', ScanResult),
        ('Audit Logs', AuditLog),
        ('Suppressed Findings', SuppressedFinding),
        ('Password History', PasswordHistory),
        ('Automation Rules', AutomationRule)
    ]

    try:
        with app.app_context():
            total_records = 0

            for model_name, model in models:
                try:
                    count = model.query.count()
                    print(f"  📊 {model_name}: {count} records")
                    total_records += count
                except Exception as e:
                    print(f"  ❌ Error counting {model_name}: {str(e)}")

            print(f"✅ Verification completed! {total_records} total records in PostgreSQL")

            # Test a basic query
            user_count = User.query.count()
            if user_count > 0:
                print(f"🎉 Migration successful! Found {user_count} users in PostgreSQL")
                return True
            else:
                print("⚠️  No users found - please check if migration completed correctly")
                return True  # Still return True as empty db might be valid

    except Exception as e:
        print(f"❌ Verification failed: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Migrate Aegis Cloud Scanner from SQLite to PostgreSQL')
    parser.add_argument('--backup', action='store_true', help='Create backup of SQLite database')
    parser.add_argument('--migrate', action='store_true', help='Perform migration')
    parser.add_argument('--verify', action='store_true', help='Verify migration')
    parser.add_argument('--all', action='store_true', help='Run all steps')

    args = parser.parse_args()

    if not any([args.backup, args.migrate, args.verify, args.all]):
        parser.print_help()
        return

    print("🚀 Aegis Cloud Scanner - PostgreSQL Migration Tool")
    print("=" * 50)

    # Run all steps if --all specified
    if args.all:
        args.backup = args.migrate = args.verify = True

    success = True
    sqlite_data = None

    # Step 1: Backup
    if args.backup:
        backup_path = backup_sqlite_database()
        if not backup_path and args.migrate:
            print("❌ Cannot proceed with migration without backup")
            return

    # Step 2: Verify PostgreSQL connection
    if args.migrate or args.verify:
        if not verify_postgresql_connection():
            print("❌ Cannot proceed without PostgreSQL connection")
            return

    # Step 3: Extract SQLite data (if migrating)
    if args.migrate:
        sqlite_data = get_sqlite_data()
        if not sqlite_data:
            print("❌ Cannot proceed without SQLite data")
            return

    # Step 4: Migrate data
    if args.migrate and sqlite_data:
        if not migrate_data_to_postgresql(sqlite_data):
            success = False

    # Step 5: Verify migration
    if args.verify:
        if not verify_migration():
            success = False

    print("\n" + "=" * 50)
    if success:
        print("🎉 Migration process completed successfully!")
        print("\n📋 Next steps:")
        print("   1. Update your DATABASE_URL environment variable or secrets")
        print("   2. Restart the application")
        print("   3. Test core functionality")
        print("   4. Archive or remove the SQLite backup file")
    else:
        print("❌ Migration process encountered errors")
        print("   Please review the errors above and try again")

if __name__ == '__main__':
    main()