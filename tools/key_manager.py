#!/usr/bin/env python3
"""
AEGIS CLOUD SCANNER - Key Manager CLI
Complete key management utility for administrators
"""
import sys
import os
import argparse
from datetime import datetime, timezone
from tabulate import tabulate

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

class KeyManager:
    """Key management operations"""
    
    def __init__(self):
        self.app = None
        self.db = None
        self.CloudCredential = None
        self._initialize_app()
    
    def _initialize_app(self):
        """Initialize Flask app context"""
        try:
            from app import app, db, CloudCredential
            self.app = app
            self.db = db
            self.CloudCredential = CloudCredential
        except ImportError as e:
            print(f"❌ Could not import app components: {e}")
            print("Make sure you're running this from the project directory")
            sys.exit(1)
    
    def list_keys(self, show_inactive=False, limit=50):
        """List access keys"""
        with self.app.app_context():
            query = self.CloudCredential.query
            
            if not show_inactive:
                query = query.filter_by(is_active=True)
            
            keys = query.order_by(self.CloudCredential.created_at.desc()).limit(limit).all()
            
            if not keys:
                print("📋 No access keys found")
                return
            
            # Prepare data for table
            headers = ["ID", "Description", "Status", "Created By", "Created", "Expires", "Usage", "Last Used"]
            rows = []
            
            now = datetime.now(timezone.utc)
            
            for key in keys:
                # Determine status
                if not key.is_active:
                    status = "❌ Revoked"
                elif key.expires_at < now:
                    status = "⏰ Expired"
                else:
                    hours_left = (key.expires_at - now).total_seconds() / 3600
                    if hours_left < 1:
                        status = "🔶 Expiring Soon"
                    else:
                        status = "✅ Active"
                
                rows.append([
                    key.id,
                    key.description[:30] + ("..." if len(key.description) > 30 else ""),
                    status,
                    key.created_by or "System",
                    key.created_at.strftime('%m/%d %H:%M'),
                    key.expires_at.strftime('%m/%d %H:%M'),
                    key.usage_count,
                    key.last_used.strftime('%m/%d %H:%M') if key.last_used else "Never"
                ])
            
            print(f"\n📊 Access Keys ({len(keys)} shown, limit: {limit})")
            print("=" * 80)
            print(tabulate(rows, headers=headers, tablefmt="grid"))
    
    def show_key_details(self, key_id):
        """Show detailed information about a specific key"""
        with self.app.app_context():
            key = self.CloudCredential.query.get(key_id)
            
            if not key:
                print(f"❌ Key with ID {key_id} not found")
                return
            
            now = datetime.now(timezone.utc)
            
            print(f"\n🔍 Key Details - ID {key.id}")
            print("=" * 50)
            print(f"Description: {key.description}")
            print(f"Created By: {key.created_by or 'System'}")
            print(f"Created: {key.created_at}")
            print(f"Expires: {key.expires_at}")
            print(f"Status: {'✅ Active' if key.is_active else '❌ Revoked'}")
            print(f"Usage Count: {key.usage_count}")
            print(f"Last Used: {key.last_used or 'Never'}")
            
            if key.is_active and key.expires_at > now:
                time_left = key.expires_at - now
                hours_left = time_left.total_seconds() / 3600
                print(f"Time Remaining: {hours_left:.1f} hours")
            
            print("=" * 50)
    
    def revoke_key(self, key_id, reason="Manually revoked"):
        """Revoke an access key"""
        with self.app.app_context():
            key = self.CloudCredential.query.get(key_id)
            
            if not key:
                print(f"❌ Key with ID {key_id} not found")
                return False
            
            if not key.is_active:
                print(f"⚠️  Key {key_id} is already inactive")
                return False
            
            key.is_active = False
            self.db.session.commit()
            
            print(f"✅ Key {key_id} has been revoked")
            print(f"   Description: {key.description}")
            print(f"   Reason: {reason}")
            return True
    
    def cleanup_expired(self):
        """Clean up expired keys"""
        with self.app.app_context():
            now = datetime.now(timezone.utc)
            
            expired_keys = self.CloudCredential.query.filter(
                self.CloudCredential.expires_at < now,
                self.CloudCredential.is_active == True
            ).all()
            
            if not expired_keys:
                print("🧹 No expired keys found")
                return 0
            
            count = 0
            for key in expired_keys:
                key.is_active = False
                count += 1
                print(f"🧹 Marked expired: {key.id} - {key.description}")
            
            self.db.session.commit()
            print(f"✅ Cleaned up {count} expired keys")
            return count
    
    def generate_stats(self):
        """Generate usage statistics"""
        with self.app.app_context():
            now = datetime.now(timezone.utc)
            
            total_keys = self.CloudCredential.query.count()
            active_keys = self.CloudCredential.query.filter_by(is_active=True).count()
            expired_keys = self.CloudCredential.query.filter(
                self.CloudCredential.expires_at < now
            ).count()
            used_keys = self.CloudCredential.query.filter(
                self.CloudCredential.usage_count > 0
            ).count()
            
            total_usage = self.db.session.query(
                self.db.func.sum(self.CloudCredential.usage_count)
            ).scalar() or 0
            
            print("\n📈 ACCESS KEY STATISTICS")
            print("=" * 40)
            print(f"Total Keys Created: {total_keys}")
            print(f"Currently Active: {active_keys}")
            print(f"Expired Keys: {expired_keys}")
            print(f"Used Keys: {used_keys}")
            print(f"Total Usage Count: {total_usage}")
            
            if total_keys > 0:
                usage_rate = (used_keys / total_keys) * 100
                print(f"Usage Rate: {usage_rate:.1f}%")
            
            # Recent activity
            recent_keys = self.CloudCredential.query.filter(
                self.CloudCredential.last_used > (now - timezone.timedelta(days=7))
            ).count()
            
            print(f"Used in Last 7 Days: {recent_keys}")
            print("=" * 40)
    
    def export_keys(self, filename=None):
        """Export key information to CSV"""
        import csv
        
        if not filename:
            filename = f"access_keys_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        with self.app.app_context():
            keys = self.CloudCredential.query.order_by(self.CloudCredential.created_at.desc()).all()
            
            if not keys:
                print("📋 No keys to export")
                return
            
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'id', 'description', 'is_active', 'created_by', 
                    'created_at', 'expires_at', 'usage_count', 'last_used'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for key in keys:
                    writer.writerow({
                        'id': key.id,
                        'description': key.description,
                        'is_active': key.is_active,
                        'created_by': key.created_by,
                        'created_at': key.created_at,
                        'expires_at': key.expires_at,
                        'usage_count': key.usage_count,
                        'last_used': key.last_used
                    })
            
            print(f"✅ Exported {len(keys)} keys to: {filename}")

def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description="Aegis Cloud Scanner - Key Manager CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  list                List all access keys
  details <id>        Show detailed info for a key
  revoke <id>         Revoke an access key
  cleanup             Clean up expired keys
  stats               Show usage statistics
  export              Export keys to CSV

Examples:
  python key_manager.py list
  python key_manager.py details 5
  python key_manager.py revoke 3
  python key_manager.py cleanup
  python key_manager.py stats
        """
    )
    
    parser.add_argument('command', choices=['list', 'details', 'revoke', 'cleanup', 'stats', 'export'],
                       help='Command to execute')
    parser.add_argument('key_id', nargs='?', type=int, help='Key ID for details/revoke commands')
    parser.add_argument('--inactive', action='store_true', help='Include inactive keys in list')
    parser.add_argument('--limit', type=int, default=50, help='Limit number of keys shown')
    parser.add_argument('--output', help='Output filename for export')
    
    args = parser.parse_args()
    
    try:
        manager = KeyManager()
        
        if args.command == 'list':
            manager.list_keys(show_inactive=args.inactive, limit=args.limit)
            
        elif args.command == 'details':
            if not args.key_id:
                print("❌ Key ID required for details command")
                return 1
            manager.show_key_details(args.key_id)
            
        elif args.command == 'revoke':
            if not args.key_id:
                print("❌ Key ID required for revoke command")
                return 1
            
            confirm = input(f"❓ Are you sure you want to revoke key {args.key_id}? (y/N): ")
            if confirm.lower() == 'y':
                manager.revoke_key(args.key_id)
            else:
                print("❌ Revocation cancelled")
                
        elif args.command == 'cleanup':
            confirm = input("❓ Clean up all expired keys? (y/N): ")
            if confirm.lower() == 'y':
                manager.cleanup_expired()
            else:
                print("❌ Cleanup cancelled")
                
        elif args.command == 'stats':
            manager.generate_stats()
            
        elif args.command == 'export':
            manager.export_keys(args.output)
        
        return 0
        
    except KeyboardInterrupt:
        print("\n👋 Operation cancelled by user")
        return 1
    except Exception as e:
        print(f"💥 Error: {e}")
        return 1

if __name__ == "__main__":
    exit(main())