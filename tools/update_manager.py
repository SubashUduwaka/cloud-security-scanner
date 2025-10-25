"""
Aegis Cloud Security Scanner - Update Manager
Handles automatic updates from GitHub releases
"""

import os
import sys
import json
import logging
import requests
import tempfile
import shutil
import hashlib
import subprocess
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

# Import version info
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from version import (
    __version__,
    GITHUB_API_URL,
    GITHUB_REPO_OWNER,
    GITHUB_REPO_NAME,
    compare_versions
)

logger = logging.getLogger(__name__)


class UpdateManager:
    """Manages application updates from GitHub releases"""

    def __init__(self, app_data_dir: str):
        self.app_data_dir = app_data_dir
        self.update_cache_file = os.path.join(app_data_dir, 'update_cache.json')
        self.cache_duration = timedelta(hours=6)  # Check for updates every 6 hours
        self.current_version = __version__

    def check_for_updates(self, force: bool = False) -> Dict[str, Any]:
        """
        Check GitHub for latest release

        Args:
            force: Skip cache and force check

        Returns:
            dict with update information
        """
        try:
            # Check cache first unless forced
            if not force:
                cached = self._get_cached_update()
                if cached:
                    logger.info("Returning cached update info")
                    return cached

            logger.info(f"Checking for updates... Current version: {self.current_version}")

            # Get latest release from GitHub
            url = f"{GITHUB_API_URL}/releases/latest"
            headers = {"Accept": "application/vnd.github.v3+json"}

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 404:
                return {
                    "update_available": False,
                    "message": "No releases found",
                    "current_version": self.current_version
                }

            response.raise_for_status()
            release_data = response.json()

            # Parse release information
            latest_version = release_data['tag_name'].lstrip('v')
            release_name = release_data['name']
            release_notes = release_data['body']
            published_at = release_data['published_at']
            html_url = release_data['html_url']

            # Find installer asset
            installer_asset = None
            for asset in release_data.get('assets', []):
                if asset['name'].endswith('.exe') and 'Setup' in asset['name']:
                    installer_asset = {
                        'name': asset['name'],
                        'download_url': asset['browser_download_url'],
                        'size': asset['size'],
                        'id': asset['id']
                    }
                    break

            # Compare versions
            comparison = compare_versions(latest_version, self.current_version)
            update_available = comparison > 0

            result = {
                "update_available": update_available,
                "current_version": self.current_version,
                "latest_version": latest_version,
                "release_name": release_name,
                "release_notes": release_notes,
                "published_at": published_at,
                "release_url": html_url,
                "installer": installer_asset,
                "checked_at": datetime.now(timezone.utc).isoformat()
            }

            # Cache the result
            self._cache_update_info(result)

            logger.info(f"Update check complete. Update available: {update_available}")
            return result

        except requests.RequestException as e:
            logger.error(f"Error checking for updates: {e}")
            return {
                "update_available": False,
                "error": f"Failed to check for updates: {str(e)}",
                "current_version": self.current_version
            }
        except Exception as e:
            logger.error(f"Unexpected error checking for updates: {e}", exc_info=True)
            return {
                "update_available": False,
                "error": f"Unexpected error: {str(e)}",
                "current_version": self.current_version
            }

    def download_update(self, download_url: str, asset_name: str) -> Tuple[bool, str]:
        """
        Download update installer from GitHub

        Args:
            download_url: URL to download from
            asset_name: Name of the asset file

        Returns:
            (success, file_path or error_message)
        """
        try:
            logger.info(f"Downloading update from: {download_url}")

            # Create downloads directory
            downloads_dir = os.path.join(self.app_data_dir, 'downloads')
            os.makedirs(downloads_dir, exist_ok=True)

            # Download file
            response = requests.get(download_url, stream=True, timeout=300)
            response.raise_for_status()

            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0

            output_path = os.path.join(downloads_dir, asset_name)

            with open(output_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)

                        # Log progress every 10%
                        if total_size > 0:
                            progress = (downloaded / total_size) * 100
                            if progress % 10 < 1:
                                logger.info(f"Download progress: {progress:.1f}%")

            logger.info(f"Download complete: {output_path}")
            return True, output_path

        except Exception as e:
            logger.error(f"Error downloading update: {e}", exc_info=True)
            return False, str(e)

    def verify_download(self, file_path: str, expected_size: int) -> bool:
        """
        Verify downloaded file integrity

        Args:
            file_path: Path to downloaded file
            expected_size: Expected file size in bytes

        Returns:
            True if valid, False otherwise
        """
        try:
            # Check file exists
            if not os.path.exists(file_path):
                logger.error(f"Downloaded file not found: {file_path}")
                return False

            # Check file size
            actual_size = os.path.getsize(file_path)
            if actual_size != expected_size:
                logger.error(f"File size mismatch. Expected: {expected_size}, Got: {actual_size}")
                return False

            logger.info(f"File verification passed: {file_path}")
            return True

        except Exception as e:
            logger.error(f"Error verifying download: {e}")
            return False

    def backup_database(self) -> Tuple[bool, str]:
        """
        Create backup of database before update

        Returns:
            (success, backup_path or error_message)
        """
        try:
            # Find database file
            db_path = os.path.join(self.app_data_dir, 'app.db')

            if not os.path.exists(db_path):
                return False, "Database file not found"

            # Create backups directory
            backup_dir = os.path.join(self.app_data_dir, 'backups')
            os.makedirs(backup_dir, exist_ok=True)

            # Create backup with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_name = f'app_backup_pre_update_{timestamp}.db'
            backup_path = os.path.join(backup_dir, backup_name)

            # Copy database
            shutil.copy2(db_path, backup_path)

            logger.info(f"Database backed up to: {backup_path}")
            return True, backup_path

        except Exception as e:
            logger.error(f"Error backing up database: {e}")
            return False, str(e)

    def install_update(self, installer_path: str) -> Tuple[bool, str]:
        """
        Execute installer for update

        Args:
            installer_path: Path to installer executable

        Returns:
            (success, message)
        """
        try:
            if not os.path.exists(installer_path):
                return False, "Installer not found"

            logger.info(f"Launching installer: {installer_path}")

            # Launch installer with elevated privileges on Windows
            if sys.platform == "win32":
                # Use runas to request admin privileges
                subprocess.Popen(
                    ['runas', '/user:Administrator', installer_path],
                    shell=True
                )
            else:
                # On Linux/Mac, just execute
                subprocess.Popen([installer_path])

            return True, "Installer launched successfully"

        except Exception as e:
            logger.error(f"Error launching installer: {e}")
            return False, str(e)

    def _get_cached_update(self) -> Optional[Dict[str, Any]]:
        """Get cached update information if still valid"""
        try:
            if not os.path.exists(self.update_cache_file):
                return None

            with open(self.update_cache_file, 'r') as f:
                cached = json.load(f)

            # Check if cache is still valid
            checked_at = datetime.fromisoformat(cached.get('checked_at', ''))
            if datetime.now(timezone.utc) - checked_at < self.cache_duration:
                return cached

            return None

        except Exception as e:
            logger.error(f"Error reading update cache: {e}")
            return None

    def _cache_update_info(self, info: Dict[str, Any]) -> None:
        """Cache update information"""
        try:
            with open(self.update_cache_file, 'w') as f:
                json.dump(info, f, indent=2)
        except Exception as e:
            logger.error(f"Error caching update info: {e}")

    def get_release_notes_summary(self, release_notes: str, max_length: int = 500) -> str:
        """
        Get truncated summary of release notes

        Args:
            release_notes: Full release notes
            max_length: Maximum length of summary

        Returns:
            Truncated summary
        """
        if not release_notes:
            return "No release notes available."

        # Remove markdown headers and excessive whitespace
        lines = [line.strip() for line in release_notes.split('\n') if line.strip()]
        summary = ' '.join(lines)

        if len(summary) > max_length:
            summary = summary[:max_length] + '...'

        return summary


# Singleton instance
_update_manager_instance = None


def get_update_manager(app_data_dir: str) -> UpdateManager:
    """Get or create UpdateManager singleton"""
    global _update_manager_instance
    if _update_manager_instance is None:
        _update_manager_instance = UpdateManager(app_data_dir)
    return _update_manager_instance
