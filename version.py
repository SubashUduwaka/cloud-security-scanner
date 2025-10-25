"""
Aegis Cloud Security Scanner - Version Information
This file is automatically updated during releases
"""

__version__ = "0.9.2"
__release_date__ = "2025-10-23"
__build_number__ = "2025102301"

# Version components
VERSION_MAJOR = 0
VERSION_MINOR = 9
VERSION_PATCH = 2

# Release information
RELEASE_NAME = "Bug Fix & Security Enhancement Release"
RELEASE_NOTES_URL = "https://github.com/SubashUduwaka/cloud-security-scanner/releases/tag/v0.9.2"

# Update configuration
GITHUB_REPO_OWNER = "SubashUduwaka"
GITHUB_REPO_NAME = "cloud-security-scanner"
GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}"

def get_version():
    """Get current version as string"""
    return __version__

def get_version_tuple():
    """Get version as tuple for comparison"""
    return (VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH)

def get_version_info():
    """Get complete version information"""
    return {
        "version": __version__,
        "release_date": __release_date__,
        "build_number": __build_number__,
        "release_name": RELEASE_NAME,
        "release_notes_url": RELEASE_NOTES_URL
    }

def compare_versions(v1, v2):
    """
    Compare two version strings
    Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
    """
    def parse_version(v):
        # Remove 'v' prefix if present and split
        v = v.strip().lstrip('v')
        parts = v.split('.')
        return tuple(int(p) for p in parts if p.isdigit())

    v1_tuple = parse_version(v1)
    v2_tuple = parse_version(v2)

    if v1_tuple < v2_tuple:
        return -1
    elif v1_tuple > v2_tuple:
        return 1
    else:
        return 0
