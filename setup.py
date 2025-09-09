import sys
import os
from cx_Freeze import setup, Executable

# --- IMPORTANT: EDIT THIS LINE ---
# Change this path to where you installed the GTK3 runtime.
gtk_path = r"C:\Program Files\GTK3-Runtime Win64"
# ---------------------------------

# Automatically find all the necessary GTK DLLs and data files
gtk_bin = os.path.join(gtk_path, "bin")
gtk_lib = os.path.join(gtk_path, "lib")
include_files = [
    ("templates", "templates"),
    ("static", "static"),
    ("scanners", "scanners"),
    ("icon.ico", "icon.ico"),
    (gtk_bin, "bin"), # Include the entire bin folder
    (gtk_lib, "lib")  # Include the entire lib folder
]

build_exe_options = {
    "packages": [
        "os", "sys", "logging", "threading", "webbrowser",
        "flask", "flask_cors", "flask_sqlalchemy", "sqlalchemy",
        "flask_migrate", "flask_login", "flask_bcrypt", "flask_mail",
        "flask_limiter", "flask_wtf", "flask_talisman",
        "boto3", "botocore", "google", "google.cloud", "google.auth",
        "pyotp", "qrcode", "weasyprint", "zxcvbn", "cryptography",
        "waitress", "dotenv"
    ],
    "include_files": include_files,
}

# Base configuration for a GUI application on Windows
base = None
if sys.platform == "win32":
    base = "Win32GUI"

setup(
    name="AegisScanner",
    version="1.0",
    description="Aegis Cloud Security Scanner",
    options={"build_exe": build_exe_options},
    executables=[Executable("app.py", base=base, target_name="AegisScanner.exe", icon="icon.ico")]
)
