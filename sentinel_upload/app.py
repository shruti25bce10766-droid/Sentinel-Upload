from flask import Flask, render_template, request, flash, redirect, url_for
import os
import re
import uuid
import logging
import webbrowser
from threading import Timer

# -------------------------
# App Initialization
# -------------------------

app = Flask(__name__)
app.secret_key = "sentinel_secret_key"  # Required for flash messages

# -------------------------
# Configuration
# -------------------------

UPLOAD_FOLDER = 'uploads'
LOG_FOLDER = 'logs'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

# Ensure required folders exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(LOG_FOLDER, exist_ok=True)

# -------------------------
# Logging Setup
# -------------------------

logging.basicConfig(
    filename=os.path.join(LOG_FOLDER, 'security.log'),
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# -------------------------
# Helper Functions
# -------------------------

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def valid_filename(filename):
    """Allow only safe characters in filename"""
    return re.match(r'^[a-zA-Z0-9_.-]+$', filename)


def check_magic_bytes(file, extension):
    """Verify file content matches extension using magic bytes"""

    file.seek(0)
    file_header = file.read(4)
    file.seek(0)

    magic_numbers = {
        'png': b'\x89PNG',
        'jpg': b'\xff\xd8\xff',
        'jpeg': b'\xff\xd8\xff',
        'pdf': b'%PDF'
    }

    expected_magic = magic_numbers.get(extension)

    if expected_magic:
        return file_header.startswith(expected_magic)

    return False


# -------------------------
# Routes
# -------------------------

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():

    if 'file' not in request.files:
        flash("Invalid request", "error")
        return redirect(url_for('home'))

    file = request.files['file']

    if file.filename == '':
        flash("No file selected", "error")
        return redirect(url_for('home'))

    filename = file.filename
    extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''

    # Validate filename pattern
    if not valid_filename(filename):
        logging.warning(f"Invalid filename attempt: {filename}")
        flash("Invalid filename. Special characters not allowed.", "error")
        return redirect(url_for('home'))

    # Validate extension
    if not allowed_file(filename):
        logging.warning(f"Blocked extension attempt: {filename}")
        flash("File type not allowed.", "error")
        return redirect(url_for('home'))

    # Validate file size
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)

    if file_size > MAX_FILE_SIZE:
        logging.warning(f"Oversized file attempt: {filename}")
        flash("File too large. Maximum size is 5MB.", "error")
        return redirect(url_for('home'))

    # Magic byte validation
    if not check_magic_bytes(file, extension):
        logging.warning(f"Magic byte mismatch: {filename}")
        flash("File content does not match its extension.", "error")
        return redirect(url_for('home'))

    # Secure rename using UUID
    secure_name = str(uuid.uuid4()) + "." + extension
    file_path = os.path.join(UPLOAD_FOLDER, secure_name)

    file.save(file_path)

    flash("File uploaded securely!", "success")
    return redirect(url_for('home'))


# -------------------------
# Auto Browser Launch
# -------------------------

def open_browser():
    webbrowser.open("http://127.0.0.1:5000")


if __name__ == '__main__':
    Timer(1.5, open_browser).start()
    app.run(debug=False)




