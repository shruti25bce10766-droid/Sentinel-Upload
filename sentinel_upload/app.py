from flask import Flask, render_template, request, redirect, url_for, flash
import os
import re
import uuid
import logging

app = Flask(__name__)
app.secret_key = "sentinel_secret_key"

UPLOAD_FOLDER = 'uploads'
LOG_FOLDER = 'logs'
ALLOWED_EXTENSIONS = {'pdf'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

# Create folders if not exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(LOG_FOLDER, exist_ok=True)

# Logging setup
logging.basicConfig(
    filename=os.path.join(LOG_FOLDER, 'security.log'),
    level=logging.WARNING,
    format='%(asctime)s - %(message)s'
)

# ---------------- Helper Functions ----------------

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def valid_filename(filename):
    return re.match(r'^[a-zA-Z0-9_.-]+$', filename)


def check_magic_bytes(file):
    file.seek(0)
    header = file.read(4)
    file.seek(0)
    return header.startswith(b'%PDF')


# ---------------- Routes ----------------

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():

    if 'file' not in request.files:
        flash("Invalid request.", "error")
        return redirect(url_for('home'))

    file = request.files['file']

    if file.filename == '':
        flash("No file selected.", "error")
        return redirect(url_for('home'))

    filename = file.filename

    if not valid_filename(filename):
        logging.warning(f"Invalid filename attempt: {filename}")
        flash("Invalid filename. Only letters, numbers, ., -, _ allowed.", "error")
        return redirect(url_for('home'))

    if not allowed_file(filename):
        logging.warning(f"Blocked extension attempt: {filename}")
        flash("Only PDF files are allowed.", "error")
        return redirect(url_for('home'))

    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)

    if size > MAX_FILE_SIZE:
        logging.warning(f"Oversized file attempt: {filename}")
        flash("File exceeds 5MB limit.", "error")
        return redirect(url_for('home'))

    if not check_magic_bytes(file):
        logging.warning(f"Magic byte mismatch: {filename}")
        flash("File content does not match PDF format.", "error")
        return redirect(url_for('home'))

    secure_name = str(uuid.uuid4()) + ".pdf"
    file.save(os.path.join(UPLOAD_FOLDER, secure_name))

    flash("File uploaded securely!", "success")
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=False)






