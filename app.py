from flask import Flask, render_template, request, redirect, url_for, abort, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import uuid
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pastes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.urandom(24)
db = SQLAlchemy(app)

class Paste(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    content = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expire_at = db.Column(db.DateTime, nullable=True)
    salt = db.Column(db.LargeBinary, nullable=True)


def get_expiry_delta(expiry_option):
    if expiry_option == "10min":
        return timedelta(minutes=10)
    elif expiry_option == "1hour":
        return timedelta(hours=1)
    elif expiry_option == "1day":
        return timedelta(days=1)
    else:
        return None


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        content = request.form['content']
        expiry = request.form['expiry']
        password = request.form.get('password')
        paste_id = str(uuid.uuid4())
        expire_at = datetime.utcnow() + get_expiry_delta(expiry) if expiry != 'never' else None

        if password:
            salt = os.urandom(16)
            key = derive_key(password, salt)
            fernet = Fernet(key)
            encrypted_content = fernet.encrypt(content.encode())
        else:
            salt = None
            encrypted_content = content.encode()

        new_paste = Paste(id=paste_id, content=encrypted_content, expire_at=expire_at, salt=salt)
        db.session.add(new_paste)
        db.session.commit()

        return redirect(url_for('view_paste', paste_id=paste_id))

    return render_template('index.html')


@app.route('/paste/<paste_id>', methods=['GET', 'POST'])
def view_paste(paste_id):
    paste = Paste.query.get(paste_id)
    if not paste:
        abort(404)
    if paste.expire_at and datetime.utcnow() > paste.expire_at:
        db.session.delete(paste)
        db.session.commit()
        abort(404)

    if paste.salt:
        if request.method == 'POST':
            password = request.form.get('password')
            try:
                key = derive_key(password, paste.salt)
                fernet = Fernet(key)
                decrypted_content = fernet.decrypt(paste.content).decode()
                return render_template('paste.html', paste=decrypted_content, requires_password=False)
            except InvalidToken:
                flash("Incorrect password.")
                return render_template('paste.html', requires_password=True)
        return render_template('paste.html', requires_password=True)

    return render_template('paste.html', paste=paste.content.decode(), requires_password=False)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)

