# SecureBin - Encrypted Pastebin in Flask
**SecureBin** is a privacy-focused paste-sharing app built with Flask. It allows users to create secure text pastes.

## Features
- Optional password-based AES encryption (Fernet + PBKDF2)
- Self-expiring pastes
- Shareable unique URLs
- Clean, responsive UI

## Tech Stack
- **Flask** - Web framework
- **SQLAlchemy** - Database management
- **cryptography** - Encryption
- **Docker** - Scalable deployment

## Getting Started
Clone the app, then install dependencies
```
pip install -r requirements.txt
```
Next, run the app locally using
```
sudo ./run.sh`
```

## Details on Encryption
For every password:
- A unique `salt` is generated.
- Key is derived using `PBKDF2HMAC`
- The plaintext is encrypted using `Fernet` and stored.

## TODO
- Display shareable link separately post creation.
- Add delete functionality.
- Add user account management to also store paste history.
- Deploy the app for public use.
