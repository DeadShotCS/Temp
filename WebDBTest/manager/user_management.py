import json
import os
import hashlib

USER_DB = 'data/users.json'

class UserManagement:
    def __init__(self):
        self._ensure_db()

    def _ensure_db(self):
        if not os.path.exists('data'):
            os.makedirs('data')
        if not os.path.exists(USER_DB):
            # Default: admin / password
            hashed_pw = hashlib.sha256("password".encode()).hexdigest()
            default_user = {"admin": {"password": hashed_pw, "role": "ADMIN"}}
            with open(USER_DB, 'w') as f:
                json.dump(default_user, f, indent=4)

    def verify_user(self, username, password):
        if not os.path.exists(USER_DB):
            return False
        
        with open(USER_DB, 'r') as f:
            try:
                users = json.load(f)
            except:
                return False
        
        if username in users:
            hashed_input = hashlib.sha256(password.encode()).hexdigest()
            return users[username]['password'] == hashed_input
        return False