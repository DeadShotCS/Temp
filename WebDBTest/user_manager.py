import json
import os

USERS_DB = 'users_registry.json'

def init_users():
    if not os.path.exists(USERS_DB):
        default_users = {
            "admin": {"password": "password123", "group": "admin", "allowed_projects": ["*"]},
            "guest": {"password": "guest", "group": "viewer", "allowed_projects": ["Default"]}
        }
        with open(USERS_DB, 'w') as f:
            json.dump(default_users, f, indent=4)

def get_users():
    init_users()
    with open(USERS_DB, 'r') as f:
        return json.load(f)

def save_users(users_dict):
    with open(USERS_DB, 'w') as f:
        json.dump(users_dict, f, indent=4)

def authenticate(username, password):
    users = get_users()
    if username in users and users[username]['password'] == password:
        return users[username]
    return None

def has_project_access(session_obj, project_name):
    allowed = session_obj.get('allowed_projects', [])
    return "*" in allowed or project_name in allowed

def has_explorer_access(session_obj):
    return session_obj.get('group') in ['admin', 'researcher']