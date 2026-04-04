import json, os
from datetime import datetime
from flask import session  # Import session here

class CommentManager:
    def __init__(self, config_name="project_config.json"):
        # Use absolute paths to avoid confusion with the flask working directory
        self.base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.config_path = os.path.join(self.base_path, config_name)
        self.data_dir = os.path.join(self.base_path, "data")
        
        if not os.path.exists(self.data_dir): 
            os.makedirs(self.data_dir)
            
        self._ensure_config_exists()

    @property
    def session_project(self):
        """
        Dynamically retrieves the project name from the current Flask session.
        If no session is active (e.g., background task), it returns None.
        """
        try:
            return session.get('active_project')
        except RuntimeError:
            # This happens if we are outside a Flask request context
            return None

    def get_active_project_name(self):
        # 1. Use the dynamic session property first
        proj = self.session_project
        if proj:
            return proj
            
        # 2. Fall back to the global default in the config file
        config = self._load_config()
        return config.get("active_project", "Default")
    
    def ensure_project_initialized(self, project_name):
        config = self._load_config()
        
        # Check if the project already exists in the config dictionary
        if 'projects' not in config:
            config['projects'] = {}
            
        if project_name not in config['projects']:
            # Define the default skeleton for a new project
            config['projects'][project_name] = {
                "tags": ["Default"],
                "entries": []
            }
            self._save_config(config)
            return True
        
        return False # Project already existed, no initialization needed

    def get_all_entries(self):
        proj = self.get_active_project_name()
        path = os.path.join(self.data_dir, f"{proj}.json")
        if not os.path.exists(path): 
            return []
        try:
            with open(path, 'r') as f:
                data = json.load(f)
                # Ensure we return a list of dicts with the name key included
                return [dict(v, name=k) for k, v in data.items()]
        except Exception as e: 
            print(f"Error loading entries: {e}")
            return []

    def get_single_entry(self, name):
        proj = self.get_active_project_name()
        path = os.path.join(self.data_dir, f"{proj}.json")
        try:
            with open(path, 'r') as f:
                data = json.load(f)
                rec = data.get(name)
                if rec: 
                    rec['name'] = name
                return rec
        except: 
            return None

    def save_entry(self, name, tag, entry_type, summary, findings, user="ADMIN"):
        proj = self.get_active_project_name()
        path = os.path.join(self.data_dir, f"{proj}.json")
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        data = {}
        if os.path.exists(path):
            with open(path, 'r') as f: 
                data = json.load(f)

        existing = data.get(name, {})
        data[name] = {
            "tag": tag,
            "type": entry_type,
            "summary": summary,
            "findings": findings,
            "created_timestamp": existing.get("created_timestamp", now),
            "created_user": existing.get("created_user", user),
            "last_updated_timestamp": now,
            "last_updated_user": user
        }
        with open(path, 'w') as f: 
            json.dump(data, f, indent=4)
        return True

    def delete_entry(self, name):
        proj = self.get_active_project_name()
        path = os.path.join(self.data_dir, f"{proj}.json")
        try:
            with open(path, 'r') as f: 
                data = json.load(f)
            if name in data:
                del data[name]
                with open(path, 'w') as f: 
                    json.dump(data, f, indent=4)
                return True
        except: 
            pass
        return False

    def _load_config(self):
        try:
            with open(self.config_path, 'r') as f: 
                return json.load(f)
        except: 
            return {"active_project": "Default", "projects": {"Default": {"tags": []}}}

    def _save_config(self, config):
        with open(self.config_path, 'w') as f: 
            json.dump(config, f, indent=4)

    def _ensure_config_exists(self):
        if not os.path.exists(self.config_path):
            self._save_config({
                "active_project": "Default", 
                "projects": {"Default": {"tags": ["General"]}}
            })