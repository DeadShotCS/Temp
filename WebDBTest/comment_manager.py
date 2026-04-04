import json
import os
import uuid
from datetime import datetime

DB_FILE = 'data_entries.json'

class CommentManager:
    def __init__(self):
        self._ensure_db()

    def _ensure_db(self):
        """Initializes the JSON file if it doesn't exist."""
        if not os.path.exists(DB_FILE):
            with open(DB_FILE, 'w') as f:
                json.dump({}, f)

    def _load_all(self):
        with open(DB_FILE, 'r') as f:
            return json.load(f)

    def _save_all(self, data):
        with open(DB_FILE, 'w') as f:
            json.dump(data, f, indent=4)

    def add_entry(self, project_name, entry_data, user="ADMIN"):
        """
        Adds a structured entry to a specific project.
        Structured to mimic a SQL 'INSERT' operation.
        """
        db = self._load_all()
        
        if project_name not in db:
            db[project_name] = []

        timestamp = datetime.now().isoformat()
        
        new_entry = {
            "id": str(uuid.uuid4()),
            "name": entry_data.get('name'),
            "tag": entry_data.get('tag'),
            "type": entry_data.get('type'),
            "summary": entry_data.get('summary'),
            "findings": entry_data.get('findings', []),
            "created_at": timestamp,
            "created_by": user,
            "last_edit_at": timestamp,
            "last_edit_by": user
        }

        db[project_name].append(new_entry)
        self._save_all(db)
        return new_entry["id"]

    def get_project_entries(self, project_name):
        """Mimics 'SELECT * FROM entries WHERE project = ...'"""
        db = self._load_all()
        return db.get(project_name, [])

    def update_entry(self, project_name, entry_id, update_data, user="ADMIN"):
        """Mimics 'UPDATE entries SET ... WHERE id = ...'"""
        db = self._load_all()
        project_list = db.get(project_name, [])
        
        for entry in project_list:
            if entry["id"] == entry_id:
                # Update core fields
                for key in ['name', 'tag', 'type', 'summary', 'findings']:
                    if key in update_data:
                        entry[key] = update_data[key]
                
                # Update metadata
                entry["last_edit_at"] = datetime.now().isoformat()
                entry["last_edit_by"] = user
                
                self._save_all(db)
                return True
        return False

    def delete_entry(self, project_name, entry_id):
        """Mimics 'DELETE FROM entries WHERE id = ...'"""
        db = self._load_all()
        if project_name in db:
            db[project_name] = [e for e in db[project_name] if e["id"] != entry_id]
            self._save_all(db)
            return True
        return False