import json
import os
import time

class ProjectManager:
    def __init__(self, config_path='project_config.json'):
        self.config_path = config_path
        self._ensure_integrity()

    def _load_config(self):
        """Aggressive disk-read to prevent stale in-memory data."""
        if not os.path.exists(self.config_path):
            return self._create_default_config()
        
        # Simple retry logic in case of file-lock during rapid saves
        for _ in range(5):
            try:
                with open(self.config_path, 'r') as f:
                    data = json.load(f)
                    if not data or "projects" not in data:
                        return self._create_default_config()
                    return data
            except (json.JSONDecodeError, IOError):
                time.sleep(0.05)
                continue
        return self._create_default_config()

    def _create_default_config(self):
        default = {
            "active_project": "default_archive",
            "projects": {
                "default_archive": {"tags": ["General"]}
            }
        }
        self._save_config(default)
        return default

    def _ensure_integrity(self):
        config = self._load_config()
        changed = False
        if "projects" not in config or not config["projects"]:
            config["projects"] = {"default_archive": {"tags": ["General"]}}
            changed = True
        if "active_project" not in config or config["active_project"] not in config["projects"]:
            config["active_project"] = list(config["projects"].keys())[0]
            changed = True
        if changed:
            self._save_config(config)

    def _save_config(self, config):
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=4)

    def get_active_project_name(self):
        config = self._load_config()
        return config.get("active_project", "default_archive")

    def update_project_config(self, project_name=None, tags=None):
        config = self._load_config()
        if project_name:
            if project_name not in config["projects"]:
                config["projects"][project_name] = {"tags": []}
            config["active_project"] = project_name
            
        active = config.get("active_project")
        if tags is not None and active in config["projects"]:
            config["projects"][active]["tags"] = tags

        self._save_config(config)