import json
import os

class CommentManager:
    def __init__(self, config_path="project_config.json"):
        # Go up one level from the 'manager' folder to find the project root
        base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.config_path = os.path.join(base_path, config_path)
        print(f"--> CommentManager active at: {self.config_path}")
        self._ensure_config_exists()

    def _ensure_config_exists(self):
        if not os.path.exists(self.config_path):
            default_config = {
                "active_project": "Default",
                "projects": {
                    "Default": {"tags": ["General", "Note", "Todo"]}
                }
            }
            self._save_config(default_config)

    def _load_config(self):
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"!! [ERROR] Loading JSON: {e}")
        return {"active_project": "Default", "projects": {"Default": {"tags": []}}}

    def _save_config(self, config):
        try:
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            print(f"!! [ERROR] Saving JSON: {e}")

    def get_active_project_name(self):
        config = self._load_config()
        return config.get("active_project", "Default")

    def update_project_config(self, project_name, tags=None):
        config = self._load_config()
        
        # Ensure project exists
        if project_name not in config["projects"]:
            config["projects"][project_name] = {"tags": ["General"]}
        
        # Update tags if they were sent (handles comma strings from UI)
        if tags is not None:
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",") if t.strip()]
            config["projects"][project_name]["tags"] = tags
            
        config["active_project"] = project_name
        self._save_config(config)
        return True