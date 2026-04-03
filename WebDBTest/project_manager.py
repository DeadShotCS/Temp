import os
import json

REGISTRY_PATH = 'project_registry.json'

def init_registry():
    if not os.path.exists(REGISTRY_PATH):
        default_data = {
            "current_project": "Default",
            "projects": {
                "Default": {"folder": "projects/default", "tags": ["initial"]}
            }
        }
        save_registry(default_data)
        os.makedirs("projects/default", exist_ok=True)

def get_config():
    if not os.path.exists(REGISTRY_PATH): init_registry()
    with open(REGISTRY_PATH, 'r') as f: return json.load(f)

def save_registry(data):
    with open(REGISTRY_PATH, 'w') as f: json.dump(data, f, indent=4)

def create_project(name, folder):
    config = get_config()
    if name not in config['projects']:
        config['projects'][name] = {"folder": folder, "tags": []}
        os.makedirs(folder, exist_ok=True)
        save_registry(config)

def switch_project(name):
    config = get_config()
    if name in config['projects']:
        config['current_project'] = name
        save_registry(config)

def add_project_tag(tag):
    config = get_config()
    curr = config['current_project']
    if tag not in config['projects'][curr]['tags']:
        config['projects'][curr]['tags'].append(tag)
        save_registry(config)

def get_current_project_path():
    config = get_config()
    return config['projects'][config['current_project']]['folder']