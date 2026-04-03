import json, os, uuid
from datetime import datetime

def _get_path(base_path):
    return os.path.join(base_path, 'data_entries.json')

def get_entries(base_path):
    fpath = _get_path(base_path)
    if not os.path.exists(fpath): return []
    with open(fpath, 'r') as f:
        try: return json.load(f)
        except: return []
        
def add_structured_entry(base_path, name, filepath, c_type, description, findings, user):
    data = get_entries(base_path)
    timestamp = datetime.now().isoformat()
    
    new_entry = {
        "Main": {
            "ID": str(uuid.uuid4()),
            "MainName": name,
            "Type": "Manual Entry",
            "Filepath": filepath,
            "Info": [{"type": "created", "timestamp": timestamp, "user": user}]
        },
        "Description": {"Type": c_type, "Info": description},
        "Findings": findings
    }
    
    data.append(new_entry)
    with open(_get_path(base_path), 'w') as f:
        json.dump(data, f, indent=4)

def delete_entry(base_path, entry_id):
    data = get_entries(base_path)
    # Filter by ID inside the Main block
    updated_data = [e for e in data if e['Main']['ID'] != entry_id]
    with open(_get_path(base_path), 'w') as f:
        json.dump(updated_data, f, indent=4)