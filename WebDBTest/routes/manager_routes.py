from flask import Blueprint, render_template, jsonify, request, session

from manager.comment_manager import CommentManager

mgmt_bp = Blueprint('mgmt', __name__)
cm = CommentManager()

@mgmt_bp.route('/api/entries', methods=['GET'])
def get_entries():
    # cm.get_all_entries() now automatically uses the session-scoped project
    return jsonify(cm.get_all_entries())

@mgmt_bp.route('/api/entries/<name>', methods=['GET'])
def get_single(name):
    entry = cm.get_single_entry(name)
    return jsonify(entry) if entry else (jsonify({"error": "not found"}), 404)

@mgmt_bp.route('/api/entries/<name>', methods=['DELETE'])
def delete_record(name):
    # cm.delete_entry() now automatically uses the session-scoped project
    return jsonify({"status": "success"}) if cm.delete_entry(name) else (jsonify({"status": "error"}), 500)

@mgmt_bp.route('/api/entries', methods=['POST'])
def add_entry():
    data = request.json
    # Removed the manual 'active' session fetch; CM handles it internally
    success = cm.save_entry(
        name=data.get('name'),
        tag=data.get('tag'),
        entry_type=data.get('type', 'GENERAL'),
        summary=data.get('summary'),
        findings=data.get('findings')
    )
    return jsonify({"status": "success" if success else "error"})

@mgmt_bp.route('/api/projects', methods=['GET'])
def get_projects():
    config = cm._load_config()
    # Use the class method to get the current project (Session-aware)
    active = cm.get_active_project_name()
    
    project_config = config.get("projects", {}).get(active, {"tags": []})
    
    return jsonify({
        "status": "success",
        "current_project": active,
        "all_projects": list(config.get("projects", {}).keys()),
        "config": project_config
    })

@mgmt_bp.route('/api/projects', methods=['POST'])
def update_project():
    data = request.json
    name = data.get('project_name')
    
    if not name:
        return jsonify({"status": "error", "message": "MISSING_IDENTIFIER"}), 400

    try:
        # DUTY 1: Ensure the project is physically/logically initialized in config
        # This calls your manager function
        cm.ensure_project_initialized(name)

        # DUTY 2: Update the active session cookie
        session['active_project'] = name
        session.permanent = True 
        
        return jsonify({
            "status": "success", 
            "current_project": name,
            "message": f"Session migrated to: {name}"
        })
    except Exception as e:
        return jsonify({
            "status": "error", 
            "message": f"PROJECT_INIT_FAILURE: {str(e)}"
        }), 500

@mgmt_bp.route('/api/tags')
def get_tags():
    config = cm._load_config()
    # This uses the session-aware name we just set up
    active = cm.get_active_project_name()
    
    # Navigate the nested dictionary: projects -> {ActiveName} -> tags
    project_data = config.get("projects", {}).get(active, {})
    tags = project_data.get("tags", [])
    
    return jsonify({"tags": tags})

@mgmt_bp.route('/api/projects/tags', methods=['POST'])
def update_tags():
    data = request.json
    config = cm._load_config()
    active = cm.get_active_project_name()
    
    if active in config.get('projects', {}):
        config['projects'][active]['tags'] = data.get('tags', [])
        cm._save_config(config)
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 404

@mgmt_bp.route('/comments')
def comments():
    # Pass the session-aware name to the template for the header display
    return render_template('comments.html', current_project=cm.get_active_project_name())