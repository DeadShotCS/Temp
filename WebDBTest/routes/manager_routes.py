from flask import Blueprint, render_template, jsonify, request, session, redirect, url_for
from manager.comment_manager import CommentManager

mgmt_bp = Blueprint('mgmt', __name__)
cm = CommentManager()

@mgmt_bp.route('/api/entries', methods=['GET'])
def get_entries():
    return jsonify(cm.get_all_entries())

@mgmt_bp.route('/api/entries/<name>', methods=['GET'])
def get_single(name):
    entry = cm.get_single_entry(name)
    return jsonify(entry) if entry else (jsonify({"error": "not found"}), 404)

@mgmt_bp.route('/api/entries/<name>', methods=['DELETE'])
def delete_record(name):
    return jsonify({"status": "success"}) if cm.delete_entry(name) else (jsonify({"status": "error"}), 500)

@mgmt_bp.route('/api/entries', methods=['POST'])
def add_entry():
    data = request.json
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
    active = cm.get_active_project_name()
    return jsonify({
        "status": "success",
        "current_project": active,
        "all_projects": list(config.get("projects", {}).keys()),
        "config": config.get("projects", {}).get(active, {"tags": []})
    })

@mgmt_bp.route('/api/projects', methods=['POST'])
def update_project():
    data = request.json
    config = cm._load_config()
    name = data.get('project_name')
    config['active_project'] = name
    if name not in config['projects']:
        config['projects'][name] = {"tags": data.get('tags', [])}
    cm._save_config(config)
    return jsonify({"status": "success"})

@mgmt_bp.route('/api/projects/tags', methods=['POST'])
def update_tags():
    data = request.json
    config = cm._load_config()
    active = cm.get_active_project_name()
    if active in config['projects']:
        config['projects'][active]['tags'] = data.get('tags', [])
        cm._save_config(config)
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 404

@mgmt_bp.route('/comments')
def comments():
    return render_template('comments.html')