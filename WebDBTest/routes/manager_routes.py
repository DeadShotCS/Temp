from flask import Blueprint, render_template, jsonify, request, session, redirect, url_for
import sys
import os

# Standard pathing for your project structure
sys.path.insert(0, os.path.abspath('..'))

from manager.comment_manager import CommentManager
from manager.user_management import UserManagement

mgmt_bp = Blueprint('mgmt', __name__)
cm = CommentManager()
um = UserManagement()

@mgmt_bp.route('/comments')
def comments():
    if 'user' not in session:
        return redirect(url_for('mgmt.login'))
    return render_template('comments.html')

@mgmt_bp.route('/api/projects', methods=['GET'])
def get_projects():
    """Returns project list and active config for Logic.init()"""
    try:
        config = cm._load_config()
        active = cm.get_active_project_name()
        all_projs = list(config.get("projects", {}).keys())
        active_cfg = config.get("projects", {}).get(active, {"tags": []})
        
        return jsonify({
            "status": "success",
            "current_project": active,
            "all_projects": all_projs,
            "config": active_cfg
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@mgmt_bp.route('/api/config', methods=['POST'])
def update_config():
    data = request.json
    try:
        project_name = data.get("project_name")
        tags = data.get("tags")
        
        # Update the backend
        cm.update_project_config(project_name=project_name, tags=tags)
        
        # Get the fresh state to send back to the UI
        config = cm._load_config()
        active_cfg = config.get("projects", {}).get(project_name, {"tags": []})
        
        return jsonify({
            "status": "success", 
            "message": "PROJECT_UPDATED",
            "current_project": project_name,
            "tags": active_cfg.get("tags", [])
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500