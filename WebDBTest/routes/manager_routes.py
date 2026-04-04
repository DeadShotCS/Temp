from flask import Blueprint, render_template, jsonify, request, session, redirect, url_for
import sys
import os

sys.path.insert(0, os.path.abspath('..'))
from manager.comment_manager import CommentManager
from manager.user_management import UserManagement

mgmt_bp = Blueprint('mgmt', __name__)
cm = CommentManager()
um = UserManagement()

@mgmt_bp.route('/comments')
def comments():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('comments.html')

@mgmt_bp.route('/api/projects', methods=['GET'])
def get_projects():
    try:
        config = cm._load_config()
        active = cm.get_active_project_name()
        return jsonify({
            "status": "success",
            "current_project": active,
            "all_projects": list(config.get("projects", {}).keys()),
            "config": config["projects"].get(active, {"tags": []})
        })
    except:
        return jsonify({"status": "error"}), 500

@mgmt_bp.route('/api/config', methods=['POST'])
def update_config():
    data = request.json
    try:
        cm.update_project_config(project_name=data.get("project_name"), tags=data.get("tags"))
        return jsonify({"status": "success"})
    except:
        return jsonify({"status": "error"}), 500

@mgmt_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if um.validate_user(request.form.get('username'), request.form.get('password')):
            session['user'] = request.form.get('username')
            return redirect(url_for('explorer.index'))
    return render_template('login.html')

@mgmt_bp.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('mgmt.login'))