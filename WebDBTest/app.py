from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import os
import json
import data_manager
import project_manager
import user_manager
import comment_manager

app = Flask(__name__)
app.secret_key = 'ARCHIVE_CORE_SECURE_KEY_2026_JAKE' 

# --- EXPLORER ---
@app.route('/')
def home():
    if 'user' not in session: return redirect(url_for('login'))
    os_list = sorted(data_manager.OS_DATA.keys()) if hasattr(data_manager, 'OS_DATA') else []
    return render_template('index.html', user=session['user'], os_list=os_list)

@app.route('/get_options/<os_name>')
def get_options(os_name):
    if 'user' not in session: return jsonify({"error": "unauthorized"}), 401
    return jsonify(data_manager.get_all_filename_versions(os_name))

@app.route('/search', methods=['POST'])
def search():
    if 'user' not in session: return jsonify({"error": "unauthorized"}), 401
    d = request.json
    result = data_manager.perform_search(d['category'], d['criteria'])
    return jsonify({"output": result})

# --- MANAGER ---
@app.route('/comments')
def comments_main():
    if 'user' not in session: return redirect(url_for('login'))
    return render_template('comments.html', user=session['user'])

@app.route('/api/projects', methods=['GET', 'POST'])
def handle_projects():
    if 'user' not in session: return jsonify({"error": "unauthorized"}), 401
    if request.method == 'POST':
        d = request.json
        action = d.get('action')
        if action == 'switch':
            project_manager.switch_project(d['name'])
            session['project_name'] = d['name']
            return jsonify({"status": "success", "message": f"Switched to {d['name']}"})
        elif action == 'add_tag':
            project_manager.add_project_tag(d['tag'])
            return jsonify({"status": "success", "message": "Tag added."})
        elif action == 'remove_tag':
            config = project_manager.get_config()
            if d['tag'] in config.get('tags', []):
                config['tags'].remove(d['tag'])
                project_manager.save_config(config)
            return jsonify({"status": "success", "message": "Tag removed."})
    return jsonify({"config": project_manager.get_config()})

@app.route('/api/current_project')
def get_current_project():
    name = session.get('project_name') or project_manager.get_config().get('current_project')
    return jsonify({"project_name": name})

@app.route('/api/entries', methods=['GET', 'POST'])
def handle_entries():
    if 'user' not in session: return jsonify({"error": "unauthorized"}), 401
    path = project_manager.get_current_project_path()
    if request.method == 'POST':
        d = request.json
        comment_manager.add_structured_entry(path, d['name'], d['filepath'], d['type'], "Entry via Manager", d['findings'], session['user'])
        return jsonify({"status": "success"})
    return jsonify(comment_manager.get_entries(path))

# --- AUTH ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u, p = request.json.get('user'), request.json.get('pass')
        user_data = user_manager.authenticate(u, p)
        if user_data:
            session['user'] = u
            return jsonify({"status": "success"})
        return jsonify({"status": "fail"}), 200
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    project_manager.init_registry()
    app.run(debug=True, port=5000)