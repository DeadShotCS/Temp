from flask import Blueprint, render_template, jsonify, request, session, redirect, url_for
import sys
import os

sys.path.insert(0, os.path.abspath('..'))
import manager.data_manager as data_manager

explorer_bp = Blueprint('explorer', __name__)

@explorer_bp.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    try:
        os_list = list(data_manager.OS_DATA.keys())
    except:
        os_list = []
    return render_template('index.html', os_list=os_list)

@explorer_bp.route('/get_options/<os_name>')
def get_options(os_name):
    try:
        options = data_manager.get_all_filename_versions(os_name)
        return jsonify(options)
    except:
        return jsonify({}), 500

@explorer_bp.route('/search', methods=['POST'])
def search():
    data = request.json
    try:
        raw_result = data_manager.perform_search(
            category=data.get('category'), 
            criteria=data.get('criteria')
        )
        return jsonify({"output": raw_result})
    except Exception as e:
        error_str = str(e) if str(e) else "Unknown System Error"
        print(f"DEBUG: Search Error -> {error_str}")
        return jsonify({
            "status": "error", 
            "message": f"SEARCH_FAILURE: {error_str}"
        }), 500