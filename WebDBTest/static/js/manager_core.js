const Logic = {
    init: async () => {
        const resp = await fetch('/api/current_project');
        const data = await resp.json();
        document.getElementById('current_project_name').innerText = data.project_name || "NONE";
        Logic.loadSettings(); // Populate dropdowns and tags immediately
    },
    loadSettings: async () => {
        const resp = await fetch('/api/projects');
        const data = await resp.json();
        
        // Populate Project Select
        const sel = document.getElementById('set_project_select');
        if (sel) {
            sel.innerHTML = data.config.projects.map(p => 
                `<option value="${p.name}" ${p.name == data.config.current_project ? 'selected' : ''}>${p.name}</option>`
            ).join('');
        }
        
        // Populate Tag List Container
        const tc = document.getElementById('tag_list_container');
        if (tc) {
            tc.innerHTML = (data.config.tags || []).map(t => 
                `<div style="background:#111; padding:4px 10px; border:1px solid #444; font-size:11px; display:flex; align-items:center; gap:8px;">
                    ${t} <span onclick="Logic.removeTag('${t}')" style="color:red; cursor:pointer; font-weight:bold;">×</span>
                </div>`
            ).join('');
        }
    },
    addTag: async () => {
        const val = document.getElementById('set_new_tag').value;
        if (!val) return;
        await fetch('/api/projects', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({action: 'add_tag', tag: val})
        });
        document.getElementById('set_new_tag').value = '';
        Logic.loadSettings();
    },
    removeTag: async (tag) => {
        await fetch('/api/projects', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({action: 'remove_tag', tag: tag})
        });
        Logic.loadSettings();
    }
};

// Hook into UI.switchTab to refresh data when settings is clicked
const UI = {
    switchTab: (tabName) => {
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        document.getElementById(`tab_${tabName}`).classList.add('active');
        if (tabName === 'settings') Logic.loadSettings();
    }
};