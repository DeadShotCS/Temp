const UI = {
    switchTab: (tabName) => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        const btn = document.getElementById(`btn_${tabName}`);
        const tab = document.getElementById(`tab_${tabName}`);
        if (btn && tab) {
            btn.classList.add('active');
            tab.classList.add('active');
            if (tabName === 'view') Table.refresh();
            if (tabName === 'settings') Logic.loadSettings();
        }
    },
    showStatus: (msg) => {
        const bar = document.getElementById('settings_status');
        bar.innerText = `[ SYSTEM ] > ${msg}`;
        bar.style.display = 'block';
        setTimeout(() => { bar.style.display = 'none'; }, 5000);
    }
};

const Logic = {
    init: async () => {
        const resp = await fetch('/api/current_project');
        const data = await resp.json();
        document.getElementById('current_project_name').innerText = data.project_name || "NONE";
    },
    loadSettings: async () => {
        const resp = await fetch('/api/projects');
        const data = await resp.json();
        
        // Projects
        const select = document.getElementById('set_project_select');
        select.innerHTML = '';
        data.config.projects.forEach(p => {
            const opt = document.createElement('option');
            opt.value = p.name; opt.innerText = p.name;
            if(p.name === data.config.current_project) opt.selected = true;
            select.appendChild(opt);
        });

        // Tags
        const tagContainer = document.getElementById('tag_list_container');
        tagContainer.innerHTML = '';
        if(data.config.tags && data.config.tags.length > 0) {
            data.config.tags.forEach(tag => {
                const item = document.createElement('div');
                item.style = "padding:5px 12px; background:#111; border:1px solid #444; font-size:11px; color:#0fa; display:flex; align-items:center; gap:10px;";
                item.innerHTML = `<span>${tag}</span><span onclick="Logic.removeTag('${tag}')" style="color:var(--error-red); cursor:pointer; font-weight:bold;">×</span>`;
                tagContainer.appendChild(item);
            });
        } else {
            tagContainer.innerHTML = '<span style="color:#555; font-size:10px;">( No Tags Registered )</span>';
        }
    },
    createNewProject: async () => {
        const name = document.getElementById('set_new_name').value;
        const folder = document.getElementById('set_new_path').value;
        if(!name) return UI.showStatus("Error: Name required.");
        const resp = await fetch('/api/projects', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ action: 'create', name: name, folder: folder })
        });
        const res = await resp.json();
        UI.showStatus(res.message);
        Logic.loadSettings();
    },
    switchActiveProject: async () => {
        const name = document.getElementById('set_project_select').value;
        const resp = await fetch('/api/projects', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ action: 'switch', name: name })
        });
        const res = await resp.json();
        document.getElementById('current_project_name').innerText = name;
        UI.showStatus(res.message);
    },
    addNewTag: async () => {
        const input = document.getElementById('set_new_tag');
        if(!input.value) return;
        const resp = await fetch('/api/projects', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ action: 'add_tag', tag: input.value })
        });
        const res = await resp.json();
        input.value = '';
        UI.showStatus(res.message);
        Logic.loadSettings();
    },
    removeTag: async (tag) => {
        const resp = await fetch('/api/projects', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ action: 'remove_tag', tag: tag })
        });
        const res = await resp.json();
        UI.showStatus(res.message);
        Logic.loadSettings();
    }
};