function updateSettingsUI(config) {
    const projectSelect = document.getElementById('setting_project_list');
    const settingsTagDisplay = document.getElementById('settings_tag_display');
    if(!projectSelect) return;

    projectSelect.innerHTML = "";
    Object.keys(config.projects).forEach(pName => {
        const opt = document.createElement('option');
        opt.value = pName; opt.innerText = pName;
        if(pName === config.current_project) opt.selected = true;
        projectSelect.appendChild(opt);
    });

    settingsTagDisplay.innerHTML = "";
    const tags = config.projects[config.current_project].tags || [];
    tags.forEach(t => {
        const span = document.createElement('span');
        span.className = "tag-badge";
        span.innerText = t;
        settingsTagDisplay.appendChild(span);
    });
}

async function addTag() {
    const val = document.getElementById('new_tag_input').value.trim();
    if(!val) return;
    
    await fetch('/api/projects', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({action: 'add_tag', tag: val})
    });
    
    document.getElementById('new_tag_input').value = "";
    loadProjectData(); // Global refresh
    if(window.showStatus) showStatus("TAG_ADDED", "success");
}

async function createNewProject() {
    const nameEl = document.getElementById('new_project_name');
    const folderEl = document.getElementById('new_project_folder');
    if(!nameEl.value || !folderEl.value) return;

    const resp = await fetch('/api/projects', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({action: 'create', name: nameEl.value, folder: folderEl.value})
    });

    if(resp.ok) {
        nameEl.value = "";
        folderEl.value = "";
        loadProjectData();
        if(window.showStatus) showStatus("PROJECT_INITIALIZED", "success");
    }
}

async function switchProject() {
    const name = document.getElementById('setting_project_list').value;
    const resp = await fetch('/api/projects', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({action: 'switch', name: name})
    });
    if(resp.ok) {
        loadProjectData();
        if(window.showStatus) showStatus("PROJECT_SWITCHED", "success");
    }
}