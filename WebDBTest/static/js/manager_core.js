const UI = {
    switchTab: (tabId) => {
        document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
        document.getElementById('pane_' + tabId).classList.add('active');
        document.querySelectorAll('.btn-nav').forEach(b => b.classList.remove('active'));
        document.getElementById('btn_' + tabId).classList.add('active');
    },

    toggleCollapse: (header) => {
        const body = header.nextElementSibling;
        const icon = header.querySelector('.toggle-icon');
        const isCollapsed = body.classList.toggle('collapsed');
        icon.innerText = isCollapsed ? '[ + ]' : '[ - ]';
    },

    addFinding: () => {
        const container = document.getElementById('findings_container');
        const clone = container.querySelector('.finding-block').cloneNode(true);
        const count = container.children.length + 1;
        
        // Reset and Update label
        clone.querySelector('.finding-header span').innerText = `FINDING_BLOCK_${count.toString().padStart(2, '0')}`;
        clone.querySelector('.finding-body').classList.remove('collapsed');
        clone.querySelector('.toggle-icon').innerText = '[ - ]';
        clone.querySelectorAll('textarea').forEach(t => t.value = '');
        
        container.appendChild(clone);
    },

    removeFinding: () => {
        const container = document.getElementById('findings_container');
        if (container.children.length > 1) container.lastElementChild.remove();
    },

    resetForm: () => {
        if(confirm("Discard all form data?")) {
            document.querySelectorAll('input, textarea').forEach(i => i.value = '');
            const container = document.getElementById('findings_container');
            while(container.children.length > 1) container.lastElementChild.remove();
        }
    }
};

const Logic = {
    init: async () => {
        try {
            const resp = await fetch('/api/projects');
            const data = await resp.json();
            
            // Fix for "Undefined" project
            const activeProj = data.current_project || "NO_PROJECT_SELECTED";
            document.getElementById('header_proj_name').innerText = activeProj;
            
            // Update Header Tags
            document.getElementById('header_tags').innerHTML = (data.config.tags || []).map(t => 
                `<span class="tag-pill">${t}</span>`).join('');

            // Update Settings Dropdowns
            const projSel = document.getElementById('settings_project_select');
            projSel.innerHTML = data.config.projects.map(p => 
                `<option value="${p.name}" ${p.name === activeProj ? 'selected' : ''}>${p.name}</option>`).join('');

            const tagSel = document.getElementById('add_tag_select');
            tagSel.innerHTML = (data.config.tags || []).map(t => `<option value="${t}">${t}</option>`).join('');

            // Update Settings Tag Cloud
            document.getElementById('settings_tag_cloud').innerHTML = (data.config.tags || []).map(t => 
                `<span class="tag-pill">${t}</span>`).join('');

        } catch (error) {
            console.error("Initialization Error:", error);
            document.getElementById('header_proj_name').innerText = "CONNECTION_ERROR";
        }
    },

    switchProject: async (name) => {
        await fetch('/api/set_project', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ project: name })
        });
        location.reload();
    },

    addTag: async () => {
        const tagName = document.getElementById('new_tag_name').value;
        if(!tagName) return;
        // This assumes your backend has an endpoint for adding tags to current project
        await fetch('/api/add_tag', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ tag: tagName })
        });
        location.reload();
    },

    saveEntry: async () => {
        const findings = [];
        document.querySelectorAll('.finding-block').forEach(b => {
            findings.push({
                type: b.querySelector('.f-type').value,
                status: b.querySelector('.f-status').value,
                info: b.querySelector('.f-info').value,
                req: b.querySelector('.f-req').value,
                ver: b.querySelector('.f-ver').value
            });
        });

        const payload = {
            name: document.getElementById('add_name').value,
            tag: document.getElementById('add_tag_select').value,
            summary: document.getElementById('add_summary').value,
            findings: findings
        };

        const resp = await fetch('/api/entries', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });

        if (resp.ok) alert("DATA_COMMITTED_TO_DB");
    }
};