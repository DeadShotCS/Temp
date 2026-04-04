const UI = {
    tagMode: 'dropdown',

    switchTab: (tabId) => {
        // Toggle Visibility
        document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
        document.getElementById('pane_' + tabId).classList.add('active');
        
        // Toggle Sidebar Active State
        document.querySelectorAll('.btn-nav').forEach(b => b.classList.remove('active'));
        document.getElementById('btn_' + tabId).classList.add('active');

        // Contextual Loaders
        if (tabId === 'view') Logic.loadEntries();
    },

    toggleTagMode: () => {
        const drop = document.getElementById('tag_drop_ui');
        const cust = document.getElementById('tag_cust_ui');
        UI.tagMode = (UI.tagMode === 'dropdown') ? 'custom' : 'dropdown';
        drop.style.display = UI.tagMode === 'dropdown' ? 'block' : 'none';
        cust.style.display = UI.tagMode === 'custom' ? 'block' : 'none';
    },

    addFinding: () => {
        const container = document.getElementById('findings_container');
        const clone = container.firstElementChild.cloneNode(true);
        clone.className = "finding-block";
        clone.querySelectorAll('textarea').forEach(t => t.value = '');
        container.appendChild(clone);
    },

    removeFinding: () => {
        const container = document.getElementById('findings_container');
        if (container.children.length > 1) container.lastElementChild.remove();
    }
};

const Logic = {
    init: async () => {
        try {
            const resp = await fetch('/api/projects');
            const data = await resp.json();
            
            const projSel = document.getElementById('active_project_select');
            projSel.innerHTML = data.config.projects.map(p => 
                `<option value="${p.name}">${p.name}</option>`).join('');

            const tagSel = document.getElementById('add_tag_select');
            tagSel.innerHTML = (data.config.tags || []).map(t => 
                `<option value="${t}">${t}</option>`).join('');
        } catch (e) {
            console.error("Initialization failed: ", e);
        }
    },

    switchProject: async (projectName) => {
        await fetch('/api/set_project', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ project: projectName })
        });
        Logic.init(); // Refresh tags
    },

    loadEntries: async () => {
        const resp = await fetch('/api/entries');
        const entries = await resp.json();
        const body = document.getElementById('view_table_body');
        body.innerHTML = entries.map(e => `
            <tr>
                <td style="color:var(--accent); font-weight:bold">${e.name}</td>
                <td>${e.tag || 'None'}</td>
                <td style="text-transform:uppercase; font-size:9px;">${e.status || 'N/A'}</td>
                <td style="text-align:right">
                    <button class="btn-nav" style="padding: 4px 8px; font-size: 8px; width: auto;">EDIT</button>
                </td>
            </tr>
        `).join('');
    },

    saveEntry: async () => {
        const tag = UI.tagMode === 'dropdown' ? 
            document.getElementById('add_tag_select').value : 
            document.getElementById('add_tag_custom').value;

        const findings = [];
        document.querySelectorAll('.finding-block').forEach(b => {
            findings.push({
                info: b.querySelector('.f-info').value,
                req: b.querySelector('.f-req').value,
                ver: b.querySelector('.f-ver').value
            });
        });

        const payload = {
            name: document.getElementById('add_name').value,
            tag: tag,
            category: document.getElementById('add_cat').value,
            type: document.getElementById('add_type').value,
            status: document.getElementById('add_stat').value,
            summary: document.getElementById('add_summary').value,
            findings: findings
        };

        const resp = await fetch('/api/entries', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });

        if (resp.ok) {
            alert("ENTRY_COMMITTED_SUCCESSFULLY");
        }
    }
};