const UI = {
    switchTab: (tabId) => {
        // Toggle Panes
        document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
        document.getElementById('pane_' + tabId).classList.add('active');
        
        // Toggle Sidebar Buttons
        document.querySelectorAll('.btn-nav').forEach(b => b.classList.remove('active'));
        document.getElementById('btn_' + tabId).classList.add('active');

        // Logic triggers
        if (tabId === 'view') Logic.loadEntries();
        if (tabId === 'settings') Logic.loadSettings();
    },

    addFinding: () => {
        const container = document.getElementById('findings_container');
        const clone = container.firstElementChild.cloneNode(true);
        const id = Date.now();
        clone.querySelectorAll('input').forEach(i => i.name = 'ft_' + id);
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
        const resp = await fetch('/api/current_project');
        const data = await resp.json();
        document.getElementById('cur_proj').innerText = data.project_name;
    },

    loadEntries: async () => {
        const resp = await fetch('/api/entries');
        const entries = await resp.json();
        const body = document.getElementById('view_table_body');
        body.innerHTML = entries.map(e => `
            <tr>
                <td style="color:var(--accent); font-weight:bold">${e.name}</td>
                <td>${e.filepath}</td>
                <td>${e.type || 'Function'}</td>
                <td style="text-align:right">
                    <button class="btn-nav" style="padding: 4px 8px; font-size: 8px;">EDIT</button>
                    <button class="btn-nav" style="padding: 4px 8px; font-size: 8px; color:var(--error-red)">DEL</button>
                </td>
            </tr>
        `).join('');
    },

    loadSettings: async () => {
        const resp = await fetch('/api/projects');
        const data = await resp.json();
        
        const sel = document.getElementById('set_project_select');
        sel.innerHTML = data.config.projects.map(p => `<option value="${p.name}">${p.name}</option>`).join('');
        
        const cloud = document.getElementById('tag_cloud');
        cloud.innerHTML = (data.config.tags || []).map(t => 
            `<span style="background:#1a1a1d; border:1px solid var(--accent); color:var(--accent); padding:2px 8px; font-size:9px;">${t}</span>`
        ).join('');
    },

    saveEntry: async () => {
        // Implementation for saving goes here
        console.log("Saving...");
    }
};