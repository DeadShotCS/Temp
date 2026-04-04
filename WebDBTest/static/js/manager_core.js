const UI = {
    switchTab: (name) => {
        document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
        document.querySelectorAll('.btn-nav').forEach(b => b.classList.remove('active'));
        document.getElementById(`pane_${name}`).classList.add('active');
        document.getElementById(`tab_btn_${name}`).classList.add('active');
        
        if(name === 'view') Table.refresh();
        if(name === 'set') Logic.loadSettings();
    },

    addFinding: () => {
        const id = Date.now();
        const html = `
            <div class="finding-block" id="f_${id}">
                <div style="font-size: 9px; color: #52525b; margin-bottom: 5px;">
                    BLOCK_ID: ${id} <span style="float:right; cursor:pointer; color:var(--error-red)" onclick="document.getElementById('f_${id}').remove()">[ REMOVE ]</span>
                </div>
                <textarea class="f-info" style="width:100%; height:60px; background:#000; border:1px solid #333; color:#9cdcfe; font-family: 'JetBrains Mono'; padding:5px;"></textarea>
                <div style="display:flex; gap:10px; margin-top:5px;">
                    <select class="f-status" style="flex:1"><option>Verified</option><option>Unverified</option></select>
                    <input type="text" class="f-tag" style="flex:1" placeholder="Tag (Optional)">
                </div>
            </div>
        `;
        document.getElementById('findings_container').insertAdjacentHTML('beforeend', html);
    }
};

const Logic = {
    init: async () => {
        const resp = await fetch('/api/current_project');
        const data = await resp.json();
        document.getElementById('current_project_display').innerText = data.project_name;
        UI.addFinding();
    },

    loadSettings: async () => {
        const resp = await fetch('/api/projects');
        const data = await resp.json();
        document.getElementById('set_project_select').innerHTML = data.config.projects.map(p => `<option value="${p.name}">${p.name}</option>`).join('');
        document.getElementById('tag_list_container').innerHTML = (data.config.tags || []).map(t => `<span class="tag-chip">${t}</span>`).join('');
    },

    saveEntry: async () => {
        const findings = [];
        document.querySelectorAll('.finding-block').forEach(b => {
            findings.push({
                info: b.querySelector('.f-info').value,
                status: b.querySelector('.f-status').value,
                tag: b.querySelector('.f-tag').value
            });
        });

        await fetch('/api/entries', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                name: document.getElementById('add_name').value,
                filepath: document.getElementById('add_path').value,
                findings: findings
            })
        });
        alert("COMMITTED TO DATABASE");
    }
};

const Table = {
    refresh: async () => {
        const resp = await fetch('/api/entries');
        const entries = await resp.json();
        document.getElementById('table_body').innerHTML = entries.map(e => `
            <tr>
                <td style="padding:10px; border-bottom:1px solid #111; color:var(--accent)">${e.name}</td>
                <td style="padding:10px; border-bottom:1px solid #111;">${e.filepath}</td>
                <td style="padding:10px; border-bottom:1px solid #111; text-align:right;"><button class="btn-nav">EDIT</button></td>
            </tr>
        `).join('');
    }
};