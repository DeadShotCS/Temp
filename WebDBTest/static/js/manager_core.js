const UI = {
    sortState: { col: null, asc: true },

    switchTab: (tabId) => {
        document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
        const target = document.getElementById('pane_' + tabId);
        if (target) target.classList.add('active');

        document.querySelectorAll('.btn-nav').forEach(b => b.classList.remove('active'));
        const activeBtn = document.getElementById('nav_' + tabId);
        if (activeBtn) activeBtn.classList.add('active');

        if (tabId === 'view') Logic.loadArchive();
    },

    resetForm: () => {
        const nameInp = document.getElementById('add_name');
        if (nameInp) {
            nameInp.value = '';
            nameInp.readOnly = false;
            nameInp.style.borderLeft = "1px solid var(--border)";
        }

        const tagSel = document.getElementById('add_tag');
        if (tagSel) {
            tagSel.disabled = false;
            tagSel.style.opacity = "1";
            tagSel.value = tagSel.options[0]?.value || "";
        }

        document.getElementById('add_type').value = 'function';
        document.getElementById('add_summary').value = '';
        document.getElementById('findings_container').innerHTML = '';
        // UI.addFinding();
    },

    toggleCollapse: (header) => {
        const body = header.nextElementSibling;
        const indicator = header.querySelector('.status-indicator');
        if (body.style.display === 'none') {
            body.style.display = 'grid';
            indicator.innerText = '[ - ]';
        } else {
            body.style.display = 'none';
            indicator.innerText = '[ + ]';
        }
    },

    addFinding: () => {
        const container = document.getElementById('findings_container');
        const template = document.getElementById('finding_template').content.cloneNode(true);
        const idx = container.children.length + 1;
        template.querySelector('.block-id').innerText = `FINDING_BLOCK_${idx.toString().padStart(2, '0')}`;
        container.appendChild(template);
    },

    removeFinding: () => {
        const container = document.getElementById('findings_container');
        if (container.lastElementChild) {
            container.lastElementChild.remove();
        }
    },

    showDeleteModal: (name) => {
        const modal = document.getElementById('delete_modal');
        document.getElementById('delete_target_name').innerText = `IDENTIFIER: ${name}`;
        modal.style.display = 'flex';
        
        document.getElementById('confirm_delete_btn').onclick = async () => {
            await Logic.executeDelete(name);
            modal.style.display = 'none';
        };
    },

    sortArchive: (n) => {
        const body = document.getElementById("archive_body");
        let rows = Array.from(body.rows);
        const isAsc = UI.sortState.col === n ? !UI.sortState.asc : true;
        UI.sortState = { col: n, asc: isAsc };

        rows.sort((a, b) => {
            let x = a.cells[n].innerText.toLowerCase();
            let y = b.cells[n].innerText.toLowerCase();
            return isAsc ? x.localeCompare(y) : y.localeCompare(x);
        });

        rows.forEach(row => body.appendChild(row));
    },

    filterArchive: () => {
        const query = document.getElementById('archive_search').value.toLowerCase();
        document.querySelectorAll('#archive_body tr').forEach(row => {
            row.style.display = row.innerText.toLowerCase().includes(query) ? '' : 'none';
        });
    }
};

const Logic = {
    currentEditingId: null,

    init: async function() {
        try { 
            const projectData = await this.loadProjects(); 
            if (projectData?.config?.tags) {
                const settingsTagInp = document.getElementById('set_tags');
                if (settingsTagInp) {
                    settingsTagInp.value = projectData.config.tags.join(', ');
                }
            }
        } catch(e) { console.error("INIT_ERR_PROJ", e); }

        try { await this.loadTags(); } catch(e) { console.error("INIT_ERR_TAGS", e); }
        try { await this.loadArchive(); } catch(e) { console.error("INIT_ERR_ARCH", e); }
        
        // UI.addFinding(); 
    },

    loadProjects: async function() {
        const select = document.getElementById('set_proj_select');
        if (!select) return;

        try {
            const res = await fetch('/api/projects');
            if (!res.ok) return;

            const data = await res.json();
            select.innerHTML = '';
            const list = data.all_projects || [];

            if (list.length === 0) {
                select.innerHTML = '<option value="">-- NO PROJECTS FOUND --</option>';
                return;
            }

            list.forEach(p => {
                const opt = document.createElement('option');
                const name = (typeof p === 'object') ? p.name : p;
                opt.value = name;
                opt.textContent = name;
                if (name === data.current_project) opt.selected = true;
                select.appendChild(opt);
            });

            return data;
        } catch (e) { console.error("LOAD_PROJ_FAIL", e); }
    },

    updateTagsOnly: async function() {
        const tagInp = document.getElementById('set_tags'); 
        if (!tagInp) return;

        const tags = tagInp.value.split(',').map(t => t.trim()).filter(t => t !== "");
        
        try {
            const res = await fetch('/api/projects/tags', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ tags: tags })
            });

            const text = await res.text();
            let data;
            try { data = JSON.parse(text); } catch (e) {
                if (window.showStatus) showStatus(`SERVER_ERROR: ${res.status}`, "error");
                return;
            }

            if (!res.ok || data.status === "error") {
                if (window.showStatus) showStatus(data.message || "TAG_UPDATE_FAILURE", "error");
            } else {
                await this.loadTags(); 
                if (window.showStatus) showStatus("PROJECT_TAGS_UPDATED", "success");
            }
        } catch (e) {
            if (window.showStatus) showStatus("NETWORK_LINK_FAILURE", "error");
        }
    },
    
    loadTags: async function(selectedTag = null) {
        const select = document.getElementById('add_tag');
        if (!select) return [];

        try {
            const res = await fetch('/api/tags');
            const data = await res.json();
            const list = data.tags || [];

            select.innerHTML = '<option value=""></option>';
            list.forEach(t => {
                const opt = document.createElement('option');
                opt.value = t; 
                opt.textContent = t;
                if (selectedTag && t === selectedTag) opt.selected = true;
                select.appendChild(opt);
            });

            const custom = document.createElement('option');
            custom.value = 'custom'; 
            custom.textContent = 'Custom...';
            select.appendChild(custom);
            
            return list;
        } catch (e) { return []; }
    },

    loadArchive: async function() {
        const body = document.getElementById('archive_body');
        if (!body) return;
        try {
            const res = await fetch('/api/entries');
            const data = await res.json();
            body.innerHTML = '';
            
            let list = Array.isArray(data) ? data : (data?.entries || []);

            if (list.length === 0) {
                body.innerHTML = '<tr><td colspan="5" style="text-align:center;">No entries found.</td></tr>';
                return;
            }

            list.forEach(item => {
                const row = document.createElement('tr');
                const successCount = (item.findings || []).filter(f => f.status === 'Success').length;
                const failCount = (item.findings || []).filter(f => f.status === 'Failure').length;
                
                let statusClass = 'status-grey';
                if (successCount > 0) statusClass = 'status-green';
                else if (failCount > 0) statusClass = 'status-red';
                else if (item.findings?.length > 0) statusClass = 'status-blue';

                row.innerHTML = `
                    <td class="cell-rel">
                        <div class="status-bar ${statusClass}"></div>
                        <b style="color:#fff">${item.name}</b>
                    </td>
                    <td><span style="color:var(--accent)">${item.tag}</span></td>
                    <td>${item.type || 'function'}</td>
                    <td class="audit-text">UP: ${item.last_updated_timestamp}</td>
                    <td>
                        <button class="btn-alt" style="padding:2px 6px; font-size:9px;" onclick="Logic.editEntry('${item.name}')">EDIT</button>
                        <button class="btn-warn" style="padding:2px 6px; font-size:9px;" onclick="Logic.deleteEntry('${item.name}')">DEL</button>
                    </td>
                `;
                body.appendChild(row);
            });
        } catch (e) { console.error("LOAD_ARCH_FAIL", e); }
    },

    editEntry: async (name) => {
        const resp = await fetch(`/api/entries/${name}`);
        const data = await resp.json();
        UI.switchTab('add');
        
        const nameInp = document.getElementById('add_name');
        nameInp.value = data.name;
        nameInp.readOnly = true;
        nameInp.style.borderLeft = "3px solid var(--accent)";

        const tagSel = document.getElementById('add_tag');
        if (tagSel) {
            tagSel.value = data.tag;
            tagSel.disabled = true;
            tagSel.style.opacity = "0.5";
        }

        document.getElementById('add_type').value = data.type || 'function';
        document.getElementById('add_summary').value = data.summary || '';
        
        const container = document.getElementById('findings_container');
        container.innerHTML = '';
        data.findings.forEach(f => {
            UI.addFinding();
            const last = container.lastElementChild;
            last.querySelector('.f-type').value = f.type;
            last.querySelector('.f-status').value = f.status;
            last.querySelector('.f-info').value = f.info;
            last.querySelector('.f-req').value = f.req;
            last.querySelector('.f-ver').value = f.ver;
        });
    },

    saveEntry: async () => {
        const nameVal = document.getElementById('add_name').value;
        if (!nameVal) {
            if (window.showStatus) showStatus("NAME_REQUIRED", "error");
            return;
        }

        const payload = {
            name: nameVal,
            tag: document.getElementById('add_tag').value,
            type: document.getElementById('add_type').value,
            summary: document.getElementById('add_summary').value,
            findings: Array.from(document.querySelectorAll('.finding-block')).map(b => ({
                type: b.querySelector('.f-type').value,
                status: b.querySelector('.f-status').value,
                info: b.querySelector('.f-info').value,
                req: b.querySelector('.f-req').value,
                ver: b.querySelector('.f-ver').value
            }))
        };

        try {
            const resp = await fetch('/api/entries', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(payload)
            });

            const text = await resp.text();
            let data;
            try { data = JSON.parse(text); } catch (e) {
                if (window.showStatus) showStatus(`SERVER_ERROR: ${resp.status}`, "error");
                return;
            }

            if (!resp.ok || data.status === "error") {
                if (window.showStatus) showStatus(data.message || "SAVE_FAILURE", "error");
            } else {
                if (window.showStatus) showStatus("ENTRY_SYNCHRONIZED", "success");
                UI.resetForm();
                UI.switchTab('view');
            }
        } catch (e) {
            if (window.showStatus) showStatus("NETWORK_LINK_FAILURE", "error");
        }
    },

    deleteEntry: (name) => {
        UI.showDeleteModal(name);
    },

    executeDelete: async (name) => {
        try {
            const resp = await fetch(`/api/entries/${name}`, { method: 'DELETE' });
            const text = await resp.text();
            let data;
            try { data = JSON.parse(text); } catch (e) {
                if (window.showStatus) showStatus(`SERVER_ERROR: ${resp.status}`, "error");
                return;
            }

            if (!resp.ok || data.status === "error") {
                if (window.showStatus) showStatus(data.message || "PURGE_FAILURE", "error");
            } else {
                if (window.showStatus) showStatus(`SYMBOL_PURGED: ${name}`, "success");
                Logic.loadArchive();
            }
        } catch (e) {
            if (window.showStatus) showStatus("NETWORK_LINK_FAILURE", "error");
        }
    },

    saveSettings: async function() {
        const proj = document.getElementById('set_proj_select').value;
        const newProj = document.getElementById('set_proj_new').value;
        const target = newProj || proj;

        if (!target) {
            if (window.showStatus) showStatus("PROJECT_NAME_REQUIRED", "error");
            return;
        }

        try {
            const res = await fetch('/api/projects', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ project_name: target }) 
            });
            
            const text = await res.text();
            let data;
            try { data = JSON.parse(text); } catch (e) {
                if (window.showStatus) showStatus(`SERVER_ERROR: ${res.status}`, "error");
                return;
            }

            if (res.ok && data.status !== "error") {
                // Clear the 'new project' input if used
                document.getElementById('set_proj_new').value = '';
                
                // Trigger an internal re-init to refresh the data without reload
                await this.init(); 
                
                if (window.showStatus) showStatus(`PROJECT_LOADED: ${target}`, "success");
            } else {
                if (window.showStatus) showStatus(data.message || "PROJECT_SWITCH_FAILURE", "error");
            }
        } catch(e) {
            if (window.showStatus) showStatus("NETWORK_LINK_FAILURE", "error");
        }
    }
};