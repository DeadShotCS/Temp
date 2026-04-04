const UI = {
    sortState: { col: null, asc: true },

    switchTab: (tabId) => {
        document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
        const target = document.getElementById('pane_' + tabId);
        if (target) target.classList.add('active');

        document.querySelectorAll('.btn-nav').forEach(b => b.classList.remove('active'));
        const activeBtn = document.getElementById('nav_' + tabId);
        if (activeBtn) activeBtn.classList.add('active');

        if (tabId === 'view') Logic.loadEntries();
    },

    resetForm: () => {
        const nameInp = document.getElementById('add_name');
        nameInp.value = '';
        nameInp.readOnly = false;
        nameInp.style.borderLeft = "1px solid var(--border)";

        const tagSel = document.getElementById('add_tag');
        if (tagSel) {
            tagSel.disabled = false;
            tagSel.style.opacity = "1";
            tagSel.value = tagSel.options[0].value;
        }

        document.getElementById('add_type').value = 'function';
        document.getElementById('add_summary').value = '';
        document.getElementById('findings_container').innerHTML = '';
        UI.addFinding();
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
    init: async () => {
        const resp = await fetch('/api/projects');
        const data = await resp.json();
        document.getElementById('header_proj_name').innerText = data.current_project;
        
        const tagSel = document.getElementById('add_tag');
        if (tagSel) {
            tagSel.innerHTML = data.config.tags.map(t => `<option value="${t}">${t}</option>`).join('') + '<option value="custom">Custom...</option>';
        }
    },

    loadEntries: async () => {
        const resp = await fetch('/api/entries');
        const data = await resp.json();
        const body = document.getElementById('archive_body');
        body.innerHTML = '';
        data.forEach(item => {
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
    },

    editEntry: async (name) => {
        const resp = await fetch(`/api/entries/${name}`);
        const data = await resp.json();
        
        // 1. Switch Tab
        UI.switchTab('add');
        
        // 2. Lock Name
        const nameInp = document.getElementById('add_name');
        nameInp.value = data.name;
        nameInp.readOnly = true;
        nameInp.style.borderLeft = "3px solid var(--accent)";

        // 3. Lock Tag (The specific fix you requested)
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
        if (!nameVal) return;

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
            const result = await resp.json();
            
            if (result.status === "success") {
                if (window.StatusHandler) {
                    StatusHandler.success("Entry Synchronized.");
                } else {
                    alert("Entry Synchronized.");
                }
                UI.resetForm();
                UI.switchTab('view');
            }
        } catch (e) {
            console.error(e);
            if (window.StatusHandler) StatusHandler.error("Save Failed.");
        }
    },

    deleteEntry: (name) => {
        UI.showDeleteModal(name);
    },

    executeDelete: async (name) => {
        try {
            const resp = await fetch(`/api/entries/${name}`, { method: 'DELETE' });
            const result = await resp.json();
            if (result.status === "success") {
                if (window.StatusHandler) StatusHandler.success(`Symbol ${name} purged.`);
                Logic.loadEntries();
            }
        } catch (e) {
            if (window.StatusHandler) StatusHandler.error("Purge Failed.");
        }
    }
};