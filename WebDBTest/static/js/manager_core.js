const UI = {
    switchTab: (tabId) => {
        document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
        const pane = document.getElementById('pane_' + tabId);
        if (pane) pane.classList.add('active');

        document.querySelectorAll('.btn-nav').forEach(b => b.classList.remove('active'));
        const btn = document.getElementById('nav_' + tabId);
        if (btn) btn.classList.add('active');
    },

    toggleCollapse: (header) => {
        const body = header.nextElementSibling;
        const indicator = header.querySelector('.status-indicator');
        if (body.style.display === 'none' || body.style.display === '') {
            body.style.display = 'grid';
            indicator.innerText = '[ - ]';
        } else {
            body.style.display = 'none';
            indicator.innerText = '[ + ]';
        }
    },

    checkCustom: (el, mode) => {
        if (el.value === 'custom') {
            const parent = el.parentElement;
            const originalId = el.id;
            el.remove();
            const input = document.createElement('input');
            input.type = 'text';
            input.id = originalId;
            input.placeholder = `Custom ${mode}...`;
            parent.appendChild(input);
            input.focus();
        }
    },

    addFinding: () => {
        const container = document.getElementById('findings_container');
        const template = document.getElementById('finding_template').content.cloneNode(true);
        const count = container.querySelectorAll('.finding-block').length + 1;
        template.querySelector('.block-id').innerText = `FINDING_BLOCK_${count.toString().padStart(2, '0')}`;
        container.appendChild(template);
    },

    removeFinding: () => {
        const container = document.getElementById('findings_container');
        if (container.children.length > 0) {
            container.lastElementChild.remove();
        } else {
            StatusHandler.show("NO_BLOCKS_TO_REMOVE", "warn");
        }
    },

    resetForm: () => { 
        if (confirm("CONFIRM_ACTION: RESET_ALL_FIELDS?")) location.reload(); 
    }
};

const Logic = {
    init: async () => {
        StatusHandler.show("SYSTEM_SYNC: PENDING...", "info");
        try {
            const resp = await fetch('/api/projects');
            const data = await resp.json();
            
            if (data.status === "error") throw new Error(data.message);

            const header = document.getElementById('header_proj_name');
            if (header) header.innerText = data.current_project || "NULL_PROJECT";
            
            const projSelect = document.getElementById('set_proj_select');
            if (projSelect) {
                if (data.all_projects && data.all_projects.length > 0) {
                    projSelect.innerHTML = data.all_projects.map(p => 
                        `<option value="${p}" ${p === data.current_project ? 'selected' : ''}>${p}</option>`
                    ).join('');
                } else {
                    projSelect.innerHTML = '<option value="">ERR: NO_PROJECTS_FOUND</option>';
                    StatusHandler.show("CRITICAL: PROJECT_LIST_EMPTY", "error");
                }
            }

            const setTags = document.getElementById('set_tags');
            if (setTags) setTags.value = (data.config.tags || []).join(', ');

            const tagSel = document.getElementById('add_tag');
            if (tagSel) {
                const tags = data.config.tags || [];
                tagSel.innerHTML = tags.map(t => `<option value="${t}">${t}</option>`).join('') + '<option value="custom">Custom...</option>';
            }
            
            if (document.getElementById('findings_container').children.length === 0) UI.addFinding();
            StatusHandler.show("SYSTEM_SYNC: COMPLETE", "success");
        } catch (e) { 
            console.error("INIT_ERR:", e);
            StatusHandler.show("INIT_FAILURE: FILE_ACCESS_DENIED", "error");
        }
    },

    saveSettings: async () => {
        const selectedProj = document.getElementById('set_proj_select').value;
        const newProjInput = document.getElementById('set_proj_new');
        const newProjName = newProjInput.value.trim();
        const targetProject = newProjName || selectedProj;

        if (!targetProject) {
            StatusHandler.show("INPUT_REQUIRED: SPECIFY_PROJECT_NAME", "warn");
            return;
        }

        StatusHandler.show(`PROJECT_MIGRATION: ${targetProject.toUpperCase()}...`, "info");

        try {
            const resp = await fetch('/api/config', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ project_name: targetProject })
            });
            
            const result = await resp.json();
            if (resp.ok) {
                StatusHandler.show("MIGRATION_SUCCESS", "success");
                newProjInput.value = "";
                
                // MANUAL UI UPDATE - NO RELOAD
                const header = document.getElementById('header_proj_name');
                if (header) header.innerText = targetProject;
                
                // Re-run init to refresh dropdowns and tags without a reload
                Logic.init(); 
            } else {
                StatusHandler.show(`MIGRATION_FAILED: ${result.message}`, "error");
            }
        } catch (e) {
            StatusHandler.show("NETWORK_ERROR: CONFIG_API_TIMEOUT", "error");
        }
    },

    updateTagsOnly: async () => {
        const tagsRaw = document.getElementById('set_tags').value;
        const tags = tagsRaw.split(',').map(t => t.trim()).filter(t => t !== "");
        
        StatusHandler.show("TAG_SYNC: UPDATING_REGISTRY...", "info");

        try {
            const resp = await fetch('/api/config', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ tags: tags })
            });

            if (resp.ok) {
                StatusHandler.show("TAG_SYNC: SUCCESS", "success");
                setTimeout(() => location.reload(), 800);
            } else {
                StatusHandler.show("TAG_SYNC: FAILED", "error");
            }
        } catch (e) {
            StatusHandler.show("NETWORK_ERROR: TAG_API_TIMEOUT", "error");
        }
    },

    saveEntry: async () => {
        StatusHandler.show("DB_COMMIT: PENDING...", "info");

        const findings = Array.from(document.querySelectorAll('.finding-block')).map(b => ({
            type: b.querySelector('.f-type').value,
            status: b.querySelector('.f-status').value,
            info: b.querySelector('.f-info').value,
            req: b.querySelector('.f-req').value,
            ver: b.querySelector('.f-ver').value
        }));

        const payload = {
            name: document.getElementById('add_name').value,
            tag: document.getElementById('add_tag').value,
            type: document.getElementById('add_type').value,
            summary: document.getElementById('add_summary').value,
            findings: findings
        };

        if (!payload.name) {
            StatusHandler.show("VALIDATION_ERROR: NAME_REQUIRED", "warn");
            return;
        }

        try {
            const resp = await fetch('/api/entries', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(payload)
            });
            
            if (resp.ok) {
                StatusHandler.show("DB_COMMIT: SUCCESSFUL", "success");
            } else {
                StatusHandler.show("DB_COMMIT: FAILED", "error");
            }
        } catch (e) {
            StatusHandler.show("NETWORK_ERROR: DB_API_UNREACHABLE", "error");
        }
    }
};