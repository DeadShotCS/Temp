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

    handleCustomField: (select, inputId) => {
        const input = document.getElementById('add_' + inputId);
        if (select.value === 'custom' || select.value === 'CREATE_NEW') {
            input.style.display = 'block';
        } else {
            input.style.display = 'none';
        }
    },

    addFinding: () => {
        const container = document.getElementById('findings_container');
        const clone = container.querySelector('.finding-block').cloneNode(true);
        const count = container.querySelectorAll('.finding-block').length + 1;
        
        clone.querySelector('.finding-header span').innerText = `FINDING_BLOCK_${count.toString().padStart(2, '0')}`;
        clone.querySelector('.finding-body').classList.remove('collapsed');
        clone.querySelector('.toggle-icon').innerText = '[ - ]';
        
        clone.querySelectorAll('textarea, input').forEach(i => i.value = '');
        container.appendChild(clone);
    },

    removeFinding: () => {
        const container = document.getElementById('findings_container');
        if (container.children.length > 1) container.lastElementChild.remove();
    },

    resetForm: () => {
        if(confirm("DANGER: This will wipe all data in the current form. Proceed?")) {
            document.querySelectorAll('#pane_add input, #pane_add textarea').forEach(i => i.value = '');
            const container = document.getElementById('findings_container');
            while(container.children.length > 1) container.lastElementChild.remove();
            
            // Reset custom inputs visibility
            document.getElementById('add_tag_cust').style.display = 'none';
            document.getElementById('add_type_cust').style.display = 'none';
            Logic.init(); 
        }
    }
};

const Logic = {
    init: async () => {
        try {
            const resp = await fetch('/api/projects');
            const data = await resp.json();
            
            const activeProj = data.current_project || "DEFAULT";
            document.getElementById('header_proj_name').innerText = activeProj;
            
            // Tags in header
            document.getElementById('header_tags').innerHTML = (data.config.tags || []).map(t => 
                `<span style="color:var(--accent); border:1px solid #333; padding:2px 6px; font-size:9px; font-weight:bold;">${t}</span>`).join('');

            // Settings Dropdown
            const projSel = document.getElementById('settings_project_select');
            if(projSel) projSel.innerHTML = data.config.projects.map(p => 
                `<option value="${p.name}" ${p.name === activeProj ? 'selected' : ''}>${p.name}</option>`).join('');

            // Add Entry Tag Dropdown
            const tagSel = document.getElementById('add_tag_select');
            let tagOptions = (data.config.tags || []).map(t => `<option value="${t}">${t}</option>`).join('');
            tagSel.innerHTML = tagOptions + `<option value="custom">CREATE_NEW...</option>`;

        } catch (error) {
            console.error("UI INIT FAILURE:", error);
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

        const tagSel = document.getElementById('add_tag_select').value;
        const finalTag = tagSel === 'custom' ? document.getElementById('add_tag_cust').value : tagSel;

        const typeSel = document.getElementById('add_func_type').value;
        const finalType = typeSel === 'custom' ? document.getElementById('add_type_cust').value : typeSel;

        const payload = {
            name: document.getElementById('add_name').value,
            tag: finalTag,
            func_type: finalType,
            summary: document.getElementById('add_summary').value,
            findings: findings
        };

        const resp = await fetch('/api/entries', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });

        if (resp.ok) {
            alert("ARCHIVE_SUCCESS: RECORD SAVED.");
            UI.resetForm();
        }
    }
};