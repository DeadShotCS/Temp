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
        if (body.style.display === 'none') {
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
        if (container.children.length > 0) container.lastElementChild.remove();
    },

    resetForm: () => { if (confirm("Clear form?")) location.reload(); }
};

const Logic = {
    init: async () => {
        try {
            const resp = await fetch('/api/projects');
            const data = await resp.json();
            document.getElementById('header_proj_name').innerText = data.current_project || "DEFAULT";
            
            const tagSel = document.getElementById('add_tag');
            if (tagSel) {
                tagSel.innerHTML = (data.config.tags || []).map(t => `<option value="${t}">${t}</option>`).join('') + '<option value="custom">Custom...</option>';
            }
            UI.addFinding();
        } catch (e) { console.error(e); }
    },

    saveEntry: async () => {
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

        const resp = await fetch('/api/entries', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        if (resp.ok) alert("ENTRY_SAVED");
    }
};