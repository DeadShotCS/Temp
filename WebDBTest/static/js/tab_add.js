let findingCounter = 0;

function handleTagSelectChange() {
    const s = document.getElementById('add_tag_select');
    const c = document.getElementById('add_tag_custom');
    if (s.value === "CUSTOM") { s.style.display = "none"; c.style.display = "block"; c.focus(); }
}

function handleTypeSelectChange() {
    const s = document.getElementById('add_type_select');
    const c = document.getElementById('add_type_custom');
    if (s.value === "CUSTOM") { s.style.display = "none"; c.style.display = "block"; c.focus(); }
}

function addFindingBlock() {
    findingCounter++;
    
    // Auto-minimize previous findings
    document.querySelectorAll('.finding-block-wrapper').forEach(b => {
        b.classList.add('minimized');
        b.classList.remove('active');
    });

    const container = document.getElementById('findings_container');
    const div = document.createElement('div');
    div.className = 'form-section finding-block-wrapper active large-input-group';
    div.id = `fblock_${findingCounter}`;
    
    // Click-to-Expand Logic
    div.onclick = function(e) {
        if (['TEXTAREA', 'SELECT', 'INPUT', 'OPTION'].includes(e.target.tagName)) return;
        
        const wasMinimized = this.classList.contains('minimized');
        document.querySelectorAll('.finding-block-wrapper').forEach(b => {
            b.classList.add('minimized');
            b.classList.remove('active');
        });

        if (wasMinimized) {
            this.classList.remove('minimized');
            this.classList.add('active');
        }
    };

    div.innerHTML = `
        <div class="section-label" style="margin-bottom:0">Finding // 0${findingCounter}</div>
        <div class="row" style="margin-top:20px;">
            <div class="col-3">
                <label>Finding Type</label>
                <select class="f-type">
                    <option value="Unknown">Unknown</option>
                    <option value="Bug">Bug</option>
                    <option value="Useful">Useful</option>
                </select>
                <div style="margin-top:40px;">
                    <label>Finding Status</label>
                    <select class="f-status">
                        <option value="Unverified">Unverified</option>
                        <option value="Success">Success</option>
                        <option value="Failure">Failure</option>
                    </select>
                </div>
            </div>
            <div class="col-5">
                <label>Finding Details / Info</label>
                <textarea class="f-details"></textarea>
            </div>
            <div class="col-4">
                <label>Requirements</label>
                <textarea class="f-reqs" style="height: 210px; margin-bottom:30px;"></textarea>
                <label>Verification</label>
                <textarea class="f-verif" style="height: 210px;"></textarea>
            </div>
        </div>
    `;
    container.appendChild(div);
}

function removeLastFinding() {
    if (findingCounter > 0) {
        document.getElementById(`fblock_${findingCounter}`).remove();
        findingCounter--;
        if (findingCounter > 0) {
            const last = document.getElementById(`fblock_${findingCounter}`);
            last.classList.remove('minimized');
            last.classList.add('active');
        }
    }
}

function resetForm() {
    document.getElementById('add_name').value = "";
    document.getElementById('add_description').value = "";
    document.getElementById('findings_container').innerHTML = "";
    
    ['add_type', 'add_tag'].forEach(prefix => {
        const s = document.getElementById(`${prefix}_select`);
        const c = document.getElementById(`${prefix}_custom`);
        s.style.display = "block"; s.value = (prefix === 'add_type' ? "Function" : "");
        c.style.display = "none"; c.value = "";
    });

    findingCounter = 0; 
    addFindingBlock();
}

async function saveAddEntry() {
    const findings = [];
    for(let i=1; i<=findingCounter; i++) {
        const b = document.getElementById(`fblock_${i}`);
        if(b) {
            findings.push({ 
                Type: b.querySelector('.f-type').value, 
                Verified: b.querySelector('.f-status').value, 
                Info: b.querySelector('.f-details').value,
                Requirements: b.querySelector('.f-reqs').value,
                Verification: b.querySelector('.f-verif').value
            });
        }
    }

    const typeS = document.getElementById('add_type_select'), typeC = document.getElementById('add_type_custom');
    const tagS = document.getElementById('add_tag_select'), tagC = document.getElementById('add_tag_custom');

    const payload = {
        name: document.getElementById('add_name').value,
        filepath: (tagS.style.display === "none") ? tagC.value : tagS.value,
        description: document.getElementById('add_description').value,
        type: (typeS.style.display === "none") ? typeC.value : typeS.value,
        findings: findings
    };

    const resp = await fetch('/api/entries', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
    });

    if(resp.ok) { resetForm(); if(window.showStatus) showStatus("ENTRY_SAVED", "success"); }
}