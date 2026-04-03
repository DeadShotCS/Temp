async function loadEntriesTable() {
    try {
        const resp = await fetch('/api/entries');
        const data = await resp.json();
        const tbody = document.getElementById('entries_tbody');
        if(!tbody) return;

        tbody.innerHTML = data.map(e => `
            <tr>
                <td style="color:#fff;">${e.Main.MainName}</td>
                <td>${e.Main.Filepath}</td>
                <td>${e.Description.Type}</td>
                <td style="text-align:right">
                    <button class="btn-core" onclick="deleteEntry('${e.Main.ID}')">DEL</button>
                </td>
            </tr>
        `).join('');
    } catch (err) {
        console.error("View Refresh Failed:", err);
    }
}

async function deleteEntry(id) {
    if(!confirm("Confirm permanent deletion of this entry?")) return;
    
    const resp = await fetch(`/api/entries/${id}`, {method: 'DELETE'});
    if(resp.ok) {
        loadEntriesTable();
        if(window.showStatus) showStatus("ENTRY_DELETED", "success");
    }
}