document.addEventListener('DOMContentLoaded', function() {
    // Actualisation du statut
    const refreshButton = document.getElementById('refresh-status');
    if (refreshButton) {
        refreshButton.addEventListener('click', function() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    updateStatusDisplay(data);
                })
                .catch(error => {
                    console.error('Erreur lors de la récupération du statut:', error);
                });
        });
    }

    function updateStatusDisplay(status) {
        const container = document.getElementById('status-container');
        if (!container) return;

        if (Object.keys(status).length === 0) {
            container.innerHTML = '<p class="text-muted">Aucune connexion active</p>';
            return;
        }

        let html = '';
        for (const [connName, connStatus] of Object.entries(status)) {
            const statusClass = connStatus.includes('established') ? 'bg-success' : 'bg-warning';
            html += `
                <div class="connection-status mb-2 p-2 border rounded">
                    <div class="d-flex justify-content-between align-items-center">
                        <strong>${connName}</strong>
                        <span class="badge ${statusClass}">${connStatus}</span>
                    </div>
                    <div class="mt-2">
                        <a href="/connections/start/${connName}" class="btn btn-sm btn-success">Démarrer</a>
                        <a href="/connections/stop/${connName}" class="btn btn-sm btn-danger">Arrêter</a>
                    </div>
                </div>
            `;
        }
        container.innerHTML = html;
    }

    // Auto-refresh toutes les 30 secondes
    setInterval(() => {
        if (document.getElementById('status-container')) {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => updateStatusDisplay(data));
        }
    }, 30000);
});