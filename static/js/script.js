document.addEventListener('DOMContentLoaded', function() {
    // Actualisation du statut
    const refreshButton = document.getElementById('refresh-status');
    if (refreshButton) {
        refreshButton.addEventListener('click', function() {
            refreshButton.disabled = true;
            refreshButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Actualisation...';
            
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    updateStatusDisplay(data);
                })
                .catch(error => {
                    console.error('Erreur:', error);
                })
                .finally(() => {
                    setTimeout(() => {
                        refreshButton.disabled = false;
                        refreshButton.innerHTML = '<i class="fas fa-redo"></i> Actualiser';
                    }, 1000);
                });
        });
    }

    function updateStatusDisplay(status) {
        const container = document.getElementById('status-container');
        if (!container) return;

        if (Object.keys(status).length === 0) {
            container.innerHTML = `
                <p class="text-muted text-center py-4">
                    <i class="fas fa-info-circle"></i> Aucune connexion configurée
                </p>
            `;
            return;
        }

        let html = '';
        for (const [connName, connStatus] of