document.addEventListener('DOMContentLoaded', () => {
    const scanButton = document.getElementById('scanButton');
    if (!scanButton) return;

    // --- DOM Elements ---
    const resultsList = document.getElementById('resultsList');
    const historyList = document.getElementById('historyList');
    const statusMessage = document.getElementById('statusMessage');
    const lastScannedTime = document.getElementById('lastScannedTime');
    const deleteHistoryButton = document.getElementById('deleteHistoryButton');

    // Chart Canvases & Instances
    const postureChartCanvas = document.getElementById('postureChart');
    const serviceBreakdownCanvas = document.getElementById('serviceBreakdownChart');
    const historicalTrendCanvas = document.getElementById('historicalTrendChart');
    let postureChart, serviceBreakdownChart, historicalTrendChart;

    // --- API Endpoints ---
    const API_BASE_URL = window.location.origin;
    const SCAN_API_URL = `${API_BASE_URL}/api/v1/scan`;
    const HISTORY_API_URL = `${API_BASE_URL}/api/v1/history`;
    const TRENDS_API_URL = `${API_BASE_URL}/api/v1/history/trends`;
    const DELETE_HISTORY_API_URL = `${API_BASE_URL}/api/v1/delete_history`;

    const renderResults = (container, results) => {
        container.innerHTML = '';
        if (results && results.length > 0) {
            results.forEach(result => {
                const resultItem = document.createElement('div');
                resultItem.classList.add('result-item');
                const statusClass = result.status ? result.status.toLowerCase() : 'ok';
                resultItem.classList.add(statusClass);
                
                let issueText = result.issue ? `<strong>Issue:</strong> ${result.issue}` : `<strong>Error:</strong> ${result.error}`;
                
                resultItem.innerHTML = `
                    <strong>Service:</strong> ${result.service}<br>
                    <strong>Resource:</strong> ${result.resource || 'N/A'}<br>
                    <strong>Status:</strong> <span class="status-${result.status}">${result.status}</span><br>
                    ${issueText}
                `;
                if(result.timestamp) {
                    resultItem.innerHTML += `<br><small>Time: ${new Date(result.timestamp).toLocaleString()}</small>`;
                }
                container.appendChild(resultItem);
            });
        } else {
            container.innerHTML = '<p>No results found.</p>';
        }
    };

    const updateDashboardCharts = (results) => {
        try {
            const validResults = results.filter(r => r && r.status);
            const criticalCount = validResults.filter(r => r.status === 'CRITICAL').length;
            const okCount = validResults.filter(r => r.status === 'OK').length;
            document.getElementById('totalResources').textContent = criticalCount + okCount;
            document.getElementById('criticalFindings').textContent = criticalCount;

            if (postureChart) postureChart.destroy();
            if (postureChartCanvas) {
                postureChart = new Chart(postureChartCanvas, {
                    type: 'doughnut', data: { labels: ['OK', 'CRITICAL'], datasets: [{ data: [okCount, criticalCount], backgroundColor: ['#2ecc71', '#e74c3c'], hoverOffset: 4 }] },
                    options: { responsive: true, maintainAspectRatio: false }
                });
            }

            const criticalByService = validResults.filter(r => r.status === 'CRITICAL').reduce((acc, result) => {
                    acc[result.service] = (acc[result.service] || 0) + 1; return acc; }, {});
            
            if (serviceBreakdownChart) serviceBreakdownChart.destroy();
            if (serviceBreakdownCanvas) {
                serviceBreakdownChart = new Chart(serviceBreakdownCanvas, {
                    type: 'bar', data: { labels: Object.keys(criticalByService), datasets: [{ label: 'Critical Findings', data: Object.values(criticalByService), backgroundColor: '#e74c3c' }] },
                    options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
                });
            }
        } catch (e) { console.error("Error updating dashboard charts:", e); }
    };

    const renderTrendChart = async () => {
        try {
            const response = await fetch(TRENDS_API_URL);
            const trendData = await response.json();
            
            if (historicalTrendChart) historicalTrendChart.destroy();
            if (historicalTrendCanvas) {
                historicalTrendChart = new Chart(historicalTrendCanvas, {
                    type: 'line', data: { labels: trendData.labels, datasets: [{
                            label: 'Critical Findings', data: trendData.data, fill: true,
                            borderColor: '#3498db', backgroundColor: 'rgba(52, 152, 219, 0.2)', tension: 0.1 }]
                    },
                    options: { responsive: true, maintainAspectRatio: false }
                });
            }
        } catch (error) { console.error('Failed to load trend data:', error); }
    };
    
    const fetchAndRenderHistory = async () => {
        try {
            const response = await fetch(HISTORY_API_URL);
            const data = await response.json();
            renderResults(historyList, data.historical_scans);
        } catch (error) {
            historyList.innerHTML = '<p>Could not load historical data.</p>';
        }
    };

    scanButton.addEventListener('click', async () => {
        statusMessage.textContent = 'Scanning in progress... This may take a moment.';
        scanButton.disabled = true;
        try {
            const response = await fetch(SCAN_API_URL);
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const data = await response.json();
            statusMessage.textContent = `Scan complete.`;
            lastScannedTime.textContent = `Last scan: ${new Date(data.timestamp).toLocaleString()}`;
            renderResults(resultsList, data.scan_results);
            updateDashboardCharts(data.scan_results);
            fetchAndRenderHistory();
            renderTrendChart();
        } catch (error) {
            statusMessage.textContent = 'Error during scan. Check the console for details.';
        } finally {
            scanButton.disabled = false;
        }
    });

    deleteHistoryButton.addEventListener('click', async () => {
        if (confirm("Are you sure you want to delete all your historical scan results? This cannot be undone.")) {
            try {
                const response = await fetch(DELETE_HISTORY_API_URL, { method: 'POST' });
                if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
                fetchAndRenderHistory();
                renderTrendChart();
                statusMessage.textContent = 'Historical data deleted.';
            } catch (error) {
                alert("Failed to delete history.");
            }
        }
    });

    // --- Initial Load ---
    fetchAndRenderHistory();
    renderTrendChart();
});