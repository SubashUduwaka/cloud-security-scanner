// app.js

// Wait for the page to be ready before we do anything.
document.addEventListener('DOMContentLoaded', () => {
    const scanButton = document.getElementById('scanButton');
    const resultsList = document.getElementById('resultsList');
    const historyList = document.getElementById('historyList');
    const statusMessage = document.getElementById('statusMessage');
    const postureChartCanvas = document.getElementById('postureChart');
    let postureChart = null; // This will hold our pretty doughnut chart.

    // Just saving our API addresses so we don't have to type them a million times.
    const SCAN_API_URL = 'http://127.0.0.1:5000/api/v1/scan';
    const HISTORY_API_URL = 'http://127.0.0.1:5000/api/v1/history';

    // A little helper to draw the results on the screen. Keeps the code clean.
    const renderResults = (container, results) => {
        container.innerHTML = ''; // Clear out the old stuff first.
        if (results && results.length > 0) {
            results.forEach(result => {
                const resultItem = document.createElement('div');
                resultItem.classList.add('result-item');
                
                // Make the scary ones red.
                if (result.status === 'CRITICAL') {
                    resultItem.classList.add('critical');
                } else {
                    resultItem.classList.add('ok');
                }
                
                resultItem.innerHTML = `
                    <strong>Service:</strong> ${result.service}<br>
                    <strong>Resource:</strong> ${result.resource}<br>
                    <strong>Status:</strong> ${result.status}<br>
                    <strong>Issue:</strong> ${result.issue}
                `;
                container.appendChild(resultItem);
            });
        } else {
            container.innerHTML = '<p>No results found.</p>';
        }
    };

    // This function makes the doughnut chart. Mmm, doughnuts.
    const updateDashboardChart = (results) => {
        // Count how many good things and bad things we found.
        const criticalCount = results.filter(r => r.status === 'CRITICAL').length;
        const okCount = results.filter(r => r.status === 'OK').length;
        const totalCount = criticalCount + okCount;

        // If a chart already exists, we gotta kill it before making a new one.
        if (postureChart) {
            postureChart.destroy();
        }

        if (totalCount > 0) {
            const data = {
                labels: ['OK', 'CRITICAL'],
                datasets: [{
                    label: 'Scan Results',
                    data: [okCount, criticalCount],
                    backgroundColor: ['#4caf50', '#f44336'], // Green for good, red for bad.
                    hoverOffset: 4
                }]
            };
            const config = {
                type: 'doughnut',
                data: data,
            };
            // Create the new chart on our canvas.
            postureChart = new Chart(postureChartCanvas, config);
        } else {
            // No data? Just say so.
            if (postureChartCanvas) {
                const ctx = postureChartCanvas.getContext('2d');
                ctx.clearRect(0, 0, postureChartCanvas.width, postureChartCanvas.height);
            }
        }
    };
    
    // First thing we do is grab the old results to show on the page.
    const fetchAndRenderHistory = async () => {
        historyList.innerHTML = '<p>Loading historical data...</p>';
        try {
            const response = await fetch(HISTORY_API_URL);
            const data = await response.json();
            renderResults(historyList, data.historical_scans);
        } catch (error) {
            historyList.innerHTML = '<p>Could not load historical data.</p>';
            console.error('Failed to fetch history:', error);
        }
    };

    // Load history when the page first loads.
    fetchAndRenderHistory();
    updateDashboardChart([]); // Start with an empty chart.

    // Here we go! User clicked the button.
    scanButton.addEventListener('click', async () => {
        statusMessage.textContent = 'Scanning in progress... Please wait.';
        resultsList.innerHTML = '';
        scanButton.disabled = true; // Gotta disable the button so the user doesn't get click-happy.

        try {
            const response = await fetch(SCAN_API_URL);
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            const scanResults = data.scan_results;
            
            statusMessage.textContent = `Scan complete. Found ${scanResults.length} items.`;
            
            // Show the new results, update the chart, and refresh the history view.
            renderResults(resultsList, scanResults);
            updateDashboardChart(scanResults);
            fetchAndRenderHistory();

        } catch (error) {
            statusMessage.textContent = 'Error during scan. Check the console for details.';
            console.error('Scan failed:', error);
        } finally {
            // Turn the button back on, no matter what happened.
            scanButton.disabled = false;
        }
    });
});
