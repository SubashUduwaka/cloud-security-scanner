document.addEventListener('DOMContentLoaded', () => {
    const scanButton = document.getElementById('scanButton');
    const resultsList = document.getElementById('resultsList');
    const statusMessage = document.getElementById('statusMessage');

    const API_URL = 'http://127.0.0.1:5000/api/v1/scan'; // flask api url

    scanButton.addEventListener('click', async () => {
        // show that we're working
        statusMessage.textContent = 'Scanning...';
        resultsList.innerHTML = '';
        scanButton.disabled = true;

        try {
            // call the backend
            const response = await fetch(API_URL);
            if (!response.ok) {
                throw new Error(`API error: ${response.status}`);
            }

            // get the json data
            const data = await response.json();
            const scanResults = data.scan_results;

            statusMessage.textContent = `Scan complete. Found ${scanResults.length} results.`;

            // display results
            if (scanResults.length > 0) {
                scanResults.forEach(result => {
                    const item = document.createElement('div');
                    item.className = 'result-item'; // use className for simplicity
                    
                    // add ok or critical class for styling
                    if (result.status === 'CRITICAL') {
                        item.classList.add('critical');
                    } else {
                        item.classList.add('ok');
                    }
                    
                    // dump the details into the html
                    item.innerHTML = `
                        <strong>Bucket:</strong> ${result.bucket || 'N/A'}<br>
                        <strong>Status:</strong> ${result.status || 'N/A'}<br>
                        <strong>Info:</strong> ${result.issue || result.details || 'N/A'}
                    `;
                    resultsList.appendChild(item);
                });
            } else {
                resultsList.innerHTML = '<p>No buckets found.</p>';
            }

        } catch (error) {
            // handle errors
            statusMessage.textContent = 'Scan failed. See console for details.';
            console.error('Error during scan:', error);

        } finally {
            // re-enable the button
            scanButton.disabled = false;
        }
    });
});