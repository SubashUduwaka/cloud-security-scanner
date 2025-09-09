document.addEventListener('DOMContentLoaded', () => {
<<<<<<< HEAD

    const initPasswordStrengthMeter = () => {
        // This selector is specific to only find password fields that have a strength bar.
        const passwordInput = document.querySelector('.password-strength-input');
        if (!passwordInput) return;

        // The container is the parent of the input, which should be the form or a div.
        const container = passwordInput.parentElement;
        const strengthBar = container.querySelector('.strength-bar');
        const strengthText = container.querySelector('.strength-text');
        
        if (!strengthBar || !strengthText) return;

        const colors = ['#D64550', '#D64550', '#FFA726', '#4CAF50', '#4CAF50']; // Corresponds to zxcvbn scores 0-4

        passwordInput.addEventListener('input', () => {
            const password = passwordInput.value;
            if (password === "") {
                strengthBar.style.width = '0%';
                strengthText.textContent = '';
                return;
            }
            
            const result = zxcvbn(password);
            const score = result.score;
            const width = (score + 1) * 20;

            strengthBar.style.width = `${width}%`;
            strengthBar.style.backgroundColor = colors[score];

            if (result.feedback && result.feedback.warning) {
                strengthText.textContent = result.feedback.warning;
            } else if (result.feedback && result.feedback.suggestions.length > 0) {
                strengthText.textContent = result.feedback.suggestions[0];
            } else {
                strengthText.textContent = '';
            }
        });
    };

    const exitButton = document.getElementById('exit-button');
	if (exitButton) {
		exitButton.addEventListener('click', (e) => {
			e.preventDefault();
			if (confirm('Are you sure you want to exit the application? The server will be stopped.')) {
				const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
				fetch('/shutdown', {
					method: 'POST',
					headers: {
						'X-CSRF-Token': csrfToken
					}
				}).then(() => {
					// Close the browser window/tab after the request is sent
					window.close();
				});
			}
		});
	}

    const initThemeSwitcher = () => {
        const themeCheckbox = document.getElementById('theme-checkbox');
        window.chartInstances = {};
        const updateAllChartColors = () => {
            const isDarkMode = document.body.classList.contains('dark-mode');
            const textColor = isDarkMode ? '#F7FAFC' : '#666';
            const cardBgColor = isDarkMode ? '#34495E' : '#FFFFFF';
            const gridColor = isDarkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)';
            if (typeof Chart === 'undefined') return;
            Chart.defaults.color = textColor;
            for (const chartName in window.chartInstances) {
                const chart = window.chartInstances[chartName];
                if (chart) {
                    if (chart.options.plugins?.title) chart.options.plugins.title.color = isDarkMode ? '#ECF0F1' : '#34495E';
                    if (chart.options.plugins?.legend) chart.options.plugins.legend.labels.color = textColor;
                    if (chart.config.type === 'doughnut' && chart.data.datasets[0]) chart.data.datasets[0].borderColor = cardBgColor;
                    if (chart.options.scales?.x) {
                        chart.options.scales.x.ticks.color = textColor;
                        chart.options.scales.x.grid.color = gridColor;
                    }
                    if (chart.options.scales?.y) {
                        chart.options.scales.y.ticks.color = textColor;
                        chart.options.scales.y.grid.color = gridColor;
                    }
                    chart.update();
                }
            }
        };
        const applyTheme = () => {
            const isDarkMode = localStorage.getItem('theme') === 'dark';
            document.body.classList.toggle('dark-mode', isDarkMode);
            if (themeCheckbox) themeCheckbox.checked = isDarkMode;
            updateAllChartColors();
        };
        if (themeCheckbox) {
            themeCheckbox.addEventListener('change', () => {
                localStorage.setItem('theme', themeCheckbox.checked ? 'dark' : 'light');
                applyTheme();
            });
        }
        applyTheme();
    };

    const initAuthPage = () => {
        const showLogin = document.getElementById('showLogin');
        const showRegister = document.getElementById('showRegister');
        const loginForm = document.getElementById('loginForm');
        const registerForm = document.getElementById('registerForm');
        const switchToLogin = () => {
            loginForm.style.display = 'block';
            registerForm.style.display = 'none';
            showLogin.classList.add('active');
            showRegister.classList.remove('active');
        };
        const switchToRegister = () => {
            loginForm.style.display = 'none';
            registerForm.style.display = 'block';
            showLogin.classList.remove('active');
            showRegister.classList.add('active');
        };
        showLogin.addEventListener('click', (e) => { e.preventDefault(); switchToLogin(); window.location.hash = '#login'; });
        showRegister.addEventListener('click', (e) => { e.preventDefault(); switchToRegister(); window.location.hash = '#register'; });
        if (window.location.hash === '#register') { switchToRegister(); } else { switchToLogin(); }
    };

    const initDashboardPage = () => {
        const scanButton = document.getElementById('scanButton');
        const credentialSelect = document.getElementById('credentialProfileSelect');
        const regionSelect = document.getElementById('regionSelect');
        const resultsList = document.getElementById('resultsList');
        const historyList = document.getElementById('historyList');
        const remediationList = document.getElementById('remediationList');
        const deleteHistoryButton = document.getElementById('deleteHistoryButton');
        const postureChartCanvas = document.getElementById('postureChart');
        const serviceBreakdownCanvas = document.getElementById('serviceBreakdownChart');
        const historicalTrendCanvas = document.getElementById('historicalTrendCanvas');
        const scanConsoleWrapper = document.getElementById('scan-console-wrapper');
        const scanConsole = document.getElementById('scan-console');
        const progressModeToggle = document.getElementById('progressModeToggle');
        let eventSource = null;

        const currentSearchInput = document.getElementById('currentSearch');
        const currentStatusFilter = document.getElementById('currentStatusFilter');
        const historySearchInput = document.getElementById('historySearch');
        const historyStatusFilter = document.getElementById('historyStatusFilter');
        
        const historyPrevBtn = document.getElementById('historyPrevBtn');
        const historyNextBtn = document.getElementById('historyNextBtn');
        const historyPageIndicator = document.getElementById('historyPageIndicator');
        let currentPage = 1;

        const API_BASE_URL = window.location.origin;
        const SCAN_API_URL = `${API_BASE_URL}/api/v1/scan`;
        const HISTORY_API_URL = `${API_BASE_URL}/api/v1/history`;
        const TRENDS_API_URL = `${API_BASE_URL}/api/v1/history/trends`;
        const DELETE_HISTORY_API_URL = `${API_BASE_URL}/api/v1/delete_history`;
        const SUPPRESS_API_URL = `${API_BASE_URL}/api/v1/suppress_finding`;

        const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

        const suppressFinding = async (findingData, elementToHide) => {
            try {
                const response = await fetch(SUPPRESS_API_URL, {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken
                    },
                    body: JSON.stringify({ finding: findingData }),
                });
                if (!response.ok) { throw new Error('Failed to suppress finding.'); }
                const data = await response.json();
                Toastify({ text: data.message, duration: 3000, gravity: "bottom", position: "right", style: { background: "linear-gradient(to right, #4A90E2, #357ABD)" } }).showToast();
                elementToHide.style.display = 'none';
            } catch (error) {
                Toastify({ text: error.message, duration: 4000, gravity: "bottom", position: "right", style: { background: "linear-gradient(to right, #D0021B, #e74c3c)" } }).showToast();
            }
        };
        
        const renderResults = (container, results) => {
            container.innerHTML = '';
            if (results && results.length > 0) {
                results.forEach(result => {
                    const resultItem = document.createElement('div');
                    resultItem.className = `result-item ${result.status ? result.status.toLowerCase() : 'ok'}`;
                    
                    const header = document.createElement('div');
                    header.className = 'result-item-header';
                    const detailsDiv = document.createElement('div');
                    const serviceStrong = document.createElement('strong');
                    serviceStrong.textContent = 'Service: ';
                    detailsDiv.appendChild(serviceStrong);
                    detailsDiv.appendChild(document.createTextNode(result.service));
                    detailsDiv.appendChild(document.createElement('br'));
                    const resourceStrong = document.createElement('strong');
                    resourceStrong.textContent = 'Resource: ';
                    detailsDiv.appendChild(resourceStrong);
                    detailsDiv.appendChild(document.createTextNode(result.resource || 'N/A'));
                    header.appendChild(detailsDiv);

                    const suppressBtn = document.createElement('button');
                    suppressBtn.className = 'button-secondary button-small suppress-btn';
                    suppressBtn.title = 'Suppress this finding';
                    suppressBtn.innerHTML = '<i class="fas fa-eye-slash"></i> Suppress';
                    suppressBtn.addEventListener('click', () => {
                        if (confirm('Are you sure you want to suppress this finding? It will be hidden from future scans.')) {
                            const findingData = { service: result.service, resource: result.resource, issue: result.issue };
                            suppressFinding(findingData, resultItem);
                        }
                    });
                    header.appendChild(suppressBtn);
                    resultItem.appendChild(header);

                    const statusStrong = document.createElement('strong');
                    statusStrong.textContent = 'Status: ';
                    resultItem.appendChild(statusStrong);
                    const statusSpan = document.createElement('span');
                    statusSpan.className = `status-${result.status}`;
                    statusSpan.textContent = result.status;
                    resultItem.appendChild(statusSpan);
                    resultItem.appendChild(document.createElement('br'));

                    const issueStrong = document.createElement('strong');
                    issueStrong.textContent = result.issue ? 'Issue: ' : 'Error: ';
                    resultItem.appendChild(issueStrong);
                    resultItem.appendChild(document.createTextNode(result.issue || result.error));

                    if (result.timestamp) {
                        resultItem.appendChild(document.createElement('br'));
                        const small = document.createElement('small');
                        small.textContent = `Time: ${new Date(result.timestamp).toLocaleString()}`;
                        resultItem.appendChild(small);
                    }

                    if (result.remediation) {
                        const remediationBlock = document.createElement('div');
                        remediationBlock.className = 'remediation-block';
                        const fixStrong = document.createElement('strong');
                        fixStrong.innerHTML = '<i class="fas fa-wrench"></i> How to Fix:';
                        remediationBlock.appendChild(fixStrong);
                        const p = document.createElement('p');
                        p.textContent = result.remediation;
                        remediationBlock.appendChild(p);
                        if (result.doc_url) {
                            const docLink = document.createElement('a');
                            docLink.href = result.doc_url;
                            docLink.target = '_blank';
                            docLink.className = 'remediation-link';
                            docLink.innerHTML = 'View Docs <i class="fas fa-external-link-alt"></i>';
                            remediationBlock.appendChild(docLink);
                        }
                        resultItem.appendChild(remediationBlock);
                    }
                    container.appendChild(resultItem);
                });
            } else {
                container.innerHTML = '<p class="empty-state">No results found.</p>';
            }
        };
        
        const updateRemediationPanel = (results) => {
            const criticalItems = results.filter(r => r.status === 'CRITICAL').slice(0, 3);
            remediationList.innerHTML = '';
            if (criticalItems.length > 0) {
                criticalItems.forEach(item => {
                    const div = document.createElement('div');
                    div.classList.add('remediation-item');
                    div.innerHTML = `<strong>${item.service}:</strong> Fix issue on <span class="resource-name">${item.resource}</span>.<div style="font-size: 0.9em; color: var(--medium-grey);">${item.issue}</div>`;
                    remediationList.appendChild(div);
                });
            } else {
                remediationList.innerHTML = '<p class="empty-state"><i class="fas fa-check-circle" style="color: var(--success-color);"></i> No critical issues found. Great job!</p>';
            }
        };

        const updateDashboardCharts = (results) => {
            if (!postureChartCanvas || !serviceBreakdownCanvas) return;
            const validResults = results.filter(r => r && r.status);
            const okCount = validResults.filter(r => r.status === 'OK').length;
            const criticalCount = validResults.filter(r => r.status === 'CRITICAL').length;
            const totalCount = okCount + criticalCount;
            document.getElementById('totalResources').textContent = totalCount;
            document.getElementById('criticalFindings').textContent = criticalCount;
            const healthScore = totalCount > 0 ? Math.round((okCount / totalCount) * 100) : 100;
            document.getElementById('healthScore').textContent = `${healthScore}%`;
            if (window.chartInstances.posture) window.chartInstances.posture.destroy();
            window.chartInstances.posture = new Chart(postureChartCanvas, { type: 'doughnut', data: { labels: ['OK', 'CRITICAL'], datasets: [{ data: [okCount, criticalCount], backgroundColor: ['#4CAF50', '#D64550'], borderWidth: 4 }] }, options: { responsive: true, maintainAspectRatio: false, cutout: '70%', plugins: { legend: { position: 'top' }, title: { display: true, text: 'Security Posture', padding: { bottom: 20 }, font: { size: 18, weight: '600' }}}} });
            const criticalByService = validResults.filter(r => r.status === 'CRITICAL').reduce((acc, r) => { acc[r.service] = (acc[r.service] || 0) + 1; return acc; }, {});
            if (window.chartInstances.service) window.chartInstances.service.destroy();
            window.chartInstances.service = new Chart(serviceBreakdownCanvas, { type: 'bar', data: { labels: Object.keys(criticalByService), datasets: [{ label: 'Critical Findings', data: Object.values(criticalByService), backgroundColor: '#D64550' }] }, options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false }, title: { display: true, text: 'Critical Findings by Service', padding: { bottom: 10 }, font: { size: 18, weight: '600' }}}} });
            document.dispatchEvent(new Event('themeChanged'));
        };

        const renderTrendChart = async () => {
            if (!historicalTrendCanvas) return;
            try {
                const response = await fetch(TRENDS_API_URL);
                const trendData = await response.json();
                if (window.chartInstances.trends) window.chartInstances.trends.destroy();
                window.chartInstances.trends = new Chart(historicalTrendCanvas, { type: 'line', data: { labels: trendData.labels, datasets: [{ label: 'Critical Findings', data: trendData.data, fill: true, borderColor: '#00A896', backgroundColor: 'rgba(0, 168, 150, 0.1)', tension: 0.1 }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { title: { display: true, text: 'Historical Trend (Last 30 Days)', padding: { bottom: 10 }, font: { size: 18, weight: '600' }}}} });
                document.dispatchEvent(new Event('themeChanged'));
            } catch (error) { console.error('Failed to load trend data:', error); }
        };

        const fetchAndRenderHistory = async (page = 1) => {
            try {
                const response = await fetch(`${HISTORY_API_URL}?page=${page}`);
                const data = await response.json();
                renderResults(historyList, data.historical_scans);
                
                currentPage = data.page;
                historyPageIndicator.textContent = `Page ${data.page} of ${data.total_pages || 1}`;
                historyPrevBtn.disabled = !data.has_prev;
                historyNextBtn.disabled = !data.has_next;

            } catch (error) {
                console.error("Failed to render history:", error);
                historyList.innerHTML = '<p class="empty-state">Could not load historical data.</p>';
            }
        };

        historyPrevBtn.addEventListener('click', () => {
            if (currentPage > 1) {
                fetchAndRenderHistory(currentPage - 1);
            }
        });

        historyNextBtn.addEventListener('click', () => {
            fetchAndRenderHistory(currentPage + 1);
        });

        scanButton.addEventListener('click', async () => {
            const selectedOption = credentialSelect.options[credentialSelect.selectedIndex];
            const selectedProfileId = selectedOption.value;
            const selectedProvider = selectedOption.dataset.provider;

            if (!selectedProfileId) {
                Toastify({ text: "Please select a credential profile.", duration: 3000, gravity: "bottom", position: "right", style: { background: "linear-gradient(to right, #F5A623, #e67e22)" } }).showToast();
                return;
            }

            const selectedRegions = Array.from(regionSelect.selectedOptions).map(option => option.value);
            if (selectedRegions.length === 0) {
                Toastify({ text: "Please select at least one region to scan.", duration: 3000, gravity: "bottom", position: "right", style: { background: "linear-gradient(to right, #F5A623, #e67e22)" } }).showToast();
                return;
            }
            const regionsParam = selectedRegions.includes('all') ? '' : selectedRegions.map(region => `regions=${region}`).join('&');

            const isProgressMode = progressModeToggle.checked;
            const originalButtonHtml = scanButton.innerHTML;
            scanButton.disabled = true;
            scanButton.innerHTML = `<i class="fas fa-spinner fa-spin"></i> Scanning...`;
            resultsList.innerHTML = '';
            scanConsoleWrapper.style.display = 'block';
            scanConsole.innerHTML = '';

            const handleFinalResults = (scanData) => {
                const results = scanData.results;
                renderResults(resultsList, results);
                updateDashboardCharts(results);
                updateRemediationPanel(results);
                fetchAndRenderHistory();
                renderTrendChart();
            };
            
            const url = `${SCAN_API_URL}?profile_id=${selectedProfileId}&provider=${selectedProvider}&progress_mode=${isProgressMode}&${regionsParam}`;
            
            // DEBUG: Log the exact API URL being called
            console.log("DEBUG: Initiating scan with URL:", url);

            if (isProgressMode) {
                eventSource = new EventSource(url);

                eventSource.onmessage = function(event) {
                    const data = JSON.parse(event.data);

                    // DEBUG: Log every message received from the server in progress mode
                    console.log("DEBUG: SSE data received:", data);

                    if (data.status === 'progress' || data.status === 'error') {
                        const color = data.status === 'error' ? 'var(--danger-color)' : 'var(--primary-color)';
                        scanConsole.innerHTML += `<div class="scan-step" style="color: ${color};">${data.message}</div>`;
                        scanConsole.scrollTop = scanConsole.scrollHeight;
                    }

                    if (data.status === 'complete') {
                        scanConsole.innerHTML += `<div class="scan-step" style="color: var(--success-color);">Scan Complete.</div>`;
                        Toastify({ text: "Scan complete!", duration: 3000, gravity: "bottom", position: "right", style: { background: "linear-gradient(to right, #2ECC71, #27ae60)" } }).showToast();
                        handleFinalResults(data);
                        eventSource.close();
                        scanButton.disabled = false;
                        scanButton.innerHTML = originalButtonHtml;
                        setTimeout(() => { scanConsoleWrapper.style.display = 'none'; }, 8000);
                    }
                };

                eventSource.onerror = function() {
                    scanConsole.innerHTML += `<div class="scan-step" style="color: var(--danger-color);">ERROR: Connection to scan server lost.</div>`;
                    Toastify({ text: "Error during scan.", duration: 4000, gravity: "bottom", position: "right", style: { background: "linear-gradient(to right, #D0021B, #e74c3c)" } }).showToast();
                    eventSource.close();
                    scanButton.disabled = false;
                    scanButton.innerHTML = originalButtonHtml;
                };
            } else {
                scanConsole.innerHTML += `<div class="scan-step">Running in standard mode. Please wait...</div>`;
                try {
                    const response = await fetch(url);
                    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
                    const data = await response.json();
                    
                    // DEBUG: Log the complete JSON response in blocking mode
                    console.log("DEBUG: Full scan response received:", data);

                    scanConsole.innerHTML += '<div class="scan-step" style="color: var(--success-color);">Scan Complete.</div>';
                    Toastify({ text: "Scan complete!", duration: 3000, gravity: "bottom", position: "right", style: { background: "linear-gradient(to right, #2ECC71, #27ae60)" } }).showToast();
                    
                    handleFinalResults(data);

                } catch (error) {
                    scanConsole.innerHTML += `<div class="scan-step" style="color: var(--danger-color);">ERROR: Scan failed. ${error.message}</div>`;
                    Toastify({ text: `Error during scan: ${error.message}`, duration: 4000, gravity: "bottom", position: "right", style: { background: "linear-gradient(to right, #D0021B, #e74c3c)" } }).showToast();
                } finally {
                    scanButton.disabled = false;
                    scanButton.innerHTML = originalButtonHtml;
                    setTimeout(() => { scanConsoleWrapper.style.display = 'none'; }, 8000);
                }
            }
        });

        deleteHistoryButton.addEventListener('click', async () => {
            if (confirm("Are you sure you want to delete all your historical scan results? This cannot be undone.")) {
                await fetch(DELETE_HISTORY_API_URL, { 
                    method: 'POST',
                    headers: {
                        'X-CSRF-Token': csrfToken
                    }
                });
                Toastify({ text: "Historical data deleted.", duration: 3000, gravity: "bottom", position: "right", style: { background: "linear-gradient(to right, #4A90E2, #357ABD)" } }).showToast();
                fetchAndRenderHistory();
                renderTrendChart();
            }
        });

        const applyFilters = (listElement, searchInput, statusFilter) => {
            const searchTerm = searchInput.value.toLowerCase();
            const status = statusFilter.value;
            listElement.querySelectorAll('.result-item').forEach(item => {
                const textContent = item.textContent.toLowerCase();
                const itemStatus = item.classList.contains('critical') ? 'critical' :
                                   item.classList.contains('warning') ? 'warning' :
                                   item.classList.contains('ok') ? 'ok' : '';
                
                const textMatch = textContent.includes(searchTerm);
                const statusMatch = (status === 'all') || (itemStatus === status);

                if (textMatch && statusMatch) {
                    item.style.display = 'block';
                } else {
                    item.style.display = 'none';
                }
            });
        };

        currentSearchInput.addEventListener('keyup', () => applyFilters(resultsList, currentSearchInput, currentStatusFilter));
        currentStatusFilter.addEventListener('change', () => applyFilters(resultsList, currentSearchInput, currentStatusFilter));
        historySearchInput.addEventListener('keyup', () => applyFilters(historyList, historySearchInput, historyStatusFilter));
        historyStatusFilter.addEventListener('change', () => applyFilters(historyList, historySearchInput, historyStatusFilter));
        
        fetchAndRenderHistory();
        renderTrendChart();
    };

    const initAdminPage = () => {
        const addTableFilter = (inputId, tableId) => {
            const searchInput = document.getElementById(inputId);
            const table = document.getElementById(tableId);
            if (searchInput && table) {
                searchInput.addEventListener('keyup', () => {
                    const searchTerm = searchInput.value.toLowerCase();
                    const rows = table.tBodies[0].rows;
                    for (const row of rows) {
                        row.style.display = row.textContent.toLowerCase().includes(searchTerm) ? '' : 'none';
                    }
                });
            }
        };
        addTableFilter('userSearch', 'userTable');
        addTableFilter('scanSearch', 'scanTable');
        addTableFilter('logSearch', 'logTable');
    };

    const initSettingsPage = () => {
        const suppressedTable = document.getElementById('suppressedFindingsTable');
        if (suppressedTable) {
            suppressedTable.addEventListener('click', async (e) => {
                if (e.target && e.target.closest('.unsuppress-btn')) {
                    const button = e.target.closest('.unsuppress-btn');
                    const suppressionId = button.dataset.suppressionId;
                    const row = button.closest('tr');

                    if (confirm('Are you sure you want to un-suppress this finding? It will reappear in future scans.')) {
                        try {
                            const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
                            const response = await fetch(`/api/v1/unsuppress_finding/${suppressionId}`, {
                                method: 'POST',
                                headers: {
                                    'X-CSRF-Token': csrfToken
                                }
                            });

                            if (!response.ok) {
                                const errorData = await response.json();
                                throw new Error(errorData.error || 'Failed to un-suppress finding.');
                            }

                            const data = await response.json();
                            Toastify({ text: data.message, duration: 3000, gravity: "bottom", position: "right", style: { background: "linear-gradient(to right, #2ECC71, #27ae60)" } }).showToast();
                            row.style.display = 'none';
                        } catch (error) {
                            Toastify({ text: error.message, duration: 4000, gravity: "bottom", position: "right", style: { background: "linear-gradient(to right, #D0021B, #e74c3c)" } }).showToast();
                        }
                    }
                }
            });
        }
        
        const providerSelect = document.getElementById('providerSelect');
        if (providerSelect) {
            const awsFields = document.getElementById('awsFields');
            const gcpFields = document.getElementById('gcpFields');
            const awsInputs = awsFields.querySelectorAll('input');
            const gcpInputs = gcpFields.querySelectorAll('textarea');

            const toggleFields = () => {
                if (providerSelect.value === 'aws') {
                    awsFields.style.display = 'block';
                    gcpFields.style.display = 'none';
                    awsInputs.forEach(input => input.required = true);
                    gcpInputs.forEach(input => input.required = false);
                } else if (providerSelect.value === 'gcp') {
                    awsFields.style.display = 'none';
                    gcpFields.style.display = 'block';
                    awsInputs.forEach(input => input.required = false);
                    gcpInputs.forEach(input => input.required = true);
                }
            };

            providerSelect.addEventListener('change', toggleFields);
            toggleFields();
        }
    };

    // Initialize all page-specific scripts
    initPasswordStrengthMeter();
    initThemeSwitcher();
    if (document.getElementById('showLogin')) { initAuthPage(); }
    if (document.getElementById('scanButton')) { initDashboardPage(); }
    if (document.getElementById('adminDashboardPage')) { initAdminPage(); }
    if (document.getElementById('providerSelect')) { initSettingsPage(); }
=======
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
>>>>>>> 89c69e853c15feb701d5ba7706fb273163f870d1
});