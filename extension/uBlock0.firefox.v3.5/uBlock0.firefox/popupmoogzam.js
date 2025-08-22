let currentTabID = null;

async function getCurrentTab() {
    try {
        const urlParams = new URLSearchParams(window.location.search);
        const tabIdParam = urlParams.get('tabId');
        const hostnameParam = urlParams.get('hostname');

        if (tabIdParam) {
            const tabId = parseInt(tabIdParam);
            if (!isNaN(tabId)) {
                return {
                    id: tabId,
                    url: hostnameParam ? decodeURIComponent(hostnameParam) : 'unknown',
                    hostname: hostnameParam ? decodeURIComponent(hostnameParam) : 'unknown'
                };
            }
        }
    } catch (error) {
        console.error('getCurrentTab error: ', error);
        throw error;
    }
}

function formatValue(value) {
    if (value === null || value === undefined) {
        return '<span class="value">—</span>';
    }

    if (typeof value === 'number') {
        return `<span class="value number">${value.toLocaleString()}</span>`;
    }

    if (typeof value === 'string') {
        if (value.startsWith('http://') || value.startsWith('https://')) {
            return `<span class="value url">${value}</span>`;
        }
        return `<span class="value">${value}</span>`;
    }

    return `<span class="value">${String(value)}</span>`;
}

function showError(message) {
    const container = document.getElementById('result');
    const div = document.createElement('div');
    div.className = 'error';
    div.textContent = message;
    container.innerHTML = '';
    container.appendChild(div);
}

function showLoading() {
    const container = document.getElementById('result');
    container.innerHTML = `
        <div class="loading">
            <div id="loading-text" class="loading-text">Analyzing page...</div>
            <div class="loading-animation">
                <div class="scanning-line"></div>
                <div class="pulse-dots">
                    <div class="pulse-dot"></div>
                    <div class="pulse-dot"></div>
                    <div class="pulse-dot"></div>
                    <div class="pulse-dot"></div>
                    <div class="pulse-dot"></div>
                </div>
            </div>
        </div>
    `;
}

function updateLoadingText(newText) {
    const loadingText = document.getElementById('loading-text');
    if (loadingText) {
        loadingText.textContent = newText;
    }
}

function displayResultsData(results) {
    const container = document.getElementById('result');

    if (!results || Object.keys(results).length === 0) {
        container.innerHTML = '<div class="no-data">No analysis data available.</div>';
        return;
    }

    const resultData = results.result || results;
    //const timestamps = results.timestamps || {};
    const executionTimes = results.executionTimes || {};

    let processingTime = '—';

    if (executionTimes.end && executionTimes.begin) {
        processingTime = ((executionTimes.end - executionTimes.begin) / 1000).toFixed(3) + 's';
    }

    let html = '';

    html += `<div class="section">
                 <div class="section-title">Page Information</div>
                 <div class="item">
                    <div class="key">URL:</div>
                    ${formatValue(results.url || 'Unknown')}
                 </div>
                 <div class="item">
                    <div class="key">Process Time:</div>
                    <span class="value number">${processingTime}</span>
                 </div>
                 <div class="item">
                    <div class="key">Analysis:</div>
                    <span class="value status-complete">Complete</span>
                 </div>
             </div>`;

    html += `<div class="section">
                <div class="section-title">Results</div>`;

    if (resultData && typeof resultData === 'object') {
        for (const [key, value] of Object.entries(resultData)) {
            if (['timestamps', 'executionTimes', 'url'].includes(key)) continue;

            html += `<div class="item">
                         <div class="key">${key}:</div>
                         ${formatValue(value)}
                     </div>`;
        }
    } else {
        html += '<div class="item"><div class="key">No analysis data available</div></div>';
    }

    html += '</div>';
    container.innerHTML = html;
}

function handleResultsMessage(response, onSuccess) {
    if (!response) {
        showError('No response received from UBE system');
        return;
    }

    if (response.error) {
        showError(response.error);
        return;
    }

    if (response.processing) {
        return;
    }

    if (!response.result && !response.tabId) {
        showError('No UBE analysis results available for this tab');
        return;
    }

    updateLoadingText('Fetching results...');
    setTimeout(() => {
        onSuccess(response);
    }, 750);
}

async function displayResults() {
    try {
        showLoading();

        const currentTab = await getCurrentTab();

        if (!currentTab?.id) {
            showError('Could not get current tab information');
            return;
        }

        currentTabID = currentTab.id;

        browser.runtime.sendMessage({
            what: 'getCheckResult',
            source: 'ubePopup',
            tabId: currentTab.id,
            url: currentTab.url
        }, (response) => {
            if (browser.runtime.lastError) {
                showError(`Communication error: ${browser.runtime.lastError.message}`);
                return;
            }

            if (response?.source === 'ubeBackgroundScript') {
                handleResultsMessage(response, (response) => {
                    displayResultsData(response.result);
                });
            }
        });

    } catch (error) {
        console.error('Unexpected error in popup: ', error);
        showError(`Unexpected error: ${error.message}`);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    document.title = 'UBE Analysis (uBlock Origin)';
    displayResults();

    const downloadBtn = document.getElementById('downloadCsvBtn');
    if (downloadBtn) {
        downloadBtn.addEventListener('click', () => {
            browser.runtime.sendMessage({
                what: 'exportCSV',
                source: 'ubePopup'});
        });
    }
});

if (browser.runtime) {
    browser.runtime.onMessage.addListener((message) => {
        if (message && message.source === 'ubeBackgroundScript' && message.what === 'analysisComplete' && message.tabId === currentTabID) {
            handleResultsMessage(message, (message) => {
                displayResultsData(message.result || message);
            });
        }
    });
}