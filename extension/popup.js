// Use the Live Tunnel URL for now, can be swapped for Render URL
const API_URL = "http://127.0.0.1:5000";
// const API_URL = "https://redirect-detector.onrender.com"; // Production URL

document.addEventListener('DOMContentLoaded', async () => {
    // Get current tab URL
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (tab && tab.url) {
        document.getElementById('targetUrl').textContent = tab.url;
    }

    document.getElementById('analyzeBtn').addEventListener('click', () => {
        analyzeUrl(tab.url);
    });
});

async function analyzeUrl(url) {
    const btn = document.getElementById('analyzeBtn');
    const loading = document.getElementById('loading');
    const results = document.getElementById('results');
    const errorCard = document.getElementById('errorCard');
    const chainList = document.getElementById('chainList');

    // Reset UI
    btn.classList.add('hidden');
    results.classList.add('hidden');
    errorCard.classList.add('hidden');
    loading.classList.remove('hidden');
    chainList.innerHTML = '';

    try {
        const response = await fetch(`${API_URL}/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) throw new Error('Network response was not ok');

        const data = await response.json();

        // Render Redirect Chain
        if (data.redirect_chain && data.redirect_chain.length > 0) {
            data.redirect_chain.forEach(hop => {
                const li = document.createElement('li');
                li.className = 'chain-item';
                li.innerHTML = `
                    <div style="display:flex; align-items:center;">
                        <span class="status-code">${hop.status}</span>
                        <span class="url-truncate" title="${hop.url}">${hop.url}</span>
                    </div>
                `;
                chainList.appendChild(li);
            });
        } else {
            chainList.innerHTML = '<li class="chain-item">No redirects found.</li>';
        }

        loading.classList.add('hidden');
        results.classList.remove('hidden');

    } catch (error) {
        loading.classList.add('hidden');
        results.classList.remove('hidden');
        errorCard.textContent = `Error: ${error.message}. Is the server running?`;
        errorCard.classList.remove('hidden');
        btn.classList.remove('hidden'); // allow retry
    }
}
