// Invisible Redirect Protector - Content Script

const API_URL = "https://invisible-redirect-detector.onrender.com/analyze";
// Note: User can change this to http://localhost:8080/analyze for local testing

// logic to inject the badge
function createBadge() {
    const badge = document.createElement('div');
    badge.id = 'ir-protector-badge';
    badge.innerHTML = `
        <div class="ir-shield logging">
            <span class="ir-icon">🛡️</span>
            <span class="ir-status">Scanning...</span>
        </div>
        <div id="ir-popup" class="ir-hidden">
            <h3 id="ir-title">Analyzing Site...</h3>
            <ul id="ir-summary"></ul>
            <a href="https://invisible-redirect-detector.onrender.com" target="_blank" class="ir-btn">View Full Report</a>
        </div>
    `;
    document.body.appendChild(badge);

    // Toggle popup on click
    badge.querySelector('.ir-shield').addEventListener('click', () => {
        const popup = document.getElementById('ir-popup');
        if (popup.classList.contains('ir-hidden')) {
            popup.classList.remove('ir-hidden');
        } else {
            popup.classList.add('ir-hidden');
        }
    });

    return badge;
}

// Logic to analyze current page
async function analyzePage() {
    const currentUrl = window.location.href;
    const badge = createBadge();
    const shield = badge.querySelector('.ir-shield');
    const statusText = badge.querySelector('.ir-status');
    const title = document.getElementById('ir-title');
    const summaryList = document.getElementById('ir-summary');

    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: currentUrl })
        });

        const data = await response.json();

        // Update UI based on Risk
        const score = data.security_scan ? data.security_scan.risk_score : 100;
        const simpleSummary = data.simple_analysis ? data.simple_analysis.summary : [];
        const isPhishing = data.simple_analysis && data.simple_analysis.phishing_verdict === 'High';

        shield.classList.remove('logging');

        if (isPhishing || score < 50) {
            shield.classList.add('danger');
            statusText.textContent = "High Risk";
            title.textContent = "🚨 Unsafe Site Detected";
            title.style.color = "#ef4444";
        } else if (score < 80) {
            shield.classList.add('warning');
            statusText.textContent = "Caution";
            title.textContent = "⚠️ Potential Risks";
            title.style.color = "#f59e0b";
        } else {
            shield.classList.add('safe');
            statusText.textContent = "Safe";
            title.textContent = "✅ Site is Secure";
            title.style.color = "#10b981";
        }

        // Populate summary
        summaryList.innerHTML = '';
        if (simpleSummary.length > 0) {
            simpleSummary.forEach(item => {
                const li = document.createElement('li');
                li.textContent = item;
                summaryList.appendChild(li);
            });
        } else {
            summaryList.innerHTML = '<li>No specific issues found.</li>';
        }

    } catch (error) {
        console.error("IR Protector Error:", error);
        shield.classList.add('error');
        statusText.textContent = "Error";
        title.textContent = "Scan Failed";
        summaryList.innerHTML = '<li>Could not connect to analysis server.</li>';
    }
}

// Run on load
analyzePage();
