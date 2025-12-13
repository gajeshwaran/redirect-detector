document.getElementById('analyzeBtn').addEventListener('click', async () => {
    const urlInput = document.getElementById('urlInput');
    const url = urlInput.value.trim();

    if (!url) {
        alert('Please enter a URL');
        return;
    }

    // Reset UI
    document.getElementById('results').classList.add('hidden');
    document.getElementById('loading').classList.remove('hidden');
    document.getElementById('analyzeBtn').disabled = true;

    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Analysis failed');
        }

        displayResults(data, url);

    } catch (error) {
        alert('Error: ' + error.message);
    } finally {
        document.getElementById('loading').classList.add('hidden');
        document.getElementById('analyzeBtn').disabled = false;
    }
});

function displayResults(data, originalInput) {
    const results = document.getElementById('results');
    results.classList.remove('hidden');

    // 1. Final Destination
    const finalUrlEl = document.getElementById('finalUrl');
    finalUrlEl.textContent = data.final_url;

    const warningBadge = document.getElementById('destinationWarning');
    // Simple check if domain changed or path changed significantly
    if (data.final_url !== originalInput && !data.final_url.includes(originalInput.replace('http://', '').replace('https://', ''))) {
        warningBadge.classList.remove('hidden');
    } else {
        warningBadge.classList.add('hidden');
    }

    const openLinkBtn = document.getElementById('openLinkBtn');
    openLinkBtn.href = data.final_url;

    // 2. Redirect Chain
    const redirectList = document.getElementById('redirectList');
    redirectList.innerHTML = '';
    data.redirect_chain.forEach((hop, index) => {
        const li = document.createElement('li');
        li.innerHTML = `<strong>Step ${index + 1}:</strong> ${hop.status} <br> <span style="color: #94a3b8; font-size: 0.9em;">${hop.url}</span>`;
        redirectList.appendChild(li);
    });

    // 3. Hidden Iframes
    const iframeList = document.getElementById('iframeList');
    const noIframes = document.getElementById('noIframes');
    iframeList.innerHTML = '';

    if (data.hidden_iframes && data.hidden_iframes.length > 0) {
        noIframes.classList.add('hidden');
        data.hidden_iframes.forEach(iframe => {
            const li = document.createElement('li');
            li.className = 'risk-high';
            li.innerHTML = `<strong>Source:</strong> ${iframe.src || 'Unknown'} <br> <strong>Risk Factors:</strong> ${iframe.risks.join(', ')}`;
            iframeList.appendChild(li);
        });
    } else {
        noIframes.classList.remove('hidden');
    }

    // 4. Clickjacking
    const clickjackingList = document.getElementById('clickjackingList');
    const noClickjacking = document.getElementById('noClickjacking');
    clickjackingList.innerHTML = '';

    if (data.clickjacking_risks && data.clickjacking_risks.length > 0) {
        noClickjacking.classList.add('hidden');
        data.clickjacking_risks.forEach(item => {
            const li = document.createElement('li');
            li.className = 'risk-high';
            li.innerHTML = `<strong>Element:</strong> &lt;${item.tag}&gt; <br> <strong>Issue:</strong> ${item.message} (Z-Index: ${item.zIndex}, Opacity: ${item.opacity})`;
            clickjackingList.appendChild(li);
        });
    } else {
        noClickjacking.classList.remove('hidden');
    }

    // 5. Form Risks
    const formList = document.getElementById('formList');
    const noForms = document.getElementById('noForms');
    formList.innerHTML = '';

    if (data.form_risks && data.form_risks.length > 0) {
        noForms.classList.add('hidden');
        data.form_risks.forEach(form => {
            const li = document.createElement('li');
            li.className = 'risk-high';
            li.innerHTML = `<strong>Action:</strong> ${form.action} <br> <strong>Warning:</strong> ${form.warning}`;
            formList.appendChild(li);
        });
    } else {
        noForms.classList.remove('hidden');
    }

    // 6. Deep Scan Results
    const deepScanTable = document.getElementById('deepScanTable');
    const deepScanBody = document.getElementById('deepScanBody');
    const noLinks = document.getElementById('noLinks');
    deepScanBody.innerHTML = '';

    if (data.deep_scan_results && data.deep_scan_results.length > 0) {
        deepScanTable.classList.remove('hidden');
        noLinks.classList.add('hidden');

        data.deep_scan_results.forEach(item => {
            const tr = document.createElement('tr');

            // Format chain
            let chainHtml = '';
            if (item.error) {
                chainHtml = `<span style="color: var(--danger)">Failed: ${item.error}</span>`;
            } else {
                chainHtml = `<div style="font-family: monospace; font-size: 0.85em;">`;
                chainHtml += `Start: ${item.original_url}<br>`;
                item.chain.forEach(hop => {
                    if (hop.url !== item.original_url) {
                        chainHtml += `↓ ${hop.status}<br>${hop.url}<br>`;
                    }
                });
                chainHtml += `</div>`;
            }

            // Verdict
            let verdictHtml = '';
            if (item.error) {
                verdictHtml = `<span class="badge badge-risk">Error</span>`;
            } else if (item.redirected) {
                verdictHtml = `<span class="badge badge-risk">Redirects</span>`;
            } else {
                verdictHtml = `<span class="badge badge-safe">Direct</span>`;
            }

            tr.innerHTML = `
                <td><strong>${item.original_text || 'Link'}</strong></td>
                <td>${chainHtml}</td>
                <td>${verdictHtml}</td>
            `;
            deepScanBody.appendChild(tr);
        });
    } else {
        deepScanTable.classList.add('hidden');
        noLinks.classList.remove('hidden');
    }
}
