import os
import logging
import re
import socket
import ssl
import datetime
import requests
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify
from playwright.sync_api import sync_playwright
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes
logging.basicConfig(level=logging.INFO)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    browser = None
    try:
        with sync_playwright() as p:
            # Launch browser with security sandbox disabled for container environments
            browser_type = p.chromium
            browser = browser_type.launch(headless=True, args=['--no-sandbox', '--disable-setuid-sandbox'])
            
            # Create a context that mimics a real user
            context = browser.new_context(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                viewport={'width': 1280, 'height': 720},
                ignore_https_errors=True
            )
            page = context.new_page()

            # --- 1. Network & Resource Logging ---
            network_activity = []
            external_domains = set()
            page_netloc = urlparse(url).netloc

            def handle_request(request):
                try:
                    # Log request details
                    network_activity.append({
                        'url': request.url[:150],  # Truncate long URLs
                        'method': request.method,
                        'resourceType': request.resource_type
                    })
                    
                    # Identify external domains (potential trackers or C2)
                    req_netloc = urlparse(request.url).netloc
                    if req_netloc and req_netloc != page_netloc and not req_netloc.endswith('.' + page_netloc):
                        external_domains.add(req_netloc)
                except Exception:
                    pass

            page.on("request", handle_request)

            # --- 2. Navigation & Redirects ---
            full_chain = []
            final_url = url
            
            try:
                logging.info(f"Navigating to {url}")
                response = page.goto(url, wait_until='networkidle', timeout=60000)
                final_url = page.url
                
                # Reconstruct the redirect chain
                request_chain = []
                if response:
                    current_request = response.request
                    while current_request:
                        redirect_origin = current_request.redirected_from
                        if redirect_origin:
                            status = 'Redirect'
                            # Try to get status from the response if possible, but redirect responses are often internal
                            request_chain.insert(0, {
                                'url': redirect_origin.url,
                                'status': status
                            })
                            current_request = redirect_origin
                        else:
                            break
                    
                    status_code = response.status
                    full_chain = request_chain + [{'url': final_url, 'status': status_code}]
                else:
                    full_chain = [{'url': url, 'status': 'No Response'}]

            except Exception as e:
                logging.error(f"Navigation error: {e}")
                return jsonify({'error': f'Failed to load page: {str(e)}'}), 500

            # --- 3. Content Security & Pattern Analysis ---
            # Scan the HTML content for suspicious keywords
            try:
                page_content = page.content()
                suspicious_patterns = []
                
                patterns = {
                    'Dangerous eval()': r'eval\(',
                    'Document Write': r'document\.write\(',
                    'VBScript': r'vbscript',
                    'Base64 Decode': r'atob\(',
                    'Cryptomining': r'Crypto|miner|coinhive',
                    'Anti-Frame (Clickjacking Protection)': r'X-Frame-Options'
                }
                
                for name, regex in patterns.items():
                    if re.search(regex, page_content, re.IGNORECASE):
                        suspicious_patterns.append(name)
            except Exception as e:
                logging.error(f"Content analysis error: {e}")
                suspicious_patterns = []

            # --- 4. DOM Analysis (Iframes, Clickjacking, Storage) ---
            try:
                dom_analysis = page.evaluate('''() => {
                    const hidden_iframes = [];
                    const risky_click_elements = [];
                    const risky_forms = [];
                    
                    // Storage Analysis
                    const storageUsage = {
                        localStorageEntries: Object.keys(localStorage).length,
                        sessionStorageEntries: Object.keys(sessionStorage).length,
                        cookiesCount: document.cookie.split(';').filter(c => c.trim()).length
                    };

                    // Iframe Analysis
                    document.querySelectorAll('iframe').forEach(iframe => {
                        const style = window.getComputedStyle(iframe);
                        const rect = iframe.getBoundingClientRect();
                        let risk = [];
                        
                        // Check for hidden or tiny iframes
                        if (style.opacity === '0') risk.push('Opacity 0');
                        if (style.visibility === 'hidden') risk.push('Hidden Visibility');
                        if (style.display === 'none') risk.push('Display None');
                        if (rect.width < 5 || rect.height < 5) risk.push('Tiny dimensions');
                        if (rect.left < -100 || rect.top < -100) risk.push('Positioned Off-screen');
                        
                        if (risk.length > 0) {
                            hidden_iframes.push({
                                src: iframe.src || 'about:blank',
                                risks: risk
                            });
                        }
                    });

                    // Clickjacking / Overlay Analysis
                    const allElements = document.querySelectorAll('div, span, a, button, img');
                    allElements.forEach(el => {
                        const style = window.getComputedStyle(el);
                        const zIndex = parseInt(style.zIndex, 10);
                        
                        // High Z-Index elements
                        if (!isNaN(zIndex) && zIndex > 50) {
                            const rect = el.getBoundingClientRect();
                            const opacity = parseFloat(style.opacity);
                            
                            // Large area, clickable, but invisible/transparent
                            if (rect.width > 50 && rect.height > 50 && style.pointerEvents !== 'none') {
                                if (opacity < 0.1 || (style.backgroundColor.includes('rgba') && style.backgroundColor.includes(', 0)'))) {
                                    risky_click_elements.push({
                                        tag: el.tagName,
                                        zIndex: zIndex,
                                        message: "Invisible high z-index overlay detected"
                                    });
                                }
                            }
                        }
                    });

                    // Form Analysis
                    document.querySelectorAll('form').forEach(form => {
                        const action = form.action;
                        if (action && !action.startsWith(window.location.origin) && action.startsWith('http')) {
                            risky_forms.push({
                                action: action,
                                method: form.method || 'GET',
                                warning: "Submits data to external domain"
                            });
                        }
                    });

                    const links = Array.from(document.querySelectorAll('a'))
                        .map(a => ({
                            text: a.innerText.slice(0, 50).trim() || 'Image/Icon',
                            href: a.href
                        }))
                        .filter(l => l.href.startsWith('http'));

                    return {
                        iframes: hidden_iframes,
                        clickjacking: risky_click_elements,
                        forms: risky_forms,
                        links: links,
                        storage: storageUsage
                    };
                }''')
            except Exception as e:
                logging.error(f"DOM Evaluation error: {e}")
                dom_analysis = {'iframes': [], 'clickjacking': [], 'forms': [], 'links': [], 'storage': {}}

            # --- 5. Screenshot & Visuals ---
            screenshot_b64 = None
            try:
                # Capture full page or viewport screenshot
                import base64
                screenshot_bytes = page.screenshot(type='jpeg', quality=60, full_page=False)
                screenshot_b64 = base64.b64encode(screenshot_bytes).decode('utf-8')
            except Exception as e:
                logging.error(f"Screenshot error: {e}")

            # --- 6. Security Header Analysis ---
            security_headers = {}
            score = 100
            risk_factors = []
            
            if response:
                headers = response.headers
                
                # Check for key security headers
                checks = {
                    'Strict-Transport-Security': 'HSTS (Prevents downgrade attacks)',
                    'Content-Security-Policy': 'CSP (Mitigates XSS/Injection)',
                    'X-Frame-Options': 'Clickjacking Protection',
                    'X-Content-Type-Options': 'MIME Sniffing Protection',
                    'Referrer-Policy': 'Referrer Leakage Control'
                }
                
                for header, desc in checks.items():
                    # Playwright headers are lowercase
                    val = headers.get(header.lower())
                    if val:
                        security_headers[header] = {'present': True, 'value': val[:50] + '...', 'desc': desc}
                    else:
                        security_headers[header] = {'present': False, 'value': 'Missing', 'desc': desc}
                        score -= 10 # Deduct score for missing headers

            # Calculate Risk Verdict
            if dom_analysis['iframes']: score -= 20
            if dom_analysis['clickjacking']: score -= 30
            if dom_analysis['forms']: score -= 10
            if suspicious_patterns: score -= 20
            if len(external_domains) > 5: score -= 10
            
            if score < 0: score = 0
            
            verdict = "Low Risk"
            if score < 70: verdict = "Medium Risk"
            if score < 40: verdict = "High Risk"

            # --- 7. Deep Link Scan (Top 5) ---
            deep_link_results = []
            unique_links = {l['href']: l['text'] for l in dom_analysis['links']}
            target_links = list(unique_links.items())[:5] # Scan top 5
            
            for link_url, link_text in target_links:
                sub_page = None
                try:
                    sub_page = context.new_page()
                    # Short timeout for deep links
                    try:
                        sub_response = sub_page.goto(link_url, wait_until='domcontentloaded', timeout=15000)
                        sub_final_url = sub_page.url
                        
                        is_redirect = (link_url != sub_final_url) and (link_url + '/' != sub_final_url)
                        
                        deep_link_results.append({
                            'original_text': link_text,
                            'original_url': link_url,
                            'final_url': sub_final_url,
                            'redirected': is_redirect
                        })
                    except Exception:
                        deep_link_results.append({
                            'original_text': link_text,
                            'original_url': link_url,
                            'error': "Connection Failed/Timeout"
                        })
                except Exception:
                    pass
                finally:
                    if sub_page:
                        sub_page.close()

            # --- 8. Threat Intelligence (Global Blacklist) ---
            threat_report = check_threat_intel(final_url)
            
            # --- 9. Server & SSL Intelligence ---
            server_info = {}
            try:
                domain = urlparse(final_url).netloc
                if ':' in domain: domain = domain.split(':')[0]
                
                ip_addr = socket.gethostbyname(domain)
                geo_info = "Unknown"
                try:
                    r = requests.get(f"http://ip-api.com/json/{ip_addr}?fields=country,isp,org", timeout=3)
                    if r.status_code == 200:
                        d = r.json()
                        geo_info = f"{d.get('country', 'Unknown')} - {d.get('isp', 'Unknown')}"
                except:
                    pass

                ssl_info = "No SSL"
                if final_url.startswith('https'):
                    try:
                        ctx = ssl.create_default_context()
                        with socket.create_connection((domain, 443), timeout=3) as sock:
                            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                                cert = ssock.getpeercert()
                                subject = dict(x[0] for x in cert['subject'])
                                issuer = dict(x[0] for x in cert['issuer'])
                                not_after = cert['notAfter']
                                ssl_info = {
                                    'issuer': issuer.get('organizationName', 'Unknown Issuer'),
                                    'subject': subject.get('commonName', domain),
                                    'expiry': not_after
                                }
                    except Exception as e:
                        ssl_info = f"SSL Error: {str(e)[:50]}"

                server_info = {'ip': ip_addr, 'location': geo_info, 'ssl': ssl_info}

            except Exception as e:
                logging.error(f"Server info error: {e}")
                server_info = {'error': str(e)}

            # --- 9. User-Friendly Intelligence (Phishing & Summary) ---
            simplified_summary = []
            phishing_score = 0
            
            # Simple Summary Checks
            if final_url.startswith('https'):
                simplified_summary.append("✅ Connection is secure (HTTPS).")
            else:
                simplified_summary.append("❌ Connection is NOT secure (Unencrypted HTTP).")
                phishing_score += 20

            if len(dom_analysis['iframes']) > 0:
                simplified_summary.append(f"⚠️ Found {len(dom_analysis['iframes'])} hidden iframes (invisible boxes).")
            
            if len(dom_analysis['clickjacking']) > 0:
                simplified_summary.append("⛔ DANGER: Invisible buttons found (Clickjacking risk).")
                phishing_score += 50
            
            if len(full_chain) > 1:
                simplified_summary.append(f"➡️ Site redirected you {len(full_chain)-1} times.")

            # Phishing Heuristics
            suspicious_keywords = ['login', 'verify', 'update', 'secure', 'account', 'banking', 'wallet', 'confirm', 'signin']
            url_lower = final_url.lower()
            found_keywords = [kw for kw in suspicious_keywords if kw in url_lower]
            
            if found_keywords:
                simplified_summary.append(f"⚠️ URL contains suspicious words: {', '.join(found_keywords)}.")
                phishing_score += 40  # INCREASED from 15

            # High Risk TLDs
            risky_tlds = ['.xyz', '.top', '.gq', '.tk', '.ml', '.cf', '.cn', '.ru']
            if any(url_lower.endswith(tld) or url_lower.endswith(tld+'/') for tld in risky_tlds):
                 simplified_summary.append("⚠️ Domain uses a high-risk TLD often used by scammers.")
                 phishing_score += 25

            # Fake urgency in content
            urgency_words = ['immediate', 'suspended', 'lock', '24 hours', 'urgent', 'action required']
            try:
                content_lower = page_content.lower()
                for w in urgency_words:
                    if w in content_lower:
                        phishing_score += 10
            except: pass

            # Threat Intel Penalty
            if threat_report['malicious']:
                phishing_score += 100 # Maximum penalty
                simplified_summary.insert(0, f"⛔ CRITICAL: Detected in Global Blacklist (Malware/Phishing). Tags: {', '.join(threat_report['tags'])}")
            else:
                simplified_summary.append("✅ Not found in Global Threat Databases.")

            # Calculate Final Score
            risk_score = max(0, 100 - phishing_score)
            
            verdict = "Safe"
            if risk_score < 80: verdict = "Suspicious"
            if risk_score < 50: verdict = "High Risk"
            if threat_report['malicious']: verdict = "CRITICAL THREAT"

            browser.close()

            return jsonify({
                'final_url': final_url,
                'redirect_chain': full_chain,
                'hidden_iframes': dom_analysis['iframes'],
                'clickjacking_risks': dom_analysis['clickjacking'],
                'form_risks': dom_analysis['forms'],
                'deep_scan_results': deep_link_results,
                'network_summary': {
                    'total_requests': len(network_activity),
                    'external_domains': list(external_domains)[:15],
                    'types': [req['resourceType'] for req in network_activity[:50]]
                },
                'security_scan': {
                    'risk_score': risk_score,
                    'verdict': verdict,
                    'suspicious_patterns': suspicious_patterns,
                    'storage_usage': dom_analysis.get('storage', {}),
                    'headers': security_headers,
                    'screenshot': screenshot_b64,
                    'risk_score': score,
                    'verdict': verdict
                },
                'server_info': server_info,
                'simple_analysis': {
                    'summary': simplified_summary,
                    'phishing_score': phishing_score,
                    'phishing_verdict': phishing_verdict
                }
            })

    except Exception as e:
        logging.error(f"Global Analysis error: {e}")
        if browser:
            browser.close()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port)
