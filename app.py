import os
import logging
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
            # Use a verified user agent to look like a real browser
            browser_type = p.chromium
            browser = browser_type.launch(headless=True, args=['--no-sandbox', '--disable-setuid-sandbox'])
            context = browser.new_context(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                viewport={'width': 1280, 'height': 720},
                ignore_https_errors=True  # Important for analyzing suspicious sites
            )
            page = context.new_page()

            # 1. Redirect Analysis
            full_chain = []
            final_url = url
            
            try:
                # Main Navigation with robust timeout
                response = page.goto(url, wait_until='networkidle', timeout=60000)
                final_url = page.url
                
                # Robust chain reconstruction
                request_chain = []
                if response:
                    current_request = response.request
                    while current_request:
                        redirect_origin = current_request.redirected_from
                        if redirect_origin:
                            request_chain.insert(0, {
                                'url': redirect_origin.url,
                                'status': 'Redirect' 
                            })
                            current_request = redirect_origin
                        else:
                            break
                    
                    # Add final status
                    status_code = response.status
                    full_chain = request_chain + [{'url': final_url, 'status': status_code}]
                else:
                    full_chain = [{'url': url, 'status': 'No Response'}]

            except Exception as e:
                logging.error(f"Navigation error: {e}")
                return jsonify({'error': f'Failed to load page: {str(e)}'}), 500

            # 2. Hidden Content & 3. Clickjacking Detection
            # We inject script to analyze the DOM safely
            try:
                analysis_results = page.evaluate('''() => {
                    const hidden_iframes = [];
                    const risky_click_elements = [];
                    const risky_forms = [];

                    // Helper to check visibility
                    function isHidden(el) {
                        const style = window.getComputedStyle(el);
                        return (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0' || style.width === '0px' || style.height === '0px');
                    }

                    // Iframe Analysis
                    document.querySelectorAll('iframe').forEach(iframe => {
                        const style = window.getComputedStyle(iframe);
                        const rect = iframe.getBoundingClientRect();
                        
                        let risk = [];
                        if (style.opacity == '0') risk.push('Opacity 0');
                        if (rect.width < 5 || rect.height < 5) risk.push('Tiny dimension');
                        if (rect.left < -100 || rect.top < -100) risk.push('Off-screen');
                        if (style.display === 'none') risk.push('Display None');
                        
                        if (risk.length > 0) {
                            hidden_iframes.push({
                                src: iframe.src || 'about:blank',
                                risks: risk,
                                location: {top: rect.top, left: rect.left}
                            });
                        }
                    });

                    // Clickjacking / UI Redress (High Z-Index + Transparency)
                    const allElements = document.querySelectorAll('div, span, a, button, img');
                    allElements.forEach(el => {
                        const style = window.getComputedStyle(el);
                        const zIndex = parseInt(style.zIndex, 10);
                        
                        // Check for potential overlay elements that are clickable
                        if (!isNaN(zIndex) && zIndex > 50) {
                            const rect = el.getBoundingClientRect();
                            // Check opacity/transparency
                            const opacity = parseFloat(style.opacity);
                            
                            // If it covers significant area and is effectively invisible
                            if (rect.width > 50 && rect.height > 50) {
                                if (opacity < 0.1) {
                                    risky_click_elements.push({
                                        tag: el.tagName,
                                        zIndex: zIndex,
                                        opacity: style.opacity,
                                        message: "Invisible high z-index overlay"
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
                                warning: "Cross-domain submission"
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
                        links: links
                    };
                }''')
            except Exception as e:
                logging.error(f"Evaluation error: {e}")
                analysis_results = {'iframes': [], 'clickjacking': [], 'forms': [], 'links': []}

            # 4. Deep Link Analysis (Recursive Scan)
            deep_link_results = []
            unique_links = {l['href']: l['text'] for l in analysis_results['links']}
            # Limit to top 5 to ensure speed on free hosting
            target_links = list(unique_links.items())[:5]
            
            for link_url, link_text in target_links:
                sub_page = None
                try:
                    sub_page = context.new_page()
                    sub_chain = []
                    
                    try:
                        # Shorter timeout for sub-scans
                        sub_response = sub_page.goto(link_url, wait_until='domcontentloaded', timeout=20000)
                        sub_final_url = sub_page.url
                        
                        if sub_response:
                            curr = sub_response.request
                            while curr.redirected_from:
                                sub_chain.insert(0, {
                                    'url': curr.redirected_from.url, 
                                    'status': 'Redirect'
                                })
                                curr = curr.redirected_from
                            status = sub_response.status
                        else:
                            status = 'Error'
                            sub_final_url = link_url
                        
                        sub_chain.append({'url': sub_final_url, 'status': status})
                        
                        is_redirect = (link_url != sub_final_url) and (link_url + '/' != sub_final_url)

                        deep_link_results.append({
                            'original_text': link_text,
                            'original_url': link_url,
                            'final_url': sub_final_url,
                            'chain': sub_chain,
                            'redirected': is_redirect
                        })

                    except Exception as e:
                        deep_link_results.append({
                            'original_text': link_text,
                            'original_url': link_url,
                            'error': "Timeout or Connect Error"
                        })
                except Exception:
                    pass
                finally:
                    if sub_page:
                        sub_page.close()

            browser.close()

            return jsonify({
                'final_url': final_url,
                'redirect_chain': full_chain,
                'hidden_iframes': analysis_results['iframes'],
                'clickjacking_risks': analysis_results['clickjacking'],
                'form_risks': analysis_results['forms'],
                'deep_scan_results': deep_link_results
            })

    except Exception as e:
        logging.error(f"Global Analysis error: {e}")
        if browser:
            browser.close()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port)
