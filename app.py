import os
import logging
from flask import Flask, render_template, request, jsonify
from playwright.sync_api import sync_playwright

app = Flask(__name__)
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

    try:
        with sync_playwright() as p:
            # Use a verified user agent to look like a real browser
            browser_type = p.chromium
            browser = browser_type.launch(headless=True)
            context = browser.new_context(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                viewport={'width': 1280, 'height': 720}
            )
            page = context.new_page()

            # 1. Redirect Analysis
            redirects = []
            
            def handle_response(response):
                if 300 <= response.status <= 399:
                     redirects.append({
                        'status': response.status,
                        'url': response.url,
                        'headers': response.headers
                    })
            
            # Listen for responses to catch redirects (including meta/js ones if they trigger new requests)
            # However, Playwright's goto resolution handles the main chain.
            # We can inspect the request chain of the final response.
            
            try:
                response = page.goto(url, wait_until='networkidle', timeout=15000)
                final_url = page.url
                
                # Reconstruct redirect chain from the request
                request_chain = []
                current_request = response.request if response else None
                while current_request:
                    redirect_origin = current_request.redirected_from
                    if redirect_origin:
                        request_chain.insert(0, {
                            'url': redirect_origin.url,
                            'status': 'Redirect' # Status code is tricky to get directly from request chain easily without event listeners, simplifying for now
                        })
                        current_request = redirect_origin
                    else:
                        break
                
                # Add the final landing
                full_chain = request_chain + [{'url': final_url, 'status': response.status if response else 'Unknown'}]

            except Exception as e:
                return jsonify({'error': f'Failed to load page: {str(e)}'}), 500

            # 2. Hidden Content & 3. Clickjacking Detection
            # We inject script to analyze the DOM
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
                    if (rect.width < 2 || rect.height < 2) risk.push('Tiny dimension');
                    if (rect.left < -100 || rect.top < -100) risk.push('Off-screen');
                    
                    if (risk.length > 0) {
                        hidden_iframes.push({
                            src: iframe.src,
                            risks: risk,
                            location: {top: rect.top, left: rect.left, width: rect.width, height: rect.height}
                        });
                    }
                });

                // Clickjacking / UI Redress (High Z-Index + Transparency)
                const allElements = document.querySelectorAll('*');
                allElements.forEach(el => {
                    const style = window.getComputedStyle(el);
                    const zIndex = parseInt(style.zIndex, 10);
                    
                    // Check for potential overlay elements that are clickable
                    if (!isNaN(zIndex) && zIndex > 100) {
                        // Check if it's transparent or covers a lot of the screen
                        const rect = el.getBoundingClientRect();
                        const isTransparent = style.opacity < 0.2 || style.backgroundColor.includes('rgba') && style.backgroundColor.includes(', 0)');
                        
                        // If it receives pointer events and is possibly invisible/overlaying
                        if (style.pointerEvents !== 'none' && isTransparent && rect.width > 100 && rect.height > 100) {
                            risky_click_elements.push({
                                tag: el.tagName,
                                zIndex: zIndex,
                                opacity: style.opacity,
                                message: "High z-index transparent element detected (potential clickjacking layer)"
                            });
                        }
                    }
                });

                // Form Analysis
                document.querySelectorAll('form').forEach(form => {
                    const action = form.action;
                    if (action && !action.startsWith(window.location.origin) && action.startsWith('http')) {
                        risky_forms.push({
                            action: action,
                            method: form.method,
                            warning: "Form submits to a different domain"
                        });
                    }
                });

                return {
                    iframes: hidden_iframes,
                    clickjacking: risky_click_elements,
                    forms: risky_forms,
                    links: Array.from(document.querySelectorAll('a')).map(a => ({
                        text: a.innerText.slice(0, 50) || 'Image/Icon',
                        href: a.href
                    })).filter(l => l.href.startsWith('http'))
                };
            }''')
            
            # 4. Deep Link Analysis (Recursive Scan)
            deep_link_results = []
            unique_links = {l['href']: l['text'] for l in analysis_results['links']}
            # Limit to top 10 to ensure speed
            target_links = list(unique_links.items())[:10]
            
            for link_url, link_text in target_links:
                try:
                    # Create a fresh page for each link to simulate a real new tab/window click
                    # We reuse the context to share cookies if needed, or create new context mainly for speed/isolation
                    # Here we reuse context for speed but new page
                    sub_page = context.new_page()
                    
                    sub_redirects = []
                    
                    # Capture redirects for this specific link
                    # Note: Playwright's response.request.redirect_chain is useful, or we can manually track
                    try:
                        sub_response = sub_page.goto(link_url, wait_until='domcontentloaded', timeout=10000)
                        sub_final_url = sub_page.url
                        
                        # Chain reconstruction
                        sub_chain = []
                        if sub_response:
                            curr = sub_response.request
                            while curr.redirected_from:
                                sub_chain.insert(0, {
                                    'url': curr.redirected_from.url, 
                                    'status': 'Redirect'
                                })
                                curr = curr.redirected_from
                        
                        # Add final status
                        status = sub_response.status if sub_response else 'Error'
                        sub_chain.append({'url': sub_final_url, 'status': status})
                        
                        deep_link_results.append({
                            'original_text': link_text,
                            'original_url': link_url,
                            'final_url': sub_final_url,
                            'chain': sub_chain,
                            'redirected': link_url != sub_final_url and link_url + '/' != sub_final_url
                        })

                    except Exception as e:
                        deep_link_results.append({
                            'original_text': link_text,
                            'original_url': link_url,
                            'error': str(e)
                        })
                    finally:
                        sub_page.close()
                        
                except Exception as e:
                    pass

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
        logging.error(f"Analysis failed: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
