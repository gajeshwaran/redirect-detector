from playwright.sync_api import sync_playwright
try:
    with sync_playwright() as p:
        print("Launching browser...")
        browser = p.chromium.launch(headless=True)
        print("Browser launched.")
        page = browser.new_page()
        print("Page created.")
        browser.close()
        print("Success.")
except Exception as e:
    print(f"Error: {e}")
