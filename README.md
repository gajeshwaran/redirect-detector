# Invisible Redirect & Clickjacking Detector

A secure tool to analyze URLs for redirection chains, hidden iframes, and clickjacking risks.

## Setup

1.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    playwright install
    ```

2.  **Run the Application:**
    ```bash
    python app.py
    ```

3.  **Access the Dashboard:**
    Open your browser and navigate to: `http://127.0.0.1:5000`

## Features

-   **Redirect Analysis:** Shows the full path of redirects (301, 302, JS).
-   **Hidden Content:** Detects 0-opacity or off-screen iframes.
-   **Clickjacking Detection:** Identifies transparent overlays with high z-index.
-   **Form Analysis:** Warns about forms submitting data to external domains.
