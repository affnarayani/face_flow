# Repository Overview

## Project Summary
- **Name**: face_flow
- **Purpose**: Automates logging into Facebook by loading encrypted cookies, launching a Chrome browser session, handling notification modals, and optionally retrieving feed information.

## Key Components
- **test_login.py**: Main automation script that decrypts cookies, initializes the Selenium Chrome WebDriver, applies session cookies, dismisses notification popups, and fetches elements from the Facebook feed.
- **encrypt.py**: Utility for encrypting data (likely used for securing cookie information).
- **get_cookie.py**: Helper script intended for retrieving or managing cookies prior to encryption.
- **cookies.json.encrypted**: Encrypted cookie storage consumed by `test_login.py`.
- **requirements.txt**: Python dependencies, including Selenium, cryptography, python-dotenv, and webdriver-manager.

## Environment & Configuration
- **Python Virtual Environment**: Located in `.venv/`; ensure it is activated before running scripts.
- **Environment Variables**:
  1. Set `DECRYPT_KEY` in `.env` to enable cookie decryption.

## Typical Workflow
1. Populate or refresh encrypted cookies using `get_cookie.py` and `encrypt.py`.
2. Activate the virtual environment (`.venv`).
3. Run `python test_login.py` to launch the automation.

## Notable Behaviors
- The automation maximizes the browser window (unless run headlessly) and attempts to dismiss Facebook notification dialogs.
- Logging is printed to stdout for each major step, aiding in debugging.