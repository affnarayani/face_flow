import json
import os
import sys
import time

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.keys import Keys
from dotenv import load_dotenv

headless = False

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
FACEBOOK_URL = "https://www.facebook.com/"
EMAIL_XPATH = '//*[@id="email"]'
PASSWORD_XPATH = '//*[@id="pass"]'
LOGIN_BUTTON_XPATH = "//*[starts-with(@id, 'u_0_5_')]"
TWO_STEP_URL_FRAGMENT = "facebook.com/two_step_verification/authentication"
COOKIES_FILE = "d:/Workspace/face_flow/cookies.json"


def load_credentials():
    """Load Facebook credentials from the .env file."""
    load_dotenv()

    email = os.getenv("FACEBOOK_EMAIL")
    password = os.getenv("FACEBOOK_PASSWORD")

    if not email or not password:
        missing = []
        if not email:
            missing.append("FACEBOOK_EMAIL")
        if not password:
            missing.append("FACEBOOK_PASSWORD")
        message = "Missing environment variable(s): " + ", ".join(missing)
        raise EnvironmentError(message)

    return email, password


def configure_driver():
    """Create and configure a Chrome WebDriver instance."""
    options = Options()

    options.add_argument(f"user-agent={USER_AGENT}")

    if headless:
        # Use the new headless mode when available for better rendering support.
        options.add_argument("--headless=new")
        options.add_argument("--window-size=1920,1080")
    else:
        options.add_argument("--start-maximized")

    options.add_argument("--disable-gpu")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--no-sandbox")
    options.add_argument("--log-level=3")  # Suppress Chrome's verbose logging
    options.add_experimental_option("excludeSwitches", ["enable-logging"])  # Hide DevTools banner

    service = Service(ChromeDriverManager().install(), log_path=os.devnull)
    driver = webdriver.Chrome(service=service, options=options)

    if not headless:
        driver.maximize_window()

    return driver


def perform_login(driver, email, password):
    """Navigate to Facebook and log in using the provided credentials."""
    driver.get(FACEBOOK_URL)

    wait = WebDriverWait(driver, 20)

    email_field = wait.until(EC.visibility_of_element_located((By.XPATH, EMAIL_XPATH)))
    password_field = wait.until(EC.visibility_of_element_located((By.XPATH, PASSWORD_XPATH)))

    email_field.clear()
    email_field.send_keys(email)

    password_field.clear()
    password_field.send_keys(password)

    login_button = wait.until(EC.element_to_be_clickable((By.XPATH, LOGIN_BUTTON_XPATH)))
    login_button.click()


def wait_for_login(driver, timeout=120):
    """Wait until the user is fully authenticated and no two-step verification is pending."""
    wait = WebDriverWait(driver, timeout, poll_frequency=1)
    two_step_notice_shown = False

    def _check_login_state(_):
        nonlocal two_step_notice_shown
        current_url = driver.current_url
        if TWO_STEP_URL_FRAGMENT in current_url:
            if not two_step_notice_shown:
                print("Human intervention required: complete the two-step verification in the browser.")
                two_step_notice_shown = True
            return False

        # Check for the presence of a session cookie to confirm authentication.
        cookies = driver.get_cookies()
        has_session_cookie = any(cookie.get("name") == "c_user" for cookie in cookies)
        return has_session_cookie

    wait.until(_check_login_state)


def save_cookies(driver):
    """Wait for login to settle, then save cookies to a JSON file."""
    time.sleep(15)
    body = driver.find_element(By.TAG_NAME, "body")
    body.send_keys(Keys.ESCAPE)
    time.sleep(15)
    cookies = driver.get_cookies()

    with open(COOKIES_FILE, "w", encoding="utf-8") as file:
        json.dump(cookies, file, indent=2)


def main():
    try:
        email, password = load_credentials()
    except EnvironmentError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)

    driver = None
    try:
        driver = configure_driver()
        perform_login(driver, email, password)
        try:
            wait_for_login(driver)
        except TimeoutException:
            print(
                "Login verification timed out. If two-step verification is enabled, "
                "complete it in the browser and re-run the script."
            )
            sys.exit(1)
        save_cookies(driver)
        print(f"Cookies saved to {COOKIES_FILE}")
    finally:
        if driver is not None:
            driver.quit()


if __name__ == "__main__":
    main()
