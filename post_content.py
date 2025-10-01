"""Automates logging into Facebook using stored cookies.

The script launches a Chrome browser, applies cookies from ``cookies.json``,
and refreshes the page to load the authenticated session.
"""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import time
from html import unescape
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
import sys

from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import urlopen

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import load_dotenv
from selenium import webdriver
from selenium.common.exceptions import (
    ElementClickInterceptedException,
    ElementNotInteractableException,
    InvalidArgumentException,
    NoSuchElementException,
    StaleElementReferenceException,
    TimeoutException,
)
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from webdriver_manager.chrome import ChromeDriverManager

# Toggle this flag to run the browser in headless mode when desired.
headless = True

COOKIES_FILE = Path(__file__).resolve().parent / "cookies.json.encrypted"
TEMP_DIR = Path(__file__).resolve().parent / "temp"
POSTED_HISTORY_FILE = Path(__file__).resolve().parent / "posted_content.json"
FACEBOOK_URL = "https://www.facebook.com/"
GITHUB_CONTENT_URL = (
    "https://github.com/affnarayani/ninetynine_credits_legal_advice_app_content/blob/main/content.json"
)
GITHUB_CONTENT_XPATH = '//*[@id="read-only-cursor-text-area"]'
CONTENT_FILENAME = "content.json"
CREATE_POST_TRIGGER_XPATH = (
    "/html/body/div[1]/div/div[1]/div/div[3]/div/div/div[1]/div[1]/div/div[2]/div/div/div/div[2]/div/div[2]/div/div/div/div[1]/div/div[1]/span"
)
# This XPath is for the media upload button within the post creation pop-up.
MEDIA_UPLOAD_XPATH = (
    "/html/body/div[1]/div/div[1]/div/div[4]/div/div/div[1]/div/div[2]/div/div/div/form/div/div[1]/div/div/div/div[2]/div[1]/div[3]/div[1]/div[1]/div/div/div"
)
LEXICAL_EDITOR_LOCATORS: Tuple[Tuple[By, str], ...] = (
    (By.CSS_SELECTOR, "[data-lexical-editor] [data-lexical-text='true']"),
    (By.CSS_SELECTOR, "div[role='dialog'] div[role='textbox'][contenteditable='true']"),
    (By.CSS_SELECTOR, "div[role='dialog'] div[role='textbox']"),
)
PAGE_HEADER_XPATH = (
    "/html/body/div[1]/div/div[1]/div/div[3]/div/div/div[1]/div[1]/div/div[1]/div/div/div[1]/div/div/div[1]/div[1]/ul/li[1]/div/div/div/a/div[1]/div/div[2]/div/div/div/span/span"
)
TARGET_PAGE_NAME = "The Legal Mind"
PBKDF2_ITERATIONS = 200_000
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
ALLOWED_COOKIE_KEYS = {
    "domain",
    "expiry",
    "httpOnly",
    "name",
    "path",
    "sameSite",
    "secure",
    "value",
}

# Reduce webdriver-manager logging noise.
os.environ.setdefault("WDM_LOG_LEVEL", "0")


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from the provided password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def _decrypt_payload(payload: Dict[str, Any], password: str) -> bytes:
    """Decrypt the AES-GCM payload using the provided password."""
    try:
        salt = base64.b64decode(payload["s"])
        nonce = base64.b64decode(payload["n"])
        ciphertext = base64.b64decode(payload["ct"])
    except KeyError as exc:
        raise ValueError("Encrypted cookies payload is missing required fields") from exc

    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def load_cookies(file_path: Path) -> List[Dict[str, Any]]:
    """Load cookies from the provided JSON file."""
    if not file_path.exists():
        raise FileNotFoundError(f"Cookies file not found: {file_path}")

    load_dotenv()
    password = os.getenv("DECRYPT_KEY")
    if not password:
        raise RuntimeError("DECRYPT_KEY is missing in environment/.env")

    with file_path.open("r", encoding="utf-8") as cookie_file:
        payload = json.load(cookie_file)

    if not isinstance(payload, dict):
        raise ValueError("Encrypted cookies file must contain a JSON object payload")

    plaintext = _decrypt_payload(payload, password)
    cookies = json.loads(plaintext.decode("utf-8"))

    if not isinstance(cookies, list):
        raise ValueError("Cookies file must contain a list of cookie objects")

    return cookies


def load_post_history(history_file: Path) -> List[Dict[str, Any]]:
    """Return the list of previously posted entries."""
    if not history_file.exists():
        return []

    try:
        data = json.loads(history_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []

    if isinstance(data, list):
        return [entry for entry in data if isinstance(entry, dict)]

    if isinstance(data, dict) and "descriptions" in data and isinstance(data["descriptions"], list):
        # Legacy structure: {"descriptions": ["..."]}
        return [
            {"title": "", "description": str(item).strip(), "image": ""}
            for item in data["descriptions"]
        ]

    return []


def has_been_posted(history: List[Dict[str, Any]], description: str) -> bool:
    """Check if a description is already present in the post history."""
    normalized = description.strip()
    return any(entry.get("description", "").strip() == normalized for entry in history)


def append_post_history(history_file: Path, entry: Dict[str, Any]) -> None:
    """Prepend the newly posted entry in the history file."""
    history_file.parent.mkdir(parents=True, exist_ok=True)

    history = load_post_history(history_file)
    new_history = [entry] + history

    history_file.write_text(json.dumps(new_history, ensure_ascii=False, indent=2), encoding="utf-8")


def sanitize_cookie(cookie: Dict[str, Any]) -> Dict[str, Any]:
    """Return a cookie dictionary compatible with Selenium."""
    sanitized = {key: cookie[key] for key in ALLOWED_COOKIE_KEYS if key in cookie}

    if "expiry" in sanitized:
        sanitized["expiry"] = int(sanitized["expiry"])

    return sanitized


def ensure_temp_dir(clean: bool = True) -> Path:
    """Prepare the temporary directory and optionally clear existing contents."""
    TEMP_DIR.mkdir(parents=True, exist_ok=True)

    if clean:
        for entry in TEMP_DIR.iterdir():
            if entry.is_dir():
                shutil.rmtree(entry)
            else:
                entry.unlink()

    return TEMP_DIR


def fetch_github_content(driver: webdriver.Chrome, temp_dir: Path) -> Path:
    """Download JSON content from GitHub and store it in the temp directory."""
    destination = temp_dir / CONTENT_FILENAME
    try:
        driver.get(GITHUB_CONTENT_URL)
        element = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.XPATH, GITHUB_CONTENT_XPATH))
        )
        content = element.text
    except TimeoutException as exc:
        raise RuntimeError(f"Unable to fetch content.json from GitHub: {exc}") from exc

    destination.write_text(content, encoding="utf-8")
    print(f"Saved GitHub content to {destination}")
    return destination


def create_driver() -> webdriver.Chrome:
    """Create and configure the Chrome WebDriver instance."""
    options = Options()

    options.add_argument(f"user-agent={USER_AGENT}")

    if headless:
        options.add_argument("--headless=new")
        # Explicit window size ensures consistent layout when headless.
        options.add_argument("--window-size=1920,1080")

    prefs = {
        "profile.default_content_setting_values.notifications": 2,
    }
    options.add_experimental_option("prefs", prefs)
    options.add_argument("--disable-notifications")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-webgl")
    options.add_argument("--enable-unsafe-swiftshader")
    options.add_argument("--no-sandbox")
    options.add_argument("--log-level=3")

    service = Service(ChromeDriverManager().install(), log_path="NUL")
    driver = webdriver.Chrome(service=service, options=options)

    if not headless:
        driver.maximize_window()

    return driver


def apply_cookies(driver: webdriver.Chrome, cookies: List[Dict[str, Any]]) -> None:
    """Apply cookies to the current browser session."""
    driver.delete_all_cookies()
    for cookie in cookies:
        sanitized_cookie = sanitize_cookie(cookie)
        if {"domain", "name", "value"}.issubset(sanitized_cookie.keys()):
            driver.add_cookie(sanitized_cookie)



def fetch_primary_feed_text(driver: webdriver.Chrome, timeout: int = 10) -> None:
    """Fetch and print the profile name from the specified XPath."""
    target_xpath = "/html/body/div[1]/div/div[1]/div/div[3]/div/div/div[1]/div[1]/div/div[1]/div/div/div[1]/div/div/div[1]/div[1]/ul/li[1]/div/div/div/a/div[1]/div/div[2]/div/div/div/span/span"
    try:
        element = WebDriverWait(driver, timeout).until(
            EC.visibility_of_element_located((By.XPATH, target_xpath))
        )
        print(f"Profile Name: {element.text}")
    except TimeoutException:
        print("Unable to locate the profile name within the given timeout.")


def dismiss_notification_popup(driver: webdriver.Chrome, timeout: int = 10) -> None:
    """Dismiss the browser notification popup if it appears."""
    try:
        popup = WebDriverWait(driver, timeout).until(
            EC.presence_of_element_located(
                (
                    By.XPATH,
                    '//div[contains(@class, "request-notifications") and contains(@role, "dialog")]'
                    ' | //div[contains(@data-pagelet, "NotificationPermissionsDialog")]'
                )
            )
        )
        block_button = popup.find_elements(By.XPATH, './/button[contains(., "Block")]')
        if not block_button:
            block_button = popup.find_elements(By.XPATH, './/span[text()="Block"]/ancestor::button')
        if not block_button:
            block_button = driver.find_elements(By.XPATH, '//button[contains(., "Block")]')
        if block_button:
            block_button[0].click()
            print("Blocked notification popup.")
            return
        print("Notification popup detected but 'Block' button not found.")
    except TimeoutException:
        print("Notification popup did not appear.")


def open_profile_menu(driver: webdriver.Chrome, timeout: int = 10) -> None:
    """Open the account menu by clicking the top-right profile image."""
    button_selectors = [
        (By.CSS_SELECTOR, 'div[aria-label="Account"]'),
        (By.CSS_SELECTOR, 'div[aria-label="Your profile"]'),
        (By.XPATH, '//div[@aria-label="Account" and @role="button"]'),
        (By.XPATH, '//div[@aria-label="Your profile" and @role="button"]'),
    ]

    for by, locator in button_selectors:
        try:
            profile_button = WebDriverWait(driver, timeout).until(
                EC.element_to_be_clickable((by, locator))
            )
            profile_button.click()
            print("Opened profile menu via top-right profile icon.")
            return
        except (TimeoutException, ElementClickInterceptedException):
            continue

    raise TimeoutException("Failed to locate the top-right profile menu button.")


def select_page_from_menu(driver: webdriver.Chrome, page_name: str, timeout: int = 10) -> None:
    """Select the specified page from the account menu."""
    candidate_xpaths = [
        f'//span[normalize-space(text())="{page_name}"]/ancestor::div[@role="menuitem"]',
        f'//div[@role="menuitem" and .//span[normalize-space(text())="{page_name}"]]',
        f'//span[normalize-space(text())="{page_name}"]',
        "/html/body/div[1]/div/div[1]/div/div[2]/div[5]/div[2]/div/div[3]/div[1]/div[1]/div/div/div/div/div/div/div/div/div/div[1]/div/div/div[1]/div[1]/div/div/div[1]/div/span/div/div/div/div/div[1]/div/div[2]/div/span",
        "/html/body/div[1]/div/div[1]/div/div[2]/div[5]/div[2]/div/div[3]/div[1]/div[1]/div/div/div/div/div/div/div/div/div/div[1]/div/div/div[1]/div[1]/div/div/a/div[1]/div[2]/span",
        "/html/body/div[1]/div/div[1]/div/div[2]/div[5]/div[2]/div/div[2]/div[1]/div[1]/div/div/div/div/div/div/div/div/div/div[1]/div/div/div[1]/div[1]/div/div/div[1]/div/span/div/div/div/div/div[1]/div/div[2]/div/span",
    ]

    for xpath in candidate_xpaths:
        try:
            target_element = WebDriverWait(driver, timeout).until(
                EC.visibility_of_element_located((By.XPATH, xpath))
            )
            time.sleep(1) # Give the element a moment to become interactable

            try:
                clickable = WebDriverWait(driver, 2).until(
                    EC.element_to_be_clickable((By.XPATH, xpath))
                )
            except TimeoutException:
                try:
                    clickable = target_element.find_element(
                        By.XPATH, "./ancestor-or-self::*[self::a or self::div[@role='menuitem']][1]"
                    )
                except NoSuchElementException:
                    clickable = target_element

            try:
                clickable.click()
            except (ElementClickInterceptedException, ElementNotInteractableException):
                driver.execute_script("arguments[0].click();", clickable)

            print(f"Selected menu item: {page_name}")
            return
        except (TimeoutException, ElementClickInterceptedException, ElementNotInteractableException, NoSuchElementException):
            continue

    raise TimeoutException(f"Unable to find menu item with text '{page_name}'.")


def download_page_source(driver: webdriver.Chrome, destination: Path) -> Path:
    """Save current page source to the destination file."""
    destination.write_text(driver.page_source, encoding="utf-8")
    print(f"Saved page source to {destination}")
    return destination


def load_content_items(content_file: Path) -> List[Dict[str, Any]]:
    """Load content entries from the JSON file."""
    if not content_file.exists():
        raise FileNotFoundError(f"Content file not found: {content_file}")

    try:
        data = json.loads(content_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("content.json contains invalid JSON") from exc

    if not isinstance(data, list):
        raise ValueError("content.json must contain a list of objects")

    return data


def strip_html_paragraphs(html_text: str) -> List[str]:
    """Convert HTML paragraphs into plain-text lines."""
    paragraphs = re.findall(r"<p>(.*?)</p>", html_text, flags=re.DOTALL | re.IGNORECASE)
    if not paragraphs:
        return [unescape(re.sub(r"<[^>]+>", "", html_text)).strip()] if html_text else []

    lines = []
    for paragraph in paragraphs:
        clean = unescape(re.sub(r"<[^>]+>", "", paragraph)).strip()
        if clean:
            lines.append(clean)
    return lines


def find_next_content_item(
    content_items: List[Dict[str, Any]], posted_history: List[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    """Return the first content item whose description has not been used."""
    posted_descriptions = {
        entry.get("description", "").strip() for entry in posted_history
    }
    for item in content_items:
        description = item.get("description", "").strip()
        if description and description not in posted_descriptions:
            return item
    return None


def download_image_to_temp(url: str, temp_dir: Path) -> Optional[Path]:
    """Download the image from the provided URL into the temp directory."""
    if not url:
        return None

    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        print(f"Skipping invalid image URL: {url}")
        return None

    filename = Path(parsed.path).name or "image.jpg"
    destination = temp_dir / filename
    try:
        with urlopen(url) as response:
            destination.write_bytes(response.read())
    except URLError as exc:
        print(f"Failed to download image from {url}: {exc}")
        return None

    print(f"Downloaded image to {destination}")
    return destination


def wait_and_click(driver: webdriver.Chrome, xpath: str, timeout: int = 10) -> None:
    """Wait for the element located by XPath to become clickable and click it."""
    element = WebDriverWait(driver, timeout).until(
        EC.element_to_be_clickable((By.XPATH, xpath))
    )
    element.click()


def wait_for_presence(
    driver: webdriver.Chrome, xpath: str, timeout: int = 10
) -> webdriver.remote.webelement.WebElement:
    """Wait for the element located by XPath to be present in DOM."""
    return WebDriverWait(driver, timeout).until(
        EC.presence_of_element_located((By.XPATH, xpath))
    )


def focus_text_field(
    driver: webdriver.Chrome,
    timeout: int = 10,
    poll_interval: float = 0.5,
) -> webdriver.remote.webelement.WebElement:
    """Acquire and focus the Facebook Lexical editor using resilient selectors."""

    end_time = time.time() + timeout

    while time.time() < end_time:
        for locator in LEXICAL_EDITOR_LOCATORS:
            try:
                element = WebDriverWait(driver, 2).until(EC.presence_of_element_located(locator))
                driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", element)
                try:
                    element.click()
                except (ElementClickInterceptedException, ElementNotInteractableException):
                    driver.execute_script("arguments[0].click();", element)

                driver.execute_script("arguments[0].focus();", element)
                is_active = driver.execute_script(
                    "return document.activeElement === arguments[0];",
                    element,
                )
                if is_active:
                    return element
            except (TimeoutException, StaleElementReferenceException):
                continue
        time.sleep(poll_interval)

    raise TimeoutException("Unable to focus the text field within timeout.")


def input_multiline_text(
    element: webdriver.remote.webelement.WebElement,
    lines: Sequence[str],
) -> None:
    """Insert lines into a content-editable element using keyboard semantics."""
    if not lines:
        return

    # Lexical does not expose .clear(); use keyboard shortcuts instead.
    element.send_keys(Keys.CONTROL, "a")
    element.send_keys(Keys.DELETE)

    for index, line in enumerate(lines):
        element.send_keys(line)
        if index < len(lines) - 1:
            element.send_keys(Keys.SHIFT, Keys.ENTER)


def upload_media(driver: webdriver.Chrome, container_xpath: str, file_path: Path) -> bool:
    """Attempt to upload media by locating a file input and sending the file path directly."""
    if not file_path or not file_path.exists():
        print("No file path provided or file does not exist.")
        return False

    # Try to find the file input element directly.
    # This is often a hidden input that the visible "Add photos/videos" button interacts with.
    try:
        # Wait for the file input element to be present and interactable.
        # We are looking for a file input that is part of the current dialog.
        # The user's provided text field XPath and the MEDIA_UPLOAD_XPATH share a common prefix,
        # so we can assume the file input is within the same general area.
        file_input = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.XPATH, f"{container_xpath}/ancestor::form//input[@type='file']"))
        )
        # Attempt to send keys directly to the file input.
        file_input.send_keys(str(file_path))
        print(f"Dynamically uploaded media from {file_path} to file input.")
        return True
    except TimeoutException:
        print("Direct file input element not found within the pop-up. Attempting fallback.")
    except (InvalidArgumentException, ElementNotInteractableException) as exc:
        print(f"Failed to upload via direct file input: {exc}. Attempting fallback.")

    # Fallback: If direct upload fails, try clicking the visible button and then finding the input.
    # This was the previous logic, which the user reported opened a system dialog.
    # We keep this as a fallback in case the direct approach doesn't work for some reason,
    # but the goal is to avoid it.
    try:
        container_element = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.XPATH, container_xpath))
        )
        container_element.click()
        print(f"Clicked media upload trigger: {container_xpath} (fallback).")
        time.sleep(1) # Give a moment for the file input to appear/become active

        input_elements = driver.find_elements(By.XPATH, "//input[@type='file']")
        for input_element in input_elements:
            try:
                if input_element.is_displayed() and input_element.is_enabled():
                    input_element.send_keys(str(file_path))
                    print(f"Uploaded media from {file_path} via fallback input.")
                    return True
            except (InvalidArgumentException, ElementNotInteractableException) as exc:
                print(f"Failed to upload via located fallback input: {exc}")

    except TimeoutException:
        print(f"Media upload trigger not found or not clickable (fallback): {container_xpath}.")
    except ElementClickInterceptedException:
        driver.execute_script("arguments[0].click();", container_element)
        print(f"Clicked media upload trigger via JS (fallback): {container_xpath}")
        time.sleep(1)
        input_elements = driver.find_elements(By.XPATH, "//input[@type='file']")
        for input_element in input_elements:
            try:
                if input_element.is_displayed() and input_element.is_enabled():
                    input_element.send_keys(str(file_path))
                    print(f"Uploaded media from {file_path} via JS fallback input.")
                    return True
            except (InvalidArgumentException, ElementNotInteractableException) as exc:
                print(f"Failed to upload via located JS fallback input: {exc}")

    print("Unable to dynamically upload media. The system file selection pop-up might still appear.")
    return False


def main() -> None:
    """Launch the browser, apply cookies, and refresh to log in."""
    print("Starting Facebook login automation...")
    cookies = load_cookies(COOKIES_FILE)

    driver = None # Initialize driver to None
    try:
        driver = create_driver()
        temp_dir = ensure_temp_dir(clean=True)
        content_file = fetch_github_content(driver, temp_dir)
        content_items = load_content_items(content_file)
        post_history_entries = load_post_history(POSTED_HISTORY_FILE)

        candidate = find_next_content_item(content_items, post_history_entries)
        if not candidate:
            print("No new content available to post. Clearing temporary folder and closing browser.")
            ensure_temp_dir(clean=True) # Clear temp folder as requested
            return # This return will now jump to the finally block

        description_html = candidate.get("description", "").strip()
        description_lines = strip_html_paragraphs(description_html)

        print("Navigating to Facebook...")
        driver.get(FACEBOOK_URL)

        print("Applying cookies...")
        apply_cookies(driver, cookies)

        print("Refreshing page to apply session...")
        driver.refresh()

        destination_file = TEMP_DIR / "page_source.html"
        download_page_source(driver, destination_file)

        dismiss_notification_popup(driver)

        open_profile_menu(driver)
        time.sleep(2) # Give the menu a moment to fully render
        select_page_from_menu(driver, TARGET_PAGE_NAME)

        try:
            WebDriverWait(driver, 15).until(
                EC.text_to_be_present_in_element((By.XPATH, PAGE_HEADER_XPATH), TARGET_PAGE_NAME)
            )
        except TimeoutException:
            print(f"Failed to confirm page header text '{TARGET_PAGE_NAME}'. Exiting.")
            return

        # Click the "Create post" trigger to open the text input field pop-up.
        # This addresses the user's first requirement:
        # "first must click this xpath ... to open text input field where you enter"
        try:
            wait_and_click(driver, CREATE_POST_TRIGGER_XPATH, timeout=15)
        except TimeoutException:
            print("Failed to locate the create-post trigger. Exiting.")
            return

        # Wait for popup to render
        print("Waiting for pop-up to appear...")
        try:
            # Wait for any of the lexical editor elements to appear
            WebDriverWait(driver, 15).until(
                lambda d: any(
                    d.find_elements(*locator) for locator in LEXICAL_EDITOR_LOCATORS
                )
            )
        except TimeoutException:
            print("Unable to locate the popup text field. Exiting.")
            return

        popup_source_path = TEMP_DIR / "popup_page_source.html"
        download_page_source(driver, popup_source_path)

        # Enter the text content in the same popup.
        # This addresses the user's second requirement:
        # "there find xpath ... and enter the content text there."
        combined_text = "\n\n".join(description_lines) if description_lines else description_html
        if combined_text:
            try:
                text_field = focus_text_field(driver, timeout=10)
                input_multiline_text(text_field, [combined_text])
                print("Text content entered successfully.")
            except TimeoutException:
                print("Failed to focus text field for content input.")
                return

        # Upload the image in the same popup.
        # This addresses the user's third requirement:
        # "then on the same opened pop up upload the image."
        image_path = download_image_to_temp(candidate.get("image", ""), temp_dir)
        if image_path:
            uploaded = upload_media(driver, MEDIA_UPLOAD_XPATH, image_path)
            if uploaded:
                print("Media uploaded successfully.")
            else:
                print("Media upload failed.")

        # Add a 15-second wait after image upload as requested by the user.
        time.sleep(15)

        # Click the "Next" button as per user request.
        # Reverting to the user's provided XPath for the "Next" button.
        NEXT_BUTTON_XPATH = "/html/body/div[1]/div/div[1]/div/div[4]/div/div/div[1]/div/div[2]/div/div/div/form/div/div[1]/div/div/div/div[3]/div[3]/div/div/div/div[1]/div/span/span"
        try:
            wait_and_click(driver, NEXT_BUTTON_XPATH, timeout=10)
            print("Clicked 'Next' button.")
        except TimeoutException:
            print("Failed to locate or click 'Next' button. Exiting.")
            return

        # Add a 15-second wait before checking the "Post" button as requested by the user.
        time.sleep(15)

        # Wait for and click the "Post" button as per user request.
        # Using a more resilient XPath for the "Post" button.
        POST_BUTTON_XPATH = "//div[@role='button']//span[normalize-space(text())='Post']"
        try:
            wait_and_click(driver, POST_BUTTON_XPATH, timeout=10)
            print("Clicked 'Post' button.")
        except TimeoutException:
            print("Failed to locate or click 'Post' button. Exiting.")
            return

        append_post_history(
            POSTED_HISTORY_FILE,
            {
                "title": candidate.get("title", "").strip(),
                "description": description_html,
                "image": candidate.get("image", "").strip(),
            },
        )
        print("Content recorded in post history.")

        fetch_primary_feed_text(driver)

        # Wait for 15 seconds after posting content.
        print("Waiting 15 seconds after posting...")
        time.sleep(15)

        # Clear the temp folder.
        print("Clearing temporary folder...")
        ensure_temp_dir(clean=True)
        print("Temporary folder cleared.")

        # Wait for another 15 seconds.
        print("Waiting another 15 seconds before closing the browser...")
        time.sleep(15)

        print("Task completed.")

    except ElementNotInteractableException as e:
        if "element not interactable" in str(e):
            print(f"An 'element not interactable' error occurred: {e}")
            print("Exiting with error to fail GitHub workflow.")
            sys.exit(1)
        else:
            print(f"An error occurred: {e}")
            print("The browser will now close due to an error.")
    except Exception as e:
        print(f"An error occurred: {e}")
        print("The browser will now close due to an error.")
    finally:
        if driver:
            print("Closing browser automatically.")
            driver.quit()


if __name__ == "__main__":
    main()
