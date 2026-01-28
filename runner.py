import time
import ssl
import socket
from datetime import datetime, timedelta
import requests
from your_database_module import SessionLocal, Sites  # adjust to your project
from your_helpers_module import notify_expiring_token, change_state, update_last_scan_time

# -------------------------
# Bulletproof scraper
# -------------------------
def basic_site_scraper(url, timeout=10):
    """
    Scrapes the site at `url`. Always returns a tuple:
        (response, response_time)
    - response: requests.Response object or None
    - response_time: float seconds or 0 if failed
    """
    try:
        start = time.time()
        response = requests.get(url, timeout=timeout, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        })
        response_time = time.time() - start
        return response, response_time
    except requests.exceptions.RequestException as e:
        print(f"[Scraper ERROR] {url} -> {e}")
        return None, 0

# -------------------------
# Bulletproof SSL checker
# -------------------------
def get_ssl_expiry_days(url):
    """
    Returns the number of days until SSL certificate expires for `url`.
    Returns None if:
        - site is not HTTPS
        - SSL cannot be read
        - any error occurs
    """
    try:
        if not url.lower().startswith("https://"):
            return None

        hostname = url.split("//")[1].split("/")[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                exp_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                days_remaining = (exp_date - datetime.utcnow()).days
                return days_remaining
    except Exception as e:
        print(f"[SSL ERROR] {url} -> {e}")
        return None

# -------------------------
# Runner loop
# -------------------------
def runner(db):
    runner_delay = 5  # seconds between loops
    monitor_expiring_token = True
    expiring_token_threshold = 30  # days

    while True:
        for site in db.query(Sites).all():
            # Compute next scan time
            next_scan_time = site.last_scan_time + timedelta(seconds=site.scan_interval)
            time_until_next_scan = (next_scan_time - datetime.now()).total_seconds()
            if time_until_next_scan > 0:
                print(f"Skipping scan for {site.name} - next scan in {time_until_next_scan:.1f} seconds")
                continue

            url = site.url
            timeout = site.timeout or 10
            scan_type = site.scan_type
            scan_value = site.scan_value
            slow_threshold = site.slow_threshold or 3
            attempts_before_trigger = site.attempts_before_trigger or 3

            # -------------------------
            # Scrape site
            # -------------------------
            response, response_time = basic_site_scraper(url, timeout)

            # -------------------------
            # Determine if site is up
            # -------------------------
            site_is_up = False
            if response is not None:
                if scan_type == "text" and scan_value in response.text:
                    site_is_up = True
                elif scan_type == "status_code" and response.status_code == int(scan_value):
                    site_is_up = True

            # -------------------------
            # SSL token alert
            # -------------------------
            ssl_days_remaining = get_ssl_expiry_days(url)
            if (
                monitor_expiring_token
                and response is not None
                and ssl_days_remaining is not None
                and ssl_days_remaining <= expiring_token_threshold
            ):
                print(f"SSL cert expiring soon for {url}: {ssl_days_remaining} days left")
                notify_expiring_token(site, ssl_days_remaining)

            # -------------------------
            # Slow site check
            # -------------------------
            site_log = site  # adjust according to your DB model
            status = site_log.status if hasattr(site_log, 'status') else "unknown"
            if response is not None and response_time >= slow_threshold and site_is_up:
                if status != "slow":
                    change_state(site_log, "slow", response_time, db, webhook_state=None, ssl_days_remaining=ssl_days_remaining)
                else:
                    update_last_scan_time(site_log, db, response_time, ssl_days_remaining)
                continue

            # -------------------------
            # Up/down status handling
            # -------------------------
            if site_log.status == "up" and site_is_up:
                update_last_scan_time(site_log, db, response_time, ssl_days_remaining)
            elif site_log.status == "down" and not site_is_up:
                update_last_scan_time(site_log, db, response_time, ssl_days_remaining)
            else:
                if site_log.attempt_count >= attempts_before_trigger:
                    if site_is_up:
                        change_state(site_log, "up", response_time, db, webhook_state=None, ssl_days_remaining=ssl_days_remaining)
                    else:
                        change_state(site_log, "down", response_time, db, webhook_state=None, ssl_days_remaining=ssl_days_remaining)
                else:
                    site_log.response_time = response_time
                    site_log.attempt_count += 1
                    site_log.last_scan_time = datetime.now()
                    db.commit()
                    db.refresh(site_log)
                    continue

        # -------------------------
        # Runner sleep
        # -------------------------
        sleep_time = max(1, runner_delay)
        print(f"Runner sleeping for {sleep_time:.1f} seconds")
        time.sleep(sleep_time)

# -------------------------
# Main
# -------------------------
if __name__ == "__main__":
    try:
        print("Starting Site Monitor Runner...")
        db = SessionLocal()
        runner(db)
    except KeyboardInterrupt:
        print("Shutting down Site Monitor Runner...")
    finally:
        db.close()
        print("Runner stopped.")
