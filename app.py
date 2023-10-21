from flask import Flask, request
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)

issues = []


def reset_issues():
    """
    Resets the issues list
    :return:
    """
    global issues
    issues = []


def check_http_security_headers(url):
    """
    Checks the HTTP security headers of a given URL
    :param url:
    :return:
    """
    try:
        response = requests.get(url)
        headers = response.headers

        security_headers = [
            "Strict-Transport-Security",
            "X-XSS-Protection",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Content-Security-Policy",
            "X-Permitted-Cross-Domain-Policies",
        ]

        for header in security_headers:
            if header not in headers:
                issues.append({"url": url, "issue": "Missing header: " + header})
    except requests.exceptions.RequestException as e:
        issues.append({"url": url, "issue": f"Failed to retrieve page: {e}"})


def check_https(url):
    """
    Checks if the URL is served over HTTPS
    :param url:
    :return:
    """
    try:
        response = requests.get(url)
        if not response.url.startswith("https://"):
            issues.append({"url": url, "issue": "Not served over HTTPS"})
    except requests.exceptions.RequestException as e:
        issues.append({"url": url, "issue": f"Failed to retrieve page: {e}"})


def check_cookie_attributes(url):
    """
    Checks the attributes of the cookies set by the URL
    :param url:
    :return:
    """
    try:
        response = requests.get(url)
        if "Set-Cookie" in response.headers:
            cookies = response.headers["Set-Cookie"].split(";")

            for cookie in cookies:
                issues_in_cookie = []
                if "Secure" not in cookie:
                    issues_in_cookie.append("Missing Secure attribute")
                if "HttpOnly" not in cookie:
                    issues_in_cookie.append("Missing HttpOnly attribute")
                if "SameSite" not in cookie:
                    issues_in_cookie.append("Missing SameSite attribute")
                if len(issues_in_cookie) > 0:
                    issues.append({"url": url, "issue": "Cookie: " + cookie + " - " + ", ".join(issues_in_cookie)})
    except requests.exceptions.RequestException as e:
        issues.append({"url": url, "issue": f"Failed to retrieve page: {e}"})


def check_exposed_server_info(url):
    """
    Checks if the server exposes information about itself
    :param url:
    :return:
    """
    try:
        response = requests.get(url)
        headers = response.headers

        exposed_headers = [
            "Server",
            "X-Powered-By",
        ]

        for header in exposed_headers:
            if header in headers:
                issues.append({"url": url, "issue": "Exposed header: " + header})

    except requests.exceptions.RequestException as e:
        issues.append({"url": url, "issue": f"Failed to retrieve page: {e}"})


def check_clickjacking_protection(url):
    """
    Checks if the URL has clickjacking protection
    :param url:
    :return:
    """
    try:
        response = requests.get(url)
        headers = response.headers

        if "X-Frame-Options" not in headers:
            issues.append({"url": url, "issue": "Missing X-Frame-Options header"})
        elif headers["X-Frame-Options"] != "DENY" and headers["X-Frame-Options"] != "SAMEORIGIN":
            issues.append({"url": url, "issue": "Invalid X-Frame-Options header"})
    except requests.exceptions.RequestException as e:
        issues.append({"url": url, "issue": f"Failed to retrieve page: {e}"})


def check_xss_protection(url):
    """
    Checks if the URL has XSS protection
    :param url:
    :return:
    """
    try:
        response = requests.get(url)
        headers = response.headers

        if "X-XSS-Protection" not in headers:
            issues.append({"url": url, "issue": "Missing X-XSS-Protection header"})
        elif headers["X-XSS-Protection"] != "1; mode=block":
            issues.append({"url": url, "issue": "Invalid X-XSS-Protection header"})

        if "Content-Security-Policy" not in headers:
            issues.append({"url": url, "issue": "Missing Content-Security-Policy header"})
        elif "script-src" not in headers["Content-Security-Policy"]:
            issues.append({"url": url, "issue": "Missing script-src in Content-Security-Policy header"})
    except requests.exceptions.RequestException as e:
        issues.append({"url": url, "issue": f"Failed to retrieve page: {e}"})


def check_directory_listing(url):
    """
    Checks if the URL has directory listing enabled
    :param url:
    :return:
    """
    common_directories = ['images/', 'img/', 'js/', 'css/', 'assets/', 'static/', 'files/', 'uploads/']

    for directory in common_directories:
        full_url = f'{url.rstrip("/")}/{directory}'
        try:
            response = requests.get(full_url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                links = soup.find_all('a')
                if len(links) > 0:
                    issues.append({"url": full_url, "issue": "Potential directory listing vulnerability"})
        except requests.exceptions.RequestException as e:
            issues.append({"url": url, "issue": f"Failed to retrieve page: {e}"})


@app.route('/')
def index():
    pass


@app.route('/scan', methods=['POST'])
def scan():
    """
    Scans a given URL for security issues
    :return:
    """
    reset_issues()
    url = str(request.form['url'])

    check_https(url)
    check_http_security_headers(url)
    check_cookie_attributes(url)
    check_exposed_server_info(url)
    check_clickjacking_protection(url)
    check_xss_protection(url)
    check_directory_listing(url)

    return {"issues": issues}


if __name__ == '__main__':
    app.run(debug=True)
