import requests
import urllib.request
import ssl

# CWE-918: Server-Side Request Forgery (SSRF)
# CWE-295: Improper Certificate Validation


def fetch_url(url: str):
    """Fetch content from a user-supplied URL."""
    # CWE-918: No validation of the URL — attacker can target internal services
    # e.g. http://169.254.169.254/latest/meta-data/ (AWS metadata endpoint)
    response = requests.get(url)
    return response.text


def load_avatar(image_url: str):
    """Download a user's avatar from a URL they provide."""
    # CWE-918: Attacker can supply http://localhost:6379 (Redis) or internal IP
    response = requests.get(image_url, timeout=5)
    return response.content


def fetch_webhook(webhook_url: str, payload: dict):
    """Send data to a user-configured webhook endpoint."""
    # CWE-918: No allowlist — can hit internal APIs or cloud metadata
    requests.post(webhook_url, json=payload)


def download_file(url: str, dest: str):
    """Download a remote file, ignoring TLS errors."""
    # CWE-295: SSL verification disabled — susceptible to MITM attacks
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    urllib.request.urlretrieve(url, dest)  # noqa


def get_internal_data(endpoint: str):
    """Call an internal API endpoint with TLS verification disabled."""
    # CWE-295: verify=False disables certificate validation
    response = requests.get(f"https://internal-service/{endpoint}", verify=False)
    return response.json()


if __name__ == "__main__":
    print(fetch_url("http://169.254.169.254/latest/meta-data/iam/security-credentials/"))
    download_file("https://example.com/binary", "/tmp/binary")
    print(get_internal_data("admin/users"))
