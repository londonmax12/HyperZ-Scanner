"""
header_scanning.py

This script provides functions for scanning through request headers

Author: Mercury Dev
Date: 21/03/24
References Used: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

Functions:
- get_insecure_headers(url, headers): Scan for insecure headers in a dictionary of headers
"""

import sys
sys.path.insert(0, '../')
from reporting.report import Vulnerability, Severity

def get_insecure_headers(url, headers: dict[str, str]) -> dict[str, str]:
    """
    Gets all within dictionary, and checks for bad practices and potential vulnerabilities

    Args:
    - url (str): The url being checked
    - headers (dict[str, str]): The headers provided by visit request.

    Returns:
    - list[Vulnerability]: A list of vulnerabilities.
    """
    # Dictionary to store vulnerabilities
    vulnerabilities  = []

    # Ensure X-Frame-Options is set to 'deny' or 'sameorigin' to prevent clickjacking attacks
    if "x-frame-options" not in headers or headers["x-frame-options"].lower() not in ["deny", "sameorigin"]:
        vulnerabilities.append(Vulnerability(
            url=url,
            name="Missing or insecure X-Frame-Options header",
            description="The X-Frame-Options header should be present and set to 'deny' or 'sameorigin' to prevent clickjacking attacks.",
            severity=Severity.HIGH
        ))

    # Ensure XSS protection is active to prevent cross-site scripting attacks
    if "x-xss-protection" not in headers:
        vulnerabilities.append(Vulnerability(
            url=url,
            name="Missing X-XSS-Protection header",
            description="The X-XSS-Protection header should be present to enable XSS protection.",
            severity=Severity.MEDIUM
        ))

    # Ensure content type options are set to 'nosniff' to prevent MIME type sniffing attacks
    if "x-content-type-options" not in headers or headers["x-content-type-options"].lower() != "nosniff":
        vulnerabilities.append(Vulnerability(
            url=url,
            name="Missing or insecure X-Content-Type-Options header",
            description="The X-Content-Type-Options header should be present and set to 'nosniff' to prevent MIME type sniffing attacks.",
            severity=Severity.MEDIUM
        ))

    # Ensure Referrer Policy is set to 'strict-origin-when-cross-origin' to stop referrer information leakage
    if "referrer-policy" not in headers or headers["referrer-policy"].lower() != "strict-origin-when-cross-origin":
        vulnerabilities.append(Vulnerability(
            url=url,
            name="Missing or insecure Referrer-Policy header",
            description="The Referrer-Policy header should be present and set to 'strict-origin-when-cross-origin' to prevent referrer information leakage.",
            severity=Severity.MEDIUM
        ))

    # Ensure Content-Type is set to 'text/html; charset=utf-8' to specify the character set and content type
    if "content-type" not in headers or "charset=utf-8" not in headers["content-type"].lower() or "text/html" not in headers["content-type"].lower():
        vulnerabilities.append(Vulnerability(
            url=url,
            name="Missing or incorrect Content-Type header",
            description="The Content-Type header should be present and set to 'text/html; charset=utf-8' to specify the character set and content type.",
            severity=Severity.HIGH
        ))

    # Ensure Strict-Transport-Security is present and contains 'max-age=' to enforce secure connections
    if "strict-transport-security" not in headers or "max-age=" not in headers["strict-transport-security"]:
        vulnerabilities.append(Vulnerability(
            url=url,
            name="Missing or insecure Strict-Transport-Security header",
            description="The Strict-Transport-Security header should be present and contain 'max-age=' to enforce secure connections.",
            severity=Severity.HIGH
        ))

    # Ensure Expect-CT is not used as it's deprecated and no longer recommended
    if "expect-ct" in headers:
        vulnerabilities.append(Vulnerability(
            url=url,
            name="Deprecated Expect-CT header",
            description="The Expect-CT header is deprecated and no longer recommended for use.",
            severity=Severity.LOW
        ))

    # Ensure Content-Security-Policy is present and configured well to prevent various types of attacks
    if "content-security-policy" not in headers:
        vulnerabilities.append(Vulnerability(
            url=url,
            name="Missing Content-Security-Policy header",
            description="The Content-Security-Policy header should be present and configured well to prevent various types of attacks.",
            severity=Severity.HIGH
        ))

    # Ensure Access-Control-Allow-Origin is not set to '*' unless required for specific functionality
    if "access-control-allow-origin" in headers and headers["access-control-allow-origin"] == "*":
        vulnerabilities.append(Vulnerability(
            url=url,
            name="Access-Control-Allow-Origin set to *",
            description="The Access-Control-Allow-Origin header should not be set to '*' unless required for specific functionality.",
            severity=Severity.MEDIUM
        ))

    # Ensure Cross-Origin-Resource-Policy is set to 'same-site' to prevent cross-site data leaks
    if "cross-origin-resource-policy" not in headers or headers["cross-origin-resource-policy"].lower() != "same-site":
        vulnerabilities.append(Vulnerability(
            url=url,
            name="Missing or insecure Cross-Origin-Resource-Policy header",
            description="The Cross-Origin-Resource-Policy header should be set to 'same-site' to prevent cross-site data leaks.",
            severity=Severity.MEDIUM
        ))

    # Ensure Permissions-Policy is present and restricts unnecessary permissions
    if "permissions-policy" in headers:
        if "geolocation=()" not in headers["permissions-policy"]:
            vulnerabilities.append(Vulnerability(
                url=url,
                name="Unnecessary geolocation permission in Permissions-Policy header",
                description="The Permissions-Policy header should disable 'geolocation=()' if not used.",
                severity=Severity.LOW
            ))
        if "camera=()" not in headers["permissions-policy"]:
            vulnerabilities.append(Vulnerability(
                url=url,
                name="Unnecessary camera permission in Permissions-Policy header",
                description="The Permissions-Policy header should disable 'camera=()' if not used.",
                severity=Severity.LOW
            ))
        if "microphone=()" not in headers["permissions-policy"]:
            vulnerabilities.append(Vulnerability(
                url=url,
                name="Unnecessary microphone permission in Permissions-Policy header",
                description="The Permissions-Policy header should disable 'microphone=()' if not used.",
                severity=Severity.LOW
            ))
        if "interest-cohort=()" not in headers["permissions-policy"]:
            vulnerabilities.append(Vulnerability(
                url=url,
                name="Missing interest-cohort permission in Permissions-Policy header",
                description="The Permissions-Policy header should have 'interest-cohort=()' to opt out of FLoC.",
                severity=Severity.MEDIUM
            ))
    else:
        vulnerabilities.append(Vulnerability(
            url=url,
            name="Missing Permissions-Policy header",
            description="The Permissions-Policy header should be present in the header.",
            severity=Severity.HIGH
        ))

    # Ensure Server header is not present to reduce information leakage
    if "server" in headers:
        vulnerabilities.append(Vulnerability(
            url=url,
            name="Server header present",
            description="The Server header should not be present in the header to reduce information leakage.",
            severity=Severity.MEDIUM
        ))

    # Ensure X-Powered-By header is not present to reduce information leakage
    if "x-powered-by" in headers:
        vulnerabilities.append(Vulnerability(
            url=url,
            name="X-Powered-By header present",
            description="The X-Powered-By header should not be present in the header to reduce information leakage.",
            severity=Severity.MEDIUM
        ))

    # Ensure X-AspNet-Version header is not present to reduce information leakage
    if "x-aspnet-version" in headers:
        vulnerabilities.append(Vulnerability(
            url=url,
            name="X-AspNet-Version header present",
            description="The X-AspNet-Version header should not be present in the header to reduce information leakage.",
            severity=Severity.MEDIUM
        ))

    # Ensure X-AspNetMvc-Version header is not present to reduce information leakage
    if "x-aspnetmvc-version" in headers:
        vulnerabilities.append(Vulnerability(
            url=url,
            name="X-AspNetMvc-Version header present",
            description="The X-AspNetMvc-Version header should not be present in the header to reduce information leakage.",
            severity=Severity.MEDIUM
        ))

    # Ensure X-DNS-Prefetch-Control is present and set to 'off' to prevent DNS prefetching
    if "x-dns-prefetch-control" not in headers or headers["x-dns-prefetch-control"].lower() != "off":
        vulnerabilities.append(Vulnerability(
            url=url,
            name="Missing or insecure X-DNS-Prefetch-Control header",
            description="The X-DNS-Prefetch-Control header should be present and set to 'off' to prevent DNS prefetching.",
            severity=Severity.LOW
        ))

    # Ensure Public-Key-Pins is not used anymore as it's deprecated
    if "public-key-pins" in headers:
        vulnerabilities.append(Vulnerability(
            url=url,
            name="Deprecated Public-Key-Pins header",
            description="The Public-Key-Pins header should not be used anymore as it's deprecated.",
            severity=Severity.LOW
        ))

    return vulnerabilities