"""
Author: Mercury Dev
Date: 21/03/24
Description: Contains functions to scan through request headers
    References: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
"""

# Function that takes in request headers and returns dict of potential vulnerabilities
def get_insecure_headers(headers):
    # Dictionary to store severities
    severities = {
        "Severe": [],
        "Moderate": [],
        "Mild": []
    }

    # Ensure X-Frame-Options is set to 'deny' or 'sameorigin' to prevent clickjacking attacks
    if "x-frame-options" not in headers or headers["x-frame-options"].lower() not in ["deny", "sameorigin"]:
        severities["Severe"].append("x-frame-options should be present and set to 'deny' or 'sameorigin'")

    # Ensure XSS protection is active to prevent cross-site scripting attacks
    if "x-xss-protection" not in headers:
        severities["Moderate"].append("x-xss-protection should be active")

    # Ensure content type options are set to 'nosniff' to prevent MIME type sniffing attacks
    if "x-content-type-options" not in headers or headers["x-content-type-options"].lower() != "nosniff":
        severities["Moderate"].append("x-content-type-options should be present and set to 'nosniff'")

    # Ensure Referrer Policy is set to 'strict-origin-when-cross-origin' to stop referrer information leakage
    if "referrer-policy" not in headers or headers["referrer-policy"].lower() != "strict-origin-when-cross-origin":
        severities["Moderate"].append("referrer-policy should be present and set to 'strict-origin-when-cross-origin'")

    # Ensure Content-Type is set to 'text/html; charset=utf-8' to specify the character set and content type
    if "content-type" not in headers or "charset=utf-8" not in headers["content-type"].lower() or "text/html" not in headers["content-type"].lower():
        severities["Mild"].append("content-type should be present and 'charset=UTF-8' and 'text/html' should be set")

    # Ensure Strict-Transport-Security is present and contains 'max-age=' to enforce secure connections
    if "strict-transport-security" not in headers or "max-age=" not in headers["strict-transport-security"]:
        severities["Moderate"].append("strict-transport-security should be present and contain 'max-age='")

    # Ensure Expect-CT is not used as it's depricated and no longer recommended
    if "expect-ct" in headers:
        severities["Moderate"].append("expect-ct usage is not recommended")

    # Ensure Content-Security-Policy is present and configured well to prevent various types of attacks
    if "content-security-policy" not in headers:
        severities["Moderate"].append("content-security-policy should be present and configured well")

    # Ensure Access-Control-Allow-Origin is not set to '*' unless required for specific functionality
    if "access-control-allow-origin" in headers and headers["access-control-allow-origin"] == "*":
        severities["Mild"].append("access-control-allow-origin should not be set to '*' unless required")

    # Ensure Cross-Origin-Resource-Policy is set to 'same-site' to prevent cross-site data leaks
    if "cross-origin-resource-policy" not in headers or headers["cross-origin-resource-policy"].lower() != "same-site":
        severities["Moderate"].append("cross-origin-resource-policy should be set to 'same-site'")

    # Ensure Permissions-Policy is present and restricts unnecessary permissions
    if "permissions-policy" in headers:
        if "geolocation=()" not in headers["permissions-policy"]:
            severities["Moderate"].append("permissions-policy should disable 'geolocation=()' if not used")
        if "camera=()" not in headers["permissions-policy"]:
            severities["Moderate"].append("permissions-policy should disable 'camera=()' if not used")
        if "microphone=()" not in headers["permissions-policy"]:
            severities["Moderate"].append("permissions-policy should disable 'microphone=()' if not used")
        if "interest-cohort=()" not in headers["permissions-policy"]:
            severities["Mild"].append("permissions-policy should have 'interest-cohort=()' to opt out of FLoC")
    else:
        severities["Moderate"].append("permissions-policy should be present in header")

    # Ensure Server header is not present to reduce information leakage
    if "server" in headers:
        severities["Severe"].append("server should not be present in header")

    # Ensure X-Powered-By header is not present to reduce information leakage
    if "x-powered-by" in headers:
        severities["Severe"].append("x-powered-by should not be present in header")

    # Ensure X-AspNet-Version header is not present to reduce information leakage
    if "x-aspnet-version" in headers:
        severities["Severe"].append("x-aspnet-version should not be present in header")

    # Ensure X-AspNetMvc-Version header is not present to reduce information leakage
    if "x-aspnetmvc-version" in headers:
        severities["Severe"].append("x-aspnetmvc-version should not be present in header")

    # Ensure X-DNS-Prefetch-Control is present and set to 'off' to prevent DNS prefetching
    if "x-dns-prefetch-control" not in headers or headers["x-dns-prefetch-control"].lower() != "off":
        severities["Mild"].append("x-dns-prefetch-control should be present and set to 'off'")

    # Ensure Public-Key-Pins is not used anymore as it's deprecated
    if "public-key-pins" in headers:
        severities["Deprecated"].append("public-key-pins should not be used anymore as it's depricated")

    return severities