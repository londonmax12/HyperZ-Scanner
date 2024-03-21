"""
utils.py

This script provides utility functions

Author: Mercury Dev
Date: 21/03/24

Functions:
- random_user_agent(): Returns a random user agent string
"""
import random

def random_user_agent() -> str:
    # List of posible browsers
    browsers = [
        "Chrome",
        "Firefox",
        "Safari",
        "Edge",
        "Opera",
        "Internet Explorer"
    ]

    # List of posible operating systems
    os = [
        "Windows NT 10.0",
        "Windows NT 6.1",
        "Windows NT 6.3",
        "Macintosh; Intel Mac OS X 10_15_7",
        "Macintosh; Intel Mac OS X 10_14_6",
        "Linux; Android 11",
        "Linux; Android 10",
        "Linux; Android 9"
    ]

    # Generate random version numbers for AppleWebKit and the browser
    webkit_version = f"{random.randint(500, 700)}.{random.randint(0, 99)}"
    browser_version = f"{random.randint(1, 99)}.{random.randint(0, 9999)}.{random.randint(0, 9999)}"

    # Generate and return a random user agent string
    return f"Mozilla/5.0 ({random.choice(os)}) AppleWebKit/{webkit_version} (KHTML, like Gecko) {random.choice(browsers)}/{browser_version} Safari/{webkit_version}"
