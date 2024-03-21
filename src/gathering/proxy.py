"""
proxy.py

This script provides proxy related functions

Author: Mercury Dev
Date: 21/03/24

Functions:
- get_proxies(): Fetches a list of proxies provided by https://www.sslproxies.org/
"""
from bs4 import BeautifulSoup
import requests

def get_proxies() -> list[str]:
    """
    Fetches a list of proxies provided by https://www.sslproxies.org/

    Returns:
        - list[str]: Array of proxies
    """
    url = 'https://www.sslproxies.org/'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }
    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.content, 'html.parser')
    proxies_table_div = soup.find('div', {'class': 'table-responsive fpl-list'})

    if proxies_table_div is None:
        raise ValueError("Unable to find proxies table on website")
    
    proxies_table = proxies_table_div.find('table')
    proxies = []

    for row in proxies_table.tbody.find_all('tr'):
        ip = row.find_all('td')[0].string
        port = row.find_all('td')[1].string
        proxies.append(f"{ip}:{port}")

    return proxies
