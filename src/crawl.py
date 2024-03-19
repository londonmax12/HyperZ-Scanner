"""
Author: Mercury Dev
Date: 19/03/24
Description: Contains function definitions to crawl
    through a website and get sub domains
"""

# Imports
import requests
from bs4 import BeautifulSoup

from urllib.parse import urlparse, urljoin

# Function that returns hrefs in a URL
def get_links(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    links = []
    # Get all anchor tag
    for link in soup.find_all('a'):
        # Get URL in anchor tag and validate it
        href = link.get('href')
        if href:
            full_url = urljoin(url, href)
            parsed_url = urlparse(full_url)
            # Remove anchor points from URLs
            url_without_anchor = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            if parsed_url.netloc == urlparse(url).netloc:
                links.append(url_without_anchor)

    return links

# Function to crawl through a URL and get links
def crawl(url, depth=10000):
    # Set of unique URLs
    visited_urls = set()
    urls_to_visit = [(url, 0)]  # Tuple of URL and depth

    # While there are more URLs to visit
    while urls_to_visit:
        # Get the next URL to visit and make sure it hasn't been visited
        current_url, current_depth = urls_to_visit.pop()
        if current_url in visited_urls or current_depth >= depth:
            continue
        
        # Crawl through URL
        visited_urls.add(current_url)
        links = get_links(current_url)

        # Add found links into URLs to visit list with depth incremented by 1
        for link in links:
            if link not in visited_urls:
                urls_to_visit.append((link, current_depth + 1))
        
    return visited_urls