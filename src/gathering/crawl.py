"""
crawl.py

This script provides functions for crawling a website and extracting internal links.

Author: Mercury Dev
Date: 19/03/24

Functions:
- get_links(url, content): Extracts internal links from a webpage's HTML content.
- crawl(url, depth, proxies, timeout): Crawls a website starting from a given URL up to a specified depth, collecting all internal links found.
"""

import requests
from bs4 import BeautifulSoup

from urllib.parse import urlparse, urljoin
import random
import logging

from gathering.utils import random_user_agent

def get_links(url: str, content: bytes) -> set[str]:
    """
    Extracts internal links from a webpage's HTML content.

    Args:
    - url (str): The URL of the webpage.
    - content (bytes): The HTML content of the webpage.

    Returns:
    - set: A set of internal URLs found in the webpage.
    """

    # Use bs4 to parse HTML content
    soup = BeautifulSoup(content, 'html.parser')

    # Set to contain all unique links
    links = set()

    # Get all anchor tags
    for link in soup.find_all('a'):
        # Get URL in anchor tag and validate it
        href = link.get('href')
        if href:
            full_url = urljoin(url, href)
            parsed_url = urlparse(full_url)
            # Remove anchor points from URLs
            url_without_anchor = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            if parsed_url.netloc == urlparse(url).netloc:
                links.add(url_without_anchor)

    return links

# Function to crawl through a URL and get links
def crawl(url: str, depth: int=10000, proxies: list=[], timeout: int=5) -> dict[str, dict]:
    """
    Crawls a website starting from a given URL up to a specified depth, collecting all internal links found.

    Args:
    - url (str): The starting URL of the crawl.
    - depth (int): The maximum depth to crawl (default is 10000). NOTE: This should be set 
        to prevent excessive crawling if not necessary
    - proxies (list): A list of proxy URLs to use
    - timeout (int): Timeout for requests


    Returns:
    - dict: A dictionary of all internal URLs visited during the crawl and their responses.
    """

    # Dictionary of URLs
    visited_urls = {}
    urls_to_visit = [(url, 0)]  # Tuple of URL and depth

    # While there are more URLs to visit
    while urls_to_visit:
        # Get the next URL to visit and make sure it hasn't been visited
        current_url, current_depth = urls_to_visit.pop()
        if current_url in visited_urls or current_depth >= depth:
            continue
          
        # Get website response
        use_proxy = len(proxies) != 0
        if use_proxy:
            proxy = None
            # While there are more proxies to go over
            while not proxy and proxies:
                # Get a random proxy
                proxy = random.choice(proxies)
                # Remove the selected proxy from the list
                proxies.remove(proxy)

                proxy_dict = {"http": proxy, "https": proxy}

                # Try to get website using proxy otherwise try again
                try:
                    response = requests.get(current_url, proxies=proxy_dict, headers={"User-Agent": random_user_agent()}, timeout=timeout)
                    break  # Break out of the loop if request succeeds
                except Exception as e:
                    logging.warning(f"Proxy {proxy} failed: {e}")
                    proxy = None  # Retry with another proxy
        # If no proxies in use
        else:
            response = requests.get(current_url, headers={"User-Agent": random_user_agent()}, timeout=timeout)

        # If using proxies and none worked skip URL
        if use_proxy and not proxy:
            logging.error(f"All proxies failed, skipping URL: {current_url}")
            visited_urls[current_url] = {
                'status': "FAILED"
            }
            continue
        
        visited_urls[current_url] = {
            'content': response.content,
            'headers': {key.lower(): value for key, value in response.headers.items()}
        }

        # Crawl through website
        links = get_links(current_url, visited_urls[current_url]['content'])

        # Add found links into URLs to visit list with depth incremented by 1
        for link in links:
            if link not in visited_urls:
                urls_to_visit.append((link, current_depth + 1))
            
    return visited_urls