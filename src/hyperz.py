"""
Author: Mercury Dev
Date: 19/03/24
Description: Contains main implementation of HyperZ scanner
"""

import argparse
import logging
import json
import sys

from crawl import crawl
from header_security import get_insecure_headers

def main():
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)
    
    arg_parser = argparse.ArgumentParser(description="HyperZ Web Application Scanner")
    arg_parser.add_argument("-u", "--url", required=True, help="URL to scan")
    arg_parser.add_argument("-d", "--depth", type=int, default=10000, help="Depth limit for crawling (default: 10000)")
    arg_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = arg_parser.parse_args()

    logging.info(f"Scanning URL: {args.url}")
    logging.info(f"Crawling {args.url}")

    links = crawl(args.url, args.depth)
    if (args.verbose):
        logging.info(f"Found {len(links)} links from crawling")

    total_severe = 0
    total_moderate = 0
    total_mild = 0

    for link, item in links.items():
        insecure_headers = get_insecure_headers(item["headers"])
        links[link]["insecure_headers"] = insecure_headers
        
        total_severe += len(insecure_headers["Severe"])
        total_moderate += len(insecure_headers["Moderate"])
        total_mild += len(insecure_headers["Mild"])
    
    total = total_mild + total_moderate + total_severe

    if total:
        logging.info(f"Found {total} potential header vulnerabilities across {len(links)} links")
        logging.info(f"\t| Severe:   {total_severe}")
        logging.info(f"\t| Moderate: {total_moderate}")
        logging.info(f"\t| Mild:     {total_mild}")

    links_dict = {link: {"request_headers": links[link]['headers'], "insecure_headers": links[link]["insecure_headers"]} for link in links}
    with open("links.json", "w") as f:
        json.dump(links_dict, f, indent=4)

if __name__ == "__main__":
    main()