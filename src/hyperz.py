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

def main():
    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    arg_parser = argparse.ArgumentParser(description="HyperZ Web Application Scanner")
    arg_parser.add_argument("-u", "--url", required=True, help="URL to scan")
    arg_parser.add_argument("-d", "--depth", type=int, default=10000, help="Depth limit for crawling (default: 10000)")
    arg_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = arg_parser.parse_args()

    if (args.verbose):
        logging.info(f"Scanning URL: {args.url}")
    links = crawl(args.url, args.depth)
    if (args.verbose):
        logging.info(f"Found {len(links)} links from crawling")

    links_dict = {link: {} for link in links}
    with open("links.json", "w") as f:
        json.dump(links_dict, f, indent=4)

if __name__ == "__main__":
    main()