"""
hyperz.py
Contains main implementation of HyperZ scanner

Author: Mercury Dev
Date: 19/03/24

Functions:
- print_header(): Prints application header
- main(): Runs main command line application

Usage:
  python hyperz.py -u <url> [-d <depth>] [-v]

Options:
  -u, --url <url>       URL to scan (required)
  -d, --depth <depth>   Depth limit for crawling (default: 5)
  -v, --verbose         Enable verbose output
  -p, --proxies         File that contains list of proxies to use
"""

import argparse
import logging
import json
import sys

from gathering.crawl import crawl
from gathering.proxy import get_proxies
from scanning.header_scanning import get_insecure_headers
from reporting.report import Report, Vulnerability, Severity

VERSION = "0.1.3"

def print_header():
    print("""
=====================================================
                                                     
  ██░ ██▓██   ██▓ ██▓███  ▓█████  ██▀███  ▒███████▒  
  ▓██░ ██▒▒██  ██▒▓██░  ██▒▓█   ▀ ▓██ ▒ ██▒▒ ▒ ▒ ▄▀░ 
 ▒██▀▀██░ ▒██ ██░▓██░ ██▓▒▒███   ▓██ ░▄█ ▒░ ▒ ▄▀▒░   
 ░▓█ ░██  ░ ▐██▓░▒██▄█▓▒ ▒▒▓█  ▄ ▒██▀▀█▄    ▄▀▒   ░  
 ░▓█▒░██▓ ░ ██▒▓░▒██▒ ░  ░░▒████▒░██▓ ▒██▒▒███████▒  
   ▒ ░░▒░▒  ██▒▒▒ ▒▓▒░ ░  ░░░ ▒░ ░░ ▒▓ ░▒▓░░▒▒ ▓░▒░▒ 
  ▒ ░▒░ ░▓██ ░▒░ ░▒ ░      ░ ░  ░  ░▒ ░ ▒░░░▒ ▒ ░ ▒  
  ░  ░░ ░▒ ▒ ░░  ░░          ░     ░░   ░ ░ ░ ░ ░ ░  
  ░  ░  ░░ ░                 ░  ░   ░       ░ ░      
         ░ ░                              ░""")
    print("HyperZ Web Application Scanner")
    print(f"  - Version: {VERSION}")
    print("  - Developed by Mercury Dev")
    print("=====================================================\n")

def main():
    # Print application header
    print_header()
    
    # Set up logging
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)
    
    # Parse command line arguments
    arg_parser = argparse.ArgumentParser(description="HyperZ Web Application Scanner")
    arg_parser.add_argument("-u", "--url", required=True, help="URL to scan")
    arg_parser.add_argument("-d", "--depth", type=int, default=5, help="Depth limit for crawling (default: 5)")
    arg_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    arg_parser.add_argument("-p", "--proxy_list", help="File list of proxies to use, if get_proxies is specified the proxies in proxy list will be added on")
    arg_parser.add_argument("-g", "--get_proxies", action="store_true", help="Get proxies to use from: https://www.sslproxies.org/")
    arg_parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout on website requests (default: 5)")
    arg_parser.add_argument("-o", "--output_file", default="report.json")
    args = arg_parser.parse_args()

    logging.info(f"Scanning URL: {args.url}")

    report = Report(args.url, VERSION)

    # Load proxies if provided
    proxies = []
    if args.proxy_list:
      with open(args.proxy_list, 'r') as file:
          proxies = [line.strip() for line in file]
      logging.info(f"Loaded proxy file with {len(proxies)} proxies")

    # Fetch proxy list if specified to
    if args.get_proxies:
        logging.info(f"Gathering proxies")
        got = get_proxies()
        if len(got) == 0:
          logging.info(f"Failed to get proxies")
          sys.exit(1)
        logging.info(f"Got {len(got)} proxies")
        proxies.extend(got)
        
    # Crawl the URL
    logging.info(f"Crawling {args.url}")
    links = crawl(args.url, args.depth, proxies, args.timeout, args.verbose)
    if (args.verbose):
        logging.info(f"Found {len(links)} link{'s' if len(links) != 1 else ''} from crawling")

    logging.info(f"Analysing request headers for potential vulnerabilities")

    # Iterate over links and responses
    for link, item in links.items():
        # Scan request headers
        insecure_headers = get_insecure_headers(link, item["headers"])

        for header in insecure_headers:
          report.add_vulnerability(header)

    # Save report
    logging.info(f"Finished scanning, saving report detail to {args.output_file}")
    report.generate_report(len(links), args.output_file)

# Run main application
if __name__ == "__main__":
    main()