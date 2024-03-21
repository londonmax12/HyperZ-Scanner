"""
hyperz.py
Contains main implementation of HyperZ scanner

Author: Mercury Dev
Date: 19/03/24

Functions:
- main(): Runs main command line application

Usage:
  python hyperz.py -u <url> [-d <depth>] [-v]

Options:
  -u, --url <url>       URL to scan (required)
  -d, --depth <depth>   Depth limit for crawling (default: 5)
  -v, --verbose         Enable verbose output
"""

import argparse
import logging
import json
import sys

from gathering.crawl import crawl
from scanning.header_scanning import get_insecure_headers

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
    print("  - Version: 0.1.2")
    print("  - Developed by Mercury Dev")
    print("=====================================================\n")

def main():
    print_header()
    
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)
    
    arg_parser = argparse.ArgumentParser(description="HyperZ Web Application Scanner")
    arg_parser.add_argument("-u", "--url", required=True, help="URL to scan")
    arg_parser.add_argument("-d", "--depth", type=int, default=5, help="Depth limit for crawling (default: 10000)")
    arg_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = arg_parser.parse_args()

    logging.info(f"Scanning URL: {args.url}")
    
    logging.info(f"Crawling {args.url}")

    links = crawl(args.url, args.depth)
    if (args.verbose):
        logging.info(f"Found {len(links)} link{'s' if len(links) != 1 else ''} from crawling")

    total_severe = 0
    total_moderate = 0
    total_mild = 0

    logging.info(f"Analysing request headers for potential vulnerabilities")
    for link, item in links.items():
        insecure_headers = get_insecure_headers(item["headers"])
        links[link]["insecure_headers"] = insecure_headers
        
        total_severe += len(insecure_headers["Severe"])
        total_moderate += len(insecure_headers["Moderate"])
        total_mild += len(insecure_headers["Mild"])
    
    total = total_mild + total_moderate + total_severe
    logging.info(f"Found {total} potential header vulnerabilities across {len(links)} link{'s' if len(links) != 1 else ''}")
    
    if total and args.verbose:
        logging.info(f"  - Severe:   {total_severe}")
        logging.info(f"  - Moderate: {total_moderate}")
        logging.info(f"  - Mild:     {total_mild}")

    save_file = "report.json"
    logging.info(f"Finished scanning, saving report detail to {save_file}")
    links_dict = {link: {"request_headers": links[link]['headers'], "insecure_headers": links[link]["insecure_headers"]} for link in links}
    with open(save_file, "w") as f:
        json.dump(links_dict, f, indent=4)

if __name__ == "__main__":
    main()