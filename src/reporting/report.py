"""
crawl.py

This script provides functions for crawling a website and extracting internal links.

Author: Mercury Dev
Date: 19/03/24

Functions:
- get_links(url, content): Extracts internal links from a webpage's HTML content.
- crawl(url, depth, proxies, timeout): Crawls a website starting from a given URL up to a specified depth, collecting all internal links found.
"""

from datetime import datetime
import json
from enum import Enum

# Define an enum for the severity levels of vulnerabilities
class Severity(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

# Define a class to represent a vulnerability
class Vulnerability:
    def __init__(self, url: str, name: str, description: str, severity: Severity, evidence: str=None) -> None:
        """
        Initializes a Vulnerability instance.

        Args:
        - url (str): The URL where the vulnerability was found.
        - name (str): The name of the vulnerability.
        - description (str): A description of the vulnerability.
        - severity (Severity): The severity level of the vulnerability.
        - evidence (str, optional): Evidence or additional information about the vulnerability. Defaults to None.
        """
        self.url = url
        self.name = name
        self.description = description
        self.severity = severity
        self.evidence = evidence
        
        self.urls = [] # Used later to store all affected URLs

class Report:
    def __init__(self, url: str, version: str) -> None:
        """
        Initializes a Report instance.

        Args:
        - url (str): The URL of the scanned website.
        - version (str): The current version of HyperZ.
        """
        self.start_time = datetime.now()
        self.url = url
        self.version = version
        self.vulnerabilities = {}

    def add_vulnerability(self, vulnerability: Vulnerability):
        """
        Adds a vulnerability to the report.

        If a vulnerability with the same name already exists, the URL is added to its list of affected URLs.

        Args:
        - vulnerability (Vulnerability): The vulnerability to add to the report.
        """
        if vulnerability.name in self.vulnerabilities:
            self.vulnerabilities[vulnerability.name].urls.append(vulnerability.url)
        else:
            self.vulnerabilities[vulnerability.name] = vulnerability
            self.vulnerabilities[vulnerability.name].urls.append(vulnerability.url)
            
    def generate_report(self, total_scanned, out_file):
        """
        Generates a report of the vulnerabilities found during the scan.

        Args:
        - total_scanned (int): The total number of URLs scanned.
        - out_file (str): The path to the output file where the report will be saved.
        """
        end_time = datetime.now() # Record the end time of the scan
        duration = end_time - self.start_time # Calculate the duration of the scan
        
        # Convert each vulnerability to a dictionary format for the report
        vulnerabilities = []
        for vulnerability in self.vulnerabilities.values():
            vulnerability_dict = {
                "name": vulnerability.name,
                "description": vulnerability.description,
                "severity": vulnerability.severity.value,
                "evidence": vulnerability.evidence,
                "urls": vulnerability.urls
            }
            vulnerabilities.append(vulnerability_dict)

        # Create report as JSON object
        report = {
            "hyperz": {
                "version": self.version
            },
            "report_details": {
                "original_url": self.url,
                "total_scanned": total_scanned,
                "duration": str(duration),
                "start_time": self.start_time.strftime("%Y-%m-%d %H:%M:%S"),
                "end_time": end_time.strftime("%Y-%m-%d %H:%M:%S"),
            },
            "vulnerabilities": vulnerabilities
        }

        # Save report to file
        with open(out_file, "w") as f:
            f.write(json.dumps(report, indent=4))