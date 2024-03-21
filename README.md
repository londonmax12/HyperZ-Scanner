# 🚀 HyperZ Vulnerability Scanner
HyperZ is a work-in-progress web application vulnerability scanner designed to crawl through a website and identify potential security issues. It can be used to discover sensitive information disclosure, and other common vulnerabilities.
## 📥 Installation
1. Clone the repository 
```
git clone https://github.com/londonmax12/hyperz-scanner
```
2. Install required dependencies
```
pip install -r requirements.txt
```
## Usage
1. Run the scanner using the following command
```
python hyperz.py -u <url> [-d <depth>] [-v] [-p <proxy_list>] [-g] [-t <timeout>] [-o <output_file>]

```
2. View results in the specified report file generated
### ⚙️ Command Options
- -u, --url <url>: URL to scan (required).
- -d, --depth <depth>: Depth limit for crawling (default: 5).
- -v, --verbose: Enable verbose output.
- --p, --proxy_list <proxy_list>: File that contains a list of proxies to use.
- -g, --get_proxies: Get proxies to use from: https://www.sslproxies.org/.
- -t, --timeout <timeout>: Timeout on website requests (default: 5).
- -o, --output_file <output_file>: Specify the output file for the report (default: report.json).
### Example
Scan example.com with a depth limit of 3 and save the report to "output.json":
```
python hyperz.py -u http://example.com -d 3 -o output.json
```
## Development Roadmap
### Features Added
- URL Crawling
    - Simple URL crawling that retrieves all href anchor tags from a specified link
- Proxy support
    - Dynamic proxy fetching
    - Proxy file
- Header Security Analysis 
    - Ability to scan request headers for potential vulnerabilities and ensure they are properly configured to prevent common attacks
- Report Generation
    - Report specifications
    - Vulnerabilities found and effect URLs
### Features To Be Added
The following features are currently **NOT** added. This simply serves as a roadmap
- Input Validation Testing
    - Other input payload attacks
- Authentication Testing
    - Check strength of authentication mechanism
        - Presence of default credentials
    - Check for weak password policies
- Session Management Testing
    - Analyse how session tokens are generated, and transfered
    - Check for session related vulnerabilities
- Authorisation
    - Check if users can access resourses they are not meant to
- Sensitive Data Exposure
    - Indentify areas where sensitive data might be exposed
- Specific Attack Testing
    - SQL Injection
    - Cross-Site Scripting
    - Cross-Site Request Forgery Testing
    - Clickjacking testing
    - Open Redirect Testing
- SSL/TLS Testing
    - Verify configuration of SSL/TLS certificates
- API Security Testing
    - API Fuzzing
- Out-of-date Software testing
    - Identify software versions that may contain known vulnerabilities
## Contributing
Contributions are welcome and appreciated! Please fork the repository and submit a pull request with your changes.
## License
This project is licensed under the MIT License