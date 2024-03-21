# HyperZ Vulnerability Scanner
HyperZ is a work-in-progress web application vulnerability scanner designed to crawl through a website and identify potential security issues. It can be used to discover sensitive information disclosure, and other common vulnerabilities.
## Installation
1. Clone the repository 
```
git clone https://github.com/your-username/hyperz.git
```
2. Install required dependencies
```
pip install -r requirements.txt
```
## Usage
1. Run the scanner using the following command
```
python main.py -u <url> -d <depth>
```
2. View results in the links.json file generated in current working directory
## Development Roadmap
### Features Added
- URL Crawling
    - Simple URL crawling that retrieves all href anchor tags from a specified link
- Proxy support
    - Dynamic proxy fetching
    - Proxy file
- Header Security Analysis
    - Ability to scan through request headers for potential vulnerabilities, ensuring they are properly configured to prevent common attacks
### Features To Be Added
These features are currently **NOT** added
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