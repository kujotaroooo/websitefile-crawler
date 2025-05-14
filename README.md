# websitefile-crawler
git clone https://github.com/kujotaroooo/web-fuzzer.git    clone this

# Web Fuzzer - Web Directory and File Scanner

A Python-based web directory and file enumeration tool that helps discover hidden files, directories, and potential entry points on web servers. This tool is designed for security testing and should only be used on systems you own or have explicit permission to test.

## Features

- Fast multi-threaded scanning
- Built-in wordlist of common files and directories
- Support for custom wordlists
- Colored output for better visibility
- Adjustable thread count and timeout settings
- Detailed scan results with status codes
- Cross-platform compatibility

## Prerequisites

- Python 3.6 or higher
- `requests` library

## Installation

1. Clone the repository:
```bash
git clone https://github.com/kujotaroooo/web-fuzzer.git
cd web-fuzzer
```

2. Install required dependencies:
```bash
pip install requests
```

## Usage

Basic usage:
```bash
python web_fuzzer.py https://example.com
```

With custom wordlist:
```bash
python web_fuzzer.py https://example.com -w /path/to/wordlist.txt
```

### Command Line Options

- `url`: Target URL to scan (required)
- `-w, --wordlist`: Path to custom wordlist file (optional)
- `-t, --threads`: Number of threads (default: 10)
- `--timeout`: Request timeout in seconds (default: 10)

### Examples

1. Basic scan with default wordlist:
```bash
python web_fuzzer.py https://example.com
```

2. Scan with custom wordlist and 20 threads:
```bash
python web_fuzzer.py https://example.com -w wordlist.txt -t 20
```

3. Scan with increased timeout:
```bash
python web_fuzzer.py https://example.com --timeout 15
```

## Default Wordlist

The tool includes a default wordlist with common web files and directories, including:
- Admin panels
- Login pages
- Backup files
- Configuration files
- Common CMS paths
- And more...

## Legal Disclaimer

This tool is provided for educational and authorized testing purposes only. Unauthorized scanning of web applications may be illegal. Always:

1. Obtain explicit permission before scanning any systems
2. Follow responsible disclosure practices
3. Comply with all applicable laws and regulations
4. Use the tool only on systems you own or have permission to test

## Contributing

Feel free to submit pull requests, report bugs, or suggest features. Please ensure your contributions align with the tool's educational and ethical purposes.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author's Note

Remember that web scanning is a powerful capability that should be used responsibly. This tool is meant for:
- Security research
- Vulnerability assessment
- Educational purposes
- Authorized penetration testing

Always use security tools ethically and legally. 
