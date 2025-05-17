# websitefile-crawler
git clone https://github.com/kujotaroooo/web-fuzzer.git    clone this



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




Always use security tools ethically and legally. 
