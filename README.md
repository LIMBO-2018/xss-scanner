# XSS Scanner

A professional-grade Cross-Site Scripting (XSS) vulnerability scanner designed to work on Termux without root access.

## Features

- Scan for XSS vulnerabilities in URL parameters, form inputs, and JavaScript
- Multi-threaded scanning for faster results
- Advanced payload detection with context-specific testing
- Crawling capability to discover more pages with potential vulnerabilities
- User-friendly interface with progress indicators
- Detailed reporting with exploitation examples
- Works on Termux without root access

## Installation

### On Termux

```bash
# Update packages
pkg update && pkg upgrade

# Install required packages
pkg install python git

# Clone the repository
git clone https://github.com/yourusername/xss-scanner.git
cd xss-scanner

# Install the tool
chmod +x install.sh
./install.sh
```

### On Other Linux Systems

```bash
# Clone the repository
git clone https://github.com/yourusername/xss-scanner.git
cd xss-scanner

# Install the tool
pip install -e .
```

## Usage

### Basic Usage

```bash
# Run the tool
xss-scanner
```

### Command Line Options

```bash
# Show help
xss-scanner --help

# Scan a specific URL
xss-scanner --url https://example.com

# Scan URLs from a file
xss-scanner --file urls.txt

# Advanced scan with more threads
xss-scanner --url https://example.com --threads 10 --advanced
```

## How It Works

1. **Input Discovery**: The scanner identifies all possible input points including URL parameters, form inputs, and JavaScript variables.

2. **Payload Testing**: It tests each input point with various XSS payloads, including basic, advanced, and context-specific payloads.

3. **Vulnerability Detection**: The scanner analyzes responses to detect if payloads are reflected in a way that could lead to XSS.

4. **Reporting**: Detailed reports are generated showing all discovered vulnerabilities with exploitation examples.

## Advanced Options

- **Threads**: Control the number of concurrent tests
- **Timeout**: Set request timeout duration
- **Delay**: Add delay between requests to avoid overwhelming the server
- **Advanced Payloads**: Use more sophisticated payloads for better detection
- **Crawling**: Discover more pages on the target site

## Disclaimer

This tool is intended for security professionals, penetration testers, and system administrators to test their own systems or systems they have permission to test. Unauthorized scanning of websites is illegal and unethical.

The developers are not responsible for any misuse or damage caused by this tool.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

