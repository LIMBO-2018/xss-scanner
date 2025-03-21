#!/bin/bash

echo "Installing XSS Scanner for Termux..."

# Update packages
pkg update -y && pkg upgrade -y

# Install required packages
pkg install -y python git

# Install Python dependencies
pip install requests beautifulsoup4 colorama tqdm urllib3 html5lib lxml

# Install the tool
pip install -e .

echo "Installation complete!"
echo "Run 'xss-scanner' to start the tool."

