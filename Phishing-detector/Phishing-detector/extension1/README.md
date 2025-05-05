# Phishing Detector Chrome Extension

This Chrome extension helps protect users from phishing websites by analyzing links before they are clicked. It integrates with a Flask-based phishing detection system to provide real-time protection.

## Features

- Real-time phishing detection when clicking links
- Visual warnings for potentially dangerous websites
- Toggle switch to enable/disable the extension
- Integration with existing phishing detection system

## Installation

1. Make sure your Flask backend server is running on `http://localhost:5000`
2. Open Chrome and go to `chrome://extensions/`
3. Enable "Developer mode" in the top right corner
4. Click "Load unpacked" and select the `phishing-extension` folder

## Usage

1. Click the extension icon in your Chrome toolbar to open the popup
2. Use the toggle switch to enable/disable the extension
3. When enabled, the extension will analyze any link you click
4. If a phishing website is detected, you'll see:
   - A warning message in the popup
   - A temporary warning banner on the webpage
   - The option to proceed or go back

## Requirements

- Chrome browser
- Running Flask backend server (from the main phishing detection project)
- Internet connection for URL analysis

## Development

The extension consists of the following files:
- `manifest.json`: Extension configuration
- `popup.html`: Extension popup interface
- `popup.js`: Popup functionality
- `content.js`: Content script for link analysis
- `background.js`: Background script for URL processing
- `images/`: Extension icons

## Security Note

This extension requires access to all websites to function properly. It only analyzes URLs when you click on links and does not collect any personal information. 