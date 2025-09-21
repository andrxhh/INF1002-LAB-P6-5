# PhishGuard GUI Integration

This document explains how to use the integrated PhishGuard GUI system.

## Overview

The PhishGuard GUI has been successfully integrated into your existing PhishGuard rule-based detection system. The integration provides:

- **Individual Email Analysis**: Analyze single emails with detailed breakdown
- **Batch Email Processing**: Process multiple emails from files
- **Visual Risk Scoring**: Color-coded results and recommendations
- **Integration with Existing Rules**: Uses your current keyword, whitelist, URL analysis, and other detection rules

## Quick Start

### Method 1: Using the CLI with GUI flag
```bash
# From project root
python -m phishguard.cli.main --gui
```

### Method 2: Using the launcher script
```bash
# From project root
python launch_gui.py
```

### Method 3: Using the installed package
```bash
# If you have installed the package
phishguard --gui
```

## Features

### Individual Analysis Tab
- Enter sender email, subject, and body text
- Get immediate analysis with:
  - Risk classification (SAFE/SUSPICIOUS/PHISHING)
  - Detailed rule breakdowns
  - Security recommendations
  - Technical analysis details

### Batch Analysis Tab
- Process multiple emails from a file
- Supported formats: .eml files, mbox files, text files with email content
- Generate summary statistics
- Export detailed reports

### System Status Tab
- View system information and configuration
- Check rule status and dependencies
- Monitor threat intelligence (when available)

## CLI Usage

The system also supports command-line usage:

```bash
# Analyze emails in a directory
phishguard emails/

# Analyze a single email file
phishguard email.eml

# Use custom configuration
phishguard --config custom.json emails/

# Save results to file
phishguard --output results.json emails/

# Verbose output
phishguard --verbose emails/
```

## Architecture

The integration consists of several key components:

### Core Integration Files
- `src/phishguard/app/detector.py` - PhishingDetector wrapper class
- `src/phishguard/app/ui.py` - Main GUI application
- `src/phishguard/normalize/parse_mime.py` - Email parsing utilities
- `src/phishguard/cli/main.py` - Updated CLI with GUI support

### Rule System
The GUI uses your existing rule system:
- Keywords detection
- Domain whitelist checking
- URL red flags analysis
- Authentication results (SPF/DKIM/DMARC)
- And more...

### Configuration
Uses your existing `config/config.json` for all rule settings and thresholds.

## Dependencies

### Required (Built-in)
- Python 3.10+
- tkinter (usually included with Python)
- email (Python standard library)
- json, csv, re (Python standard library)

### Optional (Enhanced Features)
- `python-Levenshtein` - For enhanced URL similarity analysis
- `beautifulsoup4` - For HTML parsing in URL extraction

## File Structure After Integration

```
phishguard/
├── src/phishguard/
│   ├── app/
│   │   ├── detector.py          # NEW: GUI integration wrapper
│   │   └── ui.py                # NEW: GUI application
│   ├── cli/
│   │   └── main.py              # UPDATED: Added GUI support
│   ├── normalize/
│   │   └── parse_mime.py        # NEW: Email parsing utilities
│   ├── scoring/
│   │   └── aggregate.py         # UPDATED: Implemented evaluation
│   ├── reporting/
│   │   └── writers.py           # NEW: Results output
│   └── rules/                   # EXISTING: Your rule files
├── config/
│   └── config.json              # EXISTING: Your configuration
└── launch_gui.py                # NEW: Simple launcher script
```

## Troubleshooting

### Common Issues

1. **GUI won't start**: Make sure tkinter is installed
   ```bash
   python -c "import tkinter; print('tkinter available')"
   ```

2. **Import errors**: Make sure you're running from the project root or have the package installed

3. **Rule errors**: Check the console output for rule-specific error messages

4. **No emails detected in batch**: Ensure your email files are in supported formats

### Getting Help

- Check the console output for detailed error messages
- Verify your config.json is valid JSON
- Test with the sample email first (Load Sample button)

## Next Steps

The integration provides a foundation that can be extended with:

- Dynamic threat intelligence generation
- Enhanced reporting features
- Additional rule implementations
- Email dataset analysis tools

The current implementation includes placeholder stub implementations for some rules, which can be replaced with full implementations as needed.
