# 「👻」 Spooky v1.4

<p align="center">API Key and Secret Scanner</p>

A powerful Go-based security tool designed to detect exposed API keys and secrets in web applications. It scans JavaScript files and HTML pages for potentially leaked credentials, helping developers and security professionals identify and fix security vulnerabilities before they can be exploited.

## Features

- Multi-threaded scanning for high performance
- Support for scanning Majestic Million top sites
- Configurable percentage-based scanning
- Category-based secret detection
- Framework-specific secret detection
- HTML-aware scanning with proper parsing
- Detailed statistics and reporting
- JSON output support
- Cross-platform support

## Pattern Support

Spooky supports detection patterns across multiple categories including:
- Cloud & Infrastructure (AWS, Google Cloud, Azure)
- Payment Services (Stripe, PayPal, Square)
- Databases (MongoDB, MySQL, PostgreSQL)
- Social Media & Communication
- Email & Messaging Services
- Development & CI/CD Systems
- Authentication & Identity
- Web Frameworks

See [PATTERNS.md](PATTERNS.md) for a complete list of supported patterns and secret types.

## Command Line Options

- `-s`: Silent mode (suppresses banner)
- `-t`: Number of threads (default: 50)
- `-ua`: User-Agent string (default: "Spooky")
- `-d`: Detailed mode (shows line numbers for matches)
- `-m`: Use Majestic Million list for scanning
- `-p`: Percentage of Majestic Million to scan (1-100, default: 100)
- `-c`: Category to scan (AWS, API, Cloud, Payment, Database, PrivateKey, Social, Communication, Service, Framework, or 'all')
- `-o`: Output results to JSON file (e.g., "results.json")

## Usage Examples

Scan URLs from stdin:
```bash
cat urls.txt | ./spooky
```

Scan Majestic Million top sites:
```bash
./spooky -m
```

Scan top 10% of Majestic Million:
```bash
./spooky -m -p 10
```

Scan only for AWS credentials:
```bash
cat urls.txt | ./spooky -c AWS
```

Detailed scan for payment secrets with JSON output:
```bash
cat urls.txt | ./spooky -c Payment -d -o results.json
```

Scan for framework secrets:
```bash
cat urls.txt | ./spooky -c Framework
```

## JSON Output Format

When using the `-o` flag, Spooky outputs findings in a structured JSON format. Each finding includes the URL where the secret was found, the category of the secret, and the detected secret value:

```json
[
  {
    "url": "https://example.com",
    "secrets": [
      {
        "category": "AWS",
        "pattern_type": "AWS Access Key ID",
        "value": "[EXAMPLE-AWS-KEY]"
      },
      {
        "category": "Framework",
        "pattern_type": "Django Secret Key",
        "value": "[EXAMPLE-DJANGO-KEY]"
      }
    ]
  }
]
```

This JSON format makes it easy to:
- Process findings programmatically
- Integrate with other security tools
- Generate custom reports
- Track findings across multiple scans
- Filter and analyze results by category or URL

## Install

From go:
```bash
go install github.com/gregcmartin/spooky@latest
```

From source code:
```bash
git clone https://github.com/gregcmartin/spooky
cd spooky
make
./build/spooky-amd64-linux -h
```

## Supported Platforms

The tool supports multiple platforms and architectures:

- Linux: AMD64, i386, ARM64, ARMv5, ARMv6, ARMv7
- macOS: Intel (AMD64), Apple Silicon (ARM64)
- Windows: AMD64, i386

## Performance

Spooky is designed for high performance:
- Pre-compiled regex patterns
- Concurrent scanning with configurable threads
- Memory-efficient streaming for large datasets
- Category-based filtering to reduce processing overhead
- Optimized pattern matching with early exits
- HTML-aware scanning with proper parsing
- Framework-specific pattern optimization

## Credits

This project was inspired by and builds upon the work of:
- [mantra](https://github.com/brosck/mantra) - Original API key scanning concept
- [Key-Checker](https://github.com/daffainfo/Key-Checker) - Pattern matching and validation techniques
- [keyhacks](https://github.com/streaak/keyhacks) - Comprehensive API key patterns and validation methods
- [badsecrets](https://github.com/blacklanternsecurity/badsecrets) - Framework-specific secret patterns and detection techniques
