# 「👻」 Spooky v1.2

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

## Secret Categories

Spooky can detect a wide range of secrets across multiple categories:

### Cloud & Infrastructure
- AWS (Access Keys, Secret Keys, ARNs)
- Google Cloud (API Keys, OAuth Tokens, KMS)
- Azure
- DigitalOcean
- Heroku

### Payment Services
- Stripe (Public/Private/Restricted Keys)
- PayPal (Access Tokens)
- Square (Access/OAuth Tokens)
- Braintree

### Databases
- MongoDB Connection Strings (Standard/SRV)
- MySQL Credentials
- PostgreSQL Credentials
- Redis Passwords
- Cassandra Credentials
- JDBC Connection Strings

### Social Media & Communication
- Twitter API Keys
- Facebook App Secrets
- GitHub Tokens (Personal/OAuth)
- Slack Tokens/Webhooks
- Instagram Access Tokens
- LinkedIn Client Secrets
- YouTube API Keys
- Telegram Bot Tokens

### Email & Messaging
- Twilio (Tokens, SIDs)
- SendGrid
- Mailgun
- Mailchimp
- Postmark
- Nexmo

### Development & CI/CD
- NPM Tokens
- Docker Hub Credentials
- Travis CI Tokens
- Circle CI Tokens
- Jenkins API Tokens
- Sentry Auth Tokens
- SonarQube Tokens
- Artifactory Tokens
- JWT Tokens

### Authentication & Identity
- Okta API Tokens
- Auth0 Tokens
- Private Keys (RSA, DSA, EC, SSH, PGP)
- Bearer Tokens
- API Keys & Secrets
- Basic Auth Credentials

### Web Frameworks
- Django (Secret Keys, Signing Keys)
- Flask (Session Keys)
- Express (Session/Cookie Secrets)
- Laravel (App Keys)
- Rails (Secret Key Base)
- ASP.NET (ViewState, Machine Keys)
- Symfony (App Secrets)
- JSF (ViewState Secrets)
- Telerik (Encryption/Hash Keys)

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
  },
  {
    "url": "https://another-site.com",
    "secrets": [
      {
        "category": "Database",
        "pattern_type": "MongoDB Connection String",
        "value": "[EXAMPLE-DATABASE-CONNECTION-STRING]"
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
