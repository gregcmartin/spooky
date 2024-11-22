<h1 align="center">「👻」 Spooky v1.0</h1>

<p align="center">API Key and Secret Scanner</p>

A powerful Go-based security tool designed to detect exposed API keys and secrets in web applications. It scans JavaScript files and HTML pages for potentially leaked credentials, helping developers and security professionals identify and fix security vulnerabilities before they can be exploited.

## Features

- Multi-threaded scanning for high performance
- Support for scanning Majestic Million top sites
- Configurable percentage-based scanning
- Category-based secret detection
- Detailed statistics and reporting
- Cross-platform support

## Secret Categories

Spooky can detect a wide range of secrets across multiple categories:

### Cloud & Infrastructure
- AWS (Access Keys, Secret Keys, ARNs)
- Google Cloud (API Keys, OAuth Tokens)
- Azure
- DigitalOcean
- Heroku

### Payment Services
- Stripe (Public/Private Keys)
- PayPal
- Square
- Braintree

### Databases
- MongoDB Connection Strings
- MySQL Credentials
- PostgreSQL Credentials
- Redis Passwords
- Cassandra Credentials
- JDBC Connection Strings

### Social Media & Communication
- Twitter API Keys
- Facebook App Secrets
- GitHub Tokens
- Slack Tokens/Webhooks
- Instagram Access Tokens
- LinkedIn Client Secrets
- YouTube API Keys

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

### Authentication & Identity
- Okta API Tokens
- Auth0 Tokens
- Private Keys (RSA, SSH, PGP)
- Bearer Tokens
- API Keys & Secrets

## Command Line Options

- `-s`: Silent mode (suppresses banner)
- `-t`: Number of threads (default: 50)
- `-ua`: User-Agent string (default: "Spooky")
- `-d`: Detailed mode (shows line numbers for matches)
- `-m`: Use Majestic Million list for scanning
- `-p`: Percentage of Majestic Million to scan (1-100, default: 100)
- `-c`: Category to scan (AWS, API, Cloud, Payment, Database, PrivateKey, Social, Communication, Service, or 'all')

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

Detailed scan for payment secrets:
```bash
cat urls.txt | ./spooky -c Payment -d
```

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
