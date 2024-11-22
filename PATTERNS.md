# Supported Secret Patterns

Spooky can detect a wide range of secrets across multiple categories:

## Cloud & Infrastructure [Cloud]
- AWS (Access Keys, Secret Keys, ARNs)
- Google Cloud (API Keys, OAuth Tokens, KMS)
- Azure
- DigitalOcean
- Heroku

## Payment Services [Payment]
- Stripe (Public/Private/Restricted Keys)
- PayPal (Access Tokens)
- Square (Access/OAuth Tokens)
- Braintree

## Databases [Database]
- MongoDB Connection Strings (Standard/SRV)
- MySQL Credentials
- PostgreSQL Credentials
- Redis Passwords
- Cassandra Credentials
- JDBC Connection Strings

## Social Media & Communication [Social]
- Twitter API Keys
- Facebook App Secrets
- GitHub Tokens (Personal/OAuth)
- Slack Tokens/Webhooks
- Instagram Access Tokens
- LinkedIn Client Secrets
- YouTube API Keys
- Telegram Bot Tokens

## Email & Messaging [Communication]
- Twilio (Tokens, SIDs)
- SendGrid
- Mailgun
- Mailchimp
- Postmark
- Nexmo

## Development & CI/CD [Service]
- NPM Tokens
- Docker Hub Credentials
- Travis CI Tokens
- Circle CI Tokens
- Jenkins API Tokens
- Sentry Auth Tokens
- SonarQube Tokens
- Artifactory Tokens
- JWT Tokens

## Authentication & Identity [API]
- Okta API Tokens
- Auth0 Tokens
- Private Keys (RSA, DSA, EC, SSH, PGP)
- Bearer Tokens
- API Keys & Secrets
- Basic Auth Credentials

## Web Frameworks [Framework]
- Django (Secret Keys, Signing Keys)
- Flask (Session Keys)
- Express (Session/Cookie Secrets)
- Laravel (App Keys)
- Rails (Secret Key Base)
- ASP.NET (ViewState, Machine Keys)
- Symfony (App Secrets)
- JSF (ViewState Secrets)
- Telerik (Encryption/Hash Keys)
