package patterns

// PatternType represents a specific type of secret pattern
type PatternType struct {
	Name      string
	Category  string
	Pattern   string
	RiskLevel string
	Impact    string
}

// GetPatternType returns the pattern type for a given pattern
func GetPatternType(pattern string) PatternType {
	for _, pt := range AllPatternTypes {
		if pt.Pattern == pattern {
			return pt
		}
	}
	return PatternType{} // Return empty pattern type if not found
}

// AllPatternTypes defines all supported pattern types
var AllPatternTypes = []PatternType{
	// AWS Patterns
	{"AWS Access Key ID", "AWS", `(?i)(?:^|[^a-zA-Z0-9])AKIA[0-9A-Z]{16}(?:[^a-zA-Z0-9]|$)`, "High", "Full AWS account access possible if secret key is also exposed"},
	{"AWS Secret Key", "AWS", `(?i)(?:aws|AWS)(?:[^a-zA-Z0-9]|_)(?:access|secret)(?:[^a-zA-Z0-9]|_)key(?:[^a-zA-Z0-9]|_)(?:id)?[\s]*=[\s]*["'][A-Za-z0-9/+=]{40,}["']`, "High", "Full AWS account access possible if access key ID is also exposed"},
	{"AWS Config Key", "AWS", `(?i)(?:aws_access_key_id|aws_secret_access_key)[\s]*=[\s]*['"][A-Za-z0-9/+=]{40,}['"]`, "High", "AWS configuration credentials exposed"},

	// API Key Patterns
	{"Bearer Token", "API", `(?i)(?:bearer|Bearer)(?:\s+|=|:)['"]?[a-zA-Z0-9_\-\.=]{30,}['"]?`, "Medium", "API authentication token exposed"},
	{"Authorization Token", "API", `(?i)(?<!class=["'])(?<!className=["'])(?:auth[_-]?token|access[_-]?token|api[_-]?token|authentication[_-]?token)[\s]*(?:=|:)[\s]*["'][a-zA-Z0-9_\-\.=]{30,}["']`, "Medium", "API authorization token exposed"},
	{"Generic API Key", "API", `(?i)api[_-]?key(?:[\s]*(?:=|:)[\s]*['"])[a-zA-Z0-9]{32,}['"]`, "Medium", "Generic API key exposed"},
	{"Client Secret", "API", `(?i)client[_-]?secret(?:[\s]*(?:=|:)[\s]*['"])[a-zA-Z0-9]{32,}['"]`, "Medium", "OAuth client secret exposed"},
	{"Basic Auth", "API", `(?i)basic\s+[a-zA-Z0-9+/]{40,}={0,2}(?:[^a-zA-Z0-9]|$)`, "High", "Basic authentication credentials exposed"},

	// Payment Service Patterns
	{"Stripe Secret Key", "Payment", `(?i)(?:^|[^a-zA-Z0-9])sk_live_[0-9a-zA-Z]{24}`, "Critical", "Full access to Stripe account and payment processing"},
	{"Stripe Public Key", "Payment", `(?i)(?:^|[^a-zA-Z0-9])pk_live_[0-9a-zA-Z]{24}`, "Low", "Limited to creating payment tokens"},
	{"Stripe Restricted Key", "Payment", `(?i)(?:^|[^a-zA-Z0-9])rk_live_[0-9a-zA-Z]{24}`, "Medium", "Restricted access to Stripe account features"},
	{"Square Access Token", "Payment", `(?i)(?:^|[^a-zA-Z0-9])sq0csp-[0-9a-zA-Z\-_]{43}`, "Critical", "Full access to Square account and payment processing"},
	{"Square OAuth Token", "Payment", `(?i)(?:^|[^a-zA-Z0-9])sqOatp-[0-9a-zA-Z\-_]{22}`, "Medium", "OAuth access to Square account"},
	{"PayPal Access Token", "Payment", `(?i)access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`, "Critical", "Access to PayPal payment processing"},

	// Database Patterns
	{"MongoDB URI", "Database", `(?i)mongodb(?:\+srv)?://[a-zA-Z0-9_\-\.]+:[^@\s'"]+@[a-zA-Z0-9_\-\.]+(?::[0-9]+)?/[a-zA-Z0-9_\-\.]+`, "Critical", "Full database access including read/write operations"},
	{"MySQL URI", "Database", `(?i)mysql://[a-zA-Z0-9_\-\.]+:[^@\s'"]+@[a-zA-Z0-9_\-\.]+(?::[0-9]+)?/[a-zA-Z0-9_\-\.]+`, "Critical", "Full database access including read/write operations"},
	{"PostgreSQL URI", "Database", `(?i)postgres(?:ql)?://[a-zA-Z0-9_\-\.]+:[^@\s'"]+@[a-zA-Z0-9_\-\.]+(?::[0-9]+)?/[a-zA-Z0-9_\-\.]+`, "Critical", "Full database access including read/write operations"},
	{"Redis URI", "Database", `(?i)redis://[a-zA-Z0-9_\-\.]+:[^@\s'"]+@[a-zA-Z0-9_\-\.]+(?::[0-9]+)?`, "High", "Access to Redis data store"},

	// Private Key Patterns
	{"RSA Private Key", "PrivateKey", `(?m)-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----(?:\r?\n(?:(?!-----)[\s\S])*?)-----END\s+RSA\s+PRIVATE\s+KEY-----`, "Critical", "Full cryptographic access, potential for impersonation"},
	{"Generic Private Key", "PrivateKey", `(?m)-----BEGIN\s+PRIVATE\s+KEY-----(?:\r?\n(?:(?!-----)[\s\S])*?)-----END\s+PRIVATE\s+KEY-----`, "Critical", "Full cryptographic access, potential for impersonation"},
	{"OpenSSH Private Key", "PrivateKey", `(?m)-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----(?:\r?\n(?:(?!-----)[\s\S])*?)-----END\s+OPENSSH\s+PRIVATE\s+KEY-----`, "Critical", "Full SSH access to systems"},
	{"PGP Private Key", "PrivateKey", `(?m)-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----(?:\r?\n(?:(?!-----)[\s\S])*?)-----END\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----`, "Critical", "Full PGP decryption and signing capabilities"},
	{"DSA Private Key", "PrivateKey", `(?m)-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----(?:\r?\n(?:(?!-----)[\s\S])*?)-----END\s+DSA\s+PRIVATE\s+KEY-----`, "Critical", "Full cryptographic access, potential for impersonation"},
	{"EC Private Key", "PrivateKey", `(?m)-----BEGIN\s+EC\s+PRIVATE\s+KEY-----(?:\r?\n(?:(?!-----)[\s\S])*?)-----END\s+EC\s+PRIVATE\s+KEY-----`, "Critical", "Full cryptographic access, potential for impersonation"},

	// Social Media Patterns
	{"GitHub Personal Access Token", "Social", `(?i)(?:^|[^a-zA-Z0-9])ghp_[0-9a-zA-Z]{36}`, "High", "Full repository access and account control"},
	{"GitHub Fine-grained Token", "Social", `(?i)(?:^|[^a-zA-Z0-9])github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}`, "Medium", "Limited repository access based on permissions"},
	{"Slack Token", "Social", `(?i)(?:^|[^a-zA-Z0-9])xox[baprs]-[0-9a-zA-Z]{10,48}`, "High", "Full Slack workspace access"},
	{"Twitter Access Token", "Social", `(?i)(?:^|[^a-zA-Z0-9])[1-9][0-9]+-[0-9a-zA-Z]{40}`, "Medium", "Twitter API access"},
	{"Facebook Access Token", "Social", `(?i)(?:^|[^a-zA-Z0-9])EAACEdEose0cBA[0-9A-Za-z]+`, "Medium", "Facebook API access"},
	{"Google API Key", "Social", `(?i)(?:^|[^a-zA-Z0-9])AIza[0-9A-Za-z\-_]{35}`, "Medium", "Google API service access"},
	{"Google OAuth", "Social", `(?i)(?:^|[^a-zA-Z0-9])ya29\.[0-9A-Za-z_\-]{68}`, "Medium", "Google OAuth access token"},

	// Communication Service Patterns
	{"Twilio API Key", "Communication", `(?i)(?:twilio|TWILIO)(?:[^a-zA-Z0-9]|_)SK[0-9a-fA-F]{32}`, "High", "Full Twilio account access"},
	{"Twilio Account SID", "Communication", `(?i)(?:twilio|TWILIO)(?:[^a-zA-Z0-9]|_)AC[a-zA-Z0-9]{32}`, "Medium", "Twilio account identifier"},
	{"SendGrid API Key", "Communication", `(?i)(?:^|[^a-zA-Z0-9])SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}`, "High", "Full SendGrid email service access"},
	{"Mailgun API Key", "Communication", `(?i)(?:mailgun|MAILGUN)(?:[^a-zA-Z0-9]|_)key-[0-9a-zA-Z]{32}`, "High", "Full Mailgun email service access"},
	{"Mailchimp API Key", "Communication", `(?i)(?:mailchimp|MAILCHIMP)(?:[^a-zA-Z0-9]|_)[0-9a-f]{32}-us[0-9]{1,2}`, "High", "Full Mailchimp service access"},
	{"Postmark Server Token", "Communication", `(?i)(?:postmark|POSTMARK)(?:[^a-zA-Z0-9]|_)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`, "High", "Full Postmark email service access"},

	// Service Patterns
	{"NPM Token", "Service", `(?i)(?:^|[^a-zA-Z0-9])npm_[0-9a-zA-Z]{36}`, "Medium", "NPM package publishing access"},
	{"Docker Auth", "Service", `(?i)docker[^a-zA-Z0-9]*auth[^a-zA-Z0-9]*config.*['"]\s*auth["']\s*:\s*["'][A-Za-z0-9+/=]+["']`, "Medium", "Docker registry authentication"},
	{"Travis CI Token", "Service", `(?i)TRAVIS[^a-zA-Z0-9]*TOKEN[^a-zA-Z0-9]*=\s*["'][0-9a-zA-Z]{40}["']`, "Medium", "Travis CI build access"},
	{"Circle CI Token", "Service", `(?i)circleci[^a-zA-Z0-9]*token[^a-zA-Z0-9]*["'][0-9a-zA-Z]{40}["']`, "Medium", "Circle CI build access"},
	{"SonarQube Token", "Service", `(?i)sonar\.login\s*=\s*["'][0-9a-zA-Z]{40}["']`, "Low", "SonarQube analysis access"},
	{"Vault Token", "Service", `(?i)VAULT_TOKEN\s*=\s*["'][0-9a-zA-Z\-_]{86}["']`, "Critical", "HashiCorp Vault root access"},
	{"GitHub Token", "Service", `(?i)(?:^|[^a-zA-Z0-9])gh[pousr]_[A-Za-z0-9_]{36}`, "High", "GitHub service access"},
	{"JWT Token", "Service", `(?i)(?:^|[^a-zA-Z0-9/])ey[I-L][\w-]+\.ey[\w-]+\.[\w-]+`, "Medium", "JWT authentication token"},
	{"Heroku API Key", "Service", `(?i)heroku[^a-zA-Z0-9]*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`, "High", "Full Heroku platform access"},

	// Framework Patterns
	{"Django Secret Key", "Framework", `(?i)(?:django|DJANGO)(?:[^a-zA-Z0-9]|_)secret(?:[^a-zA-Z0-9]|_)key[\s]*=[\s]*["'][0-9a-zA-Z]{40,}["']`, "High", "Django application security compromised"},
	{"Django Signing Key", "Framework", `(?i)(?:django|DJANGO)(?:[^a-zA-Z0-9]|_)signing(?:[^a-zA-Z0-9]|_)key[\s]*=[\s]*["'][0-9a-zA-Z]{40,}["']`, "High", "Django signing operations compromised"},
	{"Django Cookie Secret", "Framework", `(?i)(?:django|DJANGO)(?:[^a-zA-Z0-9]|_)cookie(?:[^a-zA-Z0-9]|_)secret[\s]*=[\s]*["'][0-9a-zA-Z]{40,}["']`, "Medium", "Django cookie security compromised"},
	{"Flask Secret Key", "Framework", `(?i)(?:flask|FLASK)(?:[^a-zA-Z0-9]|_)secret(?:[^a-zA-Z0-9]|_)key[\s]*=[\s]*["'][0-9a-zA-Z]{40,}["']`, "High", "Flask application security compromised"},
	{"Flask Session Key", "Framework", `(?i)(?:flask|FLASK)(?:[^a-zA-Z0-9]|_)session(?:[^a-zA-Z0-9]|_)key[\s]*=[\s]*["'][0-9a-zA-Z]{40,}["']`, "High", "Flask session security compromised"},
	{"Express Session Secret", "Framework", `(?i)(?:express|EXPRESS)(?:[^a-zA-Z0-9]|_)session(?:[^a-zA-Z0-9]|_)secret[\s]*=[\s]*["'][0-9a-zA-Z]{40,}["']`, "High", "Express.js session security compromised"},
	{"Express Cookie Secret", "Framework", `(?i)(?:express|EXPRESS)(?:[^a-zA-Z0-9]|_)cookie(?:[^a-zA-Z0-9]|_)secret[\s]*=[\s]*["'][0-9a-zA-Z]{40,}["']`, "Medium", "Express.js cookie security compromised"},
	{"Laravel App Key", "Framework", `(?i)APP_KEY[\s]*=[\s]*base64:(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?`, "High", "Laravel application security compromised"},
	{"Laravel Key", "Framework", `(?i)(?:laravel|LARAVEL)(?:[^a-zA-Z0-9]|_)key[\s]*=[\s]*["'][0-9a-zA-Z]{40,}["']`, "High", "Laravel application security compromised"},
	{"Rails Secret Key Base", "Framework", `(?i)(?:rails|RAILS)(?:[^a-zA-Z0-9]|_)secret(?:[^a-zA-Z0-9]|_)key(?:[^a-zA-Z0-9]|_)base[\s]*=[\s]*["'][0-9a-zA-Z]{40,}["']`, "High", "Rails application security compromised"},
	{"Rails Master Key", "Framework", `(?i)(?:rails|RAILS)(?:[^a-zA-Z0-9]|_)master(?:[^a-zA-Z0-9]|_)key[\s]*=[\s]*["'][0-9a-zA-Z]{40,}["']`, "High", "Rails master key exposed"},
	{"ASP.NET ViewState", "Framework", `(?i)(?:ViewState|__VIEWSTATE)[\s]*=[\s]*["'][0-9a-f]{64,}["']`, "Medium", "ASP.NET ViewState tampering possible"},
	{"ASP.NET Machine Key", "Framework", `(?i)machinekey(?:[^a-zA-Z0-9]|_)validationkey[\s]*=[\s]*["'][0-9a-f]{64,}["']`, "High", "ASP.NET machine key security compromised"},
	{"Symfony Secret", "Framework", `(?i)(?:symfony|SYMFONY)(?:[^a-zA-Z0-9]|_)secret[\s]*=[\s]*["'][0-9a-zA-Z]{40,}["']`, "High", "Symfony application security compromised"},
	{"Symfony App Secret", "Framework", `(?i)APP_SECRET[\s]*=[\s]*["'][0-9a-zA-Z]{40,}["']`, "High", "Symfony application security compromised"},
}

// GetAllPatterns returns all patterns organized by category
func GetAllPatterns() map[string][]string {
	patterns := make(map[string][]string)
	for _, pt := range AllPatternTypes {
		patterns[pt.Category] = append(patterns[pt.Category], pt.Pattern)
	}
	return patterns
}
