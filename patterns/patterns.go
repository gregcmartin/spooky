package patterns

// PatternType represents a specific type of secret pattern
type PatternType struct {
	Name     string
	Category string
	Pattern  string
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
	{"AWS Access Key ID", "AWS", `(?i)(?:^|[^a-zA-Z0-9])AKIA[0-9A-Z]{16}(?:[^a-zA-Z0-9]|$)`},
	{"AWS Secret Key", "AWS", `(?i)(?:aws|AWS)(?:[^a-zA-Z0-9]|_)(?:access|secret)(?:[^a-zA-Z0-9]|_)key(?:[^a-zA-Z0-9]|_)(?:id)?[\s]*=[\s]*["'][A-Za-z0-9/+=]{40,}["']`},
	{"AWS Config Key", "AWS", `(?i)(?:aws_access_key_id|aws_secret_access_key)[\s]*=[\s]*['"][A-Za-z0-9/+=]{40,}['"]`},

	// API Key Patterns
	{"Bearer Token", "API", `(?i)(?:bearer|Bearer)(?:\s+|=|:)['"]?[a-zA-Z0-9_\-\.=]{30,}['"]?`},
	{"Authorization Token", "API", `(?i)(?<!class=["'])(?<!className=["'])(?:auth[_-]?token|access[_-]?token|api[_-]?token|authentication[_-]?token)[\s]*(?:=|:)[\s]*["'][a-zA-Z0-9_\-\.=]{30,}["']`},
	{"Generic API Key", "API", `(?i)api[_-]?key(?:[\s]*(?:=|:)[\s]*['"])[a-zA-Z0-9]{32,}['"]`},
	{"Client Secret", "API", `(?i)client[_-]?secret(?:[\s]*(?:=|:)[\s]*['"])[a-zA-Z0-9]{32,}['"]`},
	{"Basic Auth", "API", `(?i)basic\s+[a-zA-Z0-9+/]{40,}={0,2}(?:[^a-zA-Z0-9]|$)`},

	// Payment Service Patterns
	{"Stripe Secret Key", "Payment", `(?i)(?:^|[^a-zA-Z0-9])sk_live_[0-9a-zA-Z]{24}`},
	{"Stripe Public Key", "Payment", `(?i)(?:^|[^a-zA-Z0-9])pk_live_[0-9a-zA-Z]{24}`},
	{"Stripe Restricted Key", "Payment", `(?i)(?:^|[^a-zA-Z0-9])rk_live_[0-9a-zA-Z]{24}`},
	{"Square Access Token", "Payment", `(?i)(?:^|[^a-zA-Z0-9])sq0csp-[0-9a-zA-Z\-_]{43}`},
	{"Square OAuth Token", "Payment", `(?i)(?:^|[^a-zA-Z0-9])sqOatp-[0-9a-zA-Z\-_]{22}`},
	{"PayPal Access Token", "Payment", `(?i)access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`},

	// Database Patterns
	{"MongoDB URI", "Database", `(?i)mongodb(?:\+srv)?://[a-zA-Z0-9_\-\.]+:[^@\s'"]+@[a-zA-Z0-9_\-\.]+(?::[0-9]+)?/[a-zA-Z0-9_\-\.]+`},
	{"MySQL URI", "Database", `(?i)mysql://[a-zA-Z0-9_\-\.]+:[^@\s'"]+@[a-zA-Z0-9_\-\.]+(?::[0-9]+)?/[a-zA-Z0-9_\-\.]+`},
	{"PostgreSQL URI", "Database", `(?i)postgres(?:ql)?://[a-zA-Z0-9_\-\.]+:[^@\s'"]+@[a-zA-Z0-9_\-\.]+(?::[0-9]+)?/[a-zA-Z0-9_\-\.]+`},
	{"Redis URI", "Database", `(?i)redis://[a-zA-Z0-9_\-\.]+:[^@\s'"]+@[a-zA-Z0-9_\-\.]+(?::[0-9]+)?`},

	// Private Key Patterns
	{"RSA Private Key", "PrivateKey", `(?m)-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----(?:\r?\n(?:(?!-----)[\s\S])*?)-----END\s+RSA\s+PRIVATE\s+KEY-----`},
	{"Generic Private Key", "PrivateKey", `(?m)-----BEGIN\s+PRIVATE\s+KEY-----(?:\r?\n(?:(?!-----)[\s\S])*?)-----END\s+PRIVATE\s+KEY-----`},
	{"OpenSSH Private Key", "PrivateKey", `(?m)-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----(?:\r?\n(?:(?!-----)[\s\S])*?)-----END\s+OPENSSH\s+PRIVATE\s+KEY-----`},
	{"PGP Private Key", "PrivateKey", `(?m)-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----(?:\r?\n(?:(?!-----)[\s\S])*?)-----END\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----`},
	{"DSA Private Key", "PrivateKey", `(?m)-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----(?:\r?\n(?:(?!-----)[\s\S])*?)-----END\s+DSA\s+PRIVATE\s+KEY-----`},
	{"EC Private Key", "PrivateKey", `(?m)-----BEGIN\s+EC\s+PRIVATE\s+KEY-----(?:\r?\n(?:(?!-----)[\s\S])*?)-----END\s+EC\s+PRIVATE\s+KEY-----`},

	// Social Media Patterns
	{"GitHub Personal Access Token", "Social", `(?i)(?:^|[^a-zA-Z0-9])ghp_[0-9a-zA-Z]{36}`},
	{"GitHub Fine-grained Token", "Social", `(?i)(?:^|[^a-zA-Z0-9])github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}`},
	{"Slack Token", "Social", `(?i)(?:^|[^a-zA-Z0-9])xox[baprs]-[0-9a-zA-Z]{10,48}`},
	{"Twitter Access Token", "Social", `(?i)(?:^|[^a-zA-Z0-9])[1-9][0-9]+-[0-9a-zA-Z]{40}`},
	{"Facebook Access Token", "Social", `(?i)(?:^|[^a-zA-Z0-9])EAACEdEose0cBA[0-9A-Za-z]+`},
	{"Google API Key", "Social", `(?i)(?:^|[^a-zA-Z0-9])AIza[0-9A-Za-z\-_]{35}`},
	{"Google OAuth", "Social", `(?i)(?:^|[^a-zA-Z0-9])ya29\.[0-9A-Za-z_\-]{68}`},

	// Communication Service Patterns
	{"Twilio API Key", "Communication", `(?i)(?:twilio|TWILIO)(?:[^a-zA-Z0-9]|_)SK[0-9a-fA-F]{32}`},
	{"Twilio Account SID", "Communication", `(?i)(?:twilio|TWILIO)(?:[^a-zA-Z0-9]|_)AC[a-zA-Z0-9]{32}`},
	{"SendGrid API Key", "Communication", `(?i)(?:^|[^a-zA-Z0-9])SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}`},
	{"Mailgun API Key", "Communication", `(?i)(?:mailgun|MAILGUN)(?:[^a-zA-Z0-9]|_)key-[0-9a-zA-Z]{32}`},
	{"Mailchimp API Key", "Communication", `(?i)(?:mailchimp|MAILCHIMP)(?:[^a-zA-Z0-9]|_)[0-9a-f]{32}-us[0-9]{1,2}`},
	{"Postmark Server Token", "Communication", `(?i)(?:postmark|POSTMARK)(?:[^a-zA-Z0-9]|_)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`},

	// Service Patterns
	{"NPM Token", "Service", `(?i)(?:^|[^a-zA-Z0-9])npm_[0-9a-zA-Z]{36}`},
	{"Docker Auth", "Service", `(?i)docker[^a-zA-Z0-9]*auth[^a-zA-Z0-9]*config.*['"]\s*auth["']\s*:\s*["'][A-Za-z0-9+/=]+["']`},
	{"Travis CI Token", "Service", `(?i)TRAVIS[^a-zA-Z0-9]*TOKEN[^a-zA-Z0-9]*=\s*["'][0-9a-zA-Z]{40}["']`},
	{"Circle CI Token", "Service", `(?i)circleci[^a-zA-Z0-9]*token[^a-zA-Z0-9]*["'][0-9a-zA-Z]{40}["']`},
	{"SonarQube Token", "Service", `(?i)sonar\.login\s*=\s*["'][0-9a-zA-Z]{40}["']`},
	{"Vault Token", "Service", `(?i)VAULT_TOKEN\s*=\s*["'][0-9a-zA-Z\-_]{86}["']`},
	{"GitHub Token", "Service", `(?i)(?:^|[^a-zA-Z0-9])gh[pousr]_[A-Za-z0-9_]{36}`},
	{"JWT Token", "Service", `(?i)(?:^|[^a-zA-Z0-9/])ey[I-L][\w-]+\.ey[\w-]+\.[\w-]+`},
	{"Heroku API Key", "Service", `(?i)heroku[^a-zA-Z0-9]*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`},

	// Cloud Service Patterns
	{"AWS Access Key ID", "Cloud", `(?i)(?:^|[^a-zA-Z0-9])AKIA[0-9A-Z]{16}`},
	{"Google OAuth", "Cloud", `(?i)(?:^|[^a-zA-Z0-9])ya29\.[0-9A-Za-z_\-]{68}`},
	{"Google API Key", "Cloud", `(?i)(?:^|[^a-zA-Z0-9])AIza[0-9A-Za-z\-_]{35}`},
	{"Google Cloud Secret", "Cloud", `(?i)projects/[a-zA-Z0-9-]+/secrets/[a-zA-Z0-9-_]+(?:/versions/[0-9]+)?`},
	{"Google Cloud KMS", "Cloud", `(?i)projects/[a-zA-Z0-9-]+/locations/[a-zA-Z0-9-]+/keyRings/[a-zA-Z0-9-]+/cryptoKeys/[a-zA-Z0-9-]+`},

	// Framework Patterns
	{"Django Secret Key", "Framework", `(?i)(?:django|DJANGO)(?:[^a-zA-Z0-9]|_)secret(?:[^a-zA-Z0-9]|_)key[\s]*=[\s]*["'][0-9a-zA-Z]{40,}["']`},
	{"Django Signing Key", "Framework", `(?i)(?:django|DJANGO)(?:[^a-zA-Z0-9]|_)signing(?:[^a-zA-Z0-9]|_)key[\s]*=[\s]*["'][0-9a-zA-Z]{40,}["']`},
	{"Django Cookie Secret", "Framework", `(?i)(?:django|DJANGO)(?:[^a-zA-Z0-9]|_)cookie(?:[^a-zA-Z0-9]|_)secret[\s]*=[\s]*["'][0-9a-zA-Z]{40,}["']`},
	{"Flask Secret Key", "Framework", `(?i)(?:flask|FLASK)(?:[^a-zA-Z0-9]|_)secret(?:[^a-zA-Z0-9]|_)key[\s]*=[\s]*["'][0-9a-zA-Z]{40,}["']`},
	{"Flask Session Key", "Framework", `(?i)(?:flask|FLASK)(?:[^a-zA-Z0-9]|_)session(?:[^a-zA-Z0-9]|_)key[\s]*=[\s]*["'][0-9a-zA-Z]{40,}["']`},
	{"Express Session Secret", "Framework", `(?i)(?:express|EXPRESS)(?:[^a-zA-Z0-9]|_)session(?:[^a-zA-Z0-9]|_)secret[\s]*=[\s]*["'][0-9a-zA-Z]{40,}["']`},
	{"Express Cookie Secret", "Framework", `(?i)(?:express|EXPRESS)(?:[^a-zA-Z0-9]|_)cookie(?:[^a-zA-Z0-9]|_)secret[\s]*=[\s]*["'][0-9a-zA-Z]{40,}["']`},
	{"Laravel App Key", "Framework", `(?i)APP_KEY[\s]*=[\s]*base64:(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?`},
	{"Laravel Key", "Framework", `(?i)(?:laravel|LARAVEL)(?:[^a-zA-Z0-9]|_)key[\s]*=[\s]*["'][0-9a-zA-Z]{40,}["']`},
	{"Rails Secret Key Base", "Framework", `(?i)(?:rails|RAILS)(?:[^a-zA-Z0-9]|_)secret(?:[^a-zA-Z0-9]|_)key(?:[^a-zA-Z0-9]|_)base[\s]*=[\s]*["'][0-9a-zA-Z]{40,}["']`},
	{"Rails Master Key", "Framework", `(?i)(?:rails|RAILS)(?:[^a-zA-Z0-9]|_)master(?:[^a-zA-Z0-9]|_)key[\s]*=[\s]*["'][0-9a-zA-Z]{40,}["']`},
	{"ASP.NET ViewState", "Framework", `(?i)(?:ViewState|__VIEWSTATE)[\s]*=[\s]*["'][0-9a-f]{64,}["']`},
	{"ASP.NET Machine Key", "Framework", `(?i)machinekey(?:[^a-zA-Z0-9]|_)validationkey[\s]*=[\s]*["'][0-9a-f]{64,}["']`},
	{"Symfony Secret", "Framework", `(?i)(?:symfony|SYMFONY)(?:[^a-zA-Z0-9]|_)secret[\s]*=[\s]*["'][0-9a-zA-Z]{40,}["']`},
	{"Symfony App Secret", "Framework", `(?i)APP_SECRET[\s]*=[\s]*["'][0-9a-zA-Z]{40,}["']`},
}

// GetAllPatterns returns all patterns organized by category
func GetAllPatterns() map[string][]string {
	patterns := make(map[string][]string)
	for _, pt := range AllPatternTypes {
		patterns[pt.Category] = append(patterns[pt.Category], pt.Pattern)
	}
	return patterns
}
