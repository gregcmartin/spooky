package patterns

// Regex patterns organized by category for better maintainability and performance
var (
	// AWS related patterns
	AWSPatterns = []string{
		`(?i)AKIA[0-9A-Z]{16}`, // AWS Access Key ID
		`(?i)(?:AWS|aws).{0,20}(?:key|KEY).{0,20}['"][0-9a-zA-Z/+]{40}['"]`, // AWS Secret Key
		`(?i)(?:aws_access_key_id|aws_secret_access_key).{0,20}=.{0,20}['"][A-Za-z0-9/+=]{40,}['"]`,
	}

	// API Key patterns
	APIKeyPatterns = []string{
		`(?i)authorization:\s*bearer\s+[a-zA-Z0-9_\-\.=]+`,            // Bearer Token
		`(?i)authorization:\s*token\s+[a-zA-Z0-9_\-\.=]+`,             // Token Auth
		`(?i)api[_-]?key['":\s]*[=]\s*['"][0-9a-zA-Z]{32,}['"]`,       // Generic API Key
		`(?i)client[_-]?secret['":\s]*[=]\s*['"][0-9a-zA-Z]{32,}['"]`, // Client Secret
		`(?i)basic\s+[a-zA-Z0-9+/]+={0,2}`,                            // Basic Auth
		`(?i)key-[a-zA-Z0-9]{32}`,                                     // Generic API Key Format
	}

	// Payment Service patterns
	PaymentPatterns = []string{
		`(?i)sk_live_[0-9a-zA-Z]{24,}`,                             // Stripe Secret Key
		`(?i)pk_live_[0-9a-zA-Z]{24,}`,                             // Stripe Public Key
		`(?i)rk_live_[0-9a-zA-Z]{24,}`,                             // Stripe Restricted Key
		`(?i)sq0csp-[0-9a-zA-Z\-_]{43}`,                            // Square
		`(?i)sqOatp-[0-9a-zA-Z\-_]{22}`,                            // Square OAuth
		`(?i)access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`, // PayPal Access Token
		`(?i)sk_test_[0-9a-zA-Z]{24,}`,                             // Stripe Test Key
		`(?i)pk_test_[0-9a-zA-Z]{24,}`,                             // Stripe Test Public Key
	}

	// Database patterns
	DatabasePatterns = []string{
		`(?i)mongodb(?:+srv)?://[^\s'"]+`,     // MongoDB URI
		`(?i)mysql://[^\s'"]+`,                // MySQL URI
		`(?i)postgres(?:ql)?://[^\s'"]+`,      // PostgreSQL URI
		`(?i)redis://[^\s'"]+`,                // Redis URI
		`(?i)mongodb://.*:(.*)@[^\s'"]+`,      // MongoDB with auth
		`(?i)mysql://.*:(.*)@[^\s'"]+`,        // MySQL with auth
		`(?i)postgresql://.*:(.*)@[^\s'"]+`,   // PostgreSQL with auth
		`(?i)redis://.*:(.*)@[^\s'"]+`,        // Redis with auth
		`(?i)mongodb\+srv://.*:(.*)@[^\s'"]+`, // MongoDB+SRV with auth
	}

	// Private Key patterns
	PrivateKeyPatterns = []string{
		`-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----[^-]*-----END\s+RSA\s+PRIVATE\s+KEY-----`,
		`-----BEGIN\s+PRIVATE\s+KEY-----[^-]*-----END\s+PRIVATE\s+KEY-----`,
		`-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----[^-]*-----END\s+OPENSSH\s+PRIVATE\s+KEY-----`,
		`-----BEGIN\s+PGP\s+PRIVATE\s+KEY-----[^-]*-----END\s+PGP\s+PRIVATE\s+KEY-----`,
		`-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----[^-]*-----END\s+DSA\s+PRIVATE\s+KEY-----`,
		`-----BEGIN\s+EC\s+PRIVATE\s+KEY-----[^-]*-----END\s+EC\s+PRIVATE\s+KEY-----`,
	}

	// Social Media patterns
	SocialPatterns = []string{
		`(?i)ghp_[0-9a-zA-Z]{36}`,                        // GitHub Personal Access Token
		`(?i)github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}`, // GitHub Fine-grained Token
		`(?i)xox[baprs]-[0-9a-zA-Z]{10,48}`,              // Slack Token
		`(?i)[1-9][0-9]+-[0-9a-zA-Z]{40}`,                // Twitter Access Token
		`(?i)EAACEdEose0cBA[0-9A-Za-z]+`,                 // Facebook Access Token
		`(?i)AIza[0-9A-Za-z\-_]{35}`,                     // Google API Key
		`(?i)ya29\.[0-9A-Za-z\-_]+`,                      // Google OAuth
		`(?i)[0-9]{8,10}:[0-9A-Za-z_-]{35}`,              // Telegram Bot Token
		`(?i)key-[0-9a-zA-Z]{32}`,                        // Mailgun API Key
		`(?i)[0-9a-f]{32}-us[0-9]{1,2}`,                  // MailChimp API Key
		`(?i)sk_test_[0-9a-zA-Z]{32}`,                    // Stripe Test Key
	}

	// Communication Service patterns
	CommunicationPatterns = []string{
		`(?i)(?:twilio|TWILIO).{0,20}SK[0-9a-fA-F]{32}`,                                                // Twilio API Key (requires "twilio" context)
		`(?i)(?:twilio|TWILIO).{0,20}AC[a-zA-Z0-9]{32}`,                                                // Twilio Account SID (requires "twilio" context)
		`(?i)SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}`,                                               // SendGrid API Key (already specific)
		`(?i)(?:mailgun|MAILGUN).{0,20}key-[0-9a-zA-Z]{32}`,                                            // Mailgun API Key (requires "mailgun" context)
		`(?i)(?:mailchimp|MAILCHIMP).{0,20}[0-9a-f]{32}-us[0-9]{1,2}`,                                  // Mailchimp API Key (requires "mailchimp" context)
		`(?i)(?:postmark|POSTMARK).{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`, // Postmark Server Token
		`(?i)sms_[a-zA-Z0-9]{32}`,                                                                      // Nexmo API Key
		`(?i)key-[a-zA-Z0-9]{32}`,                                                                      // Mailgun API Key
	}

	// Service patterns
	ServicePatterns = []string{
		`(?i)npm_[0-9a-zA-Z]{36}`,                                                  // NPM Token
		`(?i)docker_auth_config.*:.*"auth":"[^"]+`,                                 // Docker Auth
		`(?i)TRAVIS.*TOKEN.*=.*[0-9a-zA-Z]{40}`,                                    // Travis CI Token
		`(?i)circleci.*token.*[0-9a-zA-Z]{40}`,                                     // Circle CI Token
		`(?i)sonar.login=[0-9a-zA-Z]{40}`,                                          // SonarQube Token
		`(?i)VAULT_TOKEN=[0-9a-zA-Z\-_]{86}`,                                       // Vault Token
		`(?i)gh[pousr]_[A-Za-z0-9_]{36}`,                                           // GitHub Token
		`(?i)ey[I-L][\w-]*\.ey[\w-]*\.[\w-]*`,                                      // JWT Token
		`(?i)heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`, // Heroku API Key
		`(?i)sk_live_[0-9a-zA-Z]{24}`,                                              // Stripe Live Key
		`(?i)rk_live_[0-9a-zA-Z]{24}`,                                              // Stripe Restricted Key
		`(?i)[a-zA-Z0-9_-]*:[a-zA-Z0-9_-]+@github\.com`,                            // GitHub OAuth
	}

	// Cloud Service patterns
	CloudPatterns = []string{
		`(?i)AKIA[0-9A-Z]{16}`,                                   // AWS Access Key ID
		`(?i)[0-9a-zA-Z/+]{40}`,                                  // AWS Secret Key
		`(?i)ya29\.[0-9A-Za-z_\-]+`,                              // Google OAuth
		`(?i)AIza[0-9A-Za-z\-_]{35}`,                             // Google API Key
		`(?i)[0-9a-zA-Z]{32}-r[0-9a-zA-Z]{4}`,                    // Google Cloud Platform OAuth
		`(?i)projects/.*/secrets/.*`,                             // Google Cloud Secret Manager
		`(?i)projects/.*/locations/.*/keyRings/.*/cryptoKeys/.*`, // Google Cloud KMS
	}

	// Framework patterns
	FrameworkPatterns = []string{
		// Django
		`(?i)django.*secret.*key.*['"][0-9a-zA-Z]{40,}['"]`,    // Django Secret Key
		`(?i)django.*signing.*key.*['"][0-9a-zA-Z]{40,}['"]`,   // Django Signing Key
		`(?i)django.*cookie.*secret.*['"][0-9a-zA-Z]{40,}['"]`, // Django Cookie Secret

		// Flask
		`(?i)flask.*secret.*key.*['"][0-9a-zA-Z]{40,}['"]`,  // Flask Secret Key
		`(?i)flask.*session.*key.*['"][0-9a-zA-Z]{40,}['"]`, // Flask Session Key

		// Express
		`(?i)express.*session.*secret.*['"][0-9a-zA-Z]{40,}['"]`, // Express Session Secret
		`(?i)express.*cookie.*secret.*['"][0-9a-zA-Z]{40,}['"]`,  // Express Cookie Secret

		// Laravel
		`(?i)APP_KEY.*=.*base64:[A-Za-z0-9+/]{40,}`,  // Laravel App Key
		`(?i)laravel.*key.*['"][0-9a-zA-Z]{40,}['"]`, // Laravel Key

		// Rails
		`(?i)rails.*secret.*key.*base.*['"][0-9a-zA-Z]{40,}['"]`, // Rails Secret Key Base
		`(?i)rails.*master.*key.*['"][0-9a-zA-Z]{40,}['"]`,       // Rails Master Key

		// ASP.NET
		`(?i)ViewState.*[0-9a-f]{64,}`,                 // ASP.NET ViewState
		`(?i)__VIEWSTATE.*[0-9a-f]{64,}`,               // ASP.NET ViewState Field
		`(?i)machinekey.*validationkey.*[0-9a-f]{64,}`, // ASP.NET Machine Key

		// Symfony
		`(?i)symfony.*secret.*['"][0-9a-zA-Z]{40,}['"]`, // Symfony Secret
		`(?i)APP_SECRET.*=.*[0-9a-zA-Z]{40,}`,           // Symfony App Secret

		// JSF
		`(?i)jsf.*view.*state.*secret.*['"][0-9a-zA-Z]{40,}['"]`, // JSF ViewState Secret

		// Telerik
		`(?i)telerik.*encryption.*key.*['"][0-9a-zA-Z]{40,}['"]`, // Telerik Encryption Key
		`(?i)telerik.*hash.*key.*['"][0-9a-zA-Z]{40,}['"]`,       // Telerik Hash Key
	}
)

// GetAllPatterns returns all patterns organized by category
func GetAllPatterns() map[string][]string {
	return map[string][]string{
		"AWS":           AWSPatterns,
		"API":           APIKeyPatterns,
		"Payment":       PaymentPatterns,
		"Database":      DatabasePatterns,
		"PrivateKey":    PrivateKeyPatterns,
		"Social":        SocialPatterns,
		"Communication": CommunicationPatterns,
		"Service":       ServicePatterns,
		"Cloud":         CloudPatterns,
		"Framework":     FrameworkPatterns,
	}
}
