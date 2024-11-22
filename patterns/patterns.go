package patterns

// Regex patterns organized by category for better maintainability and performance
var (
	// AWS related patterns
	AWSPatterns = []string{
		`(?i)AKIA[0-9A-Z]{16}`,                     // AWS Access Key ID
		`(?i)aws[_-]access[_-]key[_-]id[=:][^\s]+`, // AWS Access Key ID with prefix
		`(?i)[^a-zA-Z0-9]AKI[a-zA-Z0-9]{17}`,       // AWS Access Key ID variant
		`(?i)aws[_-]secret[_-]key[=:][^\s]+`,       // AWS Secret Key
		`(?i)aws[_-]session[_-]token[=:][^\s]+`,    // AWS Session Token
		`(?i)arn:aws:iam::[0-9]{12}:user[^/]*/`,    // AWS ARN
	}

	// API Key patterns
	APIKeyPatterns = []string{
		`(?i)api[_-]key[=:][^\s]{8,}`,           // Generic API Key
		`(?i)authorization[:=]Bearer\s+[^\s]+`,  // Bearer Token
		`(?i)authorization[:=]Token\s+[^\s]+`,   // Token Auth
		`(?i)api[_-]token[=:][^\s]{8,}`,         // API Token
		`(?i)access[_-]token[=:][^\s]{8,}`,      // Access Token
		`(?i)auth[_-]token[=:][^\s]{8,}`,        // Auth Token
		`(?i)client[_-]secret[=:][^\s]{8,}`,     // Client Secret
		`(?i)api[_-]secret[_-]key[=:][^\s]{8,}`, // API Secret Key
	}

	// Cloud Service patterns
	CloudPatterns = []string{
		`(?i)firebase[_-]api[_-]key[=:][^\s]+`,   // Firebase
		`(?i)gcm[_-]api[_-]key[=:][^\s]+`,        // GCM
		`(?i)google[_-]api[_-]key[=:][^\s]+`,     // Google API
		`(?i)google[_-]oauth[_-]token[=:][^\s]+`, // Google OAuth
		`(?i)azure[_-]api[_-]key[=:][^\s]+`,      // Azure
		`(?i)cloudinary[_-]url[=:][^\s]+`,        // Cloudinary
		`(?i)digitalocean[_-]token[=:][^\s]+`,    // DigitalOcean
		`(?i)heroku[_-]api[_-]key[=:][^\s]+`,     // Heroku
	}

	// Payment Service patterns
	PaymentPatterns = []string{
		`(?i)stripe[_-](?:public|private)[_-]key[=:][^\s]+`, // Stripe
		`(?i)stripe[_-]live[_-]secret[_-]key[=:][^\s]+`,     // Stripe Live
		`(?i)paypal[_-]client[_-]secret[=:][^\s]+`,          // PayPal
		`(?i)square[_-]oauth[_-]secret[=:][^\s]+`,           // Square
		`(?i)square[_-]access[_-]token[=:][^\s]+`,           // Square Access Token
		`(?i)braintree[_-]access[_-]token[=:][^\s]+`,        // Braintree
	}

	// Database patterns
	DatabasePatterns = []string{
		`(?i)mongodb(?:+srv)?:\/\/[^\s]+`,              // MongoDB URI
		`(?i)mysql[_-](?:user|password)[=:][^\s]+`,     // MySQL
		`(?i)postgres[_-](?:user|password)[=:][^\s]+`,  // PostgreSQL
		`(?i)redis[_-]password[=:][^\s]+`,              // Redis
		`(?i)database[_-]url[=:][^\s]+`,                // Generic Database URL
		`(?i)jdbc:mysql:\/\/[^\s]+`,                    // JDBC MySQL
		`(?i)cassandra[_-](?:user|password)[=:][^\s]+`, // Cassandra
	}

	// Private Key patterns - using non-greedy matches for better performance
	PrivateKeyPatterns = []string{
		`-----BEGIN\sRSA\sPRIVATE\sKEY-----[^-]*?-----END\sRSA\sPRIVATE\sKEY-----`,
		`-----BEGIN\sPRIVATE\sKEY-----[^-]*?-----END\sPRIVATE\sKEY-----`,
		`-----BEGIN\sOPENSSH\sPRIVATE\sKEY-----[^-]*?-----END\sOPENSSH\sPRIVATE\sKEY-----`,
		`-----BEGIN\sPGP\sPRIVATE\sKEY-----[^-]*?-----END\sPGP\sPRIVATE\sKEY-----`,
		`-----BEGIN\sENCRYPTED\sPRIVATE\sKEY-----[^-]*?-----END\sENCRYPTED\sPRIVATE\sKEY-----`,
	}

	// Social Media patterns
	SocialPatterns = []string{
		`(?i)twitter[_-]api[_-](?:key|secret)[=:][^\s]+`,     // Twitter
		`(?i)facebook[_-](?:app|client)[_-]secret[=:][^\s]+`, // Facebook
		`(?i)github[_-](?:token|key)[=:][^\s]+`,              // GitHub
		`(?i)slack[_-](?:token|key)[=:][^\s]+`,               // Slack
		`(?i)slack[_-]webhook[_-]url[=:][^\s]+`,              // Slack Webhook
		`(?i)youtube[_-]api[_-]key[=:][^\s]+`,                // YouTube
		`(?i)instagram[_-]access[_-]token[=:][^\s]+`,         // Instagram
		`(?i)linkedin[_-]client[_-]secret[=:][^\s]+`,         // LinkedIn
	}

	// Communication Service patterns
	CommunicationPatterns = []string{
		`(?i)twilio[_-](?:token|key|sid)[=:][^\s]+`,    // Twilio
		`(?i)sendgrid[_-]api[_-]key[=:][^\s]+`,         // SendGrid
		`(?i)mailgun[_-]api[_-]key[=:][^\s]+`,          // Mailgun
		`(?i)mailchimp[_-]api[_-]key[=:][^\s]+`,        // Mailchimp
		`(?i)postmark[_-]api[_-]token[=:][^\s]+`,       // Postmark
		`(?i)nexmo[_-]api[_-](?:key|secret)[=:][^\s]+`, // Nexmo
	}

	// Additional Service patterns
	ServicePatterns = []string{
		`(?i)npm[_-]token[=:][^\s]+`,                // NPM
		`(?i)docker[_-]hub[_-]password[=:][^\s]+`,   // Docker Hub
		`(?i)travis[_-]ci[_-]token[=:][^\s]+`,       // Travis CI
		`(?i)circle[_-]ci[_-]token[=:][^\s]+`,       // Circle CI
		`(?i)jenkins[_-]api[_-]token[=:][^\s]+`,     // Jenkins
		`(?i)sentry[_-]auth[_-]token[=:][^\s]+`,     // Sentry
		`(?i)sonar[_-]token[=:][^\s]+`,              // SonarQube
		`(?i)artifactory[_-]api[_-]token[=:][^\s]+`, // Artifactory
		`(?i)okta[_-]api[_-]token[=:][^\s]+`,        // Okta
		`(?i)auth0[_-]api[_-]token[=:][^\s]+`,       // Auth0
	}
)

// GetAllPatterns returns all patterns organized by category
func GetAllPatterns() map[string][]string {
	return map[string][]string{
		"AWS":           AWSPatterns,
		"API":           APIKeyPatterns,
		"Cloud":         CloudPatterns,
		"Payment":       PaymentPatterns,
		"Database":      DatabasePatterns,
		"PrivateKey":    PrivateKeyPatterns,
		"Social":        SocialPatterns,
		"Communication": CommunicationPatterns,
		"Service":       ServicePatterns,
	}
}
