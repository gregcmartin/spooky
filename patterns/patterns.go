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
	}

	// API Key patterns
	APIKeyPatterns = []string{
		`(?i)api[_-]key[=:][^\s]{8,}`,          // Generic API Key
		`(?i)authorization[:=]Bearer\s+[^\s]+`, // Bearer Token
		`(?i)authorization[:=]Token\s+[^\s]+`,  // Token Auth
		`(?i)api[_-]token[=:][^\s]{8,}`,        // API Token
		`(?i)access[_-]token[=:][^\s]{8,}`,     // Access Token
		`(?i)auth[_-]token[=:][^\s]{8,}`,       // Auth Token
	}

	// Cloud Service patterns
	CloudPatterns = []string{
		`(?i)firebase[_-]api[_-]key[=:][^\s]+`,   // Firebase
		`(?i)gcm[_-]api[_-]key[=:][^\s]+`,        // GCM
		`(?i)google[_-]api[_-]key[=:][^\s]+`,     // Google API
		`(?i)google[_-]oauth[_-]token[=:][^\s]+`, // Google OAuth
		`(?i)azure[_-]api[_-]key[=:][^\s]+`,      // Azure
		`(?i)cloudinary[_-]url[=:][^\s]+`,        // Cloudinary
	}

	// Payment Service patterns
	PaymentPatterns = []string{
		`(?i)stripe[_-](?:public|private)[_-]key[=:][^\s]+`, // Stripe
		`(?i)stripe[_-]live[_-]secret[_-]key[=:][^\s]+`,     // Stripe Live
		`(?i)paypal[_-]client[_-]secret[=:][^\s]+`,          // PayPal
		`(?i)square[_-]oauth[_-]secret[=:][^\s]+`,           // Square
	}

	// Database patterns
	DatabasePatterns = []string{
		`(?i)mongodb[_-]uri[=:][^\s]+`,                // MongoDB URI
		`(?i)mysql[_-](?:user|password)[=:][^\s]+`,    // MySQL
		`(?i)postgres[_-](?:user|password)[=:][^\s]+`, // PostgreSQL
		`(?i)redis[_-]password[=:][^\s]+`,             // Redis
	}

	// Private Key patterns - using non-greedy matches for better performance
	PrivateKeyPatterns = []string{
		`-----BEGIN\sRSA\sPRIVATE\sKEY-----[^-]*?-----END\sRSA\sPRIVATE\sKEY-----`,
		`-----BEGIN\sPRIVATE\sKEY-----[^-]*?-----END\sPRIVATE\sKEY-----`,
		`-----BEGIN\sOPENSSH\sPRIVATE\sKEY-----[^-]*?-----END\sOPENSSH\sPRIVATE\sKEY-----`,
	}

	// Social Media patterns
	SocialPatterns = []string{
		`(?i)twitter[_-]api[_-](?:key|secret)[=:][^\s]+`,     // Twitter
		`(?i)facebook[_-](?:app|client)[_-]secret[=:][^\s]+`, // Facebook
		`(?i)github[_-](?:token|key)[=:][^\s]+`,              // GitHub
		`(?i)slack[_-](?:token|key)[=:][^\s]+`,               // Slack
		`(?i)youtube[_-]api[_-]key[=:][^\s]+`,                // YouTube
	}

	// Communication Service patterns
	CommunicationPatterns = []string{
		`(?i)twilio[_-](?:token|key|sid)[=:][^\s]+`, // Twilio
		`(?i)sendgrid[_-]api[_-]key[=:][^\s]+`,      // SendGrid
		`(?i)mailgun[_-]api[_-]key[=:][^\s]+`,       // Mailgun
		`(?i)mailchimp[_-]api[_-]key[=:][^\s]+`,     // Mailchimp
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
	}
}
