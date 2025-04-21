const fs = require('fs');
const path = require('path');
const axios = require('axios');

/***************************************************************
 *   _____ _____  _____  _   _  _____ _____ _____ _____ _____   *
 *  |  __ \  __ \|  __ \| \ | |/ ____|_   _/ ____|_   _|  __ \ *
 *  | |__) | |__) | |__) |  \| | (___   | || |      | | | |  | |*
 *  |  ___/|  _  /|  ___/| . ` |\___ \  | || |      | | | |  | |*
 *  | |    | | \ \| |    | |\  |____) |_| || |____ _| |_| |__| |*
 *  |_|    |_|  \_\_|    |_| \_|_____/|_____\_____|_____|_____/ *
 *                                                              *
 *                   SECRET SCANNER v2.1                        *
 *                     by profanatica                           *
 ***************************************************************/

// Configuration settings
const CONFIG = {
  maxRetries: 3,
  initialDelay: 1000,
  requestTimeout: 15000,
  outputDir: 'profanatica_results',
  outputFile: 'found_secrets.txt',
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',

  // Enhanced detection patterns including all requested regex
  detectionPatterns: {
    // Cloud Services
    Cloudinary: /cloudinary:\/\/.*/g,
    FirebaseURL: /.*firebaseio\.com/g,
    
    // Private Keys
    RSAPrivateKey: /-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----/g,
    DSAPrivateKey: /-----BEGIN DSA PRIVATE KEY-----[\s\S]*?-----END DSA PRIVATE KEY-----/g,
    ECPrivateKey: /-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----/g,
    PGPPrivateKey: /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/g,
    
    // AWS
    AWSKey: /AKIA[0-9A-Z]{16}/g,
    AmazonMWSAuthToken: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g,
    
    // Social Media
    FacebookAccessToken: /EAACEdEose0cBA[0-9A-Za-z]+/g,
    FacebookOAuth: /[fF][aA][cC][eE][bB][oO][oO][kK].*['"][0-9a-f]{32}['"]/g,
    TwitterAccessToken: /[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}/g,
    TwitterOAuth: /[tT][wW][iI][tT][tT][eE][rR].*['"][0-9a-zA-Z]{35,44}['"]/g,
    
    // Version Control
    GitHubToken: /[gG][iI][tT][hH][uU][bB].*['"][0-9a-zA-Z]{35,40}['"]/g,
    
    // Payment Processors
    StripeAPIKey: /sk_live_[0-9a-zA-Z]{24}/g,
    StripeRestrictedKey: /rk_live_[0-9a-zA-Z]{24}/g,
    SquareAccessToken: /sq0atp-[0-9A-Za-z\-_]{22}/g,
    SquareOAuthSecret: /sq0csp-[0-9A-Za-z\-_]{43}/g,
    PayPalBraintreeToken: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g,
    PicaticAPIKey: /sk_live_[0-9a-z]{32}/g,
    
    // Communication Services
    SlackToken: /(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})/g,
    SlackWebhook: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}/g,
    TwilioAPIKey: /SK[0-9a-fA-F]{32}/g,
    
    // Email Services
    MailgunAPIKey: /key-[0-9a-zA-Z]{32}/g,
    MailChimpAPIKey: /[0-9a-f]{32}-us[0-9]{1,2}/g,
    
    // Google Services
    GoogleAPIKey: /AIza[0-9A-Za-z\-_]{35}/g,
    GoogleOAuth: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g,
    GoogleOAuthToken: /ya29\.[0-9A-Za-z\-_]+/g,
    GoogleServiceAccount: /"type": "service_account"/g,
    
    // Other Services
    HerokuAPIKey: /[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/g,
    
    // Generic Patterns
    GenericAPIKey: /[aA][pP][iI][_]?[kK][eE][yY].*['"][0-9a-zA-Z]{32,45}['"]/g,
    GenericSecret: /[sS][eE][cC][rR][eE][tT].*['"][0-9a-zA-Z]{32,45}['"]/g,
    PasswordInURL: /[a-zA-Z]{3,10}:\/\/[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}["'\s]/g
  },

  // Key validation function
  isValidKey: function(key) {
    if (!key || key.length < 12) return false;
    
    // Check if it looks like a real key
    const hasLetters = /[a-zA-Z]/.test(key);
    const hasNumbers = /[0-9]/.test(key);
    const hasSpecial = /[-_]/.test(key);
    
    return (hasLetters && hasNumbers) || (hasLetters && hasSpecial);
  }
};

// Display the profanatica banner
function showBanner() {
  const banner = `
  ██████╗ ██████╗  ██████╗ ███████╗ █████╗ ███╗   ██╗ █████╗ ████████╗██╗ ██████╗
  ██╔══██╗██╔══██╗██╔═══██╗██╔════╝██╔══██╗████╗  ██║██╔══██╗╚══██╔══╝██║██╔════╝
  ██████╔╝██████╔╝██║   ██║█████╗  ███████║██╔██╗ ██║███████║   ██║   ██║██║     
  ██╔═══╝ ██╔══██╗██║   ██║██╔══╝  ██╔══██║██║╚██╗██║██╔══██║   ██║   ██║██║     
  ██║     ██║  ██║╚██████╔╝███████╗██║  ██║██║ ╚████║██║  ██║   ██║   ██║╚██████╗
  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝
  
  SECRET SCANNER v2.1 | by profanatica Security Research Team
  ==========================================================
  `;
  console.log(banner);
}

// Main scanning function
async function scanForSecrets(url) {
  try {
    const response = await axios.get(url, {
      headers: { 'User-Agent': CONFIG.userAgent },
      timeout: CONFIG.requestTimeout
    });
    
    const content = response.data;
    const findings = [];

    // Check each detection pattern
    for (const [patternName, regex] of Object.entries(CONFIG.detectionPatterns)) {
      let match;
      // Reset regex index for new search
      regex.lastIndex = 0;
      
      while ((match = regex.exec(content)) !== null) {
        // Get capture group or full match
        const keyValue = match[2] || match[1] || match[0];
        
        if (keyValue && CONFIG.isValidKey(keyValue)) {
          findings.push({
            type: patternName,
            value: keyValue,
            context: content.substring(match.index, match.index + 100)
          });
        }
      }
    }

    return findings;
  } catch (error) {
    console.error(`Error scanning ${url}:`, error.message);
    return [];
  }
}

// Main function
async function main() {
  showBanner();
  
  const url = process.argv[2];
  if (!url) {
    console.log('Usage: node scanner.js <URL>');
    process.exit(1);
  }

  console.log(`🔍 Scanning ${url}...`);
  const results = await scanForSecrets(url);

  if (results.length > 0) {
    console.log(`✅ Found ${results.length} potential secrets:`);
    
    // Create directory if it doesn't exist
    if (!fs.existsSync(CONFIG.outputDir)) {
      fs.mkdirSync(CONFIG.outputDir, { recursive: true });
    }

    // Prepare file content
    const outputContent = results.map(result => 
      `[${result.type}]\nValue: ${result.value}\nContext: ${result.context}\n${'-'.repeat(80)}`
    ).join('\n\n');

    // Save to file
    fs.writeFileSync(
      path.join(CONFIG.outputDir, CONFIG.outputFile),
      `Scan Report - ${new Date().toISOString()}\nURL: ${url}\n\n${outputContent}`
    );

    console.log(`📝 Results saved to ${path.join(CONFIG.outputDir, CONFIG.outputFile)}`);
  } else {
    console.log('🔍 No secrets found.');
  }
}

main().catch(err => {
  console.error('❌ Error:', err.message);
  process.exit(1);
});
