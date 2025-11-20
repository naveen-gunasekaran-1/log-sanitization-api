// ==========================================
// COMPREHENSIVE REGEX PATTERNS FOR LOG REDACTION
// ==========================================

// Network & Communication
const email_Pattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const ipv4_Pattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const ipv6_Pattern = /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b/g;
const mac_Pattern = /\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b/g;
const url_Pattern = /https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)/g;

// File paths
const windowsPath_Pattern = /[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*/g;
const unixPath_Pattern = /\/(?:[a-zA-Z0-9_\-\.]+\/)+[a-zA-Z0-9_\-\.]+/g;

// User identifiers
const username_Pattern = /(?:user(?:name)?|login|account|uid)[\s:=]+([a-zA-Z0-9_\-\.]{3,20})/gi;
const atUsername_Pattern = /@[a-zA-Z0-9_]{3,15}\b/g;

// Timestamps
const isoTimestamp_Pattern = /\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d{3})?(?:Z|[+-]\d{2}:\d{2})?/g;
const dateTime_Pattern = /\d{1,2}\/\d{1,2}\/\d{2,4}\s+\d{1,2}:\d{2}(?::\d{2})?(?:\s*[AP]M)?/gi;
const unixTimestamp_Pattern = /\b\d{10,13}\b/g;

// Financial
const creditCard_Pattern = /\b(?:\d{4}[\s\-]?){3}\d{4}\b/g;
const ssn_Pattern = /\b\d{3}-\d{2}-\d{4}\b/g;

// Phone numbers
const phone_Pattern = /(?:\+\d{1,3}[\s\-]?)?\(?(\d{3})\)?[\s\-]?(\d{3})[\s\-]?(\d{4})/g;

// API & Security
const APIPattern = /[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}/g;
const awsAccessKey_Pattern = /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g;
const awsSecretKey_Pattern = /\b[A-Za-z0-9/+=]{40}\b/g;
const awsInstanceId_Pattern = /\b[i|vol|snap|ami]-[0-9a-f]{8,17}\b/g;
const privateKey_Pattern = /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g;

// Database
const mongoUri_Pattern = /mongodb(?:\+srv)?:\/\/[^\s'"]+/g;
const sqlUri_Pattern = /(?:postgresql|mysql|mssql):\/\/[^\s'"]+/g;

// Session & Cookies
const sessionId_Pattern = /(?:session|sid|PHPSESSID|JSESSIONID)[\s:=]+([A-Za-z0-9\-_]{20,})/gi;
const bearer_Pattern = /Bearer\s+[A-Za-z0-9\-_\.]+/g;

// Personal Information
const name_Pattern = /(?:first[\s_]?name|last[\s_]?name|full[\s_]?name)[\s:=]+([A-Za-z\s]{2,30})/gi;
const address_Pattern = /\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Circle|Cir)(?:\s+(?:Apt|Suite|Unit|#)\s*[A-Za-z0-9]+)?/gi;

// Log-specific
const pid_Pattern = /(?:pid|process[\s_]?id)[\s:=]+(\d+)/gi;
const threadId_Pattern = /(?:tid|thread[\s_]?id)[\s:=]+(\d+)/gi;
// DOM elements
const fileInput = document.getElementById('fileInput');
const fileName = document.getElementById('fileName');
const results = document.getElementById('results');
const originalContent = document.getElementById('originalContent');
const redactedContent = document.getElementById('redactedContent');
const emailCount = document.getElementById('emailCount');

let redactedText = '';

// File input handler - Now sends to server API
fileInput.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    
    if (!file) {
        return;
    }

    if (!file.name.endsWith('.txt')) {
        alert('Please select a .txt file');
        fileInput.value = '';
        return;
    }

    fileName.textContent = file.name;
    
    try {
        // Create form data
        const formData = new FormData();
        formData.append('file', file);
        
        // Show loading state
        results.classList.remove('hidden');
        originalContent.textContent = 'Processing...';
        redactedContent.textContent = 'Processing...';
        emailCount.textContent = '...';
        
        // Send to server API
        const response = await fetch('/api/redact', {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to process file');
        }
        
        const result = await response.json();
        
        // Update UI with results
        originalContent.textContent = result.original;
        redactedContent.textContent = result.redacted;
        emailCount.textContent = result.statistics.TOTAL;
        
        // Log statistics to console
        console.log('[DEBUG] Comprehensive Redaction Summary:', result.statistics);
        
        // Scroll to results
        results.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        
    } catch (error) {
        alert('Error processing file: ' + error.message);
        console.error('[ERROR]', error);
        results.classList.add('hidden');
    }
});

// Redact API keys function
function redactAPIKeys(text) {
    if (!text) return text;
    
    // Prefix-based API keys 
    text = text.replace(
        /\b(?:sk|pk|ak|api|key|secret|token|bearer)[_\-][A-Za-z0-9\-\._]{8,}\b/gi,
        "[REDACTED_API_KEY]"
    );
    // JWT Tokens 
    text = text.replace(
        /\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
        "[REDACTED_JWT]"
    );
    // UUID-based tokens 
    text = text.replace(
        /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g,
        "[REDACTED_UUID_TOKEN]"
    );
    // Base64-like secrets 
    text = text.replace(
        /\b(?:[A-Za-z0-9+/]{20,}={0,2})\b/g,
        "[REDACTED_BASE64_TOKEN]"
    );
    // Long HEX secrets 
    text = text.replace(
        /\b[a-fA-F0-9]{32,128}\b/g,
        "[REDACTED_HEX_KEY]"
    );
    // 6. Generic long alphanumeric tokens
    text = text.replace(
        /\b[A-Za-z0-9_\-\.]{20,}\b/g,
        "[REDACTED_TOKEN]"
    );
    return text;
}

// Process the text and redact all sensitive data
function processText(text) {
    // Count all pattern matches before redaction
    const counts = {
        emails: (text.match(email_Pattern) || []).length,
        ipv4: (text.match(ipv4_Pattern) || []).length,
        ipv6: (text.match(ipv6_Pattern) || []).length,
        mac: (text.match(mac_Pattern) || []).length,
        urls: (text.match(url_Pattern) || []).length,
        paths: (text.match(windowsPath_Pattern) || []).length + (text.match(unixPath_Pattern) || []).length,
        usernames: (text.match(username_Pattern) || []).length + (text.match(atUsername_Pattern) || []).length,
        timestamps: (text.match(isoTimestamp_Pattern) || []).length + 
                   (text.match(dateTime_Pattern) || []).length + 
                   (text.match(unixTimestamp_Pattern) || []).length,
        creditCards: (text.match(creditCard_Pattern) || []).length,
        ssn: (text.match(ssn_Pattern) || []).length,
        phones: (text.match(phone_Pattern) || []).length,
        apis: (text.match(APIPattern) || []).length,
        awsKeys: (text.match(awsAccessKey_Pattern) || []).length + (text.match(awsSecretKey_Pattern) || []).length,
        awsResources: (text.match(awsInstanceId_Pattern) || []).length,
        privateKeys: (text.match(privateKey_Pattern) || []).length,
        dbUris: (text.match(mongoUri_Pattern) || []).length + (text.match(sqlUri_Pattern) || []).length,
        sessions: (text.match(sessionId_Pattern) || []).length + (text.match(bearer_Pattern) || []).length,
        names: (text.match(name_Pattern) || []).length,
        addresses: (text.match(address_Pattern) || []).length,
        pids: (text.match(pid_Pattern) || []).length,
        threads: (text.match(threadId_Pattern) || []).length
    };
    
    const totalCount = Object.values(counts).reduce((sum, val) => sum + val, 0);
    
    // Apply redactions in specific order to prevent conflicts
    redactedText = text;
    
    // 1. Private keys and certificates (multi-line, do first)
    redactedText = redactedText.replace(privateKey_Pattern, '[REDACTED_PRIVATE_KEY]');
    
    // 2. Database connection strings (contain special chars)
    redactedText = redactedText.replace(mongoUri_Pattern, '[REDACTED_MONGO_URI]');
    redactedText = redactedText.replace(sqlUri_Pattern, '[REDACTED_SQL_URI]');
    
    // 3. URLs (before paths to avoid breaking URL paths)
    redactedText = redactedText.replace(url_Pattern, '[REDACTED_URL]');
    
    // 4. File paths
    redactedText = redactedText.replace(windowsPath_Pattern, '[REDACTED_PATH]');
    redactedText = redactedText.replace(unixPath_Pattern, '[REDACTED_PATH]');
    
    // 5. AWS credentials and resources
    redactedText = redactedText.replace(awsAccessKey_Pattern, '[REDACTED_AWS_ACCESS_KEY]');
    redactedText = redactedText.replace(awsSecretKey_Pattern, '[REDACTED_AWS_SECRET_KEY]');
    redactedText = redactedText.replace(awsInstanceId_Pattern, '[REDACTED_AWS_RESOURCE_ID]');
    
    // 6. Session tokens and bearer tokens
    redactedText = redactedText.replace(bearer_Pattern, 'Bearer [REDACTED_TOKEN]');
    redactedText = redactedText.replace(sessionId_Pattern, '$1 [REDACTED_SESSION_ID]');
    
    // 7. Financial data
    redactedText = redactedText.replace(creditCard_Pattern, '[REDACTED_CREDIT_CARD]');
    redactedText = redactedText.replace(ssn_Pattern, '[REDACTED_SSN]');
    
    // 8. Contact information
    redactedText = redactedText.replace(phone_Pattern, '[REDACTED_PHONE]');
    redactedText = redactedText.replace(email_Pattern, '[REDACTED_EMAIL]');
    
    // 9. Network addresses
    redactedText = redactedText.replace(ipv6_Pattern, '[REDACTED_IPv6]');
    redactedText = redactedText.replace(ipv4_Pattern, '[REDACTED_IPv4]');
    redactedText = redactedText.replace(mac_Pattern, '[REDACTED_MAC_ADDRESS]');
    
    // 10. Personal information
    redactedText = redactedText.replace(name_Pattern, '$1 [REDACTED_NAME]');
    redactedText = redactedText.replace(address_Pattern, '[REDACTED_ADDRESS]');
    
    // 11. Timestamps
    redactedText = redactedText.replace(isoTimestamp_Pattern, '[REDACTED_TIMESTAMP]');
    redactedText = redactedText.replace(dateTime_Pattern, '[REDACTED_DATETIME]');
    redactedText = redactedText.replace(unixTimestamp_Pattern, '[REDACTED_UNIX_TIME]');
    
    // 12. User identifiers
    redactedText = redactedText.replace(username_Pattern, '$1 [REDACTED_USERNAME]');
    redactedText = redactedText.replace(atUsername_Pattern, '[REDACTED_USERNAME]');
    
    // 13. Process/Thread IDs
    redactedText = redactedText.replace(pid_Pattern, '$1 [REDACTED_PID]');
    redactedText = redactedText.replace(threadId_Pattern, '$1 [REDACTED_THREAD_ID]');
    
    // 14. API patterns
    redactedText = redactedText.replace(APIPattern, '[REDACTED_API]');
    
    // 15. Apply comprehensive API key redaction (JWT, UUID, Base64, HEX, tokens)
    redactedText = redactAPIKeys(redactedText);
    
    // Update UI
    originalContent.textContent = text;
    redactedContent.textContent = redactedText;
    emailCount.textContent = totalCount;
    
    // Show results
    results.classList.remove('hidden');
    
    // Scroll to results
    results.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    
    // Comprehensive debug logging
    console.log('[DEBUG] Comprehensive Redaction Summary:', {
        'Network': {
            emails: counts.emails,
            ipv4: counts.ipv4,
            ipv6: counts.ipv6,
            mac: counts.mac,
            urls: counts.urls
        },
        'File System': {
            paths: counts.paths
        },
        'User Data': {
            usernames: counts.usernames,
            names: counts.names,
            addresses: counts.addresses
        },
        'Time': {
            timestamps: counts.timestamps
        },
        'Financial': {
            creditCards: counts.creditCards,
            ssn: counts.ssn,
            phones: counts.phones
        },
        'Security': {
            apis: counts.apis,
            awsKeys: counts.awsKeys,
            awsResources: counts.awsResources,
            privateKeys: counts.privateKeys,
            dbUris: counts.dbUris,
            sessions: counts.sessions
        },
        'Process': {
            pids: counts.pids,
            threads: counts.threads
        },
        'TOTAL': totalCount
    });
}
