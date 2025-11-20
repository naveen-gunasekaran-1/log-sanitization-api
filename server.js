const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Configure multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'text/plain' || file.originalname.endsWith('.txt')) {
            cb(null, true);
        } else {
            cb(new Error('Only .txt files are allowed'), false);
        }
    },
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB limit
    }
});

// Serve static files
app.use(express.static(__dirname));
app.use(express.json());

// ==========================================
// COMPREHENSIVE REGEX PATTERNS FOR LOG REDACTION
// ==========================================

const PATTERNS = {
    // Network & Communication
    email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    ipv4: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    ipv6: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b/g,
    mac: /\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b/g,
    url: /https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)/g,
    
    // File paths
    windowsPath: /[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*/g,
    unixPath: /\/(?:[a-zA-Z0-9_\-\.]+\/)+[a-zA-Z0-9_\-\.]+/g,
    
    // User identifiers
    username: /(?:user(?:name)?|login|account|uid)[\s:=]+([a-zA-Z0-9_\-\.]{3,20})/gi,
    atUsername: /@[a-zA-Z0-9_]{3,15}\b/g,
    
    // Timestamps
    isoTimestamp: /\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d{3})?(?:Z|[+-]\d{2}:\d{2})?/g,
    dateTime: /\d{1,2}\/\d{1,2}\/\d{2,4}\s+\d{1,2}:\d{2}(?::\d{2})?(?:\s*[AP]M)?/gi,
    unixTimestamp: /\b\d{10,13}\b/g,
    
    // Financial
    creditCard: /\b(?:\d{4}[\s\-]?){3}\d{4}\b/g,
    ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
    
    // Phone numbers
    phone: /(?:\+\d{1,3}[\s\-]?)?\(?(\d{3})\)?[\s\-]?(\d{3})[\s\-]?(\d{4})/g,
    
    // API & Security
    api: /[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}/g,
    apiKeyPrefix: /\b(?:sk|pk|ak|api|key|secret|token|bearer)[_\-][A-Za-z0-9\-\._]{8,}\b/gi,
    jwt: /\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
    uuid: /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g,
    base64: /\b(?:[A-Za-z0-9+/]{20,}={0,2})\b/g,
    hex: /\b[a-fA-F0-9]{32,128}\b/g,
    token: /\b[A-Za-z0-9_\-\.]{20,}\b/g,
    awsAccessKey: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    awsSecretKey: /\b[A-Za-z0-9/+=]{40}\b/g,
    awsInstanceId: /\b[i|vol|snap|ami]-[0-9a-f]{8,17}\b/g,
    privateKey: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    
    // Database
    mongoUri: /mongodb(?:\+srv)?:\/\/[^\s'"]+/g,
    sqlUri: /(?:postgresql|mysql|mssql):\/\/[^\s'"]+/g,
    
    // Session & Cookies
    sessionId: /(?:session|sid|PHPSESSID|JSESSIONID)[\s:=]+([A-Za-z0-9\-_]{20,})/gi,
    bearer: /Bearer\s+[A-Za-z0-9\-_\.]+/g,
    
    // Personal Information
    name: /(?:first[\s_]?name|last[\s_]?name|full[\s_]?name)[\s:=]+([A-Za-z\s]{2,30})/gi,
    address: /\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Circle|Cir)(?:\s+(?:Apt|Suite|Unit|#)\s*[A-Za-z0-9]+)?/gi,
    
    // Log-specific
    pid: /(?:pid|process[\s_]?id)[\s:=]+(\d+)/gi,
    threadId: /(?:tid|thread[\s_]?id)[\s:=]+(\d+)/gi
};

// ==========================================
// REDACTION FUNCTIONS
// ==========================================

function redactAPIKeys(text) {
    if (!text) return text;
    
    let result = text;
    
    // Prefix-based API keys
    result = result.replace(PATTERNS.apiKeyPrefix, '[REDACTED_API_KEY]');
    
    // JWT Tokens
    result = result.replace(PATTERNS.jwt, '[REDACTED_JWT]');
    
    // UUID-based tokens
    result = result.replace(PATTERNS.uuid, '[REDACTED_UUID_TOKEN]');
    
    // Base64-like secrets
    result = result.replace(PATTERNS.base64, '[REDACTED_BASE64_TOKEN]');
    
    // Long HEX secrets
    result = result.replace(PATTERNS.hex, '[REDACTED_HEX_KEY]');
    
    // Generic long alphanumeric tokens
    result = result.replace(PATTERNS.token, '[REDACTED_TOKEN]');
    
    return result;
}

function countMatches(text, pattern) {
    const matches = text.match(pattern);
    return matches ? matches.length : 0;
}

function processText(text) {
    // Count all pattern matches before redaction
    const counts = {
        emails: countMatches(text, PATTERNS.email),
        ipv4: countMatches(text, PATTERNS.ipv4),
        ipv6: countMatches(text, PATTERNS.ipv6),
        mac: countMatches(text, PATTERNS.mac),
        urls: countMatches(text, PATTERNS.url),
        paths: countMatches(text, PATTERNS.windowsPath) + countMatches(text, PATTERNS.unixPath),
        usernames: countMatches(text, PATTERNS.username) + countMatches(text, PATTERNS.atUsername),
        timestamps: countMatches(text, PATTERNS.isoTimestamp) + 
                   countMatches(text, PATTERNS.dateTime) + 
                   countMatches(text, PATTERNS.unixTimestamp),
        creditCards: countMatches(text, PATTERNS.creditCard),
        ssn: countMatches(text, PATTERNS.ssn),
        phones: countMatches(text, PATTERNS.phone),
        apis: countMatches(text, PATTERNS.api),
        awsKeys: countMatches(text, PATTERNS.awsAccessKey) + countMatches(text, PATTERNS.awsSecretKey),
        awsResources: countMatches(text, PATTERNS.awsInstanceId),
        privateKeys: countMatches(text, PATTERNS.privateKey),
        dbUris: countMatches(text, PATTERNS.mongoUri) + countMatches(text, PATTERNS.sqlUri),
        sessions: countMatches(text, PATTERNS.sessionId) + countMatches(text, PATTERNS.bearer),
        names: countMatches(text, PATTERNS.name),
        addresses: countMatches(text, PATTERNS.address),
        pids: countMatches(text, PATTERNS.pid),
        threads: countMatches(text, PATTERNS.threadId)
    };
    
    const totalCount = Object.values(counts).reduce((sum, val) => sum + val, 0);
    
    // Apply redactions in specific order to prevent conflicts
    let redactedText = text;
    
    // 1. Private keys and certificates (multi-line, do first)
    redactedText = redactedText.replace(PATTERNS.privateKey, '[REDACTED_PRIVATE_KEY]');
    
    // 2. Database connection strings (contain special chars)
    redactedText = redactedText.replace(PATTERNS.mongoUri, '[REDACTED_MONGO_URI]');
    redactedText = redactedText.replace(PATTERNS.sqlUri, '[REDACTED_SQL_URI]');
    
    // 3. URLs (before paths to avoid breaking URL paths)
    redactedText = redactedText.replace(PATTERNS.url, '[REDACTED_URL]');
    
    // 4. File paths
    redactedText = redactedText.replace(PATTERNS.windowsPath, '[REDACTED_PATH]');
    redactedText = redactedText.replace(PATTERNS.unixPath, '[REDACTED_PATH]');
    
    // 5. AWS credentials and resources
    redactedText = redactedText.replace(PATTERNS.awsAccessKey, '[REDACTED_AWS_ACCESS_KEY]');
    redactedText = redactedText.replace(PATTERNS.awsSecretKey, '[REDACTED_AWS_SECRET_KEY]');
    redactedText = redactedText.replace(PATTERNS.awsInstanceId, '[REDACTED_AWS_RESOURCE_ID]');
    
    // 6. Session tokens and bearer tokens
    redactedText = redactedText.replace(PATTERNS.bearer, 'Bearer [REDACTED_TOKEN]');
    redactedText = redactedText.replace(PATTERNS.sessionId, '$1 [REDACTED_SESSION_ID]');
    
    // 7. Financial data
    redactedText = redactedText.replace(PATTERNS.creditCard, '[REDACTED_CREDIT_CARD]');
    redactedText = redactedText.replace(PATTERNS.ssn, '[REDACTED_SSN]');
    
    // 8. Contact information
    redactedText = redactedText.replace(PATTERNS.phone, '[REDACTED_PHONE]');
    redactedText = redactedText.replace(PATTERNS.email, '[REDACTED_EMAIL]');
    
    // 9. Network addresses
    redactedText = redactedText.replace(PATTERNS.ipv6, '[REDACTED_IPv6]');
    redactedText = redactedText.replace(PATTERNS.ipv4, '[REDACTED_IPv4]');
    redactedText = redactedText.replace(PATTERNS.mac, '[REDACTED_MAC_ADDRESS]');
    
    // 10. Personal information
    redactedText = redactedText.replace(PATTERNS.name, '$1 [REDACTED_NAME]');
    redactedText = redactedText.replace(PATTERNS.address, '[REDACTED_ADDRESS]');
    
    // 11. Timestamps
    redactedText = redactedText.replace(PATTERNS.isoTimestamp, '[REDACTED_TIMESTAMP]');
    redactedText = redactedText.replace(PATTERNS.dateTime, '[REDACTED_DATETIME]');
    redactedText = redactedText.replace(PATTERNS.unixTimestamp, '[REDACTED_UNIX_TIME]');
    
    // 12. User identifiers
    redactedText = redactedText.replace(PATTERNS.username, '$1 [REDACTED_USERNAME]');
    redactedText = redactedText.replace(PATTERNS.atUsername, '[REDACTED_USERNAME]');
    
    // 13. Process/Thread IDs
    redactedText = redactedText.replace(PATTERNS.pid, '$1 [REDACTED_PID]');
    redactedText = redactedText.replace(PATTERNS.threadId, '$1 [REDACTED_THREAD_ID]');
    
    // 14. API patterns
    redactedText = redactedText.replace(PATTERNS.api, '[REDACTED_API]');
    
    // 15. Apply comprehensive API key redaction (JWT, UUID, Base64, HEX, tokens)
    redactedText = redactAPIKeys(redactedText);
    
    return {
        original: text,
        redacted: redactedText,
        counts: {
            Network: {
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
            Time: {
                timestamps: counts.timestamps
            },
            Financial: {
                creditCards: counts.creditCards,
                ssn: counts.ssn,
                phones: counts.phones
            },
            Security: {
                apis: counts.apis,
                awsKeys: counts.awsKeys,
                awsResources: counts.awsResources,
                privateKeys: counts.privateKeys,
                dbUris: counts.dbUris,
                sessions: counts.sessions
            },
            Process: {
                pids: counts.pids,
                threads: counts.threads
            },
            TOTAL: totalCount
        }
    };
}

// ==========================================
// API ROUTES
// ==========================================

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'Log Redaction Service is running' });
});

// Upload and redact file
app.post('/api/redact', upload.single('file'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        
        // Convert buffer to string
        const fileContent = req.file.buffer.toString('utf-8');
        
        // Process and redact
        const result = processText(fileContent);
        
        // Log for debugging
        console.log('[INFO] File processed:', {
            filename: req.file.originalname,
            size: req.file.size,
            totalRedactions: result.counts.TOTAL
        });
        
        res.json({
            success: true,
            filename: req.file.originalname,
            original: result.original,
            redacted: result.redacted,
            statistics: result.counts
        });
        
    } catch (error) {
        console.error('[ERROR]', error);
        res.status(500).json({ 
            error: 'Failed to process file',
            message: error.message 
        });
    }
});

// Redact raw text (without file upload)
app.post('/api/redact-text', (req, res) => {
    try {
        const { text } = req.body;
        
        if (!text) {
            return res.status(400).json({ error: 'No text provided' });
        }
        
        const result = processText(text);
        
        res.json({
            success: true,
            redacted: result.redacted,
            statistics: result.counts
        });
        
    } catch (error) {
        console.error('[ERROR]', error);
        res.status(500).json({ 
            error: 'Failed to redact text',
            message: error.message 
        });
    }
});

// Error handling middleware
app.use((error, req, res, next) => {
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File too large. Maximum size is 10MB' });
        }
        return res.status(400).json({ error: error.message });
    }
    
    console.error('[ERROR]', error);
    res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════════╗
║   Log Redaction Service                    ║
║   Server running on port ${PORT}             ║
║                                            ║
║   Frontend: http://localhost:${PORT}        ║
║   API:      http://localhost:${PORT}/api    ║
╚════════════════════════════════════════════╝
    `);
});

module.exports = app;
