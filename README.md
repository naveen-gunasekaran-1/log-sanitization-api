# Log Redaction Service

A comprehensive Node.js/Express server for redacting sensitive information from log files.

## Features

- **Comprehensive Redaction**: Emails, IPs (v4/v6), URLs, file paths, API keys, credentials, PII, and more
- **RESTful API**: Easy integration with any frontend or service
- **File Upload Support**: Process `.txt` files up to 10MB
- **Detailed Statistics**: Get categorized counts of redacted items
- **Production Ready**: Error handling, validation, and logging

## Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Start the Server

```bash
npm start
```

Or for development with auto-reload:

```bash
npm run dev
```

### 3. Access the Application

- **Frontend**: http://localhost:3000
- **API**: http://localhost:3000/api

## API Endpoints

### `POST /api/redact`

Upload and redact a text file.

**Request:**
- Method: `POST`
- Content-Type: `multipart/form-data`
- Body: Form data with file field named `file`

**Response:**
```json
{
  "success": true,
  "filename": "logs.txt",
  "original": "original text...",
  "redacted": "redacted text...",
  "statistics": {
    "Network": { "emails": 5, "ipv4": 3, ... },
    "Security": { "apis": 2, ... },
    "TOTAL": 15
  }
}
```

**cURL Example:**
```bash
curl -X POST http://localhost:3000/api/redact \
  -F "file=@logs.txt"
```

### `POST /api/redact-text`

Redact raw text without file upload.

**Request:**
- Method: `POST`
- Content-Type: `application/json`
- Body: `{ "text": "your text here" }`

**Response:**
```json
{
  "success": true,
  "redacted": "redacted text...",
  "statistics": { ... }
}
```

**cURL Example:**
```bash
curl -X POST http://localhost:3000/api/redact-text \
  -H "Content-Type: application/json" \
  -d '{"text": "Contact john@example.com at 192.168.1.1"}'
```

### `GET /api/health`

Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "message": "Log Redaction Service is running"
}
```

## What Gets Redacted

### Network & Communication
- Email addresses → `[REDACTED_EMAIL]`
- IPv4 addresses → `[REDACTED_IPv4]`
- IPv6 addresses → `[REDACTED_IPv6]`
- MAC addresses → `[REDACTED_MAC_ADDRESS]`
- URLs → `[REDACTED_URL]`

### File System
- Windows paths → `[REDACTED_PATH]`
- Unix/Mac paths → `[REDACTED_PATH]`

### Security & Authentication
- API keys → `[REDACTED_API_KEY]`
- JWT tokens → `[REDACTED_JWT]`
- AWS credentials → `[REDACTED_AWS_ACCESS_KEY]`
- Private keys → `[REDACTED_PRIVATE_KEY]`
- Session IDs → `[REDACTED_SESSION_ID]`
- Bearer tokens → `Bearer [REDACTED_TOKEN]`
- Database URIs → `[REDACTED_MONGO_URI]` / `[REDACTED_SQL_URI]`

### Personal Information
- Names → `[REDACTED_NAME]`
- Addresses → `[REDACTED_ADDRESS]`
- Phone numbers → `[REDACTED_PHONE]`
- Credit cards → `[REDACTED_CREDIT_CARD]`
- SSN → `[REDACTED_SSN]`

### Timestamps
- ISO format → `[REDACTED_TIMESTAMP]`
- Date/Time → `[REDACTED_DATETIME]`
- Unix timestamps → `[REDACTED_UNIX_TIME]`

### Process Information
- Process IDs → `[REDACTED_PID]`
- Thread IDs → `[REDACTED_THREAD_ID]`

## Configuration

### Environment Variables

- `PORT`: Server port (default: 3000)

### File Upload Limits

Edit in `server.js`:
```javascript
limits: {
    fileSize: 10 * 1024 * 1024 // 10MB
}
```

## Integration Example

### JavaScript/Node.js

```javascript
const FormData = require('form-data');
const fs = require('fs');

const form = new FormData();
form.append('file', fs.createReadStream('logs.txt'));

const response = await fetch('http://localhost:3000/api/redact', {
    method: 'POST',
    body: form
});

const result = await response.json();
console.log(result.redacted);
```

### Python

```python
import requests

with open('logs.txt', 'rb') as f:
    files = {'file': f}
    response = requests.post('http://localhost:3000/api/redact', files=files)
    
result = response.json()
print(result['redacted'])
```

## Development

### Project Structure

```
├── server.js          # Main Express server
├── index.html         # Frontend UI
├── styles.css         # Frontend styles
├── script.js          # Frontend JavaScript
├── package.json       # Dependencies
└── README.md          # Documentation
```

### Adding New Patterns

1. Add pattern to `PATTERNS` object in `server.js`
2. Add corresponding redaction in `processText()` function
3. Update counts calculation

Example:
```javascript
// In PATTERNS
customPattern: /your-regex-here/g

// In processText()
redactedText = redactedText.replace(PATTERNS.customPattern, '[REDACTED_CUSTOM]');
```

## Error Handling

The server handles:
- Invalid file types
- File size limits
- Missing parameters
- Processing errors

All errors return appropriate HTTP status codes and JSON error messages.

## Security Considerations

- **No data persistence**: Files are processed in memory and not stored
- **Size limits**: Prevents memory exhaustion attacks
- **Type validation**: Only accepts .txt files
- **Sanitization**: All patterns are applied server-side

## License

MIT
