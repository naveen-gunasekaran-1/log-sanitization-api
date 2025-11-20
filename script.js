// DOM elements
const fileInput = document.getElementById('fileInput');
const fileName = document.getElementById('fileName');
const results = document.getElementById('results');
const originalContent = document.getElementById('originalContent');
const redactedContent = document.getElementById('redactedContent');
const emailCount = document.getElementById('emailCount');

// File input handler - Sends to server API
fileInput.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    
    if (!file) {
        return;
    }

    const allowedExtensions = ['.txt', '.log', '.json'];
    const isValid = allowedExtensions.some(ext => file.name.endsWith(ext));
    
    if (!isValid) {
        alert('Please select a .txt, .log, or .json file');
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
        fileInput.value = '';
        fileName.textContent = 'No file selected';
    }
});
