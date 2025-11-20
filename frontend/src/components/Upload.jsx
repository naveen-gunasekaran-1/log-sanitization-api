import { useState } from 'react'

function Upload({ onProcessComplete }) {
  const [file, setFile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [aiAnalysis, setAiAnalysis] = useState(null)

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0]
    const allowedExtensions = ['.txt', '.log', '.json']
    const isValid = allowedExtensions.some(ext => selectedFile?.name.endsWith(ext))
    
    if (selectedFile && isValid) {
      setFile(selectedFile)
      setError(null)
    } else {
      setError('Please select a .txt, .log, or .json file')
      setFile(null)
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!file) return

    setLoading(true)
    setError(null)

    const formData = new FormData()
    formData.append('file', file)

    try {
      const response = await fetch('/api/redact', {
        method: 'POST',
        body: formData
      })

      if (!response.ok) {
        throw new Error('Failed to process file')
      }

      const data = await response.json()
      setResult(data)
      onProcessComplete(data)

      // If errors detected, analyze with AI
      if (data.hasErrors && data.errorCount > 0) {
        analyzeErrors(data.redacted)
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const analyzeErrors = async (redactedText) => {
    setAnalyzing(true)
    setAiAnalysis(null)

    try {
      const response = await fetch('/api/analyze-errors', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ redactedText })
      })

      if (!response.ok) {
        throw new Error('Failed to analyze errors')
      }

      const data = await response.json()
      if (data.hasErrors && data.analyses) {
        setAiAnalysis(data.analyses)
      }
    } catch (err) {
      console.error('AI Analysis failed:', err)
    } finally {
      setAnalyzing(false)
    }
  }

  const downloadRedacted = () => {
    if (!result) return
    
    const blob = new Blob([result.redacted], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = result.filename.replace('.txt', '_redacted.txt')
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="upload-container">
      <div className="card">
        <h2>Upload Log File</h2>
        <form onSubmit={handleSubmit}>
          <div className="file-input-wrapper">
            <input
              type="file"
              accept=".txt,.log,.json"
              onChange={handleFileChange}
              id="fileInput"
            />
            <label htmlFor="fileInput" className="file-label">
              {file ? file.name : 'Choose .txt, .log, or .json file'}
            </label>
          </div>

          {error && <div className="error">{error}</div>}

          <button type="submit" disabled={!file || loading} className="btn">
            {loading ? 'Processing...' : 'Redact File'}
          </button>
        </form>
      </div>

      {result && (
        <>
          <div className="card">
            <div className="card-header">
              <h2>Results</h2>
              <button onClick={downloadRedacted} className="btn-small">
                Download Redacted
              </button>
            </div>
            {result.hasErrors && (
              <div className="stats-grid">
                <div className="stat-item">
                  <span className="stat-label">Errors Detected:</span>
                  <span className="stat-value error-badge">{result.errorCount}</span>
                </div>
              </div>
            )}
          </div>

          {result.hasErrors && (
            <div className="card ai-analysis-card">
              <h2>AI Error Analysis</h2>
              {analyzing && (
                <div className="loading-state">
                  <div className="spinner"></div>
                  <p>Analyzing errors with Gemini AI...</p>
                </div>
              )}
              {!analyzing && aiAnalysis && Array.isArray(aiAnalysis) && (
                <div className="ai-analysis-list">
                  {aiAnalysis.map((item, index) => (
                    <div key={index} className="error-analysis-item">
                      <div className="error-header">
                        <h3>Error #{item.errorNumber}</h3>
                        {item.analysis.cached && (
                          <div className="cache-badge">📦 Cached</div>
                        )}
                      </div>
                      
                      <div className="analysis-section">
                        <h4>Error Log</h4>
                        <pre className="error-log-box">{item.errorLog}</pre>
                      </div>
                      
                      <div className="analysis-section">
                        <h4>Severity Level</h4>
                        <span className={`severity-badge ${item.analysis.severity.toLowerCase()}`}>
                          {item.analysis.severity}
                        </span>
                      </div>
                      
                      <div className="analysis-section">
                        <h4>Root Cause</h4>
                        <p>{item.analysis.cause}</p>
                      </div>
                      
                      <div className="analysis-section">
                        <h4>Possible Solutions</h4>
                        <ul>
                          {item.analysis.solutions.map((solution, idx) => (
                            <li key={idx}>{solution}</li>
                          ))}
                        </ul>
                      </div>
                      
                      <div className="analysis-section">
                        <h4>Prevention Tips</h4>
                        <p>{item.analysis.prevention}</p>
                      </div>
                      
                      {item.analysis.error && (
                        <div className="analysis-error">
                          ⚠️ {item.analysis.error}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          <div className="results-grid">
            <div className="card">
              <h3>Original Content</h3>
              <pre className="content-box">{result.original}</pre>
            </div>

            <div className="card">
              <h3>Redacted Content</h3>
              <pre className="content-box">{result.redacted}</pre>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

export default Upload
