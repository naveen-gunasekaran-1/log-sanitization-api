import { useState } from 'react'
import Upload from './components/Upload'
import './App.css'

function App() {
  const [stats, setStats] = useState({
    totalFiles: 0
  })

  const handleProcessComplete = (result) => {
    setStats(prev => ({
      totalFiles: prev.totalFiles + 1
    }))
  }

  return (
    <div className="app">
      <header className="header">
        <h1>Log Redaction Service</h1>
        <div className="stats-bar">
          <span>Files Processed: {stats.totalFiles}</span>
        </div>
      </header>

      <main className="main">
        <Upload onProcessComplete={handleProcessComplete} />
      </main>
    </div>
  )
}

export default App
