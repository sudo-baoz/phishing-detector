import './i18n'
import React, { Suspense } from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <Suspense fallback={
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-cyan-400 text-2xl font-mono animate-pulse">
          Loading...
        </div>
      </div>
    }>
      <App />
    </Suspense>
  </React.StrictMode>,
)
