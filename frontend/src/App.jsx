import React, { useState } from 'react'
import LandingPage from './components/LandingPage'
import ChatInterface from './components/ChatInterface'

function App() {
  const [currentView, setCurrentView] = useState('landing')

  const startAnalysis = () => {
    setCurrentView('chat')
  }

  return (
    <div className="App">
      {currentView === 'landing' && <LandingPage onStart={startAnalysis} />}
      {currentView === 'chat' && <ChatInterface />}
    </div>
  )
}

export default App