import React from 'react'

function LandingPage({ onStart }) {
  return (
    <div className="landing-page">
      <div className="container">
        <h1 className="landing-title">ForTAI</h1>
        <p className="landing-subtitle">
          Avancerad länkanalys med AI. Klistra in en länk och få en djupgående säkerhetsanalys
          på sekunder. Skydda dig mot phishing, bedrägerier och skadliga webbsidor.
        </p>
        <button className="start-button" onClick={onStart}>
          Starta analys
        </button>
      </div>
    </div>
  )
}

export default LandingPage