import React, { useState, useEffect } from 'react'

const analysisSteps = [
  'Normaliserar URL...',
  'Utför DNS-uppslagning...',
  'Kontrollerar TLS-certifikat...',
  'Hämtar HTTP-headers...',
  'Analyserar omdirigeringar...',
  'Kontrollerar rykte...',
  'Analyserar innehåll...',
  'Sammanställer riskbedömning...',
  'Genererar rapport...'
]

function ProgressIndicator() {
  const [currentStep, setCurrentStep] = useState(0)

  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentStep(prev => {
        if (prev < analysisSteps.length - 1) {
          return prev + 1
        } else {
          return prev
        }
      })
    }, 1500)

    return () => clearInterval(interval)
  }, [])

  return (
    <div className="message bot">
      <div className="message-avatar">
        <div className="spinner"></div>
      </div>
      <div className="message-content">
        <div className="progress-indicator">
          <div className="spinner"></div>
          <span>{analysisSteps[currentStep]}</span>
        </div>
      </div>
    </div>
  )
}

export default ProgressIndicator