import React from 'react'
import { Shield, AlertTriangle, X, ExternalLink } from 'lucide-react'

function AnalysisResult({ result }) {
  const getVerdictIcon = (verdict) => {
    switch (verdict) {
      case 'safe':
        return <Shield className="text-green-600" size={24} />
      case 'suspicious':
        return <AlertTriangle className="text-yellow-600" size={24} />
      case 'dangerous':
        return <X className="text-red-600" size={24} />
      default:
        return <Shield className="text-gray-600" size={24} />
    }
  }

  const getVerdictText = (verdict) => {
    switch (verdict) {
      case 'safe':
        return 'Säker'
      case 'suspicious':
        return 'Misstänkt'
      case 'dangerous':
        return 'Farlig'
      default:
        return 'Okänd'
    }
  }

  const getRecommendation = (verdict) => {
    switch (verdict) {
      case 'safe':
        return 'Länken verkar säker att besöka.'
      case 'suspicious':
        return 'Var försiktig. Granska länken manuellt innan du besöker den.'
      case 'dangerous':
        return 'Blockera denna länk. Den kan vara skadlig eller innehålla bedrägerier.'
      default:
        return 'Kunde inte bestämma säkerhetsnivå.'
    }
  }

  if (!result) {
    return <div>Inget resultat tillgängligt</div>
  }

  return (
    <div className="message bot">
      <div className="message-avatar">
        <Shield size={20} />
      </div>
      <div className="message-content">
        <div className="analysis-result">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '15px' }}>
            {getVerdictIcon(result.verdict)}
            <span className={`verdict ${result.verdict}`}>
              {getVerdictText(result.verdict)}
            </span>
          </div>

          <div className="confidence">
            Säkerhet: {Math.round(result.confidence || 0)}%
          </div>

          <p style={{ marginBottom: '20px', fontWeight: '500' }}>
            {getRecommendation(result.verdict)}
          </p>

          {result.evidence && result.evidence.length > 0 && (
            <div>
              <h4 style={{ marginBottom: '10px', color: '#333' }}>Analysresultat:</h4>
              <ul className="evidence-list">
                {result.evidence.map((evidence, index) => (
                  <li key={index} className="evidence-item">
                    {evidence}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {result.url && (
            <div style={{ fontSize: '0.9rem', color: '#666', wordBreak: 'break-all' }}>
              <strong>Analyserad URL:</strong> {result.url}
            </div>
          )}

          {result.artifacts && (
            <div style={{ marginTop: '15px', paddingTop: '15px', borderTop: '1px solid #eee' }}>
              <h4 style={{ marginBottom: '10px', fontSize: '0.9rem', color: '#666' }}>
                Tekniska detaljer:
              </h4>

              {result.artifacts.screenshot_base64 && (
                <div style={{ marginBottom: '15px' }}>
                  <h5 style={{ marginBottom: '10px', fontSize: '0.85rem', color: '#666' }}>
                    📷 Skärmdump av webbsidan:
                  </h5>
                  <div style={{
                    border: '1px solid #ddd',
                    borderRadius: '8px',
                    overflow: 'hidden',
                    maxWidth: '400px'
                  }}>
                    <img
                      src={`data:image/png;base64,${result.artifacts.screenshot_base64}`}
                      alt="Website screenshot"
                      style={{
                        width: '100%',
                        height: 'auto',
                        display: 'block'
                      }}
                    />
                  </div>
                  {result.artifacts.page_title && (
                    <div style={{
                      fontSize: '0.8rem',
                      color: '#666',
                      marginTop: '5px',
                      fontStyle: 'italic'
                    }}>
                      Sidtitel: {result.artifacts.page_title}
                    </div>
                  )}
                </div>
              )}

              <div style={{ fontSize: '0.8rem', color: '#888' }}>
                {result.artifacts.screenshot_base64 && (
                  <div>📷 Skärmdump analyserad</div>
                )}
                {result.artifacts.redirect_chain && (
                  <div>🔗 Omdirigeringskedja dokumenterad</div>
                )}
                {result.artifacts.headers && (
                  <div>📋 HTTP-headers analyserade</div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default AnalysisResult