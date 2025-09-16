import React, { useState, useEffect, useRef } from 'react'
import { Send, Bot, User } from 'lucide-react'
import AnalysisResult from './AnalysisResult'
import ProgressIndicator from './ProgressIndicator'
import { analyzeUrl, getAnalysisResult } from '../services/api'

function ChatInterface() {
  const [messages, setMessages] = useState([
    {
      id: 1,
      type: 'bot',
      content: 'Hej! Klistra in en URL nedan så gör jag en djupanalys av länken för att kontrollera om den är säker.',
      timestamp: new Date()
    }
  ])
  const [inputValue, setInputValue] = useState('')
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [currentJobId, setCurrentJobId] = useState(null)
  const messagesEndRef = useRef(null)

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  const isValidUrl = (string) => {
    try {
      new URL(string.startsWith('http') ? string : `https://${string}`)
      return true
    } catch (_) {
      return false
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!inputValue.trim() || isAnalyzing) return

    const url = inputValue.trim()

    if (!isValidUrl(url)) {
      const errorMessage = {
        id: Date.now(),
        type: 'bot',
        content: 'Vänligen ange en giltig URL. Exempel: https://example.com eller example.com',
        timestamp: new Date()
      }
      setMessages(prev => [...prev, errorMessage])
      return
    }

    // Add user message
    const userMessage = {
      id: Date.now(),
      type: 'user',
      content: url,
      timestamp: new Date()
    }

    setMessages(prev => [...prev, userMessage])
    setInputValue('')
    setIsAnalyzing(true)

    try {
      // Start analysis
      const response = await analyzeUrl(url)
      const jobId = response.job_id
      setCurrentJobId(jobId)

      // Add progress indicator
      const progressMessage = {
        id: Date.now() + 1,
        type: 'bot',
        content: 'progress',
        timestamp: new Date(),
        jobId
      }
      setMessages(prev => [...prev, progressMessage])

      // Poll for results
      pollForResults(jobId)

    } catch (error) {
      console.error('Analysis failed:', error)
      const errorMessage = {
        id: Date.now() + 2,
        type: 'bot',
        content: 'Ett fel uppstod vid analysen. Vänligen försök igen.',
        timestamp: new Date()
      }
      setMessages(prev => [...prev, errorMessage])
      setIsAnalyzing(false)
    }
  }

  const pollForResults = async (jobId) => {
    const maxAttempts = 30
    let attempts = 0

    const poll = async () => {
      try {
        const result = await getAnalysisResult(jobId)

        if (result.status === 'completed') {
          // Remove progress indicator and add result
          setMessages(prev =>
            prev.filter(msg => msg.jobId !== jobId).concat([{
              id: Date.now(),
              type: 'bot',
              content: 'result',
              timestamp: new Date(),
              analysisResult: result
            }])
          )
          setIsAnalyzing(false)
          setCurrentJobId(null)
        } else if (result.status === 'failed') {
          setMessages(prev =>
            prev.filter(msg => msg.jobId !== jobId).concat([{
              id: Date.now(),
              type: 'bot',
              content: 'Analysen misslyckades. Vänligen försök igen.',
              timestamp: new Date()
            }])
          )
          setIsAnalyzing(false)
          setCurrentJobId(null)
        } else if (attempts < maxAttempts) {
          attempts++
          setTimeout(poll, 2000)
        } else {
          setMessages(prev =>
            prev.filter(msg => msg.jobId !== jobId).concat([{
              id: Date.now(),
              type: 'bot',
              content: 'Analysen tog för lång tid. Vänligen försök igen.',
              timestamp: new Date()
            }])
          )
          setIsAnalyzing(false)
          setCurrentJobId(null)
        }
      } catch (error) {
        console.error('Polling failed:', error)
        if (attempts < maxAttempts) {
          attempts++
          setTimeout(poll, 2000)
        } else {
          setMessages(prev =>
            prev.filter(msg => msg.jobId !== jobId).concat([{
              id: Date.now(),
              type: 'bot',
              content: 'Ett fel uppstod vid analysen. Vänligen försök igen.',
              timestamp: new Date()
            }])
          )
          setIsAnalyzing(false)
          setCurrentJobId(null)
        }
      }
    }

    poll()
  }

  const renderMessage = (message) => {
    if (message.content === 'progress') {
      return <ProgressIndicator key={message.id} />
    }

    if (message.content === 'result') {
      return <AnalysisResult key={message.id} result={message.analysisResult} />
    }

    return (
      <div key={message.id} className={`message ${message.type}`}>
        <div className="message-avatar">
          {message.type === 'bot' ? <Bot size={20} /> : <User size={20} />}
        </div>
        <div className="message-content">
          {message.content}
        </div>
      </div>
    )
  }

  return (
    <div className="chat-container">
      <div className="chat-header">
        <h1>ForTAI Länkanalys</h1>
      </div>

      <div className="chat-messages">
        {messages.map(renderMessage)}
        <div ref={messagesEndRef} />
      </div>

      <div className="chat-input-container">
        <form onSubmit={handleSubmit} className="chat-input-form">
          <input
            type="text"
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            placeholder="Klistra in URL här (t.ex. https://example.com)"
            className="chat-input"
            disabled={isAnalyzing}
          />
          <button
            type="submit"
            className="send-button"
            disabled={isAnalyzing || !inputValue.trim()}
          >
            <Send size={20} />
          </button>
        </form>
      </div>
    </div>
  )
}

export default ChatInterface