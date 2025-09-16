import axios from 'axios'

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

export const analyzeUrl = async (url, userId = null) => {
  try {
    const response = await api.post('/api/analyze/url', {
      url,
      user_id: userId,
    })
    return response.data
  } catch (error) {
    console.error('Error analyzing URL:', error)
    throw error
  }
}

export const getAnalysisResult = async (jobId) => {
  try {
    const response = await api.get(`/api/results/${jobId}`)
    return response.data
  } catch (error) {
    console.error('Error getting analysis result:', error)
    throw error
  }
}

export const getArtifact = async (artifactId) => {
  try {
    const response = await api.get(`/api/artifacts/${artifactId}`)
    return response.data
  } catch (error) {
    console.error('Error getting artifact:', error)
    throw error
  }
}

export default api