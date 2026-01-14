import React, { useEffect, useMemo, useState } from "react"
import { useNavigate } from "react-router-dom" // Add useNavigate import

const NotificationsBanner = () => {
  const baseUrl = useMemo(() => process.env.REACT_APP_API_URL || 'http://127.0.0.1:8000', [])
  const [pendingClientsCount, setPendingClientsCount] = useState(0)
  const [traitesEcheanceCount, setTraitEcheanceCount] = useState(0) // Add state for traites à échéance
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const navigate = useNavigate() // Add useNavigate hook

  const authHeaders = () => {
    const token = localStorage.getItem('token')
    const headers = { 'Accept': 'application/json' }
    if (token) headers['Authorization'] = `Bearer ${token}`
    return headers
  }

  const fetchPendingClientsCount = async () => {
    try {
      // Fetch pending clients count
      const res = await fetch(`${baseUrl}/api/pending-clients`, { headers: authHeaders() })
      if (res.ok) {
        const data = await res.json()
        const count = Array.isArray(data?.data) ? data.data.length : 0
        setPendingClientsCount(count)
        console.log('NotificationsBanner - pending clients count:', count)
      } else {
        throw new Error('Erreur chargement clients en attente')
      }
    } catch (e) {
      console.error('NotificationsBanner - error:', e)
      setError(e.message || 'Erreur inconnue')
      setPendingClientsCount(0)
    }
  }

  const fetchTraitEcheanceCount = async () => {
    try {
      // Fetch traites à échéance sous 5 jours
      const params = new URLSearchParams()
      params.append('upcoming_days', '5')
      params.append('statut', 'Non échu') // Only non-échu traites
      params.append('per_page', '200') // Get all matching records
      
      const res = await fetch(`${baseUrl}/api/traites?${params.toString()}`, { headers: authHeaders() })
      if (res.ok) {
        const data = await res.json()
        const count = Array.isArray(data?.data) ? data.data.length : 0
        setTraitEcheanceCount(count)
        console.log('NotificationsBanner - traites à échéance count:', count)
      } else {
        throw new Error('Erreur chargement traites à échéance')
      }
    } catch (e) {
      console.error('NotificationsBanner - error:', e)
      setError(e.message || 'Erreur inconnue')
      setTraitEcheanceCount(0)
    }
  }

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true)
      setError("")
      await Promise.all([
        fetchPendingClientsCount(),
        fetchTraitEcheanceCount()
      ])
      setLoading(false)
    }
    
    fetchData()
    const id = setInterval(fetchData, 5000) // refresh chaque 5s
    return () => clearInterval(id)
  }, [])

  // If no notifications or loading/error, don't show anything
  if (loading || error || (pendingClientsCount === 0 && traitesEcheanceCount === 0)) return null

  const containerStyle = {
    position: 'fixed',
    top: 12,
    right: 12,
    zIndex: 1000,
    width: 'clamp(260px, 28vw, 380px)',
    pointerEvents: 'none' // allow clicks to pass except on cards
  }

  const cardStyle = {
    border: '1px solid #f59e0b',
    background: '#fff7ed',
    borderRadius: 8,
    padding: 12,
    marginTop:80 ,
    position: 'relative',
    marginBottom: 10,
    boxShadow: '0 8px 20px rgba(0,0,0,0.08)',
    pointerEvents: 'auto',
    cursor: 'pointer' // Add cursor pointer
    
  }

  const closeBtnStyle = {
    position: 'absolute',
    top: 6,
    right: 8,
    border: 'none',
    background: 'transparent',
    cursor: 'pointer',
    color: '#9a3412',
    fontWeight: 700,
    fontSize: 16
  }

  const handleDismiss = (e, type) => {
    // Prevent navigation when closing
    e.stopPropagation()
    // Dismiss specific notification by setting count to 0
    if (type === 'pendingClients') {
      setPendingClientsCount(0)
    } else if (type === 'traitesEcheance') {
      setTraitEcheanceCount(0)
    }
  }

  const handleNavigate = (type) => {
    if (type === 'pendingClients') {
      // Navigate to pending clients view
      navigate('/dashboard?tab=credit&view=PendingClients')
    } else if (type === 'traitesEcheance') {
      // Navigate to traites view filtered by upcoming
      navigate('/dashboard?tab=traites')
    }
  }

  return (
    <div style={containerStyle}>
      <div>
        {/* Pending Clients Card */}
        {pendingClientsCount > 0 && (
          <div style={cardStyle} onClick={() => handleNavigate('pendingClients')}>
            <button aria-label="Fermer" onClick={(e) => handleDismiss(e, 'pendingClients')} style={closeBtnStyle}>×</button>
            <div style={{ fontWeight: 700, color: '#9a3412' }}>Clients en attente</div>
            <div style={{ color: '#b45309', marginTop: 2 }}>
              Vous avez {pendingClientsCount} client{pendingClientsCount > 1 ? 's' : ''} en attente d'approbation
            </div>
            <div style={{ color: '#b45309', marginTop: 4 }}>
              Cliquez ici pour les consulter
            </div>
          </div>
        )}
        
        {/* Traités à échéance Card */}
        {traitesEcheanceCount > 0 && (
          <div style={cardStyle} onClick={() => handleNavigate('traitesEcheance')}>
            <button aria-label="Fermer" onClick={(e) => handleDismiss(e, 'traitesEcheance')} style={closeBtnStyle}>×</button>
            <div style={{ fontWeight: 700, color: '#9a3412' }}>Traites à échéance</div>
            <div style={{ color: '#b45309', marginTop: 2 }}>
              Vous avez {traitesEcheanceCount} traite{traitesEcheanceCount > 1 ? 's' : ''} à échéance sous 5 jours
            </div>
            <div style={{ color: '#b45309', marginTop: 4 }}>
              Cliquez ici pour les consulter
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default NotificationsBanner