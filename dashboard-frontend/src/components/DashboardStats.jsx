import React, { useEffect, useMemo, useState } from "react"
import { useNavigate } from "react-router-dom"
import { ResponsiveContainer, LineChart, Line, CartesianGrid, XAxis, YAxis, Tooltip, Legend, PieChart, Pie, Cell, BarChart, Bar } from 'recharts'
import { 
  FileText, 
  TrendingUp, 
  Calendar, 
  CheckCircle,
  Loader2,
  Users,
  UserPlus,
  DollarSign,
  Globe
} from "lucide-react"
import Can from "./Can"
import "./DashboardStats.css"
import { useAuth } from "../hooks/useAuth" // Add useAuth hook

const DashboardStats = () => {
  const navigate = useNavigate()
  const { hasPermission } = useAuth() // Get user permissions

  // Add a new state to track the refresh timestamp
  const [refreshTimestamp, setRefreshTimestamp] = useState(Date.now())

  // Add a new useEffect for periodic refresh
  useEffect(() => {
    const interval = setInterval(() => {
      setRefreshTimestamp(Date.now())
    }, 180000) // 3 minutes
    
    return () => clearInterval(interval)
  }, [])

  // Check if user should see dashboard stats (this needs to be declared before any hooks)
  const shouldShowDashboardStats = () => {
    // Show dashboard stats only if user has dashboard access AND has access to both traites and clients
    // OR if user has dashboard access and no specific restrictions
    return hasPermission('access_dashboard') && 
           (hasPermission('access_traites') && hasPermission('access_clients')) ||
           (hasPermission('access_dashboard') && 
            !hasPermission('access_traites') && 
            !hasPermission('access_clients'));
  }

  // --- ÉTATS POUR LES STATS DES TRAITES ---
  const [loadingTraites, setLoadingTraites] = useState(true)
  const [errorTraites, setErrorTraites] = useState("")
  const [traiteStats, setTraiteStats] = useState({ total: 0, perDay: 0, perMonth: 0, overdue: 0 })
  const [traiteMonthlyData, setTraiteMonthlyData] = useState([])
  const [traiteStatusData, setTraiteStatusData] = useState([])
  const [selectedTraiteYear, setSelectedTraiteYear] = useState(new Date().getFullYear())
  const [traiteAvailableYears, setTraiteAvailableYears] = useState([new Date().getFullYear()])
  const [recentBillsCount, setRecentBillsCount] = useState(0)

  // --- ÉTATS POUR LES STATS DES CLIENTS ---
  const [loadingClients, setLoadingClients] = useState(true)
  const [errorClients, setErrorClients] = useState("")
  const [clientStats, setClientStats] = useState({ total: 0, perDay: 0, perMonth: 0, totalCredit: 0 })
  const [clientMonthlyData, setClientMonthlyData] = useState([])
  const [clientTypeData, setClientTypeData] = useState([])
  const [selectedClientYear, setSelectedClientYear] = useState(new Date().getFullYear())
  const [clientAvailableYears, setClientAvailableYears] = useState([new Date().getFullYear()])
  
  // --- ÉTATS POUR LES CLIENTS EN ATTENTE ---
  const [pendingClientsCount, setPendingClientsCount] = useState(0)
  const [loadingPendingClients, setLoadingPendingClients] = useState(true)
  const [errorPendingClients, setErrorPendingClients] = useState("")
  
  // --- ÉTATS POUR LES CLIENTS EXTERNES ---
  // const [externalClientsCount, setExternalClientsCount] = useState(0)
  // const [loadingExternalClients, setLoadingExternalClients] = useState(true)
  // const [errorExternalClients, setErrorExternalClients] = useState("")
  
  // --- ÉTATS POUR LES TRAITES EXTERNES ---
  const [externalTraitésCount, setExternalTraitésCount] = useState(0)
  const [loadingExternalTraités, setLoadingExternalTraités] = useState(true)
  const [errorExternalTraités, setErrorExternalTraités] = useState("")

  const monthNames = useMemo(() => ['Jan','Fév','Mar','Avr','Mai','Juin','Juil','Août','Sep','Oct','Nov','Déc'], [])

  // --- DONNÉES MÉMORISÉES POUR LES GRAPHIQUES ---
  const traiteMonthlyDisplay = useMemo(() => {
    const now = new Date()
    const currentYear = now.getFullYear()
    const currentMonth = now.getMonth() + 1
    const srcArr = Array.isArray(traiteMonthlyData) ? traiteMonthlyData : []
    const byName = new Map(srcArr.map(d => [String(d.name || ''), d]))
    const result = Array.from({ length: 12 }, (_, idx) => {
      const m = idx + 1
      const name = `${selectedTraiteYear}-${String(m).padStart(2, '0')}`
      const found = byName.get(name) || {}
      const baseVal = found.traites ?? 0
      const value = (selectedTraiteYear === currentYear && m > currentMonth) ? null : baseVal
      return { name, label: monthNames[m-1], traites: value }
    })
    return result
  }, [traiteMonthlyData, monthNames, selectedTraiteYear])

  const traiteStatusTotal = useMemo(() => (traiteStatusData || []).reduce((sum, s) => sum + (s.value || 0), 0), [traiteStatusData])

  const clientMonthlyDisplay = useMemo(() => {
    const now = new Date()
    const currentYear = now.getFullYear()
    const currentMonth = now.getMonth() + 1
    const srcArr = Array.isArray(clientMonthlyData) ? clientMonthlyData : []
    const byName = new Map(srcArr.map(d => [String(d.name || ''), d]))
    const result = Array.from({ length: 12 }, (_, idx) => {
      const m = idx + 1
      const name = `${selectedClientYear}-${String(m).padStart(2, '0')}`
      const found = byName.get(name) || {}
      const baseVal = found.clients ?? 0
      const value = (selectedTraiteYear === currentYear && m > currentMonth) ? null : baseVal
      return { name, label: monthNames[m-1], clients: value }
    })
    return result
  }, [clientMonthlyData, monthNames, selectedClientYear])

  const clientTypeTotal = useMemo(() => (clientTypeData || []).reduce((sum, s) => sum + (s.value || 0), 0), [clientTypeData])

  // --- FETCH DES DONNÉES POUR LES TRAITES ---
  useEffect(() => {
    let isMounted = true
    const fetchTraiteStats = async () => {
      // Don't fetch data if user shouldn't see dashboard stats
      if (!shouldShowDashboardStats()) return;
      
      setLoadingTraites(true)
      setErrorTraites("")
      try {
        const baseUrl = process.env.REACT_APP_API_URL || ''
        const token = localStorage.getItem('token')
        const headers = token ? { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' } : { 'Accept': 'application/json' }

        const [resStats, resMonthly, resStatus, resYears] = await Promise.all([
          fetch(`${baseUrl}/api/traites/stats`, { headers }),
          fetch(`${baseUrl}/api/traites/monthly?year=${selectedTraiteYear}`, { headers }),
          fetch(`${baseUrl}/api/traites/status`, { headers }),
          fetch(`${baseUrl}/api/traites/available-years`, { headers })
        ])

        if (!isMounted) return;

        if (resStats.ok) setTraiteStats(await resStats.json())
        else throw new Error("Erreur de chargement des stats traites")
      
        const monthlyPayload = resMonthly.ok ? await resMonthly.json() : []
        setTraiteMonthlyData(Array.isArray(monthlyPayload) ? monthlyPayload : [])

        const statusPayload = resStatus.ok ? await resStatus.json() : []
        setTraiteStatusData(Array.isArray(statusPayload) ? statusPayload : [])

        const yearsPayload = resYears.ok ? await resYears.json() : [new Date().getFullYear()]
        const yearsArray = Array.isArray(yearsPayload) ? yearsPayload : [new Date().getFullYear()]
        setTraiteAvailableYears(yearsArray)
        if (!yearsArray.includes(selectedTraiteYear) && yearsArray.length > 0) setSelectedTraiteYear(yearsArray[0])

      } catch (e) {
        if (isMounted) setErrorTraites(e.message || "Erreur inconnue")
      } finally {
        if (isMounted) setLoadingTraites(false)
      }
    }
    fetchTraiteStats()
    return () => { isMounted = false }
  }, [selectedTraiteYear, refreshTimestamp]) // Add refreshTimestamp as dependency

  // --- FETCH DES DONNÉES POUR LES CLIENTS ---
  useEffect(() => {
    let isMounted = true
    const fetchClientStats = async () => {
      // Don't fetch data if user shouldn't see dashboard stats
      if (!shouldShowDashboardStats()) return;
      
      setLoadingClients(true)
      setErrorClients("")
      try {
        const baseUrl = process.env.REACT_APP_API_URL || ''
        const token = localStorage.getItem('token')
        const headers = token ? { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' } : { 'Accept': 'application/json' }

        const [resStats, resMonthly, resType, resYears] = await Promise.all([
          fetch(`${baseUrl}/api/clients/stats`, { headers }),
          fetch(`${baseUrl}/api/clients/monthly?year=${selectedClientYear}`, { headers }),
          fetch(`${baseUrl}/api/clients/type-breakdown`, { headers }),
          fetch(`${baseUrl}/api/clients/available-years`, { headers })
        ])

        if (!isMounted) return;

        if (resStats.ok) setClientStats(await resStats.json())
        else throw new Error("Erreur de chargement des stats clients")
      
        const monthlyPayload = resMonthly.ok ? await resMonthly.json() : []
        setClientMonthlyData(Array.isArray(monthlyPayload) ? monthlyPayload : [])
        
        const typePayload = resType.ok ? await resType.json() : []
        setClientTypeData(Array.isArray(typePayload) ? typePayload : [])

        const yearsPayload = resYears.ok ? await resYears.json() : [new Date().getFullYear()]
        const yearsArray = Array.isArray(yearsPayload) ? yearsPayload : [new Date().getFullYear()]
        setClientAvailableYears(yearsArray)
        if (!yearsArray.includes(selectedClientYear) && yearsArray.length > 0) setSelectedClientYear(yearsArray[0])
      
      } catch (e) {
        if (isMounted) setErrorClients(e.message || "Erreur inconnue")
      } finally {
        if (isMounted) setLoadingClients(false)
      }
    }
    fetchClientStats()
    return () => { isMounted = false }
  }, [selectedClientYear, refreshTimestamp]) // Add refreshTimestamp as dependency

  // --- FETCH DES CLIENTS EN ATTENTE ---
  useEffect(() => {
    let isMounted = true
    const fetchPendingClientsCount = async () => {
      // Don't fetch data if user shouldn't see dashboard stats
      if (!shouldShowDashboardStats()) return;
      
      setLoadingPendingClients(true)
      setErrorPendingClients("")
      try {
        const baseUrl = process.env.REACT_APP_API_URL || ''
        const token = localStorage.getItem('token')
        const headers = token ? { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' } : { 'Accept': 'application/json' }

        const res = await fetch(`${baseUrl}/api/pending-clients`, { headers })
      
        if (!isMounted) return;

        if (res.ok) {
          const data = await res.json()
          setPendingClientsCount(data.count || 0)
        } else {
          throw new Error("Erreur de chargement des clients en attente")
        }
      } catch (e) {
        if (isMounted) setErrorPendingClients(e.message || "Erreur inconnue")
      } finally {
        if (isMounted) setLoadingPendingClients(false)
      }
    }
  
    // Only fetch pending clients for admin users
    if (hasPermission('access_dashboard')) {
      fetchPendingClientsCount()
    }
  
    return () => { isMounted = false }
  }, [hasPermission, refreshTimestamp]) // Add refreshTimestamp as dependency

  // --- FETCH DES CLIENTS EXTERNES ---
  // useEffect(() => {
  //   let isMounted = true
  //   const fetchExternalClientsCount = async () => {
  //     // Don't fetch data if user shouldn't see dashboard stats
  //     if (!shouldShowDashboardStats()) return;
      
  //     setLoadingExternalClients(true)
  //     setErrorExternalClients("")
  //     try {
  //       const baseUrl = process.env.REACT_APP_API_URL || ''
  //       const token = localStorage.getItem('token')
  //       const headers = token ? { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' } : { 'Accept': 'application/json' }

  //       const res = await fetch(`${baseUrl}/api/clients/external-count`, { headers })
      
  //       if (!isMounted) return;

  //       if (res.ok) {
  //         const data = await res.json()
  //         setExternalClientsCount(data.count || 0)
  //       } else {
  //         throw new Error("Erreur de chargement des clients externes")
  //       }
  //     } catch (e) {
  //       if (isMounted) setErrorExternalClients(e.message || "Erreur inconnue")
  //     } finally {
  //       if (isMounted) setLoadingExternalClients(false)
  //     }
  //   }
  
  //   // Only fetch external clients for users with appropriate permissions
  //   if (hasPermission('access_dashboard')) {
  //     fetchExternalClientsCount()
  //   }
  
  //   return () => { isMounted = false }
  // }, [hasPermission, refreshTimestamp]) // Add refreshTimestamp as dependency

  // --- FETCH DES TRAITES EXTERNES ---
  useEffect(() => {
    let isMounted = true
    const fetchExternalTraitésCount = async () => {
      // Don't fetch data if user shouldn't see dashboard stats
      if (!shouldShowDashboardStats()) return;
      
      setLoadingExternalTraités(true)
      setErrorExternalTraités("")
      try {
        const baseUrl = process.env.REACT_APP_API_URL || ''
        const token = localStorage.getItem('token')
        const headers = token ? { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' } : { 'Accept': 'application/json' }

        const res = await fetch(`${baseUrl}/api/traites/external-count`, { headers })
      
        if (!isMounted) return;

        if (res.ok) {
          const data = await res.json()
          setExternalTraitésCount(data.count || 0)
        } else {
          throw new Error("Erreur de chargement des traites externes")
        }
      } catch (e) {
        if (isMounted) setErrorExternalTraités(e.message || "Erreur inconnue")
      } finally {
        if (isMounted) setLoadingExternalTraités(false)
      }
    }
  
    // Only fetch external traites for users with appropriate permissions
    if (hasPermission('access_dashboard')) {
      fetchExternalTraitésCount()
    }
  
    return () => { isMounted = false }
  }, [hasPermission, refreshTimestamp]) // Add refreshTimestamp as dependency

  // --- FETCH DES TRAITES RÉCENTES ---
  useEffect(() => {
    let isMounted = true
    const fetchRecentBillsCount = async () => {
      // Don't fetch data if user shouldn't see dashboard stats
      if (!shouldShowDashboardStats()) return;
      
      try {
        const baseUrl = process.env.REACT_APP_API_URL || ''
        const token = localStorage.getItem('token')
        const headers = token ? { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' } : { 'Accept': 'application/json' }
        
        // Fetch bills created in the last 5 minutes
        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000)
        const fromDate = fiveMinutesAgo.toISOString().split('T')[0]
        
        const p = new URLSearchParams()
        p.append('per_page', '100')
        p.append('page', '1')
        p.append('sort', 'created_at')
        p.append('dir', 'desc')
        p.append('from', fromDate)
        
        const res = await fetch(`${baseUrl}/api/traites?${p.toString()}`, { headers })
        
        if (!isMounted) return;

        if (res.ok) {
          const data = await res.json()
          const bills = Array.isArray(data?.data) ? data.data : (Array.isArray(data) ? data : [])
          
          // Filter for truly recent bills (created in last 5 minutes)
          const now = new Date()
          const cutoffTime = new Date(now.getTime() - 5 * 60 * 1000)
          const recent = bills.filter(bill => {
            const createdAt = new Date(bill.created_at)
            return createdAt >= cutoffTime
          })
          
          console.log('Recent bills count:', recent.length)
          setRecentBillsCount(recent.length)
        }
      } catch (e) {
        console.error('Error fetching recent bills:', e)
      }
    }
    
    // Only fetch recent bills for users with permission
    if (hasPermission('access_dashboard')) {
      fetchRecentBillsCount()
      const interval = setInterval(fetchRecentBillsCount, 5000) // Refresh every 5 seconds
      return () => clearInterval(interval)
    }
    
    return () => { isMounted = false }
  }, [hasPermission, shouldShowDashboardStats, refreshTimestamp]) // Add refreshTimestamp as dependency

  // --- DONNÉES DES CARTES ---
  const traiteCardsData = [
    { icon: FileText, title: "Traites totales", value: traiteStats.total, color: "#3B82F6", bgColor: "#EFF6FF", permission: "view_traites", onClick: () => navigate('/dashboard?tab=traites') },
    { icon: TrendingUp, title: "Traites/jour", value: traiteStats.perDay, color: "#FFBB7F", bgColor: "#FEF2F2", permission: "view_traites" },
    { icon: Calendar, title: "Traites/mois", value: traiteStats.perMonth, color: "#8B5CF6", bgColor: "#F5F3FF", permission: "view_traites" },
    { 
      icon: CheckCircle, 
      title: "Traites échues", 
      value: traiteStats.overdue, 
      color: "#2AAD4D", 
      bgColor: "#ECFDF5", 
      permission: "view_traites", 
      onClick: () => navigate(`/dashboard?tab=traites&statut=${encodeURIComponent('Échu')}`),
      badge: recentBillsCount > 0 ? recentBillsCount : null
    }
  ]

  const formatCredit = (value) => new Intl.NumberFormat('fr-FR', { style: 'currency', currency: 'XAF' }).format(value || 0)

  const clientCardsData = [
    { icon: Users, title: "Clients totaux", value: clientStats.total, color: "#3B82F6", bgColor: "#EFF6FF", permission: "view_clients", onClick: () => navigate('/dashboard?tab=credit&view=GestionClients') },
    { icon: UserPlus, title: "Comptes clients/jour", value: clientStats.perDay || 0, color: "#10B981", bgColor: "#ECFDF5", permission: "view_clients" },
    { icon: Calendar, title: "Comptes clients/mois", value: clientStats.perMonth || 0, color: "#8B5CF6", bgColor: "#F5F3FF", permission: "view_clients" },
    
  ]

  // --- DONNÉES DES CARTES POUR LES CLIENTS EXTERNES ---
  // const externalClientsCardData = [
  //   { 
  //     icon: Globe, 
  //     title: "Clients externes", 
  //     value: externalClientsCount, 
  //     color: "#10B981", 
  //     bgColor: "#ECFDF5", 
  //     permission: "view_clients", 
  //     onClick: () => navigate('/dashboard?tab=credit&view=GestionClients&external=true')
  //   }
  // ]

  // --- DONNÉES DES CARTES POUR LES TRAITES EXTERNES ---
  const externalTraitésCardData = [
    { 
      icon: Globe, 
      title: "Traités externes", 
      value: externalTraitésCount, 
      color: "#10B981", 
      bgColor: "#ECFDF5", 
      permission: "view_traites", 
      onClick: () => navigate('/dashboard?tab=traites&origine=Externe')
    }
  ]

  // --- DONNÉES DES CARTES POUR LES CLIENTS EN ATTENTE ---
  const pendingClientsCardData = [
    { 
      icon: Loader2, 
      title: "Clients en attente", 
      value: pendingClientsCount, 
      color: "#F59E0B", 
      bgColor: "#FFFBEB", 
      permission: "manage_pending_clients", 
      onClick: () => navigate('/dashboard?tab=credit&view=PendingClients'),
      badge: pendingClientsCount > 0 ? pendingClientsCount : null
    }
  ]

  // If user shouldn't see dashboard stats, show nothing
  if (!shouldShowDashboardStats()) {
    return null;
  }

  return (
    <div className="dashboard-stats">
      {/* SECTION DES CARTES STATISTIQUES */}
      <h2 className="stats-title">Vue d'ensemble</h2>
      {errorTraites && <div className="error-message">{errorTraites}</div>}
      {errorClients && <div className="error-message">{errorClients}</div>}
      
      <div className="stats-grid">
        {/* Cartes des Traites */}
        {traiteCardsData.map((card, index) => (
          <Can key={`traite-${index}`} permission={card.permission}>
            <div className="stat-card" onClick={card.onClick} style={{ cursor: card.onClick ? 'pointer' : 'default', position: 'relative' }}>
              <div className="card-icon-container" style={{ backgroundColor: card.bgColor }}><card.icon size={20} color={card.color} /></div>
              <div className="card-content">
                <p className="card-title">{card.title}</p>
                <p className="card-value">{loadingTraites ? <Loader2 size={16} className="loading-spinner" /> : card.value.toLocaleString()}</p>
              </div>
              {card.badge && (
                <span className="badge" style={{
                  position: 'absolute',
                  top: '-8px',
                  right: '-8px',
                  backgroundColor: '#ef4444',
                  color: 'white',
                  borderRadius: '9999px',
                  padding: '4px 8px',
                  fontSize: '12px',
                  fontWeight: 'bold',
                  minWidth: '20px',
                  height: '20px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  {card.badge}
                </span>
              )}
            </div>
          </Can>
        ))}
        {/* Cartes des Clients */}
        {clientCardsData.map((card, index) => (
          <Can key={`client-${index}`} permission={card.permission}>
            <div className="stat-card" onClick={card.onClick} style={{ cursor: card.onClick ? 'pointer' : 'default' }}>
              <div className="card-icon-container" style={{ backgroundColor: card.bgColor }}><card.icon size={20} color={card.color} /></div>
              <div className="card-content">
                <p className="card-title">{card.title}</p>
                <p className="card-value">{loadingClients ? <Loader2 size={16} className="loading-spinner" /> : (typeof card.value === 'number' ? card.value.toLocaleString() : card.value)}</p>
              </div>
            </div>
          </Can>
        ))}
        {/* Cartes des Clients en Attente */}
        {pendingClientsCardData.map((card, index) => (
          <Can key={`pending-client-${index}`} permission={card.permission}>
            <div className="stat-card" onClick={card.onClick} style={{ cursor: card.onClick ? 'pointer' : 'default', position: 'relative' }}>
              <div className="card-icon-container" style={{ backgroundColor: card.bgColor }}><card.icon size={20} color={card.color} /></div>
              <div className="card-content">
                <p className="card-title">{card.title}</p>
                <p className="card-value">{loadingPendingClients ? <Loader2 size={16} className="loading-spinner" /> : card.value.toLocaleString()}</p>
              </div>
              {card.badge && (
                <span className="badge" style={{
                  position: 'absolute',
                  top: '-8px',
                  right: '-8px',
                  backgroundColor: '#ef4444',
                  color: 'white',
                  borderRadius: '9999px',
                  padding: '4px 8px',
                  fontSize: '12px',
                  fontWeight: 'bold',
                  minWidth: '20px',
                  height: '20px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  {card.badge}
                </span>
              )}
            </div>
          </Can>
        ))}
        {/* Cartes des Traités Externes */}
        {externalTraitésCardData.map((card, index) => (
          <Can key={`external-traite-${index}`} permission={card.permission}>
            <div className="stat-card" onClick={card.onClick} style={{ cursor: card.onClick ? 'pointer' : 'default' }}>
              <div className="card-icon-container" style={{ backgroundColor: card.bgColor }}><card.icon size={20} color={card.color} /></div>
              <div className="card-content">
                <p className="card-title">{card.title}</p>
                <p className="card-value">{loadingExternalTraités ? <Loader2 size={16} className="loading-spinner" /> : card.value.toLocaleString()}</p>
              </div>
            </div>
          </Can>
        ))}
      </div>

      {/* SECTION DES GRAPHIQUES */}
      <h2 className="stats-title" style={{ marginTop: '2rem' }}>Analyses Détaillées</h2>
      
      {/* Graphiques des Traites */}
      <Can permission="view_traites">
        <div className="stats-grid" style={{ marginTop: '1rem' }}>
          <div className="stat-card chart-card" style={{ padding: 0 }}>
            <div style={{ padding: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ margin: 0, color: '#1a365d' }}>Évolution des Traites</h3>
              <select value={selectedTraiteYear} onChange={(e) => setSelectedTraiteYear(parseInt(e.target.value))} className="year-select">
                {traiteAvailableYears.map(year => <option key={year} value={year}>{year}</option>)}
              </select>
            </div>
            <div className="chart-container">
              {loadingTraites ? <Loader2 size={20} className="loading-spinner" /> : (traiteMonthlyDisplay.length > 0) ? (
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={traiteMonthlyDisplay}>
                    <CartesianGrid strokeDasharray="4 4" stroke="#e5e7eb" />
                    <XAxis dataKey="label" />
                    <YAxis tickFormatter={(value) => Number.isInteger(value) ? value : value.toFixed(0)} allowDecimals={false} />
                    <Tooltip />
                    <Legend />
                    <Bar dataKey="traites" fill="#e11d48" name="Nombre de traites" />
                  </BarChart>
                </ResponsiveContainer>
              ) : <div className="no-data">Aucune donnée à afficher</div>}
            </div>
          </div>
          <div className="stat-card chart-card" style={{ padding: 0 }}>
            <div style={{ padding: '1rem' }}><h3 style={{ margin: 0, color: '#1a365d' }}>Répartition par Statut</h3></div>
            <div className="chart-container">
              {loadingTraites ? <Loader2 size={20} className="loading-spinner" /> : (traiteStatusTotal > 0) ? (
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie 
                      data={traiteStatusData} 
                      cx="50%" 
                      cy="50%" 
                      innerRadius={50} 
                      outerRadius={120} 
                      paddingAngle={1} 
                      dataKey="value"
                      minAngle={3}
                    >
                      {traiteStatusData.map((entry, index) => (
                        <Cell 
                          key={`cell-${index}`} 
                          fill={entry.color || '#3b82f6'} 
                          style={{ cursor: 'pointer' }} 
                          onClick={() => navigate(`/dashboard?tab=traites&statut=${encodeURIComponent(String(entry.name || '').trim())}`)} 
                        />
                      ))}
                    </Pie>
                    <Tooltip />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              ) : <div className="no-data">Aucune donnée à afficher</div>}
            </div>
          </div>
        </div>
      </Can>
      
      {/* Graphiques des Clients */}
      <Can permission="view_clients">
        <div className="stats-grid" style={{ marginTop: '1rem' }}>
          <div className="stat-card chart-card" style={{ padding: 0 }}>
            <div style={{ padding: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ margin: 0, color: '#1a365d' }}>Évolution des Clients</h3>
              <select value={selectedClientYear} onChange={(e) => setSelectedClientYear(parseInt(e.target.value))} className="year-select">
                {clientAvailableYears.map(year => <option key={year} value={year}>{year}</option>)}
              </select>
            </div>
            <div className="chart-container">
              {loadingClients ? <Loader2 size={20} className="loading-spinner" /> : (clientMonthlyDisplay.length > 0) ? (
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={clientMonthlyDisplay}>
                    <CartesianGrid strokeDasharray="4 4" stroke="#e5e7eb" />
                    <XAxis dataKey="label" />
                    <YAxis tickFormatter={(value) => Number.isInteger(value) ? value : value.toFixed(0)} allowDecimals={false} />
                    <Tooltip />
                    <Legend />
                    <Bar dataKey="clients" fill="#3b82f6" name="Nouveaux clients" />
                  </BarChart>
                </ResponsiveContainer>
              ) : <div className="no-data">Aucune donnée à afficher</div>}
            </div>
          </div>
          <div className="stat-card chart-card" style={{ padding: 0 }}>
            <div style={{ padding: '1rem' }}><h3 style={{ margin: 0, color: '#1a365d' }}>Repartition par Type</h3></div>
            <div className="chart-container">
              {loadingClients ? <Loader2 size={20} className="loading-spinner" /> : (clientTypeTotal > 0) ? (
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie 
                      data={clientTypeData} 
                      cx="50%" 
                      cy="50%" 
                      innerRadius={50} 
                      outerRadius={120} 
                      paddingAngle={1} 
                      dataKey="value" 
                      nameKey="name"
                      minAngle={3}
                    >
                      {clientTypeData.map((entry, index) => (
                        <Cell 
                          key={`cell-${index}`} 
                          fill={entry.color} 
                          style={{ cursor: 'pointer' }}
                          onClick={() => {
                            // Naviguer vers la grille des clients avec un filtre par type
                            const typeName = entry.name;
                            if (typeName === 'Client' || typeName === 'Fournisseur' || typeName === 'Salariés') {
                              navigate(`/dashboard?tab=credit&view=GestionClients&type_tiers=${encodeURIComponent(typeName)}`);
                            }
                          }}
                        />
                      ))}
                    </Pie>
                    <Tooltip 
                      formatter={(value) => [value, 'Nombre']}
                      labelFormatter={(name) => `Type: ${name}`}
                    />
                    <Legend 
                      layout="horizontal" 
                      verticalAlign="bottom" 
                      align="center"
                      formatter={(value, entry, index) => (
                        <span 
                          style={{ color: '#333', fontSize: '12px', cursor: 'pointer' }}
                          onClick={() => {
                            // Naviguer vers la grille des clients avec un filtre par type
                            const typeName = entry.value;
                            if (typeName === 'Client' || typeName === 'Fournisseur' || typeName === 'Salariés') {
                              navigate(`/dashboard?tab=credit&view=GestionClients&type_tiers=${encodeURIComponent(typeName)}`);
                            }
                          }}
                        >
                          {value} ({clientTypeData[index]?.value || 0})
                        </span>
                      )}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : <div className="no-data">Aucune donnée à afficher</div>}
            </div>
          </div>

        </div>
      </Can>
    </div>
  )
}

export default DashboardStats