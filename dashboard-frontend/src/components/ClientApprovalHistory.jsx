import React, { useEffect, useMemo, useState } from "react"
import { useNavigate } from "react-router-dom"
import { CheckCircle, XCircle, Clock, Filter, RefreshCw } from "lucide-react"
import "./Traites.css" 
import { useAuth } from '../hooks/useAuth'
// Import Pagination component
import Pagination from "./Pagination"

const ClientApprovalHistory = () => {
  const navigate = useNavigate()
  const { user } = useAuth()
  const baseUrl = useMemo(() => process.env.REACT_APP_API_URL || 'http://127.0.0.1:8000', [])
  const [historyData, setHistoryData] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [filter, setFilter] = useState("all") // all, approved, rejected
  // Pagination states
  const [currentPage, setCurrentPage] = useState(1)
  const [itemsPerPage, setItemsPerPage] = useState(5) // 5 items per page as requested

  const { handleFetchError } = useAuth(); // Récupérer la fonction handleFetchError
  const authHeaders = () => {
    const token = localStorage.getItem('token')
    const headers = { 'Accept': 'application/json' }
    if (token) headers['Authorization'] = `Bearer ${token}`
    return headers
  }

  const fetchHistory = async () => {
    setLoading(true)
    setError("")
    try {
      const res = await fetch(`${baseUrl}/api/clients/approval-history`, {
        headers: authHeaders()
      })
      
      // Vérifier si la réponse indique une erreur d'authentification
      const authOk = await handleFetchError(res);
      if (!authOk) {
        // handleFetchError a déjà géré la déconnexion
        throw new Error("Session expirée. Veuillez vous reconnecter.")
      }

      if (!res.ok) {
        throw new Error(`Erreur ${res.status}: Impossible de charger l'historique`)
      }
      
      const data = await res.json()
      
      if (!Array.isArray(data)) {
        console.error("Données reçues invalides:", data)
        throw new Error('Format de données invalide reçu du serveur')
      }
      
      setHistoryData(data)
      setCurrentPage(1) // Reset to first page when data changes
    } catch (e) {
      setError(e.message || 'Erreur lors du chargement')
      setHistoryData([])
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (user) {
      fetchHistory()
    }
  }, [user])

  const filteredData = useMemo(() => {
    if (filter === "all") return historyData
    return historyData.filter(item => item.status === filter)
  }, [historyData, filter])

  // Pagination logic
  const paginatedData = useMemo(() => {
    const startIndex = (currentPage - 1) * itemsPerPage
    const endIndex = startIndex + itemsPerPage
    return filteredData.slice(startIndex, endIndex)
  }, [filteredData, currentPage, itemsPerPage])

  const stats = useMemo(() => {
    const approved = historyData.filter(item => item.status === "approved").length
    const rejected = historyData.filter(item => item.status === "rejected").length
    return { approved, rejected, total: historyData.length }
  }, [historyData])

  const getStatusIcon = (status) => {
    switch (status) {
      case "approved":
        return <CheckCircle size={18} color="#10B981" />
      case "rejected":
        return <XCircle size={18} color="#EF4444" />
      default:
        return <Clock size={18} color="#F59E0B" />
    }
  }

  const getStatusLabel = (status) => {
    switch (status) {
      case "approved": return "Approuvé"
      case "rejected": return "Rejeté"
      default: return "En attente"
    }
  }

  return (
    <div style={{ padding: '24px', backgroundColor: '#f9fafb', minHeight: '100vh' }}>
      {/* Header */}
      <div style={{ marginBottom: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <h1 style={{ fontSize: '24px', fontWeight: '600', color: '#1f2937', margin: 0 }}>
            Historique des Approbations
          </h1>
          <button
            onClick={fetchHistory}
            disabled={loading}
            style={{
              display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 16px',
              backgroundColor: '#1f2c49', color: 'white', border: 'none', borderRadius: '6px',
              cursor: loading ? 'not-allowed' : 'pointer', opacity: loading ? 0.6 : 1
            }}
          >
            <RefreshCw size={16} className={loading ? "spin-anim" : ""} />
            Actualiser
          </button>
        </div>
        
        {/* Stats Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px', marginBottom: '24px' }}>
          <div className="stat-card" style={{ backgroundColor: 'white', padding: '16px', borderRadius: '8px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)' }}>
            <p style={{ fontSize: '14px', color: '#6b7280', margin: '0 0 4px 0' }}>Total</p>
            <p style={{ fontSize: '28px', fontWeight: '700', color: '#1f2937', margin: 0 }}>{stats.total}</p>
          </div>
          <div className="stat-card" style={{ backgroundColor: 'white', padding: '16px', borderRadius: '8px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)' }}>
            <p style={{ fontSize: '14px', color: '#6b7280', margin: '0 0 4px 0' }}>Approuvés</p>
            <p style={{ fontSize: '28px', fontWeight: '700', color: '#10B981', margin: 0 }}>{stats.approved}</p>
          </div>
          <div className="stat-card" style={{ backgroundColor: 'white', padding: '16px', borderRadius: '8px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)' }}>
            <p style={{ fontSize: '14px', color: '#6b7280', margin: '0 0 4px 0' }}>Rejetés</p>
            <p style={{ fontSize: '28px', fontWeight: '700', color: '#EF4444', margin: 0 }}>{stats.rejected}</p>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div style={{ backgroundColor: 'white', padding: '16px', borderRadius: '8px', marginBottom: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          <Filter size={18} color="#6b7280" />
          <span style={{ fontSize: '14px', fontWeight: '500', color: '#374151' }}>Filtrer :</span>
          {["all", "approved", "rejected"].map((type) => (
            <button
              key={type}
              onClick={() => {
                setFilter(type)
                setCurrentPage(1) // Reset to first page when filter changes
              }}
              style={{
                padding: '6px 16px', 
                borderRadius: '6px', 
                border: '1px solid #e5e7eb',
                // MODIFICATION ICI : Utilisation de #1f2c49 pour "all"
                backgroundColor: filter === type 
                  ? (type === 'approved' ? '#10B981' : type === 'rejected' ? '#EF4444' : '#1f2c49') 
                  : 'white',
                color: filter === type ? 'white' : '#374151', 
                cursor: 'pointer',
                transition: 'all 0.2s'
              }}
            >
              {type === 'all' ? `Tous (${stats.total})` : type === 'approved' ? `Approuvés (${stats.approved})` : `Rejetés (${stats.rejected})`}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      {loading ? (
        <div style={{ backgroundColor: 'white', padding: '48px', borderRadius: '8px', textAlign: 'center' }}>
          <div style={{ color: '#6b7280' }}>Chargement en cours...</div>
        </div>
      ) : error ? (
        <div style={{ backgroundColor: '#FEF2F2', padding: '16px', borderRadius: '8px', border: '1px solid #FEE2E2', color: '#DC2626' }}>
          {error}
        </div>
      ) : paginatedData.length === 0 ? (
        <div style={{ backgroundColor: 'white', padding: '48px', borderRadius: '8px', textAlign: 'center' }}>
          <div style={{ fontSize: '16px', color: '#6b7280' }}>Aucun historique trouvé.</div>
        </div>
      ) : (
        <>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {paginatedData.map((item) => (
              <div
                key={item.id}
                style={{
                  backgroundColor: 'white', padding: '20px', borderRadius: '8px',
                  borderLeft: `4px solid ${item.status === 'approved' ? '#10B981' : '#EF4444'}`,
                  boxShadow: '0 1px 3px rgba(0,0,0,0.1)'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div>
                    <h3 style={{ margin: '0 0 8px 0', fontSize: '18px', color: '#1f2937' }}>
                      {item.client_name}
                    </h3>
                    <p style={{ margin: 0, fontSize: '14px', color: '#6b7280' }}>
                      N° Compte: {item.account_number} | Date: {new Date(item.created_at).toLocaleDateString()}
                    </p>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '6px 12px', borderRadius: '6px', backgroundColor: item.status === 'approved' ? '#ECFDF5' : '#FEF2F2' }}>
                    {getStatusIcon(item.status)}
                    <span style={{ color: item.status === 'approved' ? '#10B981' : '#EF4444', fontWeight: '600' }}>
                      {getStatusLabel(item.status)}
                    </span>
                  </div>
                </div>

                {item.status === "rejected" && item.rejection_reason && (
                  <div style={{ marginTop: '12px', padding: '10px', backgroundColor: '#FEF2F2', borderRadius: '6px', color: '#991B1B', fontSize: '14px' }}>
                    <strong>Raison du rejet:</strong> {item.rejection_reason}
                  </div>
                )}
                
                {/* Bouton pour modifier un client rejeté */}
                {item.status === "rejected" && (
                  <div style={{ marginTop: '12px' }}>
                    <button
                      onClick={() => navigate(`/dashboard?tab=credit&view=editRejectedClient&id=${item.client_id}`)}
                      style={{
                        padding: '8px 16px',
                        // MODIFICATION ICI : Couleur #1f2c49 appliquée
                        backgroundColor: '#1f2c49',
                        color: 'white',
                        border: 'none',
                        borderRadius: '6px',
                        cursor: 'pointer',
                        fontWeight: '500',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px',
                        transition: 'opacity 0.2s'
                      }}
                      onMouseEnter={(e) => e.currentTarget.style.opacity = '0.9'}
                      onMouseLeave={(e) => e.currentTarget.style.opacity = '1'}
                    >
                      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                        <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
                      </svg>
                      Modifier la demande
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
          
          {/* Pagination Footer - Similar to ClientsGrid.jsx */}
          <div style={{ backgroundColor: 'white', padding: '16px', borderRadius: '8px', marginTop: '24px' }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "1rem" }}>
              <div style={{ fontWeight: 500, color: "#374151" }}>
                Total: {filteredData.length || 0} client{filteredData.length !== 1 ? 's' : ''}
              </div>
              <Pagination
                currentPage={currentPage}
                totalPages={Math.ceil(filteredData.length / itemsPerPage) || 1}
                totalItems={filteredData.length || 0}
                itemsPerPage={itemsPerPage}
                onPageChange={(newPage) => setCurrentPage(newPage)}
                onItemsPerPageChange={(newPerPage) => {
                  setItemsPerPage(newPerPage)
                  setCurrentPage(1) // Reset to first page when items per page changes
                }}
                itemsPerPageOptions={[5, 10, 20, 50]}
                showItemsPerPage={true}
                showTotal={true}
              />
            </div>
          </div>
        </>
      )}
      
      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        .spin-anim { animation: spin 1s linear infinite; }
      `}</style>
    </div>
  )
}

export default ClientApprovalHistory