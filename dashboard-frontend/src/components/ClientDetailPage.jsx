import React, { useEffect, useState, useMemo } from "react"
import { useNavigate, useParams } from "react-router-dom"
import { ArrowLeft, Edit3, Trash2, Printer } from "lucide-react"
import Can from './Can'; // Import the Can component
// Assurez-vous d'avoir une fonction `formatMoney` ou supprimez-la si non nécessaire
// import { formatMoney } from "../utils/format" 
import "./Traites.css" // Vous pouvez réutiliser ce CSS ou en créer un nouveau
import MonImage from "../images/image4.png"

const ClientDetailPage = () => {
  const navigate = useNavigate()
  const { id } = useParams()
  const [client, setClient] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const baseUrl = useMemo(() => process.env.REACT_APP_API_URL || '', [])

  const formatDateDDMMYYYY = (value) => {
    if (!value) return ''
    const d = new Date(value)
    if (isNaN(d)) return value
    const dd = String(d.getDate()).padStart(2, '0')
    const mm = String(d.getMonth() + 1).padStart(2, '0')
    const yyyy = d.getFullYear()
    return `${dd}-${mm}-${yyyy}`
  }

  // Exemple de fonction formatMoney si vous ne l'avez pas
  const formatMoney = (value) => {
    if (value == null) return ''
    return new Intl.NumberFormat('fr-FR', { style: 'currency', currency: 'XAF' }).format(value)
  }

  useEffect(() => {
    let mounted = true
    const fetchClient = async () => {
      try {
        const token = localStorage.getItem('token')
        const headers = { 'Accept': 'application/json' }
        if (token) headers['Authorization'] = `Bearer ${token}`
        const res = await fetch(`${baseUrl}/api/tiers/${id}`, { headers })
        if (!res.ok) throw new Error('Erreur de chargement du client')
        const data = await res.json()
        if (mounted) setClient(data)
      } catch (e) {
        setError(e.message || 'Erreur inconnue')
      } finally {
        if (mounted) setLoading(false)
      }
    }
    fetchClient()
    return () => { mounted = false }
  }, [id, baseUrl])

  const handleDelete = async () => {
    if (!window.confirm('Supprimer ce client ?')) return
    try {
      const token = localStorage.getItem('token')
      const headers = { 'Accept': 'application/json' }
      if (token) headers['Authorization'] = `Bearer ${token}`
      const res = await fetch(`${baseUrl}/api/tiers/${id}`, { method: 'DELETE', headers })
      if (!res.ok) throw new Error('Suppression échouée')
      navigate('/dashboard?tab=credit&view=GestionClients') // Redirige vers la grille des clients
    } catch (e) {
      alert(e.message || 'Erreur inconnue')
    }
  }

  const handlePrint = () => {
    if (!id) return
    const base = (process.env.REACT_APP_API_URL || '')
    const url = `${base}/print/clients/${id}/preview`
    window.open(url, '_blank')
  }
  
  if (loading) return <div style={{ padding: 16 }}>Chargement...</div>
  if (error) return <div style={{ padding: 16, color: 'crimson' }}>{error}</div>
  if (!client) return <div style={{ padding: 16 }}>Compte client non trouvé.</div>

  return (
    <div className="dashboard-stats">
      <div className="breadcrumb" style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
        <button className="icon-button" onClick={() => navigate('/dashboard?tab=credit&view=GestionClients')} aria-label="Retour" style={{ color: 'red' }}>
          <ArrowLeft size={18} />
        </button>
        <span className="crumb" onClick={() => navigate('/dashboard?tab=credit&view=GestionClients')}>Grille des clients</span>
        <span>›</span>
        <span className="crumb-current">Détail du compte client</span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '0.8fr 2.2fr', gap: 16, height: 'calc(100vh - 120px)' }} className="client-detail-layout">
        <div style={{
          backgroundImage: `url(${MonImage})`,
          backgroundSize: 'contain',
          backgroundPosition: 'center',
          backgroundRepeat: 'no-repeat',
          borderRadius: 10,
          minHeight: 360
        }} />

        <div style={{ maxHeight: 'calc(100vh - 140px)', overflowY: 'auto' }}>
          <div className="detail-header">
            <div className="detail-title">Détail du compte client</div>
          </div>

          <div className="detail-card">
            <div className="detail-grid">
              <Detail label="Numéro de compte" value={client?.numero_compte} />
              <Detail label="Nom / Raison sociale" value={client?.nom_raison_sociale} />
              <Detail label="Type d'entreprises" value={client?.categorie} />
              <Detail label="Type de tiers" value={client?.type_tiers} />
              <Detail label="N° contribuable" value={client?.n_contribuable} />
              <Detail label="Téléphone" value={client?.telephone} />
              <Detail label="Email" value={client?.email} />
              <Detail label="BP" value={client?.bp} />
              <Detail label="Ville" value={client?.ville} />
              <Detail label="Pays" value={client?.pays} />
              <Detail label="Adresse géo 1" value={client?.adresse_geo_1} />
              <Detail label="Adresse géo 2" value={client?.adresse_geo_2} />
              <Detail label="Établissement" value={client?.etablissement} />
              <Detail label="Service" value={client?.service} />
              <Detail label="Nom du signataire" value={client?.nom_signataire} />
              <div style={{ gridColumn: '1 / -1', height: 1, background: '#e5e7eb', margin: '8px 0' }} />
              <Detail label="Date de création" value={formatDateDDMMYYYY(client?.date_creation)} />
              <Detail label="Montant facture" value={formatMoney(client?.montant_facture)} />
              <Detail label="Montant payé" value={formatMoney(client?.montant_paye)} />
              <Detail label="Crédit" value={formatMoney(client?.credit)} />
              <Detail label="Motif" value={client?.motif} />
            </div>

            <div className="detail-actions" style={{ display: 'flex', gap: 8, alignItems: 'center', justifyContent: 'flex-end', flexWrap: 'nowrap', marginTop: 16 }}>
              {/* Le lien "Modifier" devra pointer vers un formulaire d'édition que vous devrez créer */}
              <Can permission="edit_clients">
                <button className="submit-button" onClick={() => navigate(`/clients/${id}/edit`)}><Edit3 size={16} style={{ marginRight: 6 }} /> Modifier</button>
              </Can>
              <button className="submit-button" onClick={handlePrint}><Printer size={16} style={{ marginRight: 6 }} /> Imprimer</button>
              <Can permission="delete_clients">
                <button className="submit-button" onClick={handleDelete}><Trash2 size={16} style={{ marginRight: 6 }} /> Supprimer</button>
              </Can>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

const Detail = ({ label, value }) => (
  <div className="detail-field">
    <div className="detail-label">{label}</div>
    <div className="detail-value">{value ?? 'N/A'}</div>
  </div>
)

export default ClientDetailPage

// Add responsive styles for the client detail page
const style = document.createElement('style')
style.textContent = `
  @media (max-width: 768px) {
    .client-detail-layout {
      grid-template-columns: 1fr;
      gap: 12px;
      height: auto !important;
    }
    
    .client-detail-layout > div:first-child {
      min-height: 200px;
      background-size: contain !important;
    }
    
    .detail-card {
      padding: 12px;
    }
    
    .detail-grid {
      grid-template-columns: 1fr;
      gap: 12px;
    }
    
    .detail-actions {
      flex-direction: column;
      align-items: stretch;
    }
    
    .detail-actions > button {
      width: 100%;
      margin-bottom: 0.5rem;
    }
  }
  
  @media (max-width: 480px) {
    .client-detail-layout {
      gap: 8px;
    }
    
    .detail-card {
      padding: 8px;
    }
    
    .detail-grid {
      gap: 8px;
    }
    
    .detail-label {
      font-size: 11px;
    }
    
    .detail-value {
      font-size: 13px;
      padding: 8px;
    }
  }
`
document.head.appendChild(style)