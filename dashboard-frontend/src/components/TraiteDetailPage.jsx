import React, { useEffect, useState, useMemo } from "react"
import { useLocation } from "react-router-dom"
import Toast from "./Toast"
import { useNavigate, useParams } from "react-router-dom"
import { ArrowLeft, Edit3, Trash2, Printer, FileText, X } from "lucide-react"
import { formatMoney } from "../utils/format"
import Can from './Can'
import { useAuth } from '../hooks/useAuth'
import axios from 'axios'
import PageLoader from './BrandedLoader'
import "./Traites.css"
import MonImage from "../images/image4.png"

const TraiteDetailPage = () => {
  const navigate = useNavigate()
  const { id } = useParams()
  const { user, token } = useAuth()
  const [item, setItem] = useState(null)
  const location = useLocation()
  const [toast, setToast] = useState(() => (location.state && location.state.toast) ? location.state.toast : null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  
  // État pour le modal d'acceptation
  const [showAcceptanceModal, setShowAcceptanceModal] = useState(false)
  const [acceptanceData, setAcceptanceData] = useState({
    decision: 'Encaissement',
    branche_code: '',
    credit: '',
    agios: 'Tiré'
  })
  
  // État pour le changement de statut avec date impayé
  const [showStatusModal, setShowStatusModal] = useState(false)
  const [statusChangeData, setStatusChangeData] = useState({
    statut: '',
    date_impaye: ''
  })

  const formatDateDDMMYYYY = (value) => {
    if (!value) return ''
    const d = new Date(value)
    if (isNaN(d)) return value
    const dd = String(d.getDate()).padStart(2, '0')
    const mm = String(d.getMonth() + 1).padStart(2, '0')
    const yyyy = d.getFullYear()
    return `${dd}-${mm}-${yyyy}`
  }

  useEffect(() => {
    const fetchTraite = async () => {
      try {
        if (!token) {
          throw new Error('Utilisateur non authentifié')
        }
        
        const response = await axios.get(`/api/traites/${id}`, {
          headers: { Authorization: `Bearer ${token}` }
        })
        
        let data = response.data
        
        // Auto-coerce statut if due reached
        try {
          const echeanceDate = data?.echeance ? new Date(data.echeance) : null
          const isNonEchu = String(data?.statut || '').toLowerCase().includes('non')
          if (echeanceDate && !isNaN(echeanceDate) && isNonEchu && echeanceDate <= new Date()) {
            await axios.patch(`/api/traites/${data.id}/statut`, 
              { statut: 'Échu' },
              { headers: { Authorization: `Bearer ${token}` } }
            )
            data = { ...data, statut: 'Échu' }
          }
        } catch (_) {}
        
        setItem(data)
      } catch (err) {
        console.error('Erreur lors du chargement de la traite:', err)
        setError('Impossible de charger les détails de la traite')
      } finally {
        setLoading(false)
      }
    }

    fetchTraite()
  }, [id, token])

  const handleDelete = async () => {
    if (!window.confirm('Supprimer cette traite ?')) return
    try {
      if (!token) {
        throw new Error('Utilisateur non authentifié')
      }
      
      await axios.delete(`/api/traites/${id}`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      navigate('/dashboard')
    } catch (err) {
      console.error('Erreur lors de la suppression:', err)
      alert('Erreur lors de la suppression de la traite')
    }
  }

  const handlePrint = () => {
    if (!item) return
    const base = (process.env.REACT_APP_API_URL || '')
    const url = `${base}/print/traites/${item.id}/preview`
    window.open(url, '_blank')
  }

  const handleAcceptance = () => {
    setShowAcceptanceModal(true)
  }

  const handleAcceptanceSubmit = async () => {
    if (!item) return
    
    // Validation des champs requis
    if (!acceptanceData.branche_code || !acceptanceData.credit) {
      alert('Veuillez remplir tous les champs obligatoires')
      return
    }

    try {
      // Envoyer la décision à l'API pour la sauvegarder dans la base de données
      const response = await axios.patch(`/api/traites/${item.id}/decision`, {
        decision: acceptanceData.decision
      }, {
        headers: { Authorization: `Bearer ${token}` }
      })

      if (response.status === 200) {
        console.log('Décision enregistrée avec succès dans la base de données')
        
        // Mettre à jour l'item local avec la nouvelle décision
        setItem(prevItem => ({
          ...prevItem,
          decision: acceptanceData.decision
        }))
      }
    } catch (error) {
      console.error('Erreur lors de l\'enregistrement de la décision:', error)
      alert('Erreur lors de l\'enregistrement de la décision dans la base de données')
      // On continue malgré l'erreur pour permettre l'impression
    }

    // Construire l'URL avec les paramètres
    const base = (process.env.REACT_APP_API_URL || '')
    const params = new URLSearchParams({
      decision: acceptanceData.decision,
      branch_dept: acceptanceData.branche_code,
      credit_account: acceptanceData.credit,
      agos_type: acceptanceData.agios
    })
    const url = `${base}/print/traites/${item.id}/acceptance?${params.toString()}`
    
    window.open(url, '_blank')
    setShowAcceptanceModal(false)
    
    // Réinitialiser le formulaire
    setAcceptanceData({
      decision: 'Encaissement',
      branche_code: '',
      credit: '',
      agios: 'Tiré'
    })
  }

  const handleUpdateStatus = async (newStatut) => {
    try {
      if (!token) {
        throw new Error('Utilisateur non authentifié')
      }
      
      // Si le statut est 'Impayé', demander la date d'impayé
      if (newStatut === 'Impayé') {
        setStatusChangeData({
          statut: newStatut,
          date_impaye: ''
        })
        setShowStatusModal(true)
        return
      }
      
      await axios.patch(`/api/traites/${id}/statut`,
        { statut: newStatut },
        { headers: { Authorization: `Bearer ${token}` } }
      )
      setItem((prev) => ({ ...prev, statut: newStatut }))
    } catch (err) {
      console.error('Erreur lors de la mise à jour du statut:', err)
      alert('Erreur lors de la mise à jour du statut')
    }
  }

  // Fonction pour soumettre le changement de statut avec la date d'impayé
  const handleStatusChangeSubmit = async () => {
    try {
      if (!token) {
        throw new Error('Utilisateur non authentifié')
      }
      
      const payload = {
        statut: statusChangeData.statut
      };
      
      // Si le statut est 'Impayé', inclure la date d'impayé
      if (statusChangeData.statut === 'Impayé') {
        if (!statusChangeData.date_impaye) {
          alert('Veuillez renseigner la date d\'impayé');
          return;
        }
        payload.date_impaye = statusChangeData.date_impaye;
      }
      
      await axios.patch(`/api/traites/${id}/statut`,
        payload,
        { headers: { Authorization: `Bearer ${token}` } }
      )
      setItem((prev) => ({ ...prev, statut: statusChangeData.statut, date_impaye: statusChangeData.date_impaye }))
      setShowStatusModal(false)
      setStatusChangeData({
        statut: '',
        date_impaye: ''
      })
    } catch (err) {
      console.error('Erreur lors de la mise à jour du statut:', err)
      alert(err.response?.data?.message || 'Erreur lors de la mise à jour du statut')
    }
  }

  if (loading) return <PageLoader message="Chargement des détails de la traite..." />
  if (error) return <div style={{ padding: 16, color: 'crimson' }}>{error}</div>

  const statusValue = (item?.statut || 'Non échu').toLowerCase()
  const statusClass = statusValue.includes('non échu') || statusValue.includes('non e') ? 'status-non-echu' :
                      statusValue.includes('échu') || statusValue.includes('echu') ? 'status-echu' :
                      statusValue.includes('impay') ? 'status-impaye' :
                      statusValue.includes('rej') ? 'status-rejete' :
                      statusValue.includes('pay') ? 'status-paye' : ''

  const isReadOnly = item && item.origine_traite === "Externe"
  return (
    <div className="dashboard-stats">
      <div className="breadcrumb" style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
        <button className="icon-button" onClick={() => navigate('/dashboard?tab=traites')} aria-label="Retour" style={{ color: 'red' }}>
          <ArrowLeft size={18} />
        </button>
        <span className="crumb" onClick={() => navigate('/dashboard?tab=traites')}>Gestion Traites</span>
        <span>›</span>
        <span className="crumb-current">Détail</span>
      </div>

      {toast && (
        <Toast title={toast.title} message={toast.message} type={toast.type} onClose={() => setToast(null)} />
      )}

      {/* Modal de changement de statut avec date impayé */}
      {showStatusModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.5)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000
        }}>
          <div style={{
            backgroundColor: 'white',
            borderRadius: 12,
            padding: 32,
            width: '90%',
            maxWidth: 500,
            maxHeight: '90vh',
            overflowY: 'auto',
            boxShadow: '0 4px 20px rgba(0,0,0,0.15)'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
              <h2 style={{ margin: 0, fontSize: 20, fontWeight: 600, color: '#1a2c4e' }}>Changement de statut</h2>
              <button 
                onClick={() => {
                  setShowStatusModal(false)
                  setStatusChangeData({
                    statut: '',
                    date_impaye: ''
                  })
                }}
                style={{
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  padding: 4,
                  display: 'flex',
                  alignItems: 'center',
                  color: '#6b7280'
                }}
              >
                <X size={20} />
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
              <div>
                <label style={{ display: 'block', marginBottom: 6, fontWeight: 500, fontSize: 14, color: '#374151' }}>
                  Statut <span style={{ color: '#ef4444' }}>*</span>
                </label>
                <select
                  className="search-input"
                  value={statusChangeData.statut}
                  onChange={(e) => setStatusChangeData({ ...statusChangeData, statut: e.target.value })}
                  style={{ 
                    width: '100%',
                    padding: '10px 12px',
                    border: '1px solid #d1d5db',
                    borderRadius: 6,
                    fontSize: 14
                  }}
                >
                  <option value="Impayé">Impayé</option>
                  <option value="Rejeté">Rejeté</option>
                  <option value="Payé">Payé</option>
                </select>
              </div>

              {statusChangeData.statut === 'Impayé' && (
                <div>
                  <label style={{ display: 'block', marginBottom: 6, fontWeight: 500, fontSize: 14, color: '#374151' }}>
                    Date d'impayé <span style={{ color: '#ef4444' }}>*</span>
                  </label>
                  <input
                    type="date"
                    className="search-input"
                    value={statusChangeData.date_impaye}
                    onChange={(e) => setStatusChangeData({ ...statusChangeData, date_impaye: e.target.value })}
                    style={{ 
                      width: '100%',
                      padding: '10px 12px',
                      border: '1px solid #d1d5db',
                      borderRadius: 6,
                      fontSize: 14
                    }}
                  />
                </div>
              )}

              <div style={{ display: 'flex', gap: 12, marginTop: 8 }}>
                <button
                  onClick={() => {
                    setShowStatusModal(false)
                    setStatusChangeData({
                      statut: '',
                      date_impaye: ''
                    })
                  }}
                  style={{
                    flex: 1,
                    padding: '10px 16px',
                    border: '1px solid #d1d5db',
                    borderRadius: 6,
                    backgroundColor: 'white',
                    cursor: 'pointer',
                    fontSize: 14,
                    fontWeight: 500,
                    color: '#374151'
                  }}
                >
                  Annuler
                </button>
                <button
                  onClick={handleStatusChangeSubmit}
                  className="submit-button"
                  style={{
                    flex: 1,
                    padding: '10px 16px',
                    fontSize: 14,
                    fontWeight: 500
                  }}
                >
                  Confirmer le changement
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Modal d'acceptation */}
      {showAcceptanceModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.5)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000
        }}>
          <div style={{
            backgroundColor: 'white',
            borderRadius: 12,
            padding: 32,
            width: '90%',
            maxWidth: 500,
            maxHeight: '90vh',
            overflowY: 'auto',
            boxShadow: '0 4px 20px rgba(0,0,0,0.15)'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
              <h2 style={{ margin: 0, fontSize: 20, fontWeight: 600, color: '#1a2c4e' }}>Informations d'acceptation</h2>
              <button 
                onClick={() => setShowAcceptanceModal(false)}
                style={{
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  padding: 4,
                  display: 'flex',
                  alignItems: 'center',
                  color: '#6b7280'
                }}
              >
                <X size={20} />
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
              {/* Décision */}
              <div>
                <label style={{ display: 'block', marginBottom: 6, fontWeight: 500, fontSize: 14, color: '#374151' }}>
                  Décision de la traite <span style={{ color: '#ef4444' }}>*</span>
                </label>
                <select
                  className="search-input"
                  value={acceptanceData.decision}
                  onChange={(e) => setAcceptanceData({ ...acceptanceData, decision: e.target.value })}
                  style={{ 
                    width: '100%',
                    padding: '10px 12px',
                    border: '1px solid #d1d5db',
                    borderRadius: 6,
                    fontSize: 14
                  }}
                >
                  <option value="Encaissement">Encaissement</option>
                  <option value="Escompte">Escompte</option>
                </select>
              </div>

              {/* Raison sociale (affichage seulement) */}
              <div>
                <label style={{ display: 'block', marginBottom: 6, fontWeight: 500, fontSize: 14, color: '#374151' }}>
                  Raison sociale
                </label>
                <input
                  type="text"
                  className="search-input"
                  value={item?.nom_raison_sociale || ''}
                  disabled
                  style={{ 
                    width: '100%',
                    padding: '10px 12px',
                    border: '1px solid #d1d5db',
                    borderRadius: 6,
                    fontSize: 14,
                    backgroundColor: '#f9fafb',
                    cursor: 'not-allowed',
                    color: '#6b7280'
                  }}
                />
              </div>

              {/* Branche & Code département */}
              <div>
                <label style={{ display: 'block', marginBottom: 6, fontWeight: 500, fontSize: 14, color: '#374151' }}>
                  Branche, Code département & Marque <span style={{ color: '#ef4444' }}>*</span>
                </label>
                <input
                  type="text"
                  className="search-input"
                  placeholder="Ex: B11 TYRES"
                  value={acceptanceData.branche_code}
                  onChange={(e) => setAcceptanceData({ ...acceptanceData, branche_code: e.target.value })}
                  style={{ 
                    width: '100%',
                    padding: '10px 12px',
                    border: '1px solid #d1d5db',
                    borderRadius: 6,
                    fontSize: 14
                  }}
                />
              </div>

              {/* Crédit */}
              <div>
                <label style={{ display: 'block', marginBottom: 6, fontWeight: 500, fontSize: 14, color: '#374151' }}>
                 Compte client <span style={{ color: '#ef4444' }}>*</span>
                </label>
                <input
                  type="text"
                  className="search-input"
                  placeholder="Ex: 4111"
                  value={acceptanceData.credit}
                  onChange={(e) => setAcceptanceData({ ...acceptanceData, credit: e.target.value })}
                  style={{ 
                    width: '100%',
                    padding: '10px 12px',
                    border: '1px solid #d1d5db',
                    borderRadius: 6,
                    fontSize: 14
                  }}
                />
              </div>

              {/* Commentaire Agios */}
              <div>
                <label style={{ display: 'block', marginBottom: 6, fontWeight: 500, fontSize: 14, color: '#374151' }}>
                  Commentaire Agios <span style={{ color: '#ef4444' }}>*</span>
                </label>
                <select
                  className="search-input"
                  value={acceptanceData.agios}
                  onChange={(e) => setAcceptanceData({ ...acceptanceData, agios: e.target.value })}
                  style={{ 
                    width: '100%',
                    padding: '10px 12px',
                    border: '1px solid #d1d5db',
                    borderRadius: 6,
                    fontSize: 14
                  }}
                >
                  <option value="Tireur">Agios au Tireur</option>
                  <option value="Tiré">Agios au Tiré</option>
                </select>
              </div>

              {/* Boutons */}
              <div style={{ display: 'flex', gap: 12, marginTop: 8 }}>
                <button
                  onClick={() => setShowAcceptanceModal(false)}
                  style={{
                    flex: 1,
                    padding: '10px 16px',
                    border: '1px solid #d1d5db',
                    borderRadius: 6,
                    backgroundColor: 'white',
                    cursor: 'pointer',
                    fontSize: 14,
                    fontWeight: 500,
                    color: '#374151'
                  }}
                >
                  Annuler
                </button>
                <button
                  onClick={handleAcceptanceSubmit}
                  className="submit-button"
                  style={{
                    flex: 1,
                    padding: '10px 16px',
                    fontSize: 14,
                    fontWeight: 500
                  }}
                >
                  Générer l'acceptation
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '0.8fr 2.2fr', gap: 16, height: 'calc(100vh - 120px)' }}>
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
            <div className="detail-title">Détail de la traite</div>
            <div className="detail-status-actions">
              <span className={`status-badge ${statusClass}`} style={{fontSize: '20px'}}>{item?.statut || 'Non échu'}</span>
              {(() => {
                const current = String(item?.statut || '').toLowerCase()
                const isManual = ['impayé','impaye','rejeté','rejete','payé','paye'].some(k => current.includes(k))
                const manualValue = isManual ? (item?.statut || '') : ''
                return (
                  <select className="search-input" value={manualValue} onChange={(e) => e.target.value && handleUpdateStatus(e.target.value)}>
                    <option value="">Choisir un statut</option>
                    <option>Impayé</option>
                    <option>Rejeté</option>
                    <option>Payé</option>
                  </select>
                )
              })()}
            </div>
          </div>

          <div className="detail-card">
            <div className="detail-grid">
              <Detail label="Numéro" value={item?.numero} />
              <Detail label="Nb traites" value={item?.nombre_traites} />
              <Detail label="1ere Échéance" value={formatDateDDMMYYYY(item?.echeance)} />
              <Detail label="Émission" value={formatDateDDMMYYYY(item?.date_emission)} />
              <Detail label="Montant de crédit" value={formatMoney(item?.montant)} />
              <Detail label="Nom/Raison sociale" value={item?.nom_raison_sociale} />
              <Detail label="Domiciliation" value={item?.domiciliation_bancaire} />
              <Detail label="RIB" value={item?.rib} />
              <Detail label="Motif" value={item?.motif} />
              <Detail label="Origine traite" value={item?.origine_traite || "Interne"} />
              <Detail label="Décision" value={item?.decision} />
              <Detail label="Date d'impayé" value={formatDateDDMMYYYY(item?.date_impaye)} />
              <Detail label="Commentaires" value={item?.commentaires} />
            </div>

            <div className="detail-actions" style={{ display: 'flex', gap: 8, alignItems: 'center', justifyContent: 'flex-end', flexWrap: 'nowrap' }}>
              <Can permission="edit_traites">
                <button 
                  className="submit-button" 
                  onClick={() => navigate(`/traites/${id}/edit`)}
                  disabled={isReadOnly}
                  style={isReadOnly ? { opacity: 0.5, cursor: 'not-allowed' } : {}}
                >
                  <Edit3 size={16} style={{ marginRight: 6 }} /> Modifier
                </button>
              </Can>
              <button 
                className="submit-button" 
                onClick={handlePrint}
                disabled={isReadOnly}
                style={isReadOnly ? { opacity: 0.5, cursor: 'not-allowed' } : {}}
              >
                <Printer size={16} style={{ marginRight: 6 }} /> Imprimer
              </button>
              <button 
                className="submit-button" 
                onClick={handleAcceptance}
                disabled={isReadOnly && item?.origine_traite !== "Externe"}
                style={(isReadOnly && item?.origine_traite !== "Externe") ? { opacity: 0.5, cursor: 'not-allowed' } : {}}
              >
                <FileText size={16} style={{ marginRight: 6 }} /> Acceptation
              </button>
              <Can permission="delete_traites">
                <button 
                  className="submit-button" 
                  onClick={handleDelete}
                  disabled={isReadOnly}
                  style={isReadOnly ? { opacity: 0.5, cursor: 'not-allowed' } : {}}
                >
                  <Trash2 size={16} style={{ marginRight: 6 }} /> Supprimer
                </button>
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
    <div className="detail-value">{value ?? ''}</div>
  </div>
)

export default TraiteDetailPage