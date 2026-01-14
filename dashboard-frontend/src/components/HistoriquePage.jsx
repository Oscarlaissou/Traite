import React, { useEffect, useMemo, useState } from "react"
import { useNavigate } from "react-router-dom"
import { Users, Calendar, ArrowLeft, Search, Download } from "lucide-react"
import { formatMoney } from "../utils/format"
import Pagination from './Pagination'
import "./Traites.css"
import MonImage from "../images/image6.png"
import * as XLSX from 'xlsx'

const HistoriquePage = () => {
  const navigate = useNavigate()
  const baseUrl = useMemo(() => process.env.REACT_APP_API_URL || 'http://127.0.0.1:8000', [])
  const [mode, setMode] = useState("client")
  const [searchClient, setSearchClient] = useState("")
  const [selectedMonth, setSelectedMonth] = useState(() => {
    const d = new Date()
    return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`
  })
  const [historiqueData, setHistoriqueData] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [page, setPage] = useState(1)
  const [perPage, setPerPage] = useState(6)
  const [pagination, setPagination] = useState({ current_page: 1, last_page: 1, total: 0 })
  const [viewportWidth, setViewportWidth] = useState(typeof window !== 'undefined' ? window.innerWidth : 1440)
  const [globalQuery, setGlobalQuery] = useState("")

  const authHeaders = () => {
    const token = localStorage.getItem('token')
    const headers = { 'Accept': 'application/json' }
    if (token) headers['Authorization'] = `Bearer ${token}`
    return headers
  }

  const fetchHistorique = async () => {
    setLoading(true)
    setError("")
    try {
      const params = new URLSearchParams()
      params.append('type', mode)
      if (mode === 'client' && searchClient) {
        params.append('nom_raison_sociale', searchClient)
      } else if (mode === 'mois' && selectedMonth) {
        params.append('month', selectedMonth)
      }
      // Demander la récupération de tous les enregistrements
      params.append('per_page', '100000')

      const res = await fetch(`${baseUrl}/api/traites/historique?${params.toString()}`, { headers: authHeaders() })
      if (!res.ok) throw new Error('Erreur lors du chargement de l\'historique')
      const data = await res.json()
      const rows = Array.isArray(data) ? data : (Array.isArray(data?.data) ? data.data : [])
      // Trier par date de dernière modification/d'activité décroissante
      const sorted = rows.slice().sort((a, b) => {
        const da = a && a.date ? new Date(a.date).getTime() : 0
        const db = b && b.date ? new Date(b.date).getTime() : 0
        return db - da
      })
      setHistoriqueData(sorted)
      setPage(1)
      setPagination({ current_page: 1, last_page: Math.max(1, Math.ceil(rows.length / perPage)), total: rows.length })
    } catch (e) {
      setError(e.message || 'Erreur inconnue')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchHistorique() }, [mode, searchClient, selectedMonth])
  useEffect(() => { setPage(1); setPagination(p => ({ ...p, current_page: 1 })) }, [globalQuery])
  useEffect(() => {
    const onResize = () => setViewportWidth(window.innerWidth)
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [])

  // Fonction pour formater les changements pour l'affichage
  const formatChanges = (changes) => {
    if (!changes || typeof changes !== 'object') return '-';

    const fieldLabels = {
      'numero': 'Numéro traite',
      'nombre_traites': 'Nombre traites',
      'echeance': 'Échéance',
      'date_emission': 'Date émission',
      'montant': 'Montant',
      'nom_raison_sociale': 'Nom/Raison sociale',
      'domiciliation_bancaire': 'Domiciliation bancaire',
      'rib': 'RIB',
      'motif': 'Motif',
      'origine_traite': 'Origine traite',
      'commentaires': 'Commentaires',
      'statut': 'Statut',
      'decision': 'Décision'
    };

    const items = [];
    for (const [key, value] of Object.entries(changes)) {
      const label = fieldLabels[key] || key;
      let oldVal = value.old || value.from || 'vide';
      let newVal = value.new || value.to || 'vide';
      
      // Convertir en chaîne de caractères si ce n'est pas déjà le cas
      oldVal = String(oldVal);
      newVal = String(newVal);
      
      items.push(`${label}: ${oldVal} → ${newVal}`);
    }

    return items.length > 0 ? items.join(' | ') : '-';
  };

  const handleExport = async () => {
    setLoading(true);
    try {
      // Appeler l'API d'export détaillé pour obtenir toutes les modifications
      const params = new URLSearchParams()
      params.append('type', mode)
      if (mode === 'client' && searchClient) {
        params.append('nom_raison_sociale', searchClient)
      } else if (mode === 'mois' && selectedMonth) {
        params.append('month', selectedMonth)
      }

      const res = await fetch(`${baseUrl}/api/traites/export-historique?${params.toString()}`, { headers: authHeaders() })
      if (!res.ok) throw new Error('Erreur lors du chargement des données d\'export')
      const data = await res.json()
      const exportData = Array.isArray(data) ? data : (Array.isArray(data?.data) ? data.data : [])

      // Les données sont déjà triées côté backend du plus récent au plus ancien
      const worksheetData = exportData.map(item => ({
        'Date': item.date ? new Date(item.date).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' }) : '',
        'Nom/Raison sociale': item.nom_raison_sociale || '',
        'Numéro Traite': item.numero_traite || item.numero_compte || '',
        'Montant': Number(item.montant) || 0,
        'Action': item.action || '',
        'Utilisateur': item.username || item.user_name || item.user_email || '',
        'Statut': item.statut || '',
        'Détails': item.changes ? formatChanges(item.changes) : '-'
      }));

      // Créer la feuille de calcul Excel
      const worksheet = XLSX.utils.json_to_sheet(worksheetData);
      
      // Créer le classeur Excel
      const workbook = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(workbook, worksheet, "Historique");
      
      // Générer le fichier Excel et le télécharger
      const fileName = `Historique_Traites${new Date().toISOString().slice(0,10)}.xlsx`;
      XLSX.writeFile(workbook, fileName);
    } catch (e) {
      setError(e.message || 'Erreur lors de l\'export');
    } finally {
      setLoading(false);
    }
  }
  

  return (
    <div className="dashboard-stats two-frames">
      <button className="icon-button" onClick={() => navigate('/dashboard?tab=traites')} aria-label="Retour" style={{ marginBottom: 8, color: 'red' }}>
        <ArrowLeft size={18} />
      </button>
      <h2 className="stats-title">Historique des traites</h2>

      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: viewportWidth >= 992 ? '0.8fr 2.2fr' : '1fr', 
        gap: viewportWidth >= 768 ? 16 : 8, 
        minHeight: viewportWidth >= 768 ? 'calc(88vh - 120px)' : 'auto'
      }}>
        <div style={{ 
          position: viewportWidth >= 992 ? 'sticky' : 'static', 
          top: 8,
          display: viewportWidth < 768 ? 'none' : 'block'
        }}>
          <div className="frame-card" style={{
            backgroundImage: `url(${MonImage})`,
            backgroundSize: 'contain',
            backgroundPosition: 'center',
            backgroundRepeat: 'no-repeat',
            minHeight: viewportWidth >= 992 ? 480 : '30vh'
          }} />
        </div>

        <div style={{ 
          maxHeight: viewportWidth >= 992 ? 'calc(100vh - 140px)' : 'none', 
          overflowY: viewportWidth >= 992 ? 'auto' : 'visible',
          padding: viewportWidth < 768 ? '0 4px' : '0'
        }}>
          {/* Mode Selection */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12, marginBottom: 16 }}>
            <button onClick={() => setMode('client')} className="stat-card" style={{ border: mode==='client' ? '2px solid #1f2c49' : undefined }}>
              <div className="card-icon-container" style={{ background: '#ffffff' }}>
                <Users size={18} color="#1f2c49" />
              </div>
              <div className="card-content">
                <div className="card-title">Historique </div>
                <div className="card-value">Par client</div>
              </div>
            </button>
            <button onClick={() => setMode('mois')} className="stat-card" style={{ border: mode==='mois' ? '2px solid #1f2c49' : undefined }}>
              <div className="card-icon-container" style={{ background: '#ecfeff' }}>
                <Calendar size={18} color="#0369a1" />
              </div>
              <div className="card-content">
                <div className="card-title">Historique</div>
                <div className="card-value">Par mois</div>
              </div>
            </button>
          </div>

          {/* Search Controls */}
          <div style={{ 
            display: 'flex', 
            gap: 8, 
            alignItems: 'center', 
            flexWrap: 'wrap', 
            marginBottom: 16,
            flexDirection: viewportWidth < 480 ? 'column' : 'row',
            alignItems: viewportWidth < 480 ? 'stretch' : 'center'
          }}>
            {mode === 'client' ? (
              <>
                <Search size={16} color="#6b7280" />
                <input 
                  type="text" 
                  placeholder="Rechercher par nom de client..." 
                  className="search-input" 
                  value={searchClient} 
                  onChange={(e) => setSearchClient(e.target.value)}
                  style={{ 
                    flex: viewportWidth < 480 ? 'none' : 1, 
                    minWidth: viewportWidth < 480 ? '100%' : 200,
                    width: viewportWidth < 480 ? '100%' : 'auto'
                  }}
                />
              </>
            ) : (
              <>
                <Calendar size={16} color="#6b7280" />
                <input 
                  type="month" 
                  className="search-input" 
                  value={selectedMonth} 
                  onChange={(e) => setSelectedMonth(e.target.value)}
                />
              </>
            )}
            <button 
              className="submit-button" 
              onClick={fetchHistorique}
              style={{ 
                width: viewportWidth < 480 ? '100%' : 'auto',
                marginBottom: viewportWidth < 480 ? 8 : 0
              }}
            >
              Rechercher
            </button>
            <button 
              className="submit-button" 
              onClick={handleExport} 
              disabled={!historiqueData.length}
              style={{ 
                width: viewportWidth < 480 ? '100%' : 'auto',
                marginBottom: viewportWidth < 480 ? 8 : 0
              }}
            >
              <Download size={16} style={{ marginRight: 6 }} /> Exporter Excel
            </button>
            
          </div>

          {/* Results */}
          {error && <div className="error-message">{error}</div>}
          {loading ? (
            <div style={{ textAlign: 'center', padding: 40 }}>
              <div>Chargement de l'historique...</div>
            </div>
          ) : (
            <div className="table-wrap">
              <table className="table-basic">
                <thead>
                  <tr>
                    <th>Date</th>
                    <th>Nom/Raison sociale</th>
                    <th>Numéro Traite</th>
                    <th>Montant</th>
                    <th>Action</th>
                    <th>Utilisateur</th>
                    <th>Détails</th>
                    <th>Statut</th>
                  </tr>
                </thead>
                <tbody>
                  {(() => {
                    const q = globalQuery.trim().toLowerCase()
                    const filtered = q ? historiqueData.filter(item => {
                      const dateStr = item.date ? new Date(item.date).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' }) : ''
                      const user = item.username || item.user_name || item.user_email || ''
                      const details = item.changes ? formatChanges(item.changes) : '-'
                      const fields = [
                        dateStr,
                        item.nom_raison_sociale,
                        item.numero_traite,
                        String(item.montant ?? ''),
                        item.action,
                        user,
                        details,
                        item.statut,
                      ].join(' \u2002 ')
                      return fields.toLowerCase().includes(q)
                    }) : historiqueData
                    const pageRows = filtered.slice((page - 1) * perPage, (page - 1) * perPage + perPage)
                    return filtered.length > 0 ? (
                      pageRows.map((item, index) => (
                      <tr key={index}>
                        <td>{new Date(item.date).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' })}</td>
                        <td>{item.nom_raison_sociale}</td>
                        <td>{item.numero_traite}</td>
                        <td style={{ whiteSpace: 'nowrap' }}>{formatMoney(item.montant)}</td>
                        <td>{item.action }</td>
                        <td>{item.username || item.user_name || item.user_email || ''}</td>
                        <td>{item.changes ? formatChanges(item.changes) : '-'}</td>
                        <td>
                          <span className={`status-badge ${
                            item.statut === 'Non échu' ? 'status-non-echu' :
                            item.statut === 'Échu' ? 'status-echu' :
                            item.statut === 'Impayé' ? 'status-impaye' :
                            item.statut === 'Rejeté' ? 'status-rejete' :
                            item.statut === 'Payé' ? 'status-paye' : ''
                          }`}>
                            {item.statut}
                          </span>
                        </td>
                      </tr>
                      ))
                    ) : (
                    <tr>
                      <td colSpan={6} style={{ textAlign: 'center', padding: 40, color: '#6b7280' }}>
                        Aucun historique trouvé. Assurez-vous d'être connecté lors de la création/modification,
                        que les migrations sont appliquées, et ajustez les filtres puis cliquez sur Rechercher.
                      </td>
                    </tr>
                    )
                  })()}
                </tbody>
                <tfoot>
                <tr>
                  <td colSpan={7}>
                    {(() => {
                      const q = globalQuery.trim().toLowerCase()
                      const filteredCount = (q ? historiqueData.filter(item => {
                        const dateStr = item.date ? new Date(item.date).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' }) : ''
                        const user = item.username || item.user_name || item.user_email || ''
                        const details = item.changes ? formatChanges(item.changes) : '-'
                        const fields = [dateStr, item.nom_raison_sociale, item.numero_traite, String(item.montant ?? ''), item.action, user, details, item.statut].join(' ')
                        return fields.toLowerCase().includes(q)
                      }) : historiqueData).length
                      const lastPage = Math.max(1, Math.ceil(filteredCount / perPage))
                      
                      return (
                        <Pagination
                          currentPage={Math.min(page, lastPage)}
                          totalPages={lastPage}
                          totalItems={filteredCount}
                          itemsPerPage={perPage}
                          onPageChange={(newPage) => {
                            setPage(newPage)
                            setPagination(ps => ({ ...ps, current_page: newPage }))
                          }}
                          onItemsPerPageChange={(newPerPage) => {
                            setPerPage(newPerPage)
                            setPage(1)
                            setPagination(p => ({ 
                              ...p, 
                              current_page: 1, 
                              last_page: Math.max(1, Math.ceil(historiqueData.length / newPerPage)), 
                              total: historiqueData.length 
                            }))
                          }}
                          itemsPerPageOptions={[6, 12, 18, 24]}
                          showItemsPerPage={true}
                          showTotal={true}
                        />
                      )
                    })()}
                  </td>
                </tr>
              </tfoot>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default HistoriquePage
