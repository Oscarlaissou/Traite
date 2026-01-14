import React, { useEffect, useMemo, useState } from "react"
import { useNavigate } from "react-router-dom"
import { formatMoney } from "../utils/format"
import { Calendar, CalendarClock, ArrowLeft } from "lucide-react"
import Pagination from './Pagination'
import "./Traites.css"
import MonImage from "../images/image3.png"

const EditionPage = () => {
  const navigate = useNavigate()
  const baseUrl = useMemo(() => process.env.REACT_APP_API_URL || 'http://127.0.0.1:8000', [])
  const [mode, setMode] = useState("jour")
  const [dateJour, setDateJour] = useState(() => new Date().toISOString().slice(0,10))
  const [mois, setMois] = useState(() => {
    const d = new Date()
    return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`
  })
  const [items, setItems] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  // Mass action removed per request
  const [page, setPage] = useState(1)
  const [perPage, setPerPage] = useState(6)
  const [pagination, setPagination] = useState({ current_page: 1, last_page: 1, total: 0 })
  const [viewportWidth, setViewportWidth] = useState(typeof window !== 'undefined' ? window.innerWidth : 1440)

  const authHeaders = () => {
    const token = localStorage.getItem('token')
    const headers = { 'Accept': 'application/json' }
    if (token) headers['Authorization'] = `Bearer ${token}`
    return headers
  }

  const computeRange = () => {
    if (mode === 'jour') {
      return { from: dateJour, to: dateJour }
    }
    const [yyyy, mm] = mois.split('-')
    const first = `${yyyy}-${mm}-01`
    const lastDate = new Date(Number(yyyy), Number(mm), 0).getDate()
    const last = `${yyyy}-${mm}-${String(lastDate).padStart(2,'0')}`
    return { from: first, to: last }
  }

  const fetchItems = async () => {
    setLoading(true)
    setError("")
    try {
      const { from, to } = computeRange()
      const params = new URLSearchParams()
      params.append('from', from)
      params.append('to', to)
      params.append('page', String(page))
      params.append('per_page', String(perPage))
      params.append('sort', 'numero')
      params.append('dir', 'desc')
      const res = await fetch(`${baseUrl}/api/traites?${params.toString()}`, { headers: authHeaders() })
      if (!res.ok) throw new Error('Erreur lors du chargement')
      const data = await res.json()
      const records = data.data || data || []
      const arrayRecords = Array.isArray(records) ? records : []
      setItems(arrayRecords)
      if (data && typeof data === 'object' && data.current_page) {
        setPagination({ current_page: data.current_page, last_page: data.last_page, total: data.total })
      } else {
        setPagination({ current_page: 1, last_page: 1, total: arrayRecords.length })
      }
    } catch (e) {
      setError(e.message || 'Erreur inconnue')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchItems() }, [mode, dateJour, mois, page, perPage])
  useEffect(() => {
    const onResize = () => setViewportWidth(window.innerWidth)
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [])

  // Mass action removed

  const handleEdit = (it) => navigate(`/traites/${it.id}/edit`)

  return (
    <div className="dashboard-stats">
      <button className="icon-button" onClick={() => navigate('/dashboard?tab=traites')} aria-label="Retour" style={{ marginBottom: 8, color: 'red' }}>
        <ArrowLeft size={18} />
      </button>
      <h2 className="stats-title">Édition des traites</h2>

      <div style={{ display: 'grid', gridTemplateColumns: viewportWidth >= 992 ? '0.8fr 2.2fr' : '1fr', gap: 16, height: viewportWidth >= 992 ? 'calc(100vh - 120px)' : 'auto' }}>
        <div style={{ position: viewportWidth >= 992 ? 'sticky' : 'static', top: 8 }}>
          <div style={{
            backgroundImage: `url(${MonImage})`,
            backgroundSize: 'contain',
            backgroundPosition: 'center',
            backgroundRepeat: 'no-repeat',
            borderRadius: 10,
            minHeight: viewportWidth >= 992 ? 480 : '40vh'
          }} />
        </div>

        <div style={{ maxHeight: viewportWidth >= 992 ? 'calc(100vh - 140px)' : 'none', overflowY: viewportWidth >= 992 ? 'auto' : 'visible' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 12, marginBottom: 12 }}>
            <button onClick={() => setMode('jour')} className="stat-card" style={{ border: mode==='jour' ? '2px solid #1f2c49' : undefined }}>
              <div className="card-icon-container" style={{ background: '#eef2ff' }}>
                <Calendar size={18} color="#1f2c49" />
              </div>
              <div className="card-content">
                <div className="card-title">Mode</div>
                <div className="card-value">Par jour</div>
              </div>
            </button>
            <button onClick={() => setMode('mois')} className="stat-card" style={{ border: mode==='mois' ? '2px solid #1f2c49' : undefined }}>
              <div className="card-icon-container" style={{ background: '#ecfeff' }}>
                <CalendarClock size={18} color="#0369a1" />
              </div>
              <div className="card-content">
                <div className="card-title">Mode</div>
                <div className="card-value">Par mois</div>
              </div>
            </button>
          </div>

          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginBottom: 12 }}>
            {mode === 'jour' ? (
              <>
                <span>Jour</span>
                <input type="date" className="search-input" value={dateJour} onChange={(e) => setDateJour(e.target.value)} />
              </>
            ) : (
              <>
                <span>Mois</span>
                <input type="month" className="search-input" value={mois} onChange={(e) => setMois(e.target.value)} />
              </>
            )}
            <button className="submit-button" onClick={fetchItems}>Rechercher</button>
          </div>

          {error && <div className="error-message">{error}</div>}
          {loading ? (
            <div>Chargement...</div>
          ) : (
            <div className="table-wrap">
              <table className="table-basic">
                <thead>
                  <tr>
                    <th>Numéro</th>
                    <th>Échéance</th>
                    <th>Montant</th>
                    <th>Client</th>
                    <th>Statut</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((it) => {
                    const s = String(it?.statut || 'Non échu').toLowerCase()
                    const cls = s.includes('non échu') || s.includes('non e') ? 'status-non-echu' :
                                s.includes('échu') || s.includes('echu') ? 'status-echu' :
                                s.includes('impay') ? 'status-impaye' :
                                s.includes('rej') ? 'status-rejete' :
                                s.includes('pay') ? 'status-paye' : ''
                    return (
                      <tr key={it.id} onClick={() => handleEdit(it)} style={{ cursor: 'pointer' }}>
                        <td>{it.numero}</td>
                        <td>{it.echeance?.slice(0,10)}</td>
                        <td style={{ whiteSpace: 'nowrap' }}>{formatMoney(it.montant)}</td>
                        <td>{it.nom_raison_sociale}</td>
                        <td><span className={`status-badge ${cls}`}>{it.statut || 'Non échu'}</span></td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
              <tfoot>
                <tr>
                  <td colSpan={5}>
                    <Pagination
                      currentPage={pagination.current_page || page}
                      totalPages={pagination.last_page || 1}
                      totalItems={pagination.total || 0}
                      itemsPerPage={perPage}
                      onPageChange={(newPage) => setPage(newPage)}
                      onItemsPerPageChange={(newPerPage) => {
                        setPerPage(newPerPage)
                        setPage(1)
                      }}
                      itemsPerPageOptions={[6, 12, 18, 24]}
                      showItemsPerPage={true}
                      showTotal={true}
                    />
                  </td>
                </tr>
              </tfoot>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default EditionPage


