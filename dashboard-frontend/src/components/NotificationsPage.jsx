import React, { useEffect, useMemo, useState } from "react"
import { AlertTriangle, Clock, RefreshCcw, CheckCircle2, ArrowLeft } from "lucide-react"
import { useNavigate } from "react-router-dom"
import Pagination from './Pagination'
import "./Traites.css"
import Logo from "../images/image2.png"

const NotificationsPage = () => {
  const baseUrl = useMemo(() => process.env.REACT_APP_API_URL || 'http://127.0.0.1:8000', [])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [sections, setSections] = useState([])
  const [todayItems, setTodayItems] = useState([])
  const [page, setPage] = useState(1)
  const [perPage, setPerPage] = useState(6)
  const [total, setTotal] = useState(0)
  const [lastPage, setLastPage] = useState(1)
  const navigate = useNavigate()

  const authHeaders = () => {
    const token = localStorage.getItem('token')
    const headers = { 'Accept': 'application/json' }
    if (token) headers['Authorization'] = `Bearer ${token}`
    return headers
  }

  const isDate = (val) => {
    if (!val) return null
    // parse YYYY-MM-DD or leading part of 'YYYY-MM-DD ...' as local date to avoid TZ shifts
    if (typeof val === 'string' && /^\d{4}-\d{2}-\d{2}/.test(val)) {
      const datePart = val.slice(0, 10)
      const [y, m, d] = datePart.split('-').map(Number)
      const dt = new Date(y, m - 1, d)
      return isNaN(dt.getTime()) ? null : dt
    }
    const d = new Date(val)
    return isNaN(d.getTime()) ? null : d
  }

  const compute = (rows) => {
    const today = new Date()
    const startOfToday = new Date(today.getFullYear(), today.getMonth(), today.getDate())
    const dayDiff = (d1, d2) => {
      const t1 = new Date(d1.getFullYear(), d1.getMonth(), d1.getDate()).getTime()
      const t2 = new Date(d2.getFullYear(), d2.getMonth(), d2.getDate()).getTime()
      return Math.round((t1 - t2) / 86400000)
    }
    const upcoming = []
    const todayArr = []
    const normalize = (s) => String(s || '')
      .toLowerCase()
      .replace(/[éèêë]/g, 'e')
      .replace(/[àâä]/g, 'a')
      .replace(/[îï]/g, 'i')
      .replace(/[ôö]/g, 'o')
      .replace(/[ûü]/g, 'u')
    const isPaidStatus = (s) => {
      const v = normalize(s)
      if (v.includes('impay')) return false
      if (v.includes('non pay')) return false
      return v.includes('pay')
    }
    const isNonEchuStatus = (s) => {
      const v = normalize(s).trim()
      return v === 'non echu'
    }
    // On ne se base pas sur le statut pour classer; uniquement la date (sauf exclusion payé)
    for (const t of rows) {
      const echeance = isDate(t.echeance)
      if (!echeance) continue
      const isPaid = isPaidStatus(t.statut)
      if (isPaid) continue
      const diff = dayDiff(echeance, startOfToday)
      if (diff < 0) continue
      if (diff === 0 && isNonEchuStatus(t.statut)) {
        todayArr.push(t)
        continue
      }
      if (isNonEchuStatus(t.statut) && diff > 0 && diff < 5) {
        upcoming.push(t)
      }
    }
    upcoming.sort((a,b) => new Date(a.echeance) - new Date(b.echeance))
    todayArr.sort((a,b) => new Date(a.echeance) - new Date(b.echeance))
    return {
      sections: [
        { key: 'upcoming', title: 'À échéance sous 5 jours', icon: <Clock size={16} color="#1f2c49" />, items: upcoming },
      ],
      today: todayArr,
    }
  }

  const getDismissed = () => {
    try { return JSON.parse(localStorage.getItem('dismissed_notifs') || '[]') } catch { return [] }
  }

  const setDismissed = (ids) => {
    localStorage.setItem('dismissed_notifs', JSON.stringify(ids))
  }

  const fetchRows = async () => {
    setLoading(true); setError("")
    try {
      // Construire YYYY-MM-DD du jour (heure locale)
      const today = new Date()
      const yyyy = today.getFullYear()
      const mm = String(today.getMonth() + 1).padStart(2, '0')
      const dd = String(today.getDate()).padStart(2, '0')
      const todayStr = `${yyyy}-${mm}-${dd}`

      // 1) Requête: traites à échéance aujourd'hui (tous statuts, hors Payé côté client)
      const p1 = (async () => {
        const p = new URLSearchParams()
        p.append('per_page', '200')
        p.append('page', '1')
        p.append('echeance_from', todayStr)
        p.append('echeance_to', todayStr)
        p.append('sort', 'numero')
        p.append('dir', 'desc')
        const res = await fetch(`${baseUrl}/api/traites?${p.toString()}`, { headers: authHeaders() })
        if (!res.ok) throw new Error('Erreur chargement (aujourd\'hui)')
        const data = await res.json()
        return Array.isArray(data?.data) ? data.data : (Array.isArray(data) ? data : [])
      })()

      // 2) Requête: traites Non échu sous 5 jours (y compris aujourd'hui)
      const p2 = (async () => {
        const p = new URLSearchParams()
        p.append('per_page', String(perPage))
        p.append('page', String(page))
        p.append('upcoming_days', '5')
        p.append('sort', 'numero')
        p.append('dir', 'desc')
        const res = await fetch(`${baseUrl}/api/traites?${p.toString()}`, { headers: authHeaders() })
        if (!res.ok) throw new Error('Erreur chargement (à venir)')
        const data = await res.json()
        return { rows: Array.isArray(data?.data) ? data.data : (Array.isArray(data) ? data : []), meta: (data?.meta || {}) }
      })()

      const [rowsTodayRaw, upcomingRes] = await Promise.all([p1, p2])

      // Construire sections à partir de la 2e requête
      const mapped = compute(upcomingRes.rows)

      // Filtrer côté client: exclure Payé des listes et retirés (dismissed)
      const dismissed = new Set(getDismissed())
      const notPaid = (s) => {
        const v = String(s || '').toLowerCase()
        return !(v.includes('payé') || v.includes('paye'))
      }
      const filteredSections = mapped.sections.map(sec => ({
        ...sec,
        items: sec.items.filter(it => notPaid(it.statut) && !dismissed.has(it.id))
      }))

      // Construire la liste du jour à partir de rowsTodayRaw (tous statuts sauf Payé)
      const filteredToday = rowsTodayRaw
        .filter(it => notPaid(it.statut) && !dismissed.has(it.id))
        .sort((a,b) => new Date(a.echeance) - new Date(b.echeance))

      setSections(filteredSections)
      setTodayItems(filteredToday)

      const totalCount = filteredSections.reduce((sum, s) => sum + s.items.length, 0) + filteredToday.length
      const meta = upcomingRes.meta || {}
      if (meta?.total && Number(meta.total) > 0) {
        setTotal(Number(meta.total) + filteredToday.length) // approx: total à venir + aujourd'hui
      } else {
        setTotal(totalCount)
      }
      if (meta?.last_page && Number(meta.last_page) > 0) {
        setLastPage(Number(meta.last_page))
      } else {
        setLastPage(Math.max(1, Math.ceil(totalCount / perPage)))
      }
    } catch (e) {
      setError(e.message || 'Erreur inconnue')
      setSections([])
      setTodayItems([])
    } finally {
      setLoading(false)
    }
  }

  const resetDismissed = () => {
    localStorage.removeItem('dismissed_notifs')
    window.dispatchEvent(new Event('dismissed_notifs_changed'))
    fetchRows()
  }

  useEffect(() => {
    fetchRows()
  }, [page, perPage])

  const handleClick = (id) => {
    const dismissed = getDismissed()
    if (!dismissed.includes(id)) {
      dismissed.push(id)
      setDismissed(dismissed)
      // notifier le menu pour qu'il retire la même traite immédiatement
      window.dispatchEvent(new Event('dismissed_notifs_changed'))
    }
    setSections(prev => prev.map(sec => ({ ...sec, items: sec.items.filter(it => it.id !== id) })))
    setTodayItems(prev => prev.filter(it => it.id !== id))
    // Rafraîchir la liste pour refléter l'état serveur
    fetchRows().catch(() => {})
    navigate(`/traites/${id}`)
  }

  const statusClass = (s) => {
    const val = String(s || '').toLowerCase()
    if (val.includes('non échu') || val.includes('non e')) return 'status-non-echu'
    if (val.includes('échu') || val.includes('echu')) return 'status-echu'
    if (val.includes('impay')) return 'status-impaye'
    if (val.includes('rej')) return 'status-rejete'
    if (val.includes('pay')) return 'status-paye'
    return ''
  }

  // Responsive layout helpers
  const [viewportWidth, setViewportWidth] = useState(typeof window !== 'undefined' ? window.innerWidth : 1440)
  useEffect(() => {
    const onResize = () => setViewportWidth(window.innerWidth)
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [])

  const gridTemplateColumns = viewportWidth >= 1400
    ? '400px 1fr'
    : viewportWidth >= 1200
      ? '350px 1fr'
      : viewportWidth >= 992
        ? '300px 1fr'
        : viewportWidth >= 768
          ? '1fr'
          : '1fr'

  const imageHeight = viewportWidth < 992 ? '40vh' : 'calc(100vh - 140px)'
  const rightAsideSticky = viewportWidth >= 992

  // Pagination styles to align with screenshot
  const pageBtnBase = {
    padding: '6px 10px',
    borderRadius: 8,
    border: '1px solid #e5e7eb',
    background: '#fff',
    color: '#111827',
    cursor: 'pointer'
  }
  const pageBtnActive = {
    ...pageBtnBase,
    background: '#0f172a',
    color: '#fff',
    cursor: 'default'
  }
  const navBtnBase = {
    padding: '6px 10px',
    borderRadius: 8,
    border: '1px solid #e5e7eb',
    background: '#fff',
    color: '#111827',
    cursor: 'pointer'
  }
  const navBtnDisabled = {
    ...navBtnBase,
    opacity: 0.6,
    cursor: 'not-allowed'
  }

  return (
    <div className="dashboard-stats" style={{ 
      maxWidth: '100vw', 
      overflowX: 'hidden',
      boxSizing: 'border-box',
      width: '100%',
      position: 'relative'
    }}>
      <div className="detail-header" style={{ 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'space-between', 
        gap: 12, 
        flexWrap: 'wrap',
        maxWidth: '100%',
        overflowX: 'hidden'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <button className="icon-button" onClick={() => navigate('/dashboard?tab=traites')} aria-label="Retour" style={{ marginBottom: 8, color: 'red' }}>
        <ArrowLeft size={18} />
      </button>
        <div className="detail-title">Notifications</div>
        </div>
        <div className="detail-status-actions" style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <button className="icon-button" onClick={fetchRows}><RefreshCcw size={16} />&nbsp;Rafraîchir</button>
        </div>
      </div>
      {error && <div className="error-message">{error}</div>}
      {loading ? (
        <div>Chargement...</div>
      ) : (
      <div className="detail-card" style={{ 
        display: viewportWidth >= 768 ? 'grid' : 'block', 
        gridTemplateColumns: viewportWidth >= 768 ? gridTemplateColumns : '1fr', 
        gap: viewportWidth >= 768 ? 16 : 8,
        maxWidth: '100vw',
        overflowX: 'hidden',
        boxSizing: 'border-box',
        width: '100%',
        position: 'relative'
      }}>
          {/* Colonne gauche: frame image (remplit sa frame uniquement) */}
          <aside style={{ display: viewportWidth < 768 ? 'none' : 'block' }}>
            <div style={{ position: viewportWidth < 992 ? 'static' : 'sticky', top: 8 }}>
              <div style={{ background: '#ffffff', borderRadius: 12, overflow: 'hidden' }}>
                <img src={Logo} alt="Visuel notifications" style={{ display: 'block', width: '100%', height: imageHeight, objectFit: 'contain' }} />
              </div>
            </div>
          </aside>
          <div style={{ 
            paddingRight: viewportWidth >= 768 ? 2 : 0,
            paddingLeft: viewportWidth < 768 ? 0 : 0,
            overflow: 'hidden',
            maxWidth: '100%',
            boxSizing: 'border-box',
            width: '100%',
            position: 'relative'
          }}>
          {/* Échéance aujourd'hui affichée en premier */}
          <div className="notification-frame">
            <div className="notif-section-title"><CheckCircle2 size={16} color="#92400e" /> <span style={{ marginLeft: 6, color: '#92400e', fontWeight: 600 }}>Échéance aujourd'hui (passera Échu)</span> <span style={{ marginLeft: 8, color: '#6b7280' }}>({todayItems.length})</span></div>
            {todayItems.length === 0 ? (
              <div className="notif-empty">Aucune aujourd'hui</div>
            ) : (
              <div style={{ 
                display: 'grid', 
                gridTemplateColumns: viewportWidth >= 768 
                  ? 'repeat(auto-fill, minmax(300px, 1fr))' 
                  : '1fr', 
                gap: viewportWidth >= 768 ? 12 : 8,
                maxWidth: '100%',
                overflow: 'hidden'
              }}>
                {todayItems.map(it => (
                  <div key={it.id} onClick={() => handleClick(it.id)} style={{ 
                    cursor: 'pointer', 
                    border: '2px solid #f59e0b', 
                    background: '#fff7ed', 
                    borderRadius: 12, 
                    padding: 12, 
                    display: 'grid', 
                    gridTemplateColumns: '1fr auto', 
                    gap: 8, 
                    alignItems: 'flex-start', 
                    boxShadow: '0 1px 2px rgba(0,0,0,0.04)', 
                    transition: 'box-shadow .2s, transform .2s', 
                    minHeight: 80,
                    maxWidth: '100%',
                    width: '100%',
                    boxSizing: 'border-box',
                    overflow: 'hidden',
                    position: 'relative'
                  }} onMouseEnter={e => { e.currentTarget.style.boxShadow = '0 6px 14px rgba(0,0,0,0.10)'; e.currentTarget.style.transform = 'translateY(-1px)' }} onMouseLeave={e => { e.currentTarget.style.boxShadow = '0 1px 2px rgba(0,0,0,0.04)'; e.currentTarget.style.transform = 'translateY(0)' }}>
                    <div style={{ minWidth: 0, maxWidth: '100%', overflow: 'hidden' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                        <CheckCircle2 size={18} color="#92400e" />
                        <div style={{ 
                          fontWeight: 700, 
                          color: '#92400e', 
                          whiteSpace: 'nowrap', 
                          overflow: 'hidden', 
                          textOverflow: 'ellipsis',
                          maxWidth: '100%'
                        }}>
                          {(() => {
                            const s = String(it.statut || '').toLowerCase()
                            const dejaEchu = s.includes('échu') || s.includes('echu')
                            return dejaEchu
                              ? `Traite ${it.numero} — Échue aujourd'hui`
                              : `Traite ${it.numero} à échéance aujourd'hui — passe Échu`
                          })()}
                        </div>
                      </div>
                      <div style={{ 
                        display: 'flex', 
                        flexWrap: 'wrap', 
                        gap: 8, 
                        rowGap: 6, 
                        color: '#6b7280', 
                        fontSize: 13,
                        maxWidth: '100%',
                        overflow: 'hidden'
                      }}>
                        <span style={{ 
                          background: '#f3f4f6', 
                          border: '1px solid #e5e7eb', 
                          borderRadius: 999, 
                          padding: '2px 8px',
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          maxWidth: '100%'
                        }}>
                          Par {it.nom_raison_sociale}
                        </span>
                        <span style={{ 
                          background: '#f3f4f6', 
                          border: '1px solid #e5e7eb', 
                          borderRadius: 999, 
                          padding: '2px 8px',
                          whiteSpace: 'nowrap',
                          fontWeight: 'bold'
                        }}>
                          {new Date(it.echeance).toLocaleDateString('fr-FR')}
                        </span>
                        <span style={{ 
                          background: '#f3f4f6', 
                          border: '1px solid #e5e7eb', 
                          borderRadius: 999, 
                          padding: '2px 8px',
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          maxWidth: '100%'
                        }}>
                          {it.numero}
                        </span>
                      </div>
                    </div>
                    <div style={{ alignSelf: 'start' }}>
                      <span style={{ border: '1px solid #e5e7eb', background: '#f8fafc', color: '#0f172a', padding: '4px 10px', borderRadius: 999, fontSize: 12, fontWeight: 600 }}>Notification</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {sections.map(sec => (
            <div key={sec.key} className="notification-frame">
              <div className="notif-section-title">{sec.icon} <span style={{ marginLeft: 6 }}>{sec.title}</span> <span style={{ marginLeft: 8, color: '#6b7280' }}>({sec.items.length})</span></div>
              {sec.items.length === 0 ? (
                <div className="notif-empty">Aucune</div>
              ) : (
                <div style={{ 
                  display: 'grid', 
                  gridTemplateColumns: viewportWidth >= 768 
                    ? 'repeat(auto-fill, minmax(300px, 1fr))' 
                    : '1fr', 
                  gap: viewportWidth >= 768 ? 12 : 8,
                  maxWidth: '100%',
                  overflow: 'hidden'
                }}>
                  {sec.items.map(it => (
                    <div key={it.id} onClick={() => handleClick(it.id)} style={{ 
                      cursor: 'pointer', 
                      border: '1px solid #e5e7eb', 
                      background: '#ffffff', 
                      borderRadius: 12, 
                      padding: 12, 
                      display: 'grid', 
                      gridTemplateColumns: '1fr auto', 
                      gap: 8, 
                      alignItems: 'flex-start', 
                      boxShadow: '0 1px 2px rgba(0,0,0,0.04)', 
                      transition: 'box-shadow .2s, transform .2s', 
                      minHeight: 80,
                      maxWidth: '100%',
                      width: '100%',
                      boxSizing: 'border-box',
                      overflow: 'hidden',
                      position: 'relative'
                    }} onMouseEnter={e => { e.currentTarget.style.boxShadow = '0 6px 14px rgba(0,0,0,0.10)'; e.currentTarget.style.transform = 'translateY(-1px)' }} onMouseLeave={e => { e.currentTarget.style.boxShadow = '0 1px 2px rgba(0,0,0,0.04)'; e.currentTarget.style.transform = 'translateY(0)' }}>
                      {/* Frame gauche: Contenu notification (sans image) */}
                      <div style={{ minWidth: 0, maxWidth: '100%', overflow: 'hidden' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                          <CheckCircle2 size={18} color="#0ea5e9" />
                          <div style={{ 
                            fontWeight: 700, 
                            color: '#0f172a', 
                            whiteSpace: 'nowrap', 
                            overflow: 'hidden', 
                            textOverflow: 'ellipsis',
                            maxWidth: '100%'
                          }}>
                            Traite {it.numero} à échéance sous 5 jours
                          </div>
                        </div>
                        <div style={{ 
                          display: 'flex', 
                          flexWrap: 'wrap', 
                          gap: 8, 
                          rowGap: 6, 
                          color: '#6b7280', 
                          fontSize: 13,
                          maxWidth: '100%',
                          overflow: 'hidden'
                        }}>
                          <span style={{ 
                            background: '#f3f4f6', 
                            border: '1px solid #e5e7eb', 
                            borderRadius: 999, 
                            padding: '2px 8px',
                            whiteSpace: 'nowrap',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            maxWidth: '100%'
                          }}>
                            Par {it.nom_raison_sociale}
                          </span>
                        <span style={{ 
                          background: '#f3f4f6', 
                          border: '1px solid #e5e7eb', 
                          borderRadius: 999, 
                          padding: '2px 8px',
                          whiteSpace: 'nowrap',
                          fontWeight: 'bold',
                          color:'black',
                        }}>
                          {new Date(it.echeance).toLocaleDateString('fr-FR')}
                        </span>
                          <span style={{ 
                            background: '#f3f4f6', 
                            border: '1px solid #e5e7eb', 
                            borderRadius: 999, 
                            padding: '2px 8px',
                            whiteSpace: 'nowrap',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            maxWidth: '100%'
                          }}>
                            {it.numero}
                          </span>
                        </div>
                      </div>
                      {/* Frame droite: Badge Notifications */}
                      <div style={{ alignSelf: 'start' }}>
                        <span style={{ border: '1px solid #e5e7eb', background: '#f8fafc', color: '#0f172a', padding: '4px 10px', borderRadius: 999, fontSize: 12, fontWeight: 600 }}>Notification</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
          {/* Footer type tfoot responsive */}
          <div style={{ marginTop: 16 }}>
            <Pagination
              currentPage={page}
              totalPages={lastPage}
              totalItems={total}
              itemsPerPage={perPage}
              onPageChange={(newPage) => setPage(newPage)}
              onItemsPerPageChange={(newPerPage) => {
                setPage(1)
                setPerPage(newPerPage)
              }}
              itemsPerPageOptions={[6, 12, 18, 24]}
              showItemsPerPage={true}
              showTotal={true}
            />
          </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default NotificationsPage


