import React, { useEffect, useMemo, useRef, useState } from "react"
import { Bell, AlertTriangle, Clock } from "lucide-react"
import { useLocation, useNavigate } from "react-router-dom"
import { useAuth } from "../hooks/useAuth" // Import useAuth hook

const NotificationsMenu = () => {
  const baseUrl = useMemo(() => process.env.REACT_APP_API_URL || 'http://127.0.0.1:8000', [])
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [items, setItems] = useState([])
  const [todayItems, setTodayItems] = useState([])
  const [pendingClients, setPendingClients] = useState([]) // Add pending clients state
  const [userNotifications, setUserNotifications] = useState([]) // Add user notifications state
  const [count, setCount] = useState(0)
  const menuRef = useRef(null)
  const location = useLocation()
  const navigate = useNavigate()
  const { hasPermission } = useAuth() // Get hasPermission function from auth context
  
  // Fonction utilitaire pour vérifier les permissions
  const userHasPermission = (permission) => {
    try {
      return hasPermission(permission)
    } catch (e) {
      console.error('Error checking permission:', e)
      return false
    }
  }

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

  const computeNotifications = (records) => {
    const today = new Date()
    const startOfToday = new Date(today.getFullYear(), today.getMonth(), today.getDate())

    const upcoming = []
    const todayArr = []

    const dayDiff = (d1, d2) => {
      const t1 = new Date(d1.getFullYear(), d1.getMonth(), d1.getDate()).getTime()
      const t2 = new Date(d2.getFullYear(), d2.getMonth(), d2.getDate()).getTime()
      return Math.round((t1 - t2) / 86400000)
    }

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
      // Exiger exactement "non echu" (accents/majuscules ignorés)
      return v === 'non echu'
    }
    const isEchuStatus = (s) => normalize(s).includes('echu')

    // On ne se base pas sur le statut pour classer; uniquement la date (sauf exclusion payé)

    for (const t of records) {
      const echeance = isDate(t.echeance)
      if (!echeance) continue
      const isPaid = isPaidStatus(t.statut)
      if (isPaid) continue

      const diff = dayDiff(echeance, startOfToday)
      // Ignorer les échéances passées (hier et avant)
      if (diff < 0) continue
      // Jour J: inclure Non échu ET déjà Échu (pour notification immédiate)
      if (diff === 0 && (isNonEchuStatus(t.statut) || isEchuStatus(t.statut))) {
        todayArr.push(t)
        continue
      }
      // Sous 5 jours (1..4) si statut Non échu
      if (isNonEchuStatus(t.statut) && diff > 0 && diff < 5) {
        upcoming.push(t)
      }
    }

    // Sort by date ascending
    upcoming.sort((a, b) => new Date(a.echeance) - new Date(b.echeance))
    todayArr.sort((a, b) => new Date(a.echeance) - new Date(b.echeance))

    const mapped = []
    if (upcoming.length) {
      mapped.push({
        type: 'upcoming',
        title: 'À échéance sous 5 jours',
        icon: <Clock size={16} color="#1f2c49" />,
        items: upcoming.map(t => ({
          id: t.id,
          label: `${t.numero} • ${t.nom_raison_sociale}`,
          sub: `Échéance: ${new Date(t.echeance).toLocaleDateString('fr-FR')}`,
        }))
      })
    }

    return { mapped, count: upcoming.length + todayArr.length, today: todayArr }
  }

  const getDismissed = () => {
    try { return JSON.parse(localStorage.getItem('dismissed_notifs') || '[]') } catch { return [] }
  }

  const setDismissed = (ids) => {
    localStorage.setItem('dismissed_notifs', JSON.stringify(ids))
  }

  const fetchData = async () => {
    setLoading(true)
    setError("")
    try {
      // Construire YYYY-MM-DD (local) pour aujourd'hui
      const now = new Date()
      const yyyy = now.getFullYear()
      const mm = String(now.getMonth() + 1).padStart(2, '0')
      const dd = String(now.getDate()).padStart(2, '0')
      const todayStr = `${yyyy}-${mm}-${dd}`

      // Vérifier les permissions de l'utilisateur
      const canManagePendingClients = userHasPermission('manage_pending_clients');
      const canViewTraites = userHasPermission('view_traites');
      const canViewClients = userHasPermission('view_clients');
      
      console.log('User permissions:', {
        canManagePendingClients,
        canViewTraites,
        canViewClients
      });

      // 1) Aujourd'hui (tous statuts) via plage echeance_from/echeance_to
      // Seulement pour les utilisateurs avec accès aux traites et pas seulement gestionnaires clients
      const p1 = (async () => {
        // Ne pas charger les notifications de traites pour les gestionnaires clients uniquement
        if (!canViewTraites || (canViewClients && !canManagePendingClients && !canViewTraites)) {
          console.log('Skipping traites notifications for clients manager only');
          return [];
        }
        
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

      // 2) À venir (Non échu) sous 5 jours
      // Seulement pour les utilisateurs avec accès aux traites et pas seulement gestionnaires clients
      const p2 = (async () => {
        // Ne pas charger les notifications de traites pour les gestionnaires clients uniquement
        if (!canViewTraites || (canViewClients && !canManagePendingClients && !canViewTraites)) {
          console.log('Skipping upcoming traites notifications for clients manager only');
          return [];
        }
        
        const p = new URLSearchParams()
        p.append('per_page', '200')
        p.append('upcoming_days', '5')
        p.append('sort', 'numero')
        p.append('dir', 'desc')
        const res = await fetch(`${baseUrl}/api/traites?${p.toString()}`, { headers: authHeaders() })
        if (!res.ok) throw new Error('Erreur chargement (à venir)')
        const data = await res.json()
        return Array.isArray(data?.data) ? data.data : (Array.isArray(data) ? data : [])
      })()

      // 3) Fetch pending clients data (seulement pour les admins)
      const p3 = (async () => {
        // Vérifier si l'utilisateur a la permission de gérer les clients en attente
        const hasPermission = userHasPermission('manage_pending_clients')
        if (!hasPermission) {
          return []
        }
        
        const res = await fetch(`${baseUrl}/api/pending-clients`, { headers: authHeaders() })
        if (!res.ok) return []
        const data = await res.json()
        return Array.isArray(data?.data) ? data.data : []
      })()

      // 4) Fetch user notifications (seulement pour les utilisateurs qui ont des permissions)
      const p4 = (async () => {
        // Vérifier si l'utilisateur a des permissions spéciales (pas pour les simples gestionnaires)
        const hasSpecialPermissions = userHasPermission('manage_pending_clients') || 
                                 userHasPermission('access_dashboard') || 
                                 userHasPermission('view_traites') || 
                                 userHasPermission('view_clients')
    
        console.log('Checking user permissions for notifications:', {
          hasManagePendingClients: userHasPermission('manage_pending_clients'),
          hasAccessDashboard: userHasPermission('access_dashboard'),
          hasViewTraites: userHasPermission('view_traites'),
          hasViewClients: userHasPermission('view_clients'),
          hasSpecialPermissions
        })
    
        if (!hasSpecialPermissions) {
          console.log('User does not have special permissions, skipping user notifications')
          return []
        }
    
        // Les utilisateurs avec la permission 'manage_pending_clients' ne doivent pas voir les notifications système
        // car ils sont ceux qui effectuent les actions d'approbation/rejet
        const canManagePendingClients = userHasPermission('manage_pending_clients');
        if (canManagePendingClients) {
          console.log('User can manage pending clients, skipping system notifications');
          return [];
        }
    
        console.log('Fetching user notifications...')
        const res = await fetch(`${baseUrl}/api/user/notifications`, { headers: authHeaders() })
        console.log('User notifications response status:', res.status)
    
        if (!res.ok) {
          console.error('Failed to fetch user notifications:', res.status, res.statusText)
          return []
        }
    
        const data = await res.json()
        console.log('User notifications fetched:', data.length)
        
        return Array.isArray(data) ? data : [];
      })()

      const [rowsTodayRaw, upcomingRows, pendingClients, userNotifications] = await Promise.all([p1, p2, p3, p4])
      console.log('NotificationsMenu - today data:', rowsTodayRaw.length, 'items')
      console.log('NotificationsMenu - upcoming data:', upcomingRows.length, 'items')
      console.log('NotificationsMenu - pending clients data:', pendingClients.length, 'items')
      console.log('NotificationsMenu - user notifications:', userNotifications.length, 'items')

      // Construire sections pour à venir avec l'existant
      const { mapped } = computeNotifications(upcomingRows)

      // Filtrages communs
      const dismissed = new Set(getDismissed())
      const notPaid = (s) => {
        const v = String(s || '').toLowerCase()
        return !(v.includes('payé') || v.includes('paye'))
      }

      // Filtrer sections et aujourd'hui
      const filteredSections = mapped.map(sec => ({
        ...sec,
        items: sec.items.filter(it => !dismissed.has(it.id))
      }))
      const filteredToday = rowsTodayRaw.filter(it => notPaid(it.statut) && !dismissed.has(it.id))
      console.log('NotificationsMenu - filtered today data:', filteredToday.length, 'items')
      console.log('NotificationsMenu - filtered sections data:', filteredSections)

      // Store pending clients and user notifications for display
      setPendingClients(pendingClients)
      setUserNotifications(userNotifications)

      // Mettre à jour état et badge
      setItems(filteredSections)
      setTodayItems(filteredToday)
      const newCount = filteredSections.reduce((acc, sec) => acc + sec.items.length, 0) + 
                      filteredToday.length + 
                      pendingClients.length + 
                      userNotifications.length
      console.log('NotificationsMenu - total count:', newCount)
      setCount(newCount)
    } catch (e) {
      console.error('NotificationsMenu - error:', e)
      setError(e.message || 'Erreur inconnue')
      setItems([])
      setTodayItems([])
      setPendingClients([])
      setUserNotifications([])
      setCount(0)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
    const id = setInterval(fetchData, 5000) // refresh chaque 5s
    return () => clearInterval(id)
  }, [])

  // Réagir aux dismiss déclenchés ailleurs (page notifications)
  useEffect(() => {
    const onExternalDismiss = () => {
      const dismissed = new Set(getDismissed())
      setItems(prev => {
        const next = prev.map(sec => ({ ...sec, items: sec.items.filter(it => !dismissed.has(it.id)) }))
        return next
      })
      setTodayItems(prev => prev.filter(it => !dismissed.has(it.id)))
      setCount(prev => {
        const itemsCount = (arr) => arr.reduce((acc, sec) => acc + sec.items.length, 0)
        const currentItems = typeof items === 'object' ? items : []
        const nextItemsCount = itemsCount(currentItems)
        const nextTodayCount = Math.max(0, (Array.isArray(todayItems) ? todayItems.length : 0) - 0)
        const nextPendingCount = Math.max(0, (Array.isArray(pendingClients) ? pendingClients.length : 0) - 0)
        const nextUserNotificationsCount = Math.max(0, (Array.isArray(userNotifications) ? userNotifications.length : 0) - 0)
        return nextItemsCount + nextTodayCount + nextPendingCount + nextUserNotificationsCount
      })
    }
    window.addEventListener('dismissed_notifs_changed', onExternalDismiss)
    return () => window.removeEventListener('dismissed_notifs_changed', onExternalDismiss)
  }, [])
  
  // Réagir aux changements de permissions ou d'utilisateur
  useEffect(() => {
    // Refetch data when permissions change
    fetchData()
  }, [hasPermission])

  // Ouvrir via sidebar: ?tab=notifications
  useEffect(() => {
    const params = new URLSearchParams(location.search)
    if (params.get('tab') === 'notifications') {
      setOpen(true)
    }
  }, [location.search])

  // Fermer au clic extérieur
  useEffect(() => {
    const onClick = (e) => {
      if (open && menuRef.current && !menuRef.current.contains(e.target)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [open])

  const handleClickItem = (id) => {
    // marquer comme vu → décrémente badge
    const dismissed = getDismissed()
    if (!dismissed.includes(id)) {
      dismissed.push(id)
      setDismissed(dismissed)
      // notifier les autres composants
      window.dispatchEvent(new Event('dismissed_notifs_changed'))
    }
    setItems(prev => prev.map(sec => ({ ...sec, items: sec.items.filter(it => it.id !== id) })))
    setTodayItems(prev => prev.filter(it => it.id !== id))
    setCount(prev => Math.max(0, prev - 1))
    // Rafraîchir immédiatement depuis l'API pour refléter l'état réel
    fetchData().catch(() => {})
    // naviguer vers la fiche traite
    navigate(`/traites/${id}`)
  }

  return (
    <div className="notif-container" ref={menuRef}>
      <button className="notif-bell" onClick={() => setOpen(o => !o)} aria-label="Notifications">
        <Bell size={18} />
        {count > 0 && <span className="notif-badge">{count}</span>}
      </button>
      {open && (
        <div className="notif-menu">
          <div className="notif-header">Notifications</div>
          {userNotifications.length > 0 && (
            <div className="notif-user-notifications" style={{ padding: '8px 16px', borderBottom: '1px solid #eee' }}>
              <div className="notif-section-title" style={{ fontWeight: 600, color: '#374151', marginBottom: 8 }}>
                Notifications système
              </div>
              {userNotifications.slice(0, 5).map(notification => {
                // Determine background color based on notification type
                const isApproval = notification.data && notification.data.type === 'client_approved';
                const isRejection = notification.data && notification.data.type === 'client_rejected';
                
                let backgroundColor = '#10a54e'; // Default green
                let titleColor = '#ffffff';
                let subtitleColor = '#ffffff';
                
                if (isRejection) {
                  backgroundColor = '#ef4444'; // Red for rejections
                } else if (isApproval) {
                  backgroundColor = '#10a54e'; // Green for approvals
                }
                
                return (
                  <div 
                    key={notification.id} 
                    className="notif-item" 
                    onClick={async () => {
                      // Mark notification as read
                      try {
                        const res = await fetch(`${baseUrl}/api/user/notifications/${notification.id}/read`, {
                          method: 'POST',
                          headers: authHeaders()
                        });
                        if (res.ok) {
                          // Remove notification from list
                          setUserNotifications(prev => prev.filter(n => n.id !== notification.id));
                          setCount(prev => Math.max(0, prev - 1));
                          
                          // Close the notification menu
                          setOpen(false);
                          
                          // Handle navigation based on notification type
                          if (notification.data && notification.data.type === 'client_approved') {
                            // Navigate to the client approval history page
                            navigate('/dashboard?tab=credit&view=ClientApprovalHistory');
                          } else if (notification.data && notification.data.type === 'client_rejected') {
                            // Navigate to edit the rejected client request
                            
                            // Try multiple possible field names for client ID
                            const clientId = notification.data.client_id || 
                                          notification.data.pending_client_id || 
                                          notification.data.clientId || 
                                          notification.data.id;
                            
                            if (clientId) {
                              navigate(`/dashboard?tab=credit&view=editRejectedClient&id=${clientId}`);
                            } else {
                              // Fallback to approval history if no client_id
                              navigate('/dashboard?tab=credit&view=ClientApprovalHistory');
                            }
                          } else {
                            // Default navigation to approval history for other notifications
                            navigate('/dashboard?tab=credit&view=ClientApprovalHistory');
                          }
                        }
                      } catch (e) {
                        console.error('Error deleting notification:', e);
                      }
                    }} 
                    style={{ cursor: 'pointer', padding: '8px', backgroundColor, borderRadius: 4, marginBottom: 8 }}
                  >
                    <div className="notif-item-label" style={{ fontWeight: 600, color: titleColor }}>
                      {notification.data.message}
                    </div>
                    <div className="notif-item-sub" style={{ color: subtitleColor, fontSize: '0.875rem' }}>
                      {new Date(notification.created_at).toLocaleDateString('fr-FR', { 
                        hour: '2-digit', 
                        minute: '2-digit' 
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
          {pendingClients.length > 0 && (
            <div className="notif-pending-clients" style={{ padding: '8px 16px', borderBottom: '1px solid #eee' }}>
              <div className="notif-section-title" style={{ fontWeight: 600, color: '#f59e0b', marginBottom: 8 }}>
                Clients en attente
              </div>
              <div 
                className="notif-item" 
                onClick={() => {
                  setOpen(false);
                  navigate('/dashboard?tab=credit&view=PendingClients');
                }} 
                style={{ cursor: 'pointer', padding: '8px', backgroundColor: '#fff7ed', borderRadius: 4, marginBottom: 8 }}
              >
                <div className="notif-item-label" style={{ fontWeight: 600, color: '#92400e' }}>
                  {pendingClients.length} client{pendingClients.length > 1 ? 's' : ''} en attente d'approbation
                </div>
                <div className="notif-item-sub" style={{ color: '#b45309', fontSize: '0.875rem' }}>
                  Cliquez pour consulter
                </div>
              </div>
            </div>
          )}
          {todayItems.length > 0 && (
            <div className="notif-today-cards" style={{ padding: 8 }}>
              {todayItems.map(it => (
                <div key={it.id} className="notif-today-card" onClick={() => handleClickItem(it.id)} style={{ border: '2px solid #f59e0b', background: '#fff7ed', borderRadius: 8, padding: 8, marginBottom: 8, cursor: 'pointer' }}>
                  <div className="notif-item-label" style={{ fontWeight: 600, color: '#92400e' }}>{it.numero} • {it.nom_raison_sociale}</div>
                  <div className="notif-item-sub" style={{ color: '#92400e' }}>Échéance aujourd'hui — passe/échue • {new Date(it.echeance).toLocaleDateString('fr-FR')}</div>
                </div>
              ))}
            </div>
          )}
          {loading && <div className="notif-empty">Chargement...</div>}
          {error && <div className="notif-error">{error}</div>}
          {!loading && !error && items.length === 0 && pendingClients.length === 0 && todayItems.length === 0 && userNotifications.length === 0 && (
            <div className="notif-empty">Aucune notification</div>
          )}
          {!loading && !error && items.map(section => (
            <div key={section.type} className="notif-section">
              <div className="notif-section-title">{section.icon} <span style={{ marginLeft: 6 }}>{section.title}</span></div>
              <ul className="notif-list">
                {section.items.map(it => (
                  <li key={it.id} className="notif-item" onClick={() => handleClickItem(it.id)} style={{ cursor: 'pointer' }}>
                    <div className="notif-item-label">{it.label}</div>
                    <div className="notif-item-sub">{it.sub}</div>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default NotificationsMenu


