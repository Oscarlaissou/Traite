"use client"
import React, { useEffect, useState } from "react"
import { useNavigate } from "react-router-dom"
import "./Sidebar.css"
import { LogOut, Users, Bell, Settings, Home, Briefcase, CreditCard, Table, Edit, History, ChevronLeft, ChevronRight, Plus, CheckCircle } from "lucide-react"
import Can from "./Can"
import { useAuth } from "../hooks/useAuth" // Import du hook

const Sidebar = ({ activeMenuItem, activeSubItem, setActiveMenuItem, setActiveSubItem }) => {
  const navigate = useNavigate()
  const { logout, hasPermission, organization } = useAuth() // Utilisation du contexte auth
  const sidebarId = React.useRef(Math.random().toString(36).substr(2, 9)).current
  const [collapsed, setCollapsed] = React.useState(() => {
    try {
      return localStorage.getItem('sidebar_collapsed') === '1'
    } catch (_) {
      return false
    }
  })
  const [pendingClientsCount, setPendingClientsCount] = useState(0) // State for pending clients count
  const [loadingPendingClients, setLoadingPendingClients] = useState(false) // Loading state

  // Fetch pending clients count
  const fetchPendingClientsCount = async () => {
    // Only fetch if user has permission to manage pending clients
    if (!hasPermission('manage_pending_clients')) {
      setPendingClientsCount(0)
      return
    }
    
    setLoadingPendingClients(true)
    try {
      const baseUrl = process.env.REACT_APP_API_URL || ''
      const token = localStorage.getItem('token')
      const headers = token ? { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' } : { 'Accept': 'application/json' }

      const res = await fetch(`${baseUrl}/api/pending-clients`, { headers })
      
      if (res.ok) {
        const data = await res.json()
        const count = Array.isArray(data?.data) ? data.data.length : 0
        setPendingClientsCount(count)
      } else {
        setPendingClientsCount(0)
      }
    } catch (e) {
      console.error('Error fetching pending clients count:', e)
      setPendingClientsCount(0)
    } finally {
      setLoadingPendingClients(false)
    }
  }

  useEffect(() => {
    fetchPendingClientsCount()
    
    // Refresh every 5 seconds
    const interval = setInterval(fetchPendingClientsCount, 5000)
    return () => clearInterval(interval)
  }, [hasPermission])

  // Listen for WebSocket events to update pending clients count
  useEffect(() => {
    // Only listen for events if user has permission to manage pending clients
    if (!hasPermission('manage_pending_clients')) {
      return
    }

    // Listen for custom event when pending clients count changes
    const handlePendingClientsCountChange = () => {
      fetchPendingClientsCount()
    }
    
    window.addEventListener('pendingClientsCountChanged', handlePendingClientsCountChange)
    
    // Create a polling mechanism as fallback
    const interval = setInterval(fetchPendingClientsCount, 5000)
    
    return () => {
      window.removeEventListener('pendingClientsCountChanged', handlePendingClientsCountChange)
      clearInterval(interval)
    }
  }, [hasPermission])

  const toggleCollapsed = () => {
    setCollapsed((prev) => {
      const next = !prev
      try { localStorage.setItem('sidebar_collapsed', next ? '1' : '0') } catch (_) {}
      return next
    })
  }

  // Si un sous-menu est actif, s'assurer que la sidebar est élargie
  React.useEffect(() => {
    if (activeSubItem) {
      setCollapsed(false)
      try { localStorage.setItem('sidebar_collapsed', '0') } catch (_) {}
    }
  }, [activeSubItem])

  const handleLogout = async () => {
    try {
      console.log(`Déconnexion en cours (Sidebar ID: ${sidebarId})`)
      await logout() // Utilise la fonction logout du contexte
      console.log(`Déconnexion réussie (Sidebar ID: ${sidebarId})`)
    } catch (error) {
      console.error(`Erreur lors de la déconnexion (Sidebar ID: ${sidebarId}):`, error)
      // Force la déconnexion même en cas d'erreur
      localStorage.removeItem("token")
      localStorage.removeItem("user")
      navigate("/")
    }
  }

  console.log(`Rendu de Sidebar (ID: ${sidebarId}) à:`, new Date().toISOString())
  
  return (
  
      <>
      {/* Bouton externe, positionné à l'extérieur de la sidebar */}
      <button
        className="sidebar-external-toggle"
        onClick={toggleCollapsed}
        aria-label={collapsed ? 'Déplier la barre latérale' : 'Réduire la barre latérale'}
        style={{
          left: collapsed ? 120 : 300, // aligné au bord droit de la sidebar
        }}
      >
        {collapsed ? <ChevronRight size={18} /> : <ChevronLeft size={18} />}
      </button>

      <aside className={`sidebar ${collapsed ? 'collapsed' : ''}`} data-sidebar-id={sidebarId}>
      <div className="sidebar-header">
        <div className="logo">
          <img src={organization.logo} alt={`${organization.name} Logo`} style={{ width: "190px", height: "auto" }} />
          <div className="logo-icon"></div>
        </div>
        <div
          className="logo-text"
          style={{ fontSize: "16px", fontWeight: "bold", color: "#333", textAlign: "center", marginTop: "10px" }}
        >
          {organization.name}
        </div>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section">
          {/* Only show Dashboard menu item if user has dashboard access and access to both traites and clients */}
          {(hasPermission('access_dashboard') && 
            (hasPermission('access_traites') && hasPermission('access_clients'))) || 
            (hasPermission('access_dashboard') && 
            !hasPermission('access_traites') && 
            !hasPermission('access_clients')) ? (
            <Can permission="access_dashboard">
              <button
                className={`nav-item ${activeMenuItem === "Dashboard" ? "active" : ""}`}
                onClick={() => { 
                  if (typeof setActiveMenuItem === 'function') {
                    setActiveMenuItem("Dashboard"); 
                  }
                  if (typeof setActiveSubItem === 'function') {
                    setActiveSubItem(null); 
                  }
                  navigate('/dashboard') 
                }}
              >
                <span className="nav-icon">
                  <Home size={16} />
                </span>
                <span className="nav-text">Dashboard</span>
              </button>
            </Can>
          ) : null}
          <Can permission="view_traites">
            <button
              className={`nav-item ${activeMenuItem === "Gestion Traites" ? "active" : ""}`}
              onClick={() => { 
                if (typeof setActiveMenuItem === 'function') {
                  setActiveMenuItem("Gestion Traites"); 
                }
                if (typeof setActiveSubItem === 'function') {
                  setActiveSubItem("Grille de saisie"); 
                }
                setCollapsed(false);
                try { localStorage.setItem('sidebar_collapsed', '0') } catch (_) {}
                navigate('/dashboard') 
              }}
            >
              <span className="nav-icon">
                <Briefcase size={16} />
              </span>
              <span className="nav-text">Gestion Traites</span>
            </button>
          </Can>
          <Can permission="view_traites">
            {activeMenuItem === "Gestion Traites" && (
              <div className="subitems-group">
                <button className={`nav-subitem ${activeSubItem === "Grille de saisie" ? "active" : ""}`} onClick={() => { 
                  if (typeof setActiveSubItem === 'function') {
                    setActiveSubItem("Grille de saisie"); 
                  }
                  navigate('/dashboard') 
                }}>
                  <span className="nav-icon">
                    <Table size={16} />
                  </span>
                  <span className="nav-text">Grille de saisie</span>
                </button>

                <button className={`nav-subitem ${activeSubItem === "Edition" ? "active" : ""}`} onClick={() => { 
                  if (typeof setActiveSubItem === 'function') {
                    setActiveSubItem("Edition"); 
                  }
                  navigate('/dashboard') 
                }}>
                  <span className="nav-icon">
                    <Edit size={16} />
                  </span>
                  <span className="nav-text">Modification</span>
                </button>
                <Can permission="manage_pending_clients">
                  <button className={`nav-subitem ${activeSubItem === "Historique" ? "active" : ""}`} onClick={() => { 
                    if (typeof setActiveSubItem === 'function') {
                      setActiveSubItem("Historique"); 
                    }
                    navigate('/dashboard') 
                  }}>
                    <span className="nav-icon">
                      <History size={16} />
                    </span>
                    <span className="nav-text">Historique</span>
                  </button>
                </Can>
                <button className={`nav-subitem ${activeSubItem === "Notification" ? "active" : ""}`} onClick={() => { 
                  if (typeof setActiveSubItem === 'function') {
                    setActiveSubItem("Notification"); 
                  }
                  navigate('/notifications') 
                }}>
                  <span className="nav-icon">
                    <Bell size={16} />
                  </span>
                  <span className="nav-text">Notification</span>
                </button>
              </div>
            )}
          </Can>
          <Can permission="view_clients">
           <button
  className={`nav-item ${activeMenuItem === "Credit compte" ? "active" : ""}`}
  onClick={() => { 
    // setActiveMenuItem est maintenant une fonction valide passée par le parent
    if (typeof setActiveMenuItem === 'function') {
        setActiveMenuItem("Credit compte");
    }
    // setActiveSubItem est aussi une fonction
    if (setActiveSubItem) {
        setActiveSubItem("Gestion des comptes clients");
    }
    
    setCollapsed(false);
    try { localStorage.setItem('sidebar_collapsed', '0') } catch (_) {}
    navigate('/dashboard?tab=credit&view=GestionClients');
  }}
>
              <span className="nav-icon">
                <CreditCard size={16} />
              </span>
              <span className="nav-text">Comptes clients</span>
            </button>
          </Can>
          <Can permission="view_clients">
            {activeMenuItem === "Credit compte" && (
              <div className="subitems-group">
                <button className={`nav-subitem ${activeSubItem === "Gestion des comptes clients" ? "active" : ""}`} onClick={() => { 
                  if (typeof setActiveSubItem === 'function') {
                    setActiveSubItem("Gestion des comptes clients"); 
                  }
                  navigate('/dashboard?tab=credit&view=GestionClients') 
                }}>
                  <span className="nav-icon">
                    <Users size={16} />
                  </span>
                  <span className="nav-text">Gestion des comptes clients</span>
                </button>
                <Can permission="manage_pending_clients">
                  <button className={`nav-subitem ${activeSubItem === "Historique clients" ? "active" : ""}`} onClick={() => { 
                    if (typeof setActiveSubItem === 'function') {
                      setActiveSubItem("Historique clients"); 
                    }
                    navigate('/dashboard?tab=credit&view=HistoriqueClients') 
                  }}>
                    <span className="nav-icon">
                      <History size={16} />
                    </span>
                    <span className="nav-text">Historique comptes clients</span>
                  </button>
                </Can>
                <Can permission="create_clients">
                  <button className={`nav-subitem ${activeSubItem === "Nouveau client" ? "active" : ""}`} onClick={() => { 
                  if (typeof setActiveSubItem === 'function') {
                    setActiveSubItem("Nouveau client"); 
                  }
                  navigate('/dashboard?tab=credit&view=NewClient') 
                }}>
                    <span className="nav-icon">
                      <Plus size={16} />
                    </span>
                    <span className="nav-text">Nouveau compte client</span>
                  </button>
                </Can>
                {/* Afficher "Clients en attente" pour les admins (manage_pending_clients) */}
                {hasPermission('manage_pending_clients') && (
                  <button className={`nav-subitem ${activeSubItem === "PendingClients" ? "active" : ""}`} onClick={() => { 
                  if (typeof setActiveSubItem === 'function') {
                    setActiveSubItem("PendingClients"); 
                  }
                  navigate('/dashboard?tab=credit&view=PendingClients') 
                }}>
                    <span className="nav-icon">
                      <Users size={16} />
                    </span>
                    <span className="nav-text">
                      Clients en attente
                      {pendingClientsCount > 0 && (
                        <span className="pending-count-badge">
                          {loadingPendingClients ? '...' : pendingClientsCount}
                        </span>
                      )}
                    </span>
                  </button>
                )}
              {/* Historique Approuvés/Rejetés - visible UNIQUEMENT pour les gestionnaires (create_clients) et NON pour les admins */}
{hasPermission('create_clients') && !hasPermission('manage_pending_clients') && (
  <button className={`nav-subitem ${activeSubItem === "ClientApprovalHistory" ? "active" : ""}`} onClick={() => { 
    if (typeof setActiveSubItem === 'function') {
      setActiveSubItem("ClientApprovalHistory"); 
    }
    navigate('/dashboard?tab=credit&view=ClientApprovalHistory') 
  }}>
    <span className="nav-icon">
      <CheckCircle size={16} />
    </span>
    <span className="nav-text">
      Historique Approuvés/Rejetés
    </span>
  </button>
)}              </div>
            )}
          </Can>
        </div>


      </nav>

      <div className="sidebar-footer">
        {/* Show settings button if user has manage_company_info or manage_users permission */}
        {(hasPermission('manage_company_info') || hasPermission('manage_users')) && (
          <button
            className={`nav-item ${activeMenuItem === "Paramètres" ? "active" : ""}`}
            onClick={() => { 
              if (typeof setActiveMenuItem === 'function') {
                setActiveMenuItem("Paramètres"); 
              }
              navigate('/settings') 
            }}
            style={{ marginBottom: '10px', width: '100%' }}
          >
            <span className="nav-icon">
              <Settings size={16} />
            </span>
            <span className="nav-text">Paramètres</span>
          </button>
        )}
        <button className="logout-button" onClick={handleLogout}>
          <LogOut size={16} />
          <span>Déconnexion</span>
        </button>
      </div>
    </aside>
    </>
  )
}

export default Sidebar