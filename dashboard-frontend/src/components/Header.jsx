import React, { useState } from "react"
import "./Header.css"
import { Search } from "lucide-react"
import NotificationsMenu from "./NotificationsMenu"
import NotificationsBanner from "./NotificationsBanner"
import { useNavigate } from "react-router-dom"
import { useAuth } from "../hooks/useAuth" // Import useAuth hook

const Header = () => {
  const navigate = useNavigate()
  const { user, hasPermission } = useAuth() // Get user and permissions from auth context
  const [q, setQ] = useState("")
  
  console.log('Header - user:', user)
  
  // Only show NotificationsBanner to users who can manage pending clients
  const canManagePendingClients = hasPermission('manage_pending_clients');
  
  const handleSubmit = (e) => {
    e.preventDefault(); // Empêcher le rechargement de la page
    runSearch();
  }

  const runSearch = async () => {
    const query = (q || "").trim().toLowerCase()
    const originalQuery = (q || "").trim()
    
    // route by keyword - ces cas ne nécessitent pas de vérification
    if (query.includes('histor') || query.includes('history')) {
      const params = new URLSearchParams()
      params.set('tab', 'traites')
      params.set('view', 'Historique')
      if (originalQuery) params.set('search', originalQuery)
      navigate(`/dashboard?${params.toString()}`)
      return
    } else if (query.includes('edit') || query.includes('édition') || query.includes('edition')) {
      const params = new URLSearchParams()
      params.set('tab', 'traites')
      params.set('view', 'Edition')
      if (originalQuery) params.set('search', originalQuery)
      navigate(`/dashboard?${params.toString()}`)
      return
    } else if (query.includes('notif')) {
      navigate('/notifications')
      return
    } else if (query.includes('nouvelle') || query.includes('new') || query.includes('créer') || query.includes('creer')) {
      navigate('/traites/new')
      return
    } else if (query.match(/^#?\d+$/)) {
      // direct id navigation: "#123" or "123"
      const id = query.replace('#','')
      navigate(`/traites/${id}`)
      return
    }

    // Pour les recherches normales, aller dans la grille des traites
    // avec les paramètres de recherche
    const params = new URLSearchParams()
    params.set('tab', 'traites')
    params.set('view', 'Grille')
    if (originalQuery) params.set('search', originalQuery)
    
    // Vérifier s'il y a des résultats dans la grille des traites
    // Si aucun résultat, basculer automatiquement vers la grille des clients
    try {
      const baseUrl = process.env.REACT_APP_API_URL || ''
      const token = localStorage.getItem('token')
      const headers = token ? { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' } : { 'Accept': 'application/json' }
      
      // Effectuer une requête rapide pour vérifier s'il y a des résultats
      const searchParams = new URLSearchParams()
      if (originalQuery) searchParams.set('search', originalQuery)
      searchParams.set('per_page', '1') // Nous voulons juste savoir s'il y a des résultats
      
      const response = await fetch(`${baseUrl}/api/traites?${searchParams.toString()}`, { headers })
      
      if (response.ok) {
        const data = await response.json()
        const results = data.data || []
        
        // S'il n'y a pas de résultats dans les traites, basculer vers les clients
        if (results.length === 0) {
          const clientParams = new URLSearchParams()
          clientParams.set('tab', 'credit')
          clientParams.set('view', 'GestionClients')
          if (originalQuery) clientParams.set('search', originalQuery)
          navigate(`/dashboard?${clientParams.toString()}`)
          return
        }
      }
    } catch (error) {
      console.error('Erreur lors de la vérification des résultats:', error)
    }
    
    // Si nous arrivons ici, c'est qu'il y a des résultats dans les traites ou une erreur
    navigate(`/dashboard?${params.toString()}`)
  }
  return (
    <header className="header">
      {canManagePendingClients && <NotificationsBanner />}
      <div className="header-left">
        <h1 className="page-title">Dashboard</h1>
      </div>
      <div className="header-center">
        <form onSubmit={handleSubmit} className="search-container">
          <input 
            type="text" 
            placeholder="Search..." 
            className="search-input" 
            value={q} 
            onChange={(e) => setQ(e.target.value)} 
            onKeyDown={(e) => { 
              if (e.key === 'Enter') {
                e.preventDefault(); // Empêcher le rechargement de la page
                runSearch();
              }
            }} 
          />
          <button 
            type="submit" 
            className="search-button" 
            onClick={(e) => {
              e.preventDefault(); // Empêcher le rechargement de la page
              runSearch();
            }} 
            aria-label="Rechercher"
          >
            <Search size={16} />
          </button>
        </form>
      </div>
      <div className="header-right">
        <NotificationsMenu />
        <div className="user-profile">
          <div className="user-avatar">
            <img src="/person.png" alt="User Avatar" />
          </div>
          <span className="user-name">Bienvenue, {user?.username || 'Utilisateur'}</span>
          
        </div>
      </div>
    </header>
  )
}

export default Header