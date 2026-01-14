"use client"

import React, { useState, useEffect } from "react"
import Sidebar from "./Sidebar"
import DashboardStats from "./DashboardStats"
import Header from "./Header"
import TraitesGrid from "./TraitesGrid"
import ClientsGrid from "./ClientsGrid"
import ClientFormPage from "./ClientFormPage"
import ClientsHistoriquePage from "./ClientsHistoriquePage"
import ClientDetailPage from "./ClientDetailPage"
import EditionPage from "./EditionPage"
import HistoriquePage from "./HistoriquePage"
import TraiteFormPage from "./TraiteFormPage"
import TraiteDetailPage from "./TraiteDetailPage"
import PendingClientsGrid from "./PendingClientsGrid"
import NotificationsPage from "./NotificationsPage"
import ClientApprovalHistory from "./ClientApprovalHistory"
import EditRejectedClient from "./EditRejectedClient"
import { useLocation } from "react-router-dom"
import { useAuth } from "../hooks/useAuth"
import "./Dashboard.css"

const Dashboard = () => {
  const [activeMenuItem, setActiveMenuItem] = useState(null)
  const [activeSubItem, setActiveSubItem] = useState(null)
  const [currentSearch, setCurrentSearch] = useState("")
  const [menuInitialized, setMenuInitialized] = useState(false)
  
  const location = useLocation()
  const { hasPermission, permissions, isLoading } = useAuth()
  
  // DEBUG: Afficher les permissions
  useEffect(() => {
    console.log('Permissions chargées:', permissions);
    console.log('isLoading:', isLoading);
  }, [permissions, isLoading]);

  // Définir le menu par défaut selon le rôle (UNE SEULE FOIS au montage)
  useEffect(() => {
    // Attendre que les permissions soient chargées
    if (isLoading) return;
    if (menuInitialized) return;
    
    const params = new URLSearchParams(location.search)
    const tab = params.get('tab')
    
    // Si URL a des paramètres, laisser l'autre useEffect gérer
    if (tab) {
      setMenuInitialized(true);
      return;
    }
    
    // Vérifier les permissions réelles
    const hasClients = hasPermission('view_clients') || hasPermission('create_clients') || hasPermission('edit_clients')
    const hasTraites = hasPermission('view_traites') || hasPermission('create_traites') || hasPermission('edit_traites')
    const hasDashboard = hasPermission('access_dashboard') || hasPermission('view_dashboard')
    
    console.log('Permissions détectées:', { hasClients, hasTraites, hasDashboard, allPermissions: permissions }); // Debug
    
    // Gestionnaire de clients uniquement → Grille clients
    if (hasClients && !hasTraites) {
      console.log('✅ Redirection vers Credit compte - Gestion clients');
      setActiveMenuItem("Credit compte");
      setActiveSubItem("Gestion des comptes clients");
      setMenuInitialized(true);
    }
    // Gestionnaire de traites uniquement → Grille traites
    else if (hasTraites && !hasClients) {
      console.log('✅ Redirection vers Gestion Traites - Grille de saisie');
      setActiveMenuItem("Gestion Traites");
      setActiveSubItem("Grille de saisie");
      setMenuInitialized(true);
    }
    // Accès complet (clients ET traites) → Dashboard
    else if (hasTraites && hasClients) {
      console.log('✅ Redirection vers Dashboard (accès complet)');
      setActiveMenuItem("Dashboard");
      setActiveSubItem(null);
      setMenuInitialized(true);
    }
    // Si dashboard uniquement
    else if (hasDashboard) {
      console.log('✅ Redirection vers Dashboard');
      setActiveMenuItem("Dashboard");
      setActiveSubItem(null);
      setMenuInitialized(true);
    }
    // Par défaut → Dashboard
    else {
      console.log('⚠️ Aucune permission spécifique, affichage Dashboard par défaut');
      setActiveMenuItem("Dashboard");
      setMenuInitialized(true);
    }
  }, [hasPermission, menuInitialized, location.search, isLoading, permissions])

  // Gestion de l'URL pour activer les bons menus
  useEffect(() => {
    const params = new URLSearchParams(location.search)
    const tab = params.get('tab')
    const view = params.get('view')
    const searchParam = params.get('search') || ""
    
    setCurrentSearch(searchParam)

    if (tab === 'traites') {
      setActiveMenuItem('Gestion Traites')
      if (view === 'Edition') setActiveSubItem('Edition')
      else if (view === 'Historique') setActiveSubItem('Historique')
      else if (view === 'Notification') setActiveSubItem('Notification')
      else if (view === 'Clients') setActiveSubItem('Grille clients')
      else setActiveSubItem('Grille de saisie')
    } else if (tab === 'credit') {
      setActiveMenuItem('Credit compte')
      if (view === 'GestionClients') setActiveSubItem('Gestion des comptes clients')
      else if (view === 'HistoriqueClients') setActiveSubItem('Historique clients')
      else if (view === 'NewClient') setActiveSubItem('Nouveau client')
      else if (view === 'PendingClients') setActiveSubItem('PendingClients')
      else if (view === 'ClientApprovalHistory') setActiveSubItem('ClientApprovalHistory')
      else if (view === 'editRejectedClient') setActiveSubItem('editRejectedClient')
      else setActiveSubItem('Gestion des comptes clients')
    } else if (location.pathname.startsWith('/notifications')) {
      setActiveMenuItem('Gestion Traites')
      setActiveSubItem('Notification')
    }
  }, [location.search, location.pathname])

  // Fonction pour gérer le changement de menu
  const handleMenuChange = (newItem) => {
    setActiveMenuItem(newItem)
    
    if (newItem === "Gestion Traites") {
      setActiveSubItem("Grille de saisie")
    } else if (newItem === "Dashboard") {
      setActiveSubItem(null)
    } else if (newItem === "Credit compte") {
      setActiveSubItem("Gestion des comptes clients")
    }
  }

  // Afficher un loader pendant le chargement des permissions
  if (isLoading) {
    return (
      <div className="dashboard-container">
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
          Chargement...
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard-container">
      <div className="dashboard-wrapper">
        <Sidebar 
          activeMenuItem={activeMenuItem} 
          activeSubItem={activeSubItem} 
          setActiveMenuItem={handleMenuChange} 
          setActiveSubItem={setActiveSubItem} 
        />
        
        <div className="main-content">
          <Header />
          <div className="content-area">
            {/* --- ROUTAGE --- */}
            {location.pathname.startsWith('/traites/new') || location.pathname.match(/^\/traites\/\d+\/edit$/) ? (
              <TraiteFormPage />
            ) : location.pathname.match(/^\/traites\/\d+$/) ? (
              <TraiteDetailPage />
            ) : location.pathname.match(/^\/clients\/\d+\/edit$/) ? (
              <ClientFormPage key={location.pathname} />
            ) : location.pathname.match(/^\/clients\/\d+$/) ? (
              <ClientDetailPage />
            ) : location.pathname.startsWith('/clients/new') ? (
              <ClientFormPage key={location.pathname} />
            ) : location.pathname.startsWith('/notifications') ? (
              <NotificationsPage />
            
            ) : activeMenuItem === "Dashboard" ? (
              <DashboardStats />
              
            ) : activeMenuItem === "Gestion Traites" ? (
              activeSubItem === "Edition" ? <EditionPage /> : 
              activeSubItem === "Historique" ? <HistoriquePage /> : 
              activeSubItem === "Notification" ? <NotificationsPage /> : 
              activeSubItem === "Grille clients" ? (
                <ClientsGrid />
              ) : (
                <TraitesGrid key={`traites-grid-${currentSearch}`} searchTerm={currentSearch} />
              )
            
            ) : activeMenuItem === "Credit compte" ? (
              activeSubItem === "Gestion des comptes clients" ? (
                <ClientsGrid />
              ) :
              activeSubItem === "Historique clients" ? <ClientsHistoriquePage /> :
              activeSubItem === "Nouveau client" ? <ClientFormPage /> :
              activeSubItem === "PendingClients" ? <PendingClientsGrid /> :
              activeSubItem === "ClientApprovalHistory" ? <ClientApprovalHistory /> :
              activeSubItem === "editRejectedClient" ? <EditRejectedClient /> :
              <ClientsGrid />
            ) : null}
            
          </div>
        </div>
      </div>
    </div>
  )
}

export default Dashboard