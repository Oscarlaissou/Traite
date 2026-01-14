import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './hooks/useAuth';
import LoginForm from './components/LoginForm';
import Dashboard from './components/Dashboard';
import PageLoader from './components/BrandedLoader';
import TraiteDetailPage from './components/TraiteDetailPage';
import ClientFormPage from './components/ClientFormPage';
import SessionTimeout from './components/SessionTimeout';

// AJOUTS : import des composants clients
import ClientsGrid from './components/ClientsGrid';
import ClientDetailPage from './components/ClientDetailPage';
import SettingsPage from './components/SettingsPage';
import PendingClientsGrid from './components/PendingClientsGrid';
import EditRejectedClient from './components/EditRejectedClient';
// Removed unused import TraiteAcceptancePreview
// Removed ClientApprovalHistory import since it will be rendered within the Dashboard

// Composant pour les routes protégées
function ProtectedRoute({ children }) {
  const { isAuthenticated, isLoading } = useAuth();
  
  if (isLoading) {
      return <PageLoader message="Vérification de vos accès..." />;
  }
  
  return isAuthenticated ? children : <Navigate to="/login" replace />;
}

// Composant pour les routes publiques (redirige si déjà connecté)
function PublicRoute({ children }) {
    const { isAuthenticated, isLoading } = useAuth();
    
    if (isLoading) {
        return <div className="loading">Chargement...</div>;
    }
    
    return !isAuthenticated ? children : <Navigate to="/dashboard" replace />;
}

function AppRoutes() {
    return (
        <Routes>
            <Route 
                path="/login" 
                element={
                    <PublicRoute>
                        <LoginForm />
                    </PublicRoute>
                } 
            />
            <Route 
                path="/dashboard" 
                element={
                    <ProtectedRoute>
                        <Dashboard />
                    </ProtectedRoute>
                } 
            />
            
            <Route 
                path="/settings" 
                element={
                    <ProtectedRoute>
                        <SettingsPage />
                    </ProtectedRoute>
                } 
            />

            {/* ---------- ROUTES CLIENTS ---------- */}
            <Route
                path="/clients"
                element={
                    <ProtectedRoute>
                        <ClientsGrid />
                    </ProtectedRoute>
                }
            />
            <Route 
                path="/clients/new" 
                element={
                    <ProtectedRoute>
                        <Dashboard />
                    </ProtectedRoute>
                } 
            />
            <Route 
                path="/clients/:id/edit" 
                element={
                    <ProtectedRoute>
                        <Dashboard />
                    </ProtectedRoute>
                } 
            />
            <Route 
                path="/clients/:id" 
                element={
                    <ProtectedRoute>
                        <Dashboard />
                    </ProtectedRoute>
                } 
            />

            {/* ------------------------------------------------------------------ */}
            {/* AJOUT : routes alternatives avec préfixe /dashboard/clients */}
            <Route
                path="/dashboard/clients"
                element={
                    <ProtectedRoute>
                        <ClientsGrid />
                    </ProtectedRoute>
                }
            />
            <Route
                path="/dashboard/clients/new"
                element={
                    <ProtectedRoute>
                        <ClientFormPage />
                    </ProtectedRoute>
                }
            />
            <Route
                path="/dashboard/clients/:id/edit"
                element={
                    <ProtectedRoute>
                        <ClientFormPage />
                    </ProtectedRoute>
                }
            />
            <Route 
                path="/dashboard/clients/:id" 
                element={
                    <ProtectedRoute>
                        <Dashboard />
                    </ProtectedRoute>
                } 
            />
            {/* ------------------------------------------------------------------ */}

            {/* Route pour modifier un client rejeté */}
            <Route
                path="/dashboard/clients/edit/:id"
                element={
                    <ProtectedRoute>
                        <EditRejectedClient />
                    </ProtectedRoute>
                }
            />

            <Route 
                path="/pending-clients" 
                element={
                    <ProtectedRoute>
                        <PendingClientsGrid />
                    </ProtectedRoute>
                } 
            />

            <Route 
                path="/notifications" 
                element={
                <ProtectedRoute>
                    <Dashboard />
                </ProtectedRoute>
                } 
            />
            <Route 
                path="/traites/new" 
                element={
                    <ProtectedRoute>
                        <Dashboard />
                    </ProtectedRoute>
                } 
            />
            <Route 
                path="/traites/:id/edit" 
                element={
                    <ProtectedRoute>
                        <Dashboard />
                    </ProtectedRoute>
                } 
            />
            <Route 
                path="/traites/:id" 
                element={
                    <ProtectedRoute>
                        <Dashboard />
                    </ProtectedRoute>
                } 
            />
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            
            {/* Route pour les pages non trouvées */}
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
    );
}

function App() {
    return (
        <Router>
            <AuthProvider>
                <SessionTimeout />
                <AppRoutes />
            </AuthProvider>
        </Router>
    );
}

export default App;