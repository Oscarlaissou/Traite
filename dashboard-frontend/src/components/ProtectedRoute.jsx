import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import PageLoader from './BrandedLoader';

const ProtectedRoute = ({ children, permission }) => {
  const { isAuthenticated, hasPermission, isLoading } = useAuth();

  // Afficher le loader pendant la vérification
  if (isLoading) {
    return <PageLoader message="Vérification de vos accès..." />;
  }

  // Rediriger vers login si non authentifié
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  // Si une permission est requise, la vérifier
  if (permission && !hasPermission(permission)) {
    return (
      <div style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        height: '100vh',
        padding: '20px',
        textAlign: 'center'
      }}>
        <h1 style={{ fontSize: '48px', marginBottom: '20px' }}>🚫</h1>
        <h2 style={{ marginBottom: '10px' }}>Accès refusé</h2>
        <p style={{ color: '#666', marginBottom: '20px' }}>
          Vous n'avez pas la permission d'accéder à cette page.
        </p>
        <button 
          onClick={() => window.history.back()}
          style={{
            padding: '10px 20px',
            backgroundColor: '#007bff',
            color: 'white',
            border: 'none',
            borderRadius: '5px',
            cursor: 'pointer'
          }}
        >
          Retour
        </button>
      </div>
    );
  }

  // Afficher le contenu si tout est OK
  return children;
};

export default ProtectedRoute;