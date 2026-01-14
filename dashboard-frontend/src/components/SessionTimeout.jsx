import React, { useEffect, useRef } from 'react';
import { useAuth } from '../hooks/useAuth';
import { useNavigate } from 'react-router-dom';

// 24 heures en millisecondes (24 * 60 * 60 * 1000)
const INACTIVITY_TIMEOUT = 24 * 60 * 60 * 1000;

const SessionTimeout = () => {
  const { logout } = useAuth();
  const navigate = useNavigate();
  const timeoutRef = useRef(null);

  useEffect(() => {
    // Fonction pour redémarrer le minuteur
    const resetTimer = () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
      
      timeoutRef.current = setTimeout(() => {
        // Déconnecter l'utilisateur après la période d'inactivité
        handleLogout();
      }, INACTIVITY_TIMEOUT);
    };

    // Fonction pour gérer la déconnexion
    const handleLogout = async () => {
      try {
        await logout();
        // Rediriger vers la page de connexion
        navigate('/login');
      } catch (error) {
        console.error('Erreur lors de la déconnexion automatique:', error);
        // Même en cas d'erreur, rediriger vers la page de connexion
        navigate('/login');
      }
    };

    // Écouter les événements d'activité de l'utilisateur
    const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click', 'wheel'];
    
    // Initialiser le minuteur
    resetTimer();

    // Ajouter les écouteurs d'événements
    events.forEach(event => {
      document.addEventListener(event, resetTimer, true);
    });

    // Nettoyer les écouteurs et le minuteur lors du démontage
    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
      
      events.forEach(event => {
        document.removeEventListener(event, resetTimer, true);
      });
    };
  }, [logout, navigate]);

  return null; // Ce composant ne rend rien visuellement
};

export default SessionTimeout;