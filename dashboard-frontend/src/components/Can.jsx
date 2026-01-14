import React from 'react';
import { useAuth } from '../hooks/useAuth';

/**
 * Composant Can pour vérifier les permissions
 * Utilisation : 
 * 1. Avec permission unique : <Can permission="view_clients">...</Can>
 * 2. Avec plusieurs permissions (OR) : <Can permissions={['view_clients', 'edit_clients']}>...</Can>
 * 3. Avec fallback : <Can permission="view_clients" fallback={<div>Accès refusé</div>}>...</Can>
 */
const Can = ({ 
    permission, 
    permissions = [], 
    children, 
    fallback = null,
    condition = true // Permet d'ajouter des conditions supplémentaires
}) => {
    const { hasPermission, hasAnyPermission } = useAuth();
    
    // Si une condition explicite est fausse, ne pas afficher
    if (!condition) {
        return fallback;
    }
    
    // Vérifier les permissions
    let hasAccess = false;
    
    if (permission) {
        // Vérification d'une permission unique
        hasAccess = hasPermission(permission);
    } else if (permissions.length > 0) {
        // Vérification de plusieurs permissions (OR)
        hasAccess = hasAnyPermission(permissions);
    } else {
        // Si aucune permission n'est spécifiée, autoriser par défaut
        hasAccess = true;
    }
    
    return hasAccess ? children : fallback;
};

export default Can;