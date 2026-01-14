import { createContext, useContext, useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
    const [authState, setAuthState] = useState({
        isAuthenticated: false,
        user: null,
        permissions: [],
        token: localStorage.getItem('token'),
        organization: {
            name: 'CFAO MOBILITY CAMEROON',
            logo: '/images/LOGO.png'
        },
        isLoading: true,
    });
    
    const navigate = useNavigate();
    const baseUrl = process.env.REACT_APP_API_URL || 'http://localhost:8000';

    useEffect(() => {
        const token = localStorage.getItem('token');
        if (token) {
            Promise.all([
                verifyToken(token),
                fetchOrganizationSettings(token)
            ]).then(() => {
                setAuthState(prev => ({ ...prev, isLoading: false }));
            }).catch(() => {
                setAuthState(prev => ({ ...prev, isLoading: false }));
            });
        } else {
            setAuthState(prev => ({ ...prev, isLoading: false }));
        }
    }, []);

    const verifyToken = async (token) => {
        try {
            // Récupérer le cookie CSRF
            await fetch(`${baseUrl}/sanctum/csrf-cookie`, {
                method: 'GET',
                credentials: 'include',
            });

            const response = await fetch(`${baseUrl}/api/user`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Accept': 'application/json',
                },
                credentials: 'include',
            });

            if (response.ok) {
                const userData = await response.json();
                
                // Extraire les permissions directement de la réponse
                const permissions = userData.permissions || [];
                
                // Stocker les permissions dans le localStorage
                localStorage.setItem('permissions', JSON.stringify(permissions));

                setAuthState(prev => ({
                    ...prev,
                    isAuthenticated: true,
                    user: userData.user, // Extraire l'utilisateur de la réponse
                    permissions: permissions,
                    token: token,
                }));
            } else {
                // Token invalide ou expiré
                localStorage.removeItem('token');
                localStorage.removeItem('user');
                setAuthState(prev => ({
                    ...prev,
                    isAuthenticated: false,
                    user: null,
                    permissions: [],
                    token: null,
                }));
            }
        } catch (error) {
            console.error('Erreur de vérification du token:', error);
            localStorage.removeItem('token');
            localStorage.removeItem('user');
            setAuthState(prev => ({
                ...prev,
                isAuthenticated: false,
                user: null,
                permissions: [],
                token: null,
            }));
        }
    };

    const fetchOrganizationSettings = async (token) => {
        try {
            const response = await fetch(`${baseUrl}/api/organization/settings`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Accept': 'application/json',
                },
            });

            if (response.ok) {
                const data = await response.json();
                setAuthState(prev => ({
                    ...prev,
                    organization: {
                        name: data.name,
                        logo: data.logo
                    }
                }));
            }
        } catch (error) {
            console.error('Erreur lors de la récupération des paramètres de l\'organisation:', error);
        }
    };

    const login = async (username, password) => {
        try {
            // Récupérer le cookie CSRF
            await fetch(`${baseUrl}/sanctum/csrf-cookie`, {
                method: 'GET',
                credentials: 'include',
            });

            const response = await fetch(`${baseUrl}/api/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                },
                body: JSON.stringify({ username, password }),
                credentials: 'include',
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.message || 'Erreur de connexion');
            }

            const data = await response.json();
            
            if (data.success) {
                localStorage.setItem('token', data.token);
                // Stocker les données utilisateur et permissions séparément
                localStorage.setItem('user', JSON.stringify(data.user));
                localStorage.setItem('permissions', JSON.stringify(data.permissions || []));
                
                // Fetch organization settings after login
                await fetchOrganizationSettings(data.token);
                
                setAuthState(prev => ({
                    ...prev,
                    isAuthenticated: true,
                    user: data.user,
                    permissions: data.permissions || [],
                    token: data.token,
                }));
                
                return { success: true };
            } else {
                throw new Error(data.message || 'Erreur de connexion');
            }
        } catch (error) {
            return {
                success: false,
                message: error.message 
            };
        }
    };

    const logout = async () => {
        try {
            const token = localStorage.getItem('token');
            if (token) {
                await fetch(`${baseUrl}/api/logout`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Accept': 'application/json',
                    },
                    credentials: 'include',
                });
            }
        } catch (error) {
            console.error('Erreur lors de la déconnexion:', error);
        } finally {
            localStorage.removeItem('token');
            localStorage.removeItem('user');
            localStorage.removeItem('permissions'); // Nettoyer les permissions aussi
            setAuthState(prev => ({
                ...prev,
                isAuthenticated: false,
                user: null,
                permissions: [],
                token: null,
                organization: {
                    name: 'CFAO MOBILITY CAMEROON',
                    logo: '/images/LOGO.png'
                },
            }));
            navigate('/login');
        }
    };

    // Fonction pour vérifier si l'utilisateur a une permission spécifique
    const hasPermission = (permissionName) => {
        // Vérifier si les permissions sont disponibles
        if (!authState.permissions || !Array.isArray(authState.permissions)) {
            return false;
        }
        
        // Vérifier si la permission existe dans le tableau des permissions de l'utilisateur
        return authState.permissions.includes(permissionName);
    };

    // Fonction pour vérifier si l'utilisateur a au moins une des permissions spécifiées
    const hasAnyPermission = (permissionNames) => {
        // Vérifier si les permissions sont disponibles
        if (!authState.permissions || !Array.isArray(authState.permissions) || !Array.isArray(permissionNames)) {
            return false;
        }
        
        // Vérifier si au moins une permission existe dans le tableau des permissions de l'utilisateur
        return permissionNames.some(permission => authState.permissions.includes(permission));
    };

    // Fonction pour mettre à jour les paramètres de l'organisation
    const updateOrganizationSettings = (settings) => {
        setAuthState(prev => ({
            ...prev,
            organization: {
                name: settings.name || prev.organization.name,
                logo: settings.logo || prev.organization.logo
            }
        }));
    };

    // Fonction utilitaire pour gérer les erreurs de fetch
    const handleFetchError = async (response) => {
        if (response.status === 401) {
            // Token expiré ou invalide, déconnecter l'utilisateur
            console.warn('Token expiré ou invalide, déconnexion automatique...');
            await logout();
            return false; // Indiquer que la requête a échoué à cause d'une authentification
        }
        return true; // La requête peut continuer normalement
    };

    const value = {
        ...authState,
        login,
        logout,
        hasPermission,
        hasAnyPermission,
        updateOrganizationSettings,
        handleFetchError, // Ajouter la fonction pour gérer les erreurs de fetch
    };

    return (
        <AuthContext.Provider value={value}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
};