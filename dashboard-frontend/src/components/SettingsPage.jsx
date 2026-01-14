import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '../hooks/useAuth';
import { useNavigate } from 'react-router-dom';
import Header from './Header';
import Sidebar from './Sidebar';
import Can from './Can'; // Import the Can component
import './SettingsPage.css';
import Pagination from './Pagination'; // Import the Pagination component

const SettingsPage = () => {
  const { user, hasPermission, updateOrganizationSettings } = useAuth();
  const navigate = useNavigate();
  const [activeMenuItem, setActiveMenuItem] = useState('Paramètres');
  const [activeSubItem, setActiveSubItem] = useState(null);
  const [activeTab, setActiveTab] = useState('organization');
  const [users, setUsers] = useState([]);
  const [permissions, setPermissions] = useState([]);
  const [page, setPage] = useState(1); // Add pagination state
  const [perPage, setPerPage] = useState(5); // Change from 10 to 5 items per page
  const [organizationSettings, setOrganizationSettings] = useState({
    name: 'CFAO MOBILITY CAMEROON',
    logo: '/logo192.png'
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const fileInputRef = useRef(null);
  const baseUrl = process.env.REACT_APP_API_URL || 'http://localhost:8000';

  // Form states for user management
  const [newUser, setNewUser] = useState({
    username: '',
    password: '',
    role: 'admin', // Default to admin role
    ville: '',
    is_ad_user: false
  });
  
  // Password visibility states
  const [showNewUserPassword, setShowNewUserPassword] = useState(false);
  const [showEditUserPassword, setShowEditUserPassword] = useState(false);
  
  // Define roles with descriptions
  const roles = [
    { name: 'traites_manager', description: 'Gestionnaire des traites' },
    { name: 'clients_manager', description: 'Gestionnaire des clients' },
    { name: 'admin', description: 'Administrateur' },
    { name: 'super_admin', description: 'Super Administrateur' }
  ];
  
  // New state for user permissions
  const [userPermissions, setUserPermissions] = useState({});
  
  const [editingUser, setEditingUser] = useState(null);
  const [editForm, setEditForm] = useState({
    username: '',
    password: '',
    role: 'admin',
    ville: '',
    is_ad_user: false
  });
  
  // State for permissions tab
  const [permissionsTabUser, setPermissionsTabUser] = useState(null);

  // Fetch users, permissions and organization settings
  useEffect(() => {
    fetchUsers();
    fetchPermissions();
    fetchOrganizationSettings();
  }, []);

  const fetchUsers = async () => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`${baseUrl}/api/users`, {
        headers: {
          'Accept': 'application/json',
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (res.ok) {
        const data = await res.json();
        setUsers(data);
      }
    } catch (err) {
      console.error('Error fetching users:', err);
    }
  };

  const fetchPermissions = async () => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`${baseUrl}/api/permissions`, {
        headers: {
          'Accept': 'application/json',
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (res.ok) {
        const data = await res.json();
        setPermissions(data);
        
        // Initialize userPermissions state - deduplicated version
        const initialPermissions = {};
        const uniquePermissions = [];
        const permissionNames = new Set();
        
        data.forEach(permission => {
          if (!permissionNames.has(permission.name)) {
            permissionNames.add(permission.name);
            uniquePermissions.push(permission);
            initialPermissions[permission.name] = false;
          }
        });
        
        setUserPermissions(initialPermissions);
      }
    } catch (err) {
      console.error('Error fetching permissions:', err);
    }
  };

  const fetchOrganizationSettings = async () => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`${baseUrl}/api/organization/settings`, {
        headers: {
          'Accept': 'application/json',
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (res.ok) {
        const data = await res.json();
        setOrganizationSettings(data);
      }
    } catch (err) {
      console.error('Error fetching organization settings:', err);
    }
  };

  const handleOrganizationSettingsChange = (e) => {
    const { name, value } = e.target;
    setOrganizationSettings(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleNewUserChange = (e) => {
    const { name, value } = e.target;
    setNewUser(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleEditUserChange = (e) => {
    const { name, value } = e.target;
    setEditForm(prev => ({
      ...prev,
      [name]: value
    }));
  };

  // Handle permission toggle
  const handlePermissionToggle = (permissionName) => {
    setUserPermissions(prev => ({
      ...prev,
      [permissionName]: !prev[permissionName]
    }));
  };

  const triggerFileInput = () => {
    fileInputRef.current.click();
  };

  const handleLogoUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      // Créer une URL locale pour l'aperçu immédiat
      const logoUrl = URL.createObjectURL(file);
      setOrganizationSettings(prev => ({
        ...prev,
        logo: logoUrl
      }));
      
      // Envoyer automatiquement le nouveau logo au serveur
      saveOrganizationSettingsWithLogo(file);
    }
  };

  const saveOrganizationSettingsWithLogo = async (logoFile) => {
    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      const token = localStorage.getItem('token');
      
      // Créer un FormData avec le nom actuel et le nouveau logo
      const formData = new FormData();
      formData.append('name', organizationSettings.name || '');
      if (logoFile) {
        formData.append('logo', logoFile);
      }
      
      const res = await fetch(`${baseUrl}/api/organization/settings`, {
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: formData
      });
      
      if (res.ok) {
        const data = await res.json();
        setOrganizationSettings(data);
        setSuccess('Logo mis à jour avec succès');
        
        // Mettre à jour le logo dans le contexte d'authentification
        updateOrganizationSettings(data);
        
        // Réinitialiser l'input file
        if (fileInputRef.current) {
          fileInputRef.current.value = '';
        }
      } else {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.message || errorData.error || 'Failed to update organization settings');
      }
    } catch (err) {
      setError('Erreur lors de la mise à jour du logo: ' + err.message);
      console.error('Error saving organization logo:', err);
      
      // En cas d'erreur, revenir au logo précédent
      fetchOrganizationSettings();
    } finally {
      setLoading(false);
    }
  };

  const saveOrganizationSettings = async () => {
    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      const token = localStorage.getItem('token');
      
      // Créer un FormData pour le nom seulement (pas de logo)
      const formData = new FormData();
      formData.append('name', organizationSettings.name || '');
      
      const res = await fetch(`${baseUrl}/api/organization/settings`, {
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: formData
      });
      
      if (res.ok) {
        const data = await res.json();
        setOrganizationSettings(data);
        setSuccess('Nom de l\'organisation mis à jour avec succès');
        
        // Mettre à jour le logo dans le contexte d'authentification
        updateOrganizationSettings(data);
      } else {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.message || errorData.error || 'Failed to update organization settings');
      }
    } catch (err) {
      setError('Erreur lors de la mise à jour du nom: ' + err.message);
      console.error('Error saving organization name:', err);
    } finally {
      setLoading(false);
    }
  };

  const createUser = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      const token = localStorage.getItem('token');
      // Create user object without password if it's empty (for AD users)
      const userPayload = { ...newUser };
      if (!newUser.password.trim()) {
        delete userPayload.password; // Don't send password field if it's empty
      }
      
      const res = await fetch(`${baseUrl}/api/users`, {
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(userPayload)
      });
      
      if (res.ok) {
        const data = await res.json();
        setUsers(prev => [...prev, data]);
        setNewUser({
          username: '',
          password: '',
          role: 'admin',
          ville: ''
        });
        setSuccess('Utilisateur créé avec succès');
        fetchUsers(); // Refresh the user list
      } else {
        const errorData = await res.json();
        throw new Error(errorData.message || 'Failed to create user');
      }
    } catch (err) {
      setError(err.message || 'Erreur lors de la création de l\'utilisateur');
      console.error('Error creating user:', err);
    } finally {
      setLoading(false);
    }
  };

  const startEditingUser = (user) => {
    setEditingUser(user);
    setEditForm({
      username: user.username,
      password: '',
      role: user.role || 'admin',
      ville: user.ville || '',
      is_ad_user: user.is_ad_user || false
    });
  };
  
  const startPermissionsEdit = (user) => {
    setPermissionsTabUser(user);
    setActiveTab('user-permissions');
    // Fetch user permissions
    fetchUserPermissions(user.id);
  };

  const fetchUserPermissions = async (userId) => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`${baseUrl}/api/users/${userId}/permissions`, {
        headers: {
          'Accept': 'application/json',
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (res.ok) {
        const data = await res.json();
        // Update userPermissions state with user's current permissions - deduplicated version
        setUserPermissions(prev => {
          const updated = { ...prev };
          const uniquePermissions = Array.from(new Set(data));
          Object.keys(updated).forEach(permission => {
            updated[permission] = uniquePermissions.includes(permission);
          });
          return updated;
        });
      }
    } catch (err) {
      console.error('Error fetching user permissions:', err);
    }
  };

  const updateUser = async (e) => {
    e.preventDefault();
    if (!editingUser) return;
    
    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      const token = localStorage.getItem('token');
      // Create form object without password if it's empty (for AD users)
      const formPayload = { ...editForm };
      if (!editForm.password.trim()) {
        delete formPayload.password; // Don't send password field if it's empty
      }
      
      const res = await fetch(`${baseUrl}/api/users/${editingUser.id}`, {
        method: 'PUT',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(formPayload)
      });
      
      if (res.ok) {
        const data = await res.json();
        setUsers(prev => prev.map(u => u.id === data.id ? data : u));
        setEditingUser(null);
        setSuccess('Utilisateur mis à jour avec succès');
        fetchUsers(); // Refresh the user list
      } else {
        const errorData = await res.json();
        throw new Error(errorData.message || 'Failed to update user');
      }
    } catch (err) {
      setError(err.message || 'Erreur lors de la mise à jour de l\'utilisateur');
      console.error('Error updating user:', err);
    } finally {
      setLoading(false);
    }
  };

  const updateUserPermissions = async (userId) => {
    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      const token = localStorage.getItem('token');
      const selectedPermissions = Object.keys(userPermissions).filter(permission => userPermissions[permission]);
      
      const res = await fetch(`${baseUrl}/api/users/${userId}/permissions`, {
        method: 'PUT',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ permissions: selectedPermissions })
      });
      
      if (res.ok) {
        const data = await res.json();
        setSuccess('Permissions mises à jour avec succès');
        // Close the permissions tab and go back to users list
        setActiveTab('users');
        setPermissionsTabUser(null);
        fetchUsers(); // Refresh the user list
      } else {
        const errorData = await res.json();
        throw new Error(errorData.message || 'Failed to update permissions');
      }
    } catch (err) {
      setError(err.message || 'Erreur lors de la mise à jour des permissions');
      console.error('Error updating permissions:', err);
    } finally {
      setLoading(false);
    }
  };

  const deleteUser = async (userId) => {
    if (!window.confirm('Êtes-vous sûr de vouloir supprimer cet utilisateur ?')) {
      return;
    }
    
    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`${baseUrl}/api/users/${userId}`, {
        method: 'DELETE',
        headers: {
          'Accept': 'application/json',
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (res.ok) {
        setUsers(prev => prev.filter(u => u.id !== userId));
        setSuccess('Utilisateur supprimé avec succès');
      } else {
        const errorData = await res.json();
        throw new Error(errorData.error || 'Failed to delete user');
      }
    } catch (err) {
      setError(err.message || 'Erreur lors de la suppression de l\'utilisateur');
      console.error('Error deleting user:', err);
    } finally {
      setLoading(false);
    }
  };

  // Group permissions by category for better UI - improved version to avoid duplicates
  const groupPermissions = (permissions) => {
    const groups = {
      'Clients': [],
      'Traites': [],
      'Système': []
    };
    
    const addedPermissions = new Set();
    
    permissions.forEach(permission => {
      // Skip if already added
      if (addedPermissions.has(permission.name)) return;
      
      if (permission.name.includes('client')) {
        groups['Clients'].push(permission);
        addedPermissions.add(permission.name);
      } else if (permission.name.includes('traite')) {
        groups['Traites'].push(permission);
        addedPermissions.add(permission.name);
      } else {
        // Check if not already added to system group
        if (!addedPermissions.has(permission.name)) {
          groups['Système'].push(permission);
          addedPermissions.add(permission.name);
        }
      }
    });
    
    return groups;
  };

  const permissionGroups = groupPermissions(permissions);

  const getUsersForCurrentPage = () => {
    const startIndex = (page - 1) * perPage;
    const endIndex = startIndex + perPage;
    return users.slice(startIndex, endIndex);
  };

  const usersForCurrentPage = getUsersForCurrentPage();

  return (
    <div className="dashboard-container">
      <div className="dashboard-wrapper">
        <Sidebar 
          activeMenuItem={activeMenuItem} 
          activeSubItem={activeSubItem}
          setActiveMenuItem={setActiveMenuItem}
          setActiveSubItem={setActiveSubItem}
        />
        <div className="main-content">
          <Header />
          <div className="content-area">
            <div className="settings-page">
              <h1>Paramètres</h1>
              
              {error && <div className="alert alert-error">{error}</div>}
              {success && <div className="alert alert-success">{success}</div>}
              
              <div className="settings-tabs">
                <button 
                  className={`tab-button ${activeTab === 'organization' ? 'active' : ''}`}
                  onClick={() => setActiveTab('organization')}
                >
                  Organisation
                </button>
                {hasPermission('manage_users') && (
                  <button 
                    className={`tab-button ${activeTab === 'users' ? 'active' : ''}`}
                    onClick={() => setActiveTab('users')}
                  >
                    Gestion des utilisateurs
                  </button>
                )}
                {hasPermission('manage_users') && activeTab === 'user-permissions' && (
                  <button 
                    className={`tab-button active`}
                  >
                    Permissions - {permissionsTabUser?.username}
                  </button>
                )}
              </div>
              
              <div className="settings-content">
                {activeTab === 'organization' && (
                  <div className="organization-settings">
                    <h2>Paramètres de l'organisation</h2>
                    <div className="form-section">
                      <div className="form-group">
                        <label htmlFor="name">Nom de l'organisation</label>
                        <input
                          type="text"
                          id="name"
                          name="name"
                          value={organizationSettings.name}
                          onChange={handleOrganizationSettingsChange}
                          className="form-control"
                        />
                      </div>
                      
                      <div className="form-group">
                        <label>Logo de l'organisation</label>
                        <div className="logo-upload-container">
                          <img 
                            src={organizationSettings.logo} 
                            alt="Logo de l'organisation" 
                            className="logo-preview"
                          />
                          <button 
                            type="button" 
                            className="upload-button"
                            onClick={triggerFileInput}
                          >
                            Changer le logo
                          </button>
                          <input
                            type="file"
                            ref={fileInputRef}
                            onChange={handleLogoUpload}
                            accept="image/*"
                            className="file-input"
                          />
                        </div>
                      </div>
                      
                      <button 
                        className="submit-button"
                        onClick={saveOrganizationSettings}
                        disabled={loading}
                      >
                        {loading ? 'Enregistrement...' : 'Enregistrer les paramètres'}
                      </button>
                    </div>
                  </div>
                )}
                
                {activeTab === 'users' && hasPermission('manage_users') && (
                  <div className="user-management">
                    <h2>Gestion des utilisateurs</h2>
                    
                    {/* Create new user form */}
                    <div className="form-section">
                      <h3>Créer un nouvel utilisateur</h3>
                      <form onSubmit={createUser}>
                        <div className="form-row">
                          <div className="form-group">
                            <label htmlFor="username">Nom d'utilisateur</label>
                            <input
                              type="text"
                              id="username"
                              name="username"
                              value={newUser.username}
                              onChange={handleNewUserChange}
                              className="form-control"
                              required
                            />
                          </div>
                          
                          <div className="form-group">
                            <label htmlFor="ville">Ville</label>
                            <input
                              type="text"
                              id="ville"
                              name="ville"
                              value={newUser.ville}
                              onChange={handleNewUserChange}
                              className="form-control"
                            />
                          </div>
                        </div>
                        
                        <div className="form-row">
                          <div className="form-group">
                            <label htmlFor="password">Mot de passe (optionnel pour les utilisateurs AD)</label>
                            <input
                              type={showNewUserPassword ? 'text' : 'password'}
                              id="password"
                              name="password"
                              value={newUser.password}
                              onChange={handleNewUserChange}
                              className="form-control"
                              minLength="0"
                            />
                            <button 
                              type="button" 
                              className="toggle-password"
                              onClick={() => setShowNewUserPassword(!showNewUserPassword)}
                              title={showNewUserPassword ? 'Masquer le mot de passe' : 'Afficher le mot de passe'}
                            >
                              {showNewUserPassword ? '👁️' : '👁️‍🗨️'}
                            </button>
                          </div>
                          
                          <div className="form-group checkbox-group">
                            <label className="checkbox-label">
                              <input
                                type="checkbox"
                                id="is_ad_user"
                                name="is_ad_user"
                                checked={newUser.is_ad_user}
                                onChange={(e) => setNewUser({...newUser, is_ad_user: e.target.checked})}
                                className="checkbox-input"
                              />
                              <span className="checkbox-text">Utilisateur Active Directory</span>
                            </label>
                          </div>
                        </div>
                        
                        <div className="form-row">
                          <div className="form-group">
                            <label htmlFor="role">Rôle</label>
                            <select
                              id="role"
                              name="role"
                              value={newUser.role}
                              onChange={handleNewUserChange}
                              className="form-control"
                            >
                              {roles.map(role => (
                                <option 
                                  key={role.name} 
                                  value={role.name}
                                  disabled={role.name === 'super_admin' && users.some(u => u.role === 'super_admin')}
                                >
                                  {role.description}
                                </option>
                              ))}
                            </select>
                          </div>
                        </div>
                        
                        <button 
                          type="submit" 
                          className="submit-button"
                          disabled={loading}
                        >
                          {loading ? 'Création...' : 'Créer un utilisateur'}
                        </button>
                      </form>
                    </div>
                    
                    {/* Users list */}
                    <div className="form-section">
                      <h3>Liste des utilisateurs</h3>
                      <div className="table-wrap">
                        <table className="table-basic">
                          <thead>
                            <tr>
                              <th>Nom d'utilisateur</th>
                              <th>Rôle</th>
                              <th>Ville</th>
                              <th>Actions</th>
                            </tr>
                          </thead>
                          <tbody>
                            {usersForCurrentPage.map(user => (
                              <tr key={user.id}>
                                <td>{user.username}</td>
                                <td>
                                  <span className={`role-badge role-${user.role}`}>
                                    {roles.find(r => r.name === user.role)?.description || user.role}
                                  </span>
                                </td>
                                <td>{user.ville || '-'}</td>
                                <td>
                                  <div className="action-buttons">
                                    <button 
                                      className="edit-button"
                                      onClick={() => startEditingUser(user)}
                                    >
                                      Modifier
                                    </button>
                                    <button 
                                      className="permissions-button"
                                      onClick={() => startPermissionsEdit(user)}
                                    >
                                      Permissions
                                    </button>
                                    <Can permission="manage_users">
                                      <button 
                                        className="delete-button"
                                        onClick={() => deleteUser(user.id)}
                                        disabled={user.role === 'super_admin'}
                                      >
                                        Supprimer
                                      </button>
                                    </Can>
                                  </div>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                          <tfoot>
                            <tr>
                              <td colSpan="4" style={{ textAlign: "center", padding: "0.75rem", backgroundColor: "#f9fafb", borderTop: "2px solid #e5e7eb" }}>
                                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "1rem" }}>
                                  <div style={{ fontWeight: 500, color: "#374151" }}>
                                    Total: {users.length} utilisateur{users.length !== 1 ? 's' : ''}
                                  </div>
                                  <Pagination
                                    currentPage={page}
                                    totalPages={Math.ceil(users.length / perPage) || 1}
                                    totalItems={users.length}
                                    itemsPerPage={perPage}
                                    onPageChange={(newPage) => setPage(newPage)}
                                    onItemsPerPageChange={(newPerPage) => {
                                      setPerPage(newPerPage);
                                      setPage(1);
                                    }}
                                    itemsPerPageOptions={[5, 10, 20, 50]}
                                    showItemsPerPage={true}
                                    showTotal={true}
                                  />
                                </div>
                              </td>
                            </tr>
                          </tfoot>
                        </table>
                      </div>
                    </div>
                    
                    {/* Edit user modal */}
                    {editingUser && (
                      <div className="modal-overlay">
                        <div className="modal-content">
                          <h3>Modifier l'utilisateur</h3>
                          <form onSubmit={updateUser}>
                            <div className="form-group">
                              <label htmlFor="edit-username">Nom d'utilisateur</label>
                              <input
                                type="text"
                                id="edit-username"
                                name="username"
                                value={editForm.username}
                                onChange={handleEditUserChange}
                                className="form-control"
                                required
                              />
                            </div>
                            
                            <div className="form-group">
                              <label htmlFor="edit-ville">Ville</label>
                              <input
                                type="text"
                                id="edit-ville"
                                name="ville"
                                value={editForm.ville}
                                onChange={handleEditUserChange}
                                className="form-control"
                              />
                            </div>
                            
                            <div className="form-row">
                              <div className="form-group">
                                <label htmlFor="edit-password">Nouveau mot de passe (laisser vide pour ne pas changer)</label>
                                <input
                                  type={showEditUserPassword ? 'text' : 'password'}
                                  id="edit-password"
                                  name="password"
                                  value={editForm.password}
                                  onChange={handleEditUserChange}
                                  className="form-control"
                                  minLength="8"
                                />
                                <button 
                                  type="button" 
                                  className="toggle-password"
                                  onClick={() => setShowEditUserPassword(!showEditUserPassword)}
                                  title={showEditUserPassword ? 'Masquer le mot de passe' : 'Afficher le mot de passe'}
                                >
                                  {showEditUserPassword ? '👁️' : '👁️‍🗨️'}
                                </button>
                              </div>
                              
                              <div className="form-group checkbox-group">
                                <label className="checkbox-label">
                                  <input
                                    type="checkbox"
                                    id="edit-is_ad_user"
                                    name="is_ad_user"
                                    checked={editForm.is_ad_user}
                                    onChange={(e) => setEditForm({...editForm, is_ad_user: e.target.checked})}
                                    className="checkbox-input"
                                  />
                                  <span className="checkbox-text">Utilisateur Active Directory</span>
                                </label>
                              </div>
                            </div>
                            
                            <div className="form-row">
                              <div className="form-group">
                                <label htmlFor="edit-role">Rôle</label>
                                <select
                                  id="edit-role"
                                  name="role"
                                  value={editForm.role}
                                  onChange={handleEditUserChange}
                                  className="form-control"
                                >
                                  {roles.map(role => (
                                    <option 
                                      key={role.name} 
                                      value={role.name}
                                      disabled={role.name === 'super_admin' && users.some(u => u.role === 'super_admin' && u.id !== editingUser.id)}
                                    >
                                      {role.description}
                                    </option>
                                  ))}
                                </select>
                              </div>
                            </div>
                            
                            <div className="modal-actions">
                              <button 
                                type="button" 
                                className="cancel-button"
                                onClick={() => setEditingUser(null)}
                              >
                                Annuler
                              </button>
                              <button 
                                type="submit" 
                                className="submit-button"
                                disabled={loading}
                              >
                                {loading ? 'Mise à jour...' : 'Mettre à jour'}
                              </button>
                              <Can permission="manage_users">
                                <button 
                                  type="button" 
                                  className="delete-button"
                                  onClick={() => {
                                    if (window.confirm('Êtes-vous sûr de vouloir supprimer cet utilisateur ?')) {
                                      deleteUser(editingUser.id);
                                      setEditingUser(null);
                                    }
                                  }}
                                  disabled={editingUser.role === 'super_admin'}
                                >
                                  Supprimer
                                </button>
                              </Can>
                            </div>
                          </form>
                        </div>
                      </div>
                    )}
                  </div>
                )}
                
                {activeTab === 'user-permissions' && hasPermission('manage_users') && permissionsTabUser && (
                  <div className="user-permissions">
                    <h2>Permissions pour {permissionsTabUser.username}</h2>
                    <div className="permissions-section">
                      <div className="permissions-grid">
                        {Object.keys(permissionGroups).map(groupName => (
                          <div key={groupName} className="permission-group">
                            <h3>{groupName}</h3>
                            {permissionGroups[groupName].map(permission => (
                              <div key={`${groupName}-${permission.name}`} className="permission-toggle">
                                <label className="toggle yellow-toggle">
                                  <input
                                    type="checkbox"
                                    checked={userPermissions[permission.name] || false}
                                    onChange={() => handlePermissionToggle(permission.name)}
                                  />
                                  <span className="slider"></span>
                                </label>
                                <span className="permission-label">
                                  {permission.description || permission.name}
                                </span>
                              </div>
                            ))}
                          </div>
                        ))}
                      </div>
                      
                      <div className="modal-actions" style={{ marginTop: '30px' }}>
                        <button 
                          type="button" 
                          className="cancel-button"
                          onClick={() => {
                            setActiveTab('users');
                            setPermissionsTabUser(null);
                          }}
                        >
                          Annuler
                        </button>
                        <button 
                          type="button" 
                          className="submit-button"
                          onClick={() => updateUserPermissions(permissionsTabUser.id)}
                          disabled={loading}
                        >
                          {loading ? 'Mise à jour...' : 'Mettre à jour les permissions'}
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SettingsPage;