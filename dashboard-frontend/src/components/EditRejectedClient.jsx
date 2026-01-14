import React, { useState, useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../hooks/useAuth";

const CATEGORIES = [
  "Sté Privées Hors Grp",
  "Société Groupe",
  "Individuel",
  "Personnel Groupe",
  "Administration",
  "Collectivité locale",
  "Entreprise Publique",
  "Société de financement",
];

const TYPE_TIERS = ["Client", "Fournisseur","Salariés"];

const EditRejectedClient = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { user } = useAuth();
  const baseUrl = process.env.REACT_APP_API_URL || 'http://127.0.0.1:8000';
  
  // Extract ID from URL parameters
  const urlParams = new URLSearchParams(location.search);
  const id = urlParams.get('id') || urlParams.get('clientId') || urlParams.get('client_id');
  
  const [clientData, setClientData] = useState({
    nom_raison_sociale: "",
    numero_compte: "",
    bp: "",
    ville: "",
    pays: "",
    adresse_geo_1: "",
    adresse_geo_2: "",
    telephone: "",
    email: "",
    categorie: CATEGORIES[0],
    n_contribuable: "",
    type_tiers: TYPE_TIERS[0],
    date_creation: "",
    montant_facture: "",
    montant_paye: "",
    credit: "",
    motif: "",
    etablissement: "",
    service: "",
    nom_signataire: ""
  });
  
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [canSubmit, setCanSubmit] = useState(false);
  const [clientExists, setClientExists] = useState(true);

  const authHeaders = () => {
    const token = localStorage.getItem('token');
    const headers = { 
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    return headers;
  };

  // Charger les données du client
  useEffect(() => {
    const fetchClientData = async () => {
      console.log('EditRejectedClient - Fetching client data for ID:', id);
      
      if (!id) {
        setError("ID du client non spécifié.");
        setClientExists(false);
        return;
      }
      
      setLoading(true);
      setError("");
      try {
        const res = await fetch(`${baseUrl}/api/pending-clients/${id}`, {
          headers: authHeaders()
        });
        
        console.log('EditRejectedClient - API response status:', res.status);
        
        if (res.status === 404) {
          const data = await res.json().catch(() => ({}));
          if (data.status === 'approved') {
            // Client déjà approuvé, afficher un message approprié
            setError(`Client avec ID ${id} a déjà été approuvé.`);
            setClientExists(false);
          } else {
            setError(`Client avec ID ${id} non trouvé. Il a peut-être déjà été approuvé ou supprimé.`);
            setClientExists(false);
          }
          setLoading(false);
          return;
        }
        
        if (!res.ok) {
          throw new Error(`Erreur ${res.status}: Impossible de charger les données du client`);
        }
        
        const data = await res.json();
        console.log('EditRejectedClient - Received client data:', data);
        
        // Vérifier si le client est déjà approuvé
        if (data.status === 'approved') {
          setError(`Client avec ID ${id} a déjà été approuvé.`);
          setClientExists(false);
          setLoading(false);
          return;
        }
        
        setClientData({
          nom_raison_sociale: data.nom_raison_sociale || "",
          numero_compte: data.numero_compte || "",
          bp: data.bp || "",
          ville: data.ville || "",
          pays: data.pays || "",
          adresse_geo_1: data.adresse_geo_1 || "",
          adresse_geo_2: data.adresse_geo_2 || "",
          telephone: data.telephone || "",
          email: data.email || "",
          categorie: data.categorie || CATEGORIES[0],
          n_contribuable: data.n_contribuable || "",
          type_tiers: data.type_tiers || TYPE_TIERS[0],
          date_creation: data.date_creation || "",
          montant_facture: data.montant_facture || "",
          montant_paye: data.montant_paye || "",
          credit: data.credit || "",
          motif: data.motif || "",
          etablissement: data.etablissement || "",
          service: data.service || "",
          nom_signataire: data.nom_signataire || ""
        });
        setClientExists(true);
      } catch (e) {
        console.error('EditRejectedClient - Error fetching client data:', e);
        setError(e.message || "Erreur lors du chargement des données du client");
      } finally {
        setLoading(false);
      }
    };

    if (id) {
      fetchClientData();
    }
  }, [id]);

  // Sauvegarder les modifications
  const handleSave = async () => {
    if (!clientExists || !id) return;
    
    // Validation: Check if all required fields are filled
    const requiredFields = [
      { name: 'nom_raison_sociale', value: clientData.nom_raison_sociale },
      { name: 'bp', value: clientData.bp },
      { name: 'ville', value: clientData.ville },
      { name: 'pays', value: clientData.pays },
      { name: 'adresse_geo_1', value: clientData.adresse_geo_1 },
      { name: 'adresse_geo_2', value: clientData.adresse_geo_2 },
      { name: 'telephone', value: clientData.telephone },
      { name: 'email', value: clientData.email },
      { name: 'categorie', value: clientData.categorie },
      { name: 'n_contribuable', value: clientData.n_contribuable },
      { name: 'date_creation', value: clientData.date_creation },
      { name: 'montant_facture', value: clientData.montant_facture },
      { name: 'montant_paye', value: clientData.montant_paye },
      { name: 'credit', value: clientData.credit },
      { name: 'motif', value: clientData.motif },
      { name: 'etablissement', value: clientData.etablissement },
      { name: 'service', value: clientData.service },
      { name: 'nom_signataire', value: clientData.nom_signataire }
    ];
    
    const emptyFields = requiredFields.filter(field => {
      const value = field.value;
      // Check if value is null/undefined or if it's a string that is empty or only whitespace
      if (value == null) return true;
      if (typeof value === 'string') return value.trim() === '';
      // For non-string values, convert to string and check
      return String(value).trim() === '';
    });
    
    if (emptyFields.length > 0) {
      setError(`Veuillez remplir tous les champs obligatoires. Champs manquants: ${emptyFields.map(field => field.name).join(', ')}`);
      return;
    }
    
    setSaving(true);
    setError("");
    setSuccess("");
    try {
      const res = await fetch(`${baseUrl}/api/pending-clients/${id}`, {
        method: 'PUT',
        headers: authHeaders(),
        body: JSON.stringify(clientData)
      });
      
      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(`Erreur ${res.status}: ${errorData.message || 'Impossible de sauvegarder les modifications'}`);
      }
      
      const updatedData = await res.json();
      setSuccess("Modifications enregistrées avec succès");
      setCanSubmit(true);
    } catch (e) {
      setError(e.message || "Erreur lors de l'enregistrement");
    } finally {
      setSaving(false);
    }
  };

  // Soumettre pour approbation
  const handleSubmit = async () => {
    if (!clientExists || !id) return;
    
    setSubmitting(true);
    setError("");
    setSuccess("");
    try {
      const res = await fetch(`${baseUrl}/api/pending-clients/${id}/submit`, {
        method: 'POST',
        headers: authHeaders()
      });
      
      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        // Vérifier si le client a déjà été approuvé
        if (errorData.message && errorData.message.includes('not found')) {
          throw new Error(`Client avec ID ${id} non trouvé. Il a peut-être déjà été approuvé ou supprimé.`);
        }
        throw new Error(`Erreur ${res.status}: ${errorData.message || 'Impossible de soumettre pour approbation'}`);
      }
      
      setSuccess("Demande soumise pour approbation avec succès");
      // Rediriger vers l'historique après soumission
      setTimeout(() => {
        navigate('/dashboard?tab=credit&view=ClientApprovalHistory');
      }, 2000);
    } catch (e) {
      setError(e.message || "Erreur lors de la soumission");
    } finally {
      setSubmitting(false);
    }
  };

  // Function to format number as currency without decimals
  const formatCurrency = (value) => {
    if (!value) return '';
    const num = parseFloat(value.toString().replace(/\s+/g, '').replace(',', '.'));
    if (isNaN(num)) return '';
    return new Intl.NumberFormat('fr-FR', {
      minimumFractionDigits: 0,
      maximumFractionDigits: 0
    }).format(Math.floor(num));
  };

  // Function to parse formatted currency back to number
  const parseCurrency = (formattedValue) => {
    if (!formattedValue) return '';
    return formattedValue.toString().replace(/\s/g, '').replace(/,/g, '.');
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    
    // Handle currency fields specially
    if (['montant_facture', 'montant_paye', 'credit'].includes(name)) {
      setClientData(prev => ({
        ...prev,
        [name]: parseCurrency(value)
      }));
    } else if (name === 'telephone') {
      // Only allow digits for telephone field
      const phoneValue = value.replace(/[^0-9]/g, '');
      setClientData(prev => ({
        ...prev,
        [name]: phoneValue
      }));
    } else {
      setClientData(prev => ({
        ...prev,
        [name]: value
      }));
    }
  };

  const handleCancel = () => {
    navigate('/dashboard?tab=credit&view=ClientApprovalHistory');
  };

  if (loading) {
    return (
      <div style={{ padding: '24px', textAlign: 'center' }}>
        Chargement des données du client...
      </div>
    );
  }

  return (
    <div style={{ padding: '24px', backgroundColor: '#f9fafb', minHeight: '100vh' }}>
      <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
        <h1 style={{ fontSize: '24px', fontWeight: '600', color: '#1f2937', marginBottom: '24px' }}>
          Modifier la Demande Rejetée
        </h1>
        
        {error && (
          <div style={{ 
            backgroundColor: '#FEF2F2', 
            padding: '12px', 
            borderRadius: '6px', 
            border: '1px solid #FEE2E2', 
            color: '#DC2626', 
            marginBottom: '16px' 
          }}>
            {error}
          </div>
        )}
        
        {success && (
          <div style={{ 
            backgroundColor: '#ECFDF5', 
            padding: '12px', 
            borderRadius: '6px', 
            border: '1px solid #D1FAE5', 
            color: '#047857', 
            marginBottom: '16px' 
          }}>
            {success}
          </div>
        )}
        
        {!clientExists ? (
          <div style={{ 
            backgroundColor: '#FEF2F2', 
            padding: '24px', 
            borderRadius: '8px', 
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
            textAlign: 'center'
          }}>
            <h2 style={{ color: '#DC2626', marginBottom: '16px' }}>Client non trouvé</h2>
            <p>{error || "Le client que vous tentez de modifier n'existe plus. Il a peut-être déjà été approuvé ou supprimé."}</p>
            <button
              onClick={handleCancel}
              style={{
                marginTop: '16px',
                padding: '10px 20px',
                backgroundColor: '#3b82f6',
                color: 'white',
                border: 'none',
                borderRadius: '6px',
                cursor: 'pointer',
                fontWeight: '500'
              }}
            >
              Retour à l'historique
            </button>
          </div>
        ) : (
          <div style={{ 
            backgroundColor: 'white', 
            padding: '24px', 
            borderRadius: '8px', 
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
            marginBottom: '24px'
          }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '16px' }}>
              <div>
                <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500', color: '#374151' }}>
                  Nom/Raison Sociale *
                </label>
                <input
                  type="text"
                  name="nom_raison_sociale"
                  value={clientData.nom_raison_sociale}
                  onChange={handleChange}
                  style={{
                    width: '100%',
                    padding: '10px',
                    border: '1px solid #d1d5db',
                    borderRadius: '6px',
                    fontSize: '16px'
                  }}
                  required
                />
              </div>
              
              <div>
                <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500', color: '#374151' }}>
                  Numéro de Compte
                </label>
                <input
                  type="text"
                  name="numero_compte"
                  value={clientData.numero_compte}
                  onChange={handleChange}
                  style={{
                    width: '100%',
                    padding: '10px',
                    border: '1px solid #d1d5db',
                    borderRadius: '6px',
                    fontSize: '16px'
                  }}
                  readOnly
                />
              </div>
              
              <div>
                <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500', color: '#374151' }}>
                  BP *
                </label>
                <input
                  type="text"
                  name="bp"
                  value={clientData.bp}
                  onChange={handleChange}
                  style={{
                    width: '100%',
                    padding: '10px',
                    border: '1px solid #d1d5db',
                    borderRadius: '6px',
                    fontSize: '16px'
                  }}
                  required
                />
              </div>
              
              <div>
                <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500', color: '#374151' }}>
                  Ville *
                </label>
                <input
                  type="text"
                  name="ville"
                  value={clientData.ville}
                  onChange={handleChange}
                  style={{
                    width: '100%',
                    padding: '10px',
                    border: '1px solid #d1d5db',
                    borderRadius: '6px',
                    fontSize: '16px'
                  }}
                  required
                />
              </div>
              
              <div>
                <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500', color: '#374151' }}>
                  Pays *
                </label>
                <input
                  type="text"
                  name="pays"
                  value={clientData.pays}
                  onChange={handleChange}
                  style={{
                    width: '100%',
                    padding: '10px',
                    border: '1px solid #d1d5db',
                    borderRadius: '6px',
                    fontSize: '16px'
                  }}
                  required
                />
              </div>
              
              <div>
                <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500', color: '#374151' }}>
                  Adresse Géo 1 *
                </label>
                <input
                  type="text"
                  name="adresse_geo_1"
                  value={clientData.adresse_geo_1}
                  onChange={handleChange}
                  style={{
                    width: '100%',
                    padding: '10px',
                    border: '1px solid #d1d5db',
                    borderRadius: '6px',
                    fontSize: '16px'
                  }}
                  required
                />
              </div>
              
              <div>
                <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500', color: '#374151' }}>
                  Adresse Géo 2 *
                </label>
                <input
                  type="text"
                  name="adresse_geo_2"
                  value={clientData.adresse_geo_2}
                  onChange={handleChange}
                  style={{
                    width: '100%',
                    padding: '10px',
                    border: '1px solid #d1d5db',
                    borderRadius: '6px',
                    fontSize: '16px'
                  }}
                  required
                />
              </div>
              
              <div>
                <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500', color: '#374151' }}>
                  Téléphone *
                </label>
                <input
                  type="text"
                  name="telephone"
                  value={clientData.telephone}
                  onChange={handleChange}
                  style={{
                    width: '100%',
                    padding: '10px',
                    border: '1px solid #d1d5db',
                    borderRadius: '6px',
                    fontSize: '16px'
                  }}
                  required
                />
              </div>
              
              <div>
                <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500', color: '#374151' }}>
                  Email *
                </label>
                <input
                  type="email"
                  name="email"
                  value={clientData.email}
                  onChange={handleChange}
                  style={{
                    width: '100%',
                    padding: '10px',
                    border: '1px solid #d1d5db',
                    borderRadius: '6px',
                    fontSize: '16px'
                  }}
                  required
                />
              </div>
              
              <div>
                <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500', color: '#374151' }}>
                  Catégorie *
                </label>
                <select
                  name="categorie"
                  value={clientData.categorie}
                  onChange={handleChange}
                  style={{
                    width: '100%',
                    padding: '10px',
                    border: '1px solid #d1d5db',
                    borderRadius: '6px',
                    fontSize: '16px'
                  }}
                  required
                >
                  <option value="">Sélectionnez une catégorie</option>
                  {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
                </select>
              </div>
              
              <div>
                <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500', color: '#374151' }}>
                  N° Contribuable *
                </label>
                <input
                  type="text"
                  name="n_contribuable"
                  value={clientData.n_contribuable}
                  onChange={handleChange}
                  style={{
                    width: '100%',
                    padding: '10px',
                    border: '1px solid #d1d5db',
                    borderRadius: '6px',
                    fontSize: '16px'
                  }}
                  required
                />
              </div>
              
              <div>
                <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500', color: '#374151' }}>
                  Type de Tiers
                </label>
                <select
                  name="type_tiers"
                  value={clientData.type_tiers}
                  onChange={handleChange}
                  style={{
                    width: '100%',
                    padding: '10px',
                    border: '1px solid #d1d5db',
                    borderRadius: '6px',
                    fontSize: '16px'
                  }}
                >
                  {TYPE_TIERS.map((t) => <option key={t} value={t}>{t}</option>)}
                </select>
              </div>
              
              <div>
                <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500', color: '#374151' }}>
                  Date de Création *
                </label>
                <input
                  type="date"
                  name="date_creation"
                  value={clientData.date_creation}
                  onChange={handleChange}
                  style={{
                    width: '100%',
                    padding: '10px',
                    border: '1px solid #d1d5db',
                    borderRadius: '6px',
                    fontSize: '16px'
                  }}
                  required
                />
              </div>
              
              <div>
                <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500', color: '#374151' }}>
                  Montant Facture *
                </label>
                <input
                  type="text"
                  name="montant_facture"
                  value={formatCurrency(clientData.montant_facture)}
                  onChange={handleChange}
                  style={{
                    width: '100%',
                    padding: '10px',
                    border: '1px solid #d1d5db',
                    borderRadius: '6px',
                    fontSize: '16px'
                  }}
                  required
                />
              </div>
              
              <div>
                <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500', color: '#374151' }}>
                  Montant Payé *
                </label>
                <input
                  type="text"
                  name="montant_paye"
                  value={formatCurrency(clientData.montant_paye)}
                  onChange={handleChange}
                  style={{
                    width: '100%',
                    padding: '10px',
                    border: '1px solid #d1d5db',
                    borderRadius: '6px',
                    fontSize: '16px'
                  }}
                  required
                />
              </div>
              
              <div>
                <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500', color: '#374151' }}>
                  Crédit *
                </label>
                <input
                  type="text"
                  name="credit"
                  value={formatCurrency(clientData.credit)}
                  onChange={handleChange}
                  style={{
                    width: '100%',
                    padding: '10px',
                    border: '1px solid #d1d5db',
                    borderRadius: '6px',
                    fontSize: '16px'
                  }}
                  required
                />

              </div>
              
              <div>
                <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500', color: '#374151' }}>
                  Motif *
                </label>
                <textarea
                  name="motif"
                  value={clientData.motif}
                  onChange={handleChange}
                  style={{
                    width: '100%',
                    padding: '10px',
                    border: '1px solid #d1d5db',
                    borderRadius: '6px',
                    fontSize: '16px',
                    minHeight: '80px'
                  }}
                  required
                />
              </div>
              
              <div>
                <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500', color: '#374151' }}>
                  Établissement *
                </label>
                <input
                  type="text"
                  name="etablissement"
                  value={clientData.etablissement}
                  onChange={handleChange}
                  style={{
                    width: '100%',
                    padding: '10px',
                    border: '1px solid #d1d5db',
                    borderRadius: '6px',
                    fontSize: '16px'
                  }}
                  required
                />
              </div>
              
              <div>
                <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500', color: '#374151' }}>
                  Service *
                </label>
                <input
                  type="text"
                  name="service"
                  value={clientData.service}
                  onChange={handleChange}
                  style={{
                    width: '100%',
                    padding: '10px',
                    border: '1px solid #d1d5db',
                    borderRadius: '6px',
                    fontSize: '16px'
                  }}
                  required
                />
              </div>
              
              <div>
                <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500', color: '#374151' }}>
                  Nom du Signataire *
                </label>
                <input
                  type="text"
                  name="nom_signataire"
                  value={clientData.nom_signataire}
                  onChange={handleChange}
                  style={{
                    width: '100%',
                    padding: '10px',
                    border: '1px solid #d1d5db',
                    borderRadius: '6px',
                    fontSize: '16px'
                  }}
                  required
                />
              </div>
            </div>
          </div>
        )}
        
        {clientExists && (
          <div style={{ display: 'flex', gap: '12px' }}>
            <button
              onClick={handleSave}
              disabled={saving}
              style={{
                padding: '10px 20px',
                backgroundColor: '#111827',
                color: 'white',
                border: 'none',
                borderRadius: '6px',
                cursor: saving ? 'not-allowed' : 'pointer',
                fontWeight: '500',
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}
            >
              {saving ? "Enregistrement..." : "Enregistrer"}
            </button>
            
            {canSubmit && (
              <button
                onClick={handleSubmit}
                disabled={submitting}
                style={{
                  padding: '10px 20px',
                  backgroundColor: '#10B981',
                  color: 'white',
                  border: 'none',
                  borderRadius: '6px',
                  cursor: submitting ? 'not-allowed' : 'pointer',
                  fontWeight: '500',
                  display: 'flex',
                }}
              >
                {submitting ? "Soumission..." : "Soumettre pour Approbation"}
              </button>
            )}
            
            <button
              onClick={handleCancel}
              style={{
                padding: '10px 20px',
                backgroundColor: '#9CA3AF',
                color: 'white',
                border: 'none',
                borderRadius: '6px',
                cursor: 'pointer',
                fontWeight: '500'
              }}
            >
              Annuler
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default EditRejectedClient;