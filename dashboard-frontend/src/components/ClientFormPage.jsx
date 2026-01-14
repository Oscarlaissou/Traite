import React, { useEffect, useMemo, useState } from "react"
import { useNavigate, useParams } from "react-router-dom"
import { useAuth } from "../hooks/useAuth" // Importer le hook d'authentification

const CATEGORIES = [
  "Sté Privées Hors Grp",
  "Société Groupe",
  "Individuel",
  "Personnel Groupe",
  "Administration",
  "Collectivité locale",
  "Entreprise Publique",
  "Société de financement",
]

const TYPE_TIERS = ["Client", "Fournisseur","Salariés"];

const ClientFormPage = () => {
  // Champs Tiers
  const [numero_compte, setNumeroCompte] = useState("")
  const [nom_raison_sociale, setNomRaisonSociale] = useState("")
  const [bp, setBp] = useState("")
  const [ville, setVille] = useState("")
  const [pays, setPays] = useState("")
  const [adresse_geo_1, setAdresseGeo1] = useState("")
  const [adresse_geo_2, setAdresseGeo2] = useState("")
  const [telephone, setTelephone] = useState("")
  const [email, setEmail] = useState("")
  const [categorie, setCategorie] = useState(CATEGORIES[0])
  const [n_contribuable, setNContribuable] = useState("")
  const [type_tiers, setTypeTiers] = useState(TYPE_TIERS[0])

  // Champs Demande d'ouverture de compte
  const [date_creation, setDateCreation] = useState("")
  const [montant_facture, setMontantFacture] = useState("")
  const [montant_paye, setMontantPaye] = useState("")
  const [credit, setCredit] = useState("")
  const [motif, setMotif] = useState("")
  const [etablissement, setEtablissement] = useState("")
  const [service, setService] = useState("")
  const [nom_signataire, setNomSignataire] = useState("")
  const [agences, setAgences] = useState([])
  
  const { user, hasPermission } = useAuth() // Utiliser le hook d'authentification pour obtenir les infos utilisateur
  // Vérifier si l'utilisateur est un administrateur en utilisant les permissions
  const isAdmin = hasPermission('manage_pending_clients')
  
  const syncFromSignataire = (value) => {
    if (!value) return
    const match = agences.find((ag) => {
      const sign = (ag?.nom_signataire || "").trim()
      if (!sign) return false
      if (sign !== value) return false
      if (etablissement && (ag?.etablissement || "").trim() !== etablissement) return false
      if (service && (ag?.service || "").trim() !== service) return false
      return true
    })
    if (match) {
      if (match.etablissement) setEtablissement((match.etablissement || "").trim())
      if (match.service) setService((match.service || "").trim())
    }
  }

  const etablissementOptions = useMemo(() => {
    const values = agences.map((a) => (a?.etablissement || "").trim()).filter((v) => v.length)
    return Array.from(new Set(values))
  }, [agences])

  const serviceOptions = useMemo(() => {
    const filtered = agences.filter((a) => {
      if (etablissement) {
        return (a?.etablissement || "").trim() === etablissement
      }
      return true
    })
    const values = filtered.map((a) => (a?.service || "").trim()).filter((v) => v.length)
    return Array.from(new Set(values))
  }, [agences, etablissement])

  const signataireOptions = useMemo(() => {
    const filtered = agences.filter((a) => {
      if (etablissement && (a?.etablissement || "").trim() !== etablissement) return false
      if (service && (a?.service || "").trim() !== service) return false
      return true
    })
    const values = filtered.map((a) => (a?.nom_signataire || "").trim()).filter((v) => v.length)
    return Array.from(new Set(values))
  }, [agences, etablissement, service])

  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)

  const navigate = useNavigate()
  const baseUrl = useMemo(() => process.env.REACT_APP_API_URL || "", [])
  const { id } = useParams()

  const authHeaders = () => {
    const token = localStorage.getItem("token")
    const headers = { "Accept": "application/json", "Content-Type": "application/json" }
    if (token) headers["Authorization"] = `Bearer ${token}`
    return headers
  }

  useEffect(() => {
    let cancelled = false
    const fetchAgences = async () => {
      try {
        const token = localStorage.getItem("token")
        const headers = { Accept: "application/json" }
        if (token) headers["Authorization"] = `Bearer ${token}`
        const res = await fetch(`${baseUrl}/api/agences`, { headers })
        if (!res.ok) throw new Error("Échec du chargement des agences")
        const data = await res.json()
        if (!cancelled) {
          setAgences(Array.isArray(data) ? data : [])
        }
      } catch (err) {
        console.warn("Chargement des agences impossible:", err)
      }
    }
    fetchAgences()
    return () => {
      cancelled = true
    }
  }, [baseUrl])

  // Chargement initial en mode édition
  useEffect(() => {
    const load = async () => {
      if (!id) return
      setLoading(true)
      setError("")
      try {
        const res = await fetch(`${baseUrl}/api/tiers/${id}`, { headers: { Accept: "application/json", Authorization: `Bearer ${localStorage.getItem("token") || ""}` } })
        if (!res.ok) throw new Error("Échec du chargement du client")
        const data = await res.json()
        setNumeroCompte(data.numero_compte || "")
        setNomRaisonSociale(data.nom_raison_sociale || "")
        setBp(data.bp || "")
        setVille(data.ville || "")
        setPays(data.pays || "")
        setAdresseGeo1(data.adresse_geo_1 || "")
        setAdresseGeo2(data.adresse_geo_2 || "")
        setTelephone(data.telephone || "")
        setEmail(data.email || "")
        setCategorie(data.categorie || CATEGORIES[0])
        setNContribuable(data.n_contribuable || "")
        setTypeTiers(data.type_tiers || TYPE_TIERS[0])
        setDateCreation(data.date_creation ? String(data.date_creation).slice(0, 10) : "")
        setMontantFacture(data.montant_facture != null ? String(data.montant_facture) : "")
        setMontantPaye(data.montant_paye != null ? String(data.montant_paye) : "")
        setCredit(data.credit != null ? String(data.credit) : "")
        setMotif(data.motif || "")
        setEtablissement(data.etablissement || "")
        setService(data.service || "")
        setNomSignataire(data.nom_signataire || "")
      } catch (e) {
        setError(e.message || "Erreur inconnue")
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [id, baseUrl])

  // Réinitialiser le formulaire quand on est en mode "nouveau"
  useEffect(() => {
    if (!id) {
      setNumeroCompte("")
      setNomRaisonSociale("")
      setBp("")
      setVille("")
      setPays("")
      setAdresseGeo1("")
      setAdresseGeo2("")
      setTelephone("")
      setEmail("")
      setCategorie(CATEGORIES[0])
      setNContribuable("")
      setTypeTiers(TYPE_TIERS[0])
      setDateCreation("")
      setMontantFacture("")
      setMontantPaye("")
      setCredit("")
      setMotif("")
      setEtablissement("")
      setService("")
      setNomSignataire("")
    }
  }, [id])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError("")
    setSubmitting(true)
    
    // Validation: Check if all required fields are filled
    const requiredFields = [
      { name: 'nom_raison_sociale', value: nom_raison_sociale },
      { name: 'categorie', value: categorie },
      { name: 'type_tiers', value: type_tiers },
      { name: 'date_creation', value: date_creation },
      { name: 'montant_facture', value: montant_facture },
      { name: 'montant_paye', value: montant_paye },
      { name: 'credit', value: credit },
      { name: 'motif', value: motif },
      { name: 'etablissement', value: etablissement },
      { name: 'service', value: service },
      { name: 'nom_signataire', value: nom_signataire }
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
      setSubmitting(false);
      return;
    }
    
    try {
      // For new clients, we don't send the numero_compte as it should be generated automatically
      const payload = id ? {
        numero_compte,
        nom_raison_sociale,
        bp,
        ville,
        pays,
        adresse_geo_1,
        adresse_geo_2,
        telephone,
        email,
        categorie,
        n_contribuable,
        type_tiers,
        date_creation: date_creation || null,
        montant_facture: montant_facture ? Number(montant_facture) : null,
        montant_paye: montant_paye ? Number(montant_paye) : null,
        credit: credit ? Number(credit) : null,
        motif,
        etablissement,
        service,
        nom_signataire,
      } : {
        // For new clients, exclude numero_compte so it gets generated automatically
        nom_raison_sociale,
        bp,
        ville,
        pays,
        adresse_geo_1,
        adresse_geo_2,
        telephone,
        email,
        categorie,
        n_contribuable,
        type_tiers,
        date_creation: date_creation || null,
        montant_facture: montant_facture ? Number(montant_facture) : null,
        montant_paye: montant_paye ? Number(montant_paye) : null,
        credit: credit ? Number(credit) : null,
        motif,
        etablissement,
        service,
        nom_signataire,
      }

      // For new clients, save to pending clients table
      // For existing clients (with id), update directly in tiers table
      // For admins, create directly in tiers table bypassing pending approval
      if (id) {
        // Update existing client directly
        const url = `${baseUrl}/api/tiers/${id}`
        const method = "PUT"
        const res = await fetch(url, {
          method,
          headers: authHeaders(),
          body: JSON.stringify(payload),
        })
        if (!res.ok) {
          const msg = await res.text()
          throw new Error(msg || "Échec de la mise à jour du client")
        }
        // Redirection: en édition -> détail
        navigate(`/clients/${id}`)
      } else {
        // Save new client - admins go directly to tiers table, others to pending clients
        if (isAdmin) {
          // Admins create directly in tiers table
          const url = `${baseUrl}/api/tiers`
          const method = "POST"
          const res = await fetch(url, {
            method,
            headers: authHeaders(),
            body: JSON.stringify(payload),
          })
          if (!res.ok) {
            const errorData = await res.json()
            // Check if it's a duplicate account number error
            if (errorData.message && errorData.message.includes('numero_compte')) {
              throw new Error("Un client avec ce numéro de compte existe déjà.")
            } else {
              const msg = errorData.message || "Échec de la création du client"
              throw new Error(msg)
            }
          }
          // Redirection: en création -> grille clients
          navigate("/dashboard?tab=credit&view=GestionClients")
        } else {
          // Non-admins save to pending clients table
          const url = `${baseUrl}/api/pending-clients`
          const method = "POST"
          const res = await fetch(url, {
            method,
            headers: authHeaders(),
            body: JSON.stringify(payload),
          })
          if (!res.ok) {
            const errorData = await res.json()
            // Check if it's a duplicate account number error
            if (errorData.message && errorData.message.includes('numero_compte')) {
              throw new Error("Un client avec ce numéro de compte existe déjà.")
            } else {
              const msg = errorData.message || "Échec de la création du client en attente"
              throw new Error(msg)
            }
          }
          // Redirection: en création -> grille clients
          navigate("/dashboard?tab=credit&view=GestionClients")
        }
      }
    } catch (err) {
      setError(err.message || "Erreur inconnue")
    } finally {
      setSubmitting(false)
    }
  }

  const formatNumber = (value) => {
    if (!value) return ""
    const stringValue = String(value).replace(/\s/g, "")
    return new Intl.NumberFormat("fr-FR").format(Number(stringValue))
  }

  const handleChange = (setter) => (e) => {
    const value = e.target.value.replace(/\s/g, "")
    if (!isNaN(value)) {
      setter(value)
    }
  }

  return (
    <div className="dashboard-stats">
      <h2 className="stats-title">{id ? "Modifier le client" : "Nouveau compte client"}</h2>
      {error && <div className="error-message" style={{ marginBottom: 12 }}>{error}</div>}
      {loading ? (
        <div>Chargement...</div>
      ) : (
      <form onSubmit={handleSubmit} style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        {/* Champs Tiers */}
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <label>Numéro de compte {!id && "(généré automatiquement)"}</label>
          {id ? (
            <input value={numero_compte} onChange={(e) => setNumeroCompte(e.target.value)} className="search-input" />
          ) : (
            <input value="" placeholder="Sera généré automatiquement" className="search-input" readOnly disabled />
          )}
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <label>Nom / Raison sociale *</label>
          <input value={nom_raison_sociale} onChange={(e) => setNomRaisonSociale(e.target.value)} className="search-input" required />
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <label>BP *</label>
          <input value={bp} onChange={(e) => setBp(e.target.value)} className="search-input" required />
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <label>Ville *</label>
          <input value={ville} onChange={(e) => setVille(e.target.value)} className="search-input" required />
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <label>Pays *</label>
          <input value={pays} onChange={(e) => setPays(e.target.value)} className="search-input" required />
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <label>Adresse géo 1 *</label>
          <input value={adresse_geo_1} onChange={(e) => setAdresseGeo1(e.target.value)} className="search-input" required />
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <label>Adresse géo 2 *</label>
          <input value={adresse_geo_2} onChange={(e) => setAdresseGeo2(e.target.value)} className="search-input" required />
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <label>Téléphone *</label>
          <input 
            value={telephone} 
            onChange={(e) => {
              // Only allow digits
              const value = e.target.value.replace(/[^0-9]/g, '');
              setTelephone(value);
            }} 
            className="search-input" 
            required 
          />
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <label>Email *</label>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} className="search-input" required />
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <label>Type d'entreprises *</label>
          <select value={categorie} onChange={(e) => setCategorie(e.target.value)} className="search-input" required>
            {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <label>N° contribuable *</label>
          <input value={n_contribuable} onChange={(e) => setNContribuable(e.target.value)} className="search-input" required />
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <label>Type de tiers *</label>
          <select value={type_tiers} onChange={(e) => setTypeTiers(e.target.value)} className="search-input" required>
            {TYPE_TIERS.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <label>Date de création *</label>
          <input type="date" value={date_creation} onChange={(e) => setDateCreation(e.target.value)} className="search-input" required />
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        <label>Montant facturé *</label>
        <input
          type="text"
          inputMode="numeric"
          value={formatNumber(montant_facture)}
          onChange={handleChange(setMontantFacture)}
          className="search-input"
          placeholder="Ex: 100 000"
          required
        />
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        <label>Montant payé *</label>
        <input
          type="text"
          inputMode="numeric"
          value={formatNumber(montant_paye)}
          onChange={handleChange(setMontantPaye)}
          className="search-input"
          placeholder="Ex: 100 000"
          required
        />
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        <label>Crédit *</label>
        <input
          type="text"
          inputMode="numeric"
          value={formatNumber(credit)}
          onChange={handleChange(setCredit)}
          className="search-input"
          placeholder="Ex: 100 000"
          required
        />
      </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <label>Établissement *</label>
          <input value={etablissement} onChange={(e) => setEtablissement(e.target.value)} className="search-input" required />
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <label>Service *</label>
          <input value={service} onChange={(e) => setService(e.target.value)} className="search-input" required />
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <label>Nom du signataire *</label>
          <input value={nom_signataire} onChange={(e) => setNomSignataire(e.target.value)} className="search-input" required />
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <label>Motif *</label>
          <textarea value={motif} onChange={(e) => setMotif(e.target.value)} className="search-input" rows={3} required />
        </div>

        <div style={{ gridColumn: "1 / -1", display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 12 }}>
          <button type="button" className="submit-button" style={{ backgroundColor: "#9ca3af" }} onClick={() => navigate(-1)}>
            Annuler
          </button>
          <button type="submit" className="submit-button" disabled={submitting}>
            {submitting ? "Enregistrement..." : (id ? "Mettre à jour" : "Enregistrer")}
          </button>
        </div>
      </form>
      )}
    </div>
  )
}

export default ClientFormPage

// Add responsive styles for the client form page
const style = document.createElement('style')
style.textContent = `
  @media (max-width: 768px) {
    .dashboard-stats form {
      grid-template-columns: 1fr;
      gap: 16px;
    }
    
    .dashboard-stats form > div {
      width: 100%;
    }
    
    .search-input {
      font-size: 16px; /* Prevent zoom on iOS */
      padding: 10px;
    }
    
    .dashboard-stats form > div:last-child {
      flex-direction: column;
    }
    
    .dashboard-stats form > div:last-child > button {
      width: 100%;
      margin-bottom: 0.5rem;
    }
  }
  
  @media (max-width: 480px) {
    .dashboard-stats form {
      gap: 12px;
    }
    
    .search-input {
      padding: 8px;
      font-size: 14px;
    }
    
    .dashboard-stats h2.stats-title {
      font-size: 18px;
    }
  }
`
document.head.appendChild(style)