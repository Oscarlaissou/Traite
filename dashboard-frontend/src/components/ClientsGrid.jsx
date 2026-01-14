import React, { useEffect, useMemo, useRef, useState } from "react"
import { ArrowLeft, Plus, Upload, Download, X, Search, Printer } from "lucide-react"
import { useNavigate, useLocation } from "react-router-dom"
import { useAuth } from "../hooks/useAuth"
import Pagination from "./Pagination"
import Can from "./Can"
import "./Traites.css"

// Ajout de la bibliothèque XLSX pour l'export Excel
import * as XLSX from 'xlsx'

// Helper function to format dates
const formatDateDDMMYYYY = (value) => {
  if (!value) return ''
  const d = new Date(value)
  if (isNaN(d)) return value
  const dd = String(d.getDate()).padStart(2, '0')
  const mm = String(d.getMonth() + 1).padStart(2, '0')
  const yyyy = d.getFullYear()
  return `${dd}-${mm}-${yyyy}`
}

const Columns = [
  { key: "numero_compte", label: "Numéro de compte" },
  { key: "nom_raison_sociale", label: "Nom / Raison sociale" },
  { key: "bp", label: "BP" },
  { key: "ville", label: "Ville" },
  { key: "pays", label: "Pays" },
  { key: "type_tiers", label: "Type" }
]

const DEFAULT_CATEGORIES = [
  "Client",
  "Fournisseur"
]

const ClientsGrid = () => {
  const { user, authHeaders: authHeadersHook, baseUrl: baseUrlHook } = useAuth();
  const [items, setItems] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const [search, setSearch] = useState("")
  const [appliedSearch, setAppliedSearch] = useState("")
  const [page, setPage] = useState(1)
  const [perPage, setPerPage] = useState(10)
  const [printPerPage] = useState(53) // Nombre d'éléments par page pour l'impression
  const [pagination, setPagination] = useState({ current_page: 1, last_page: 1, total: 0 })
  const [sort, setSort] = useState({ key: "numero_compte", dir: "desc" }) 
  const [availableCategories, setAvailableCategories] = useState(DEFAULT_CATEGORIES)
  
  // State pour le filtre de type (Client/Fournisseur)
  const [selectedTypeTiers, setSelectedTypeTiers] = useState("")
  
  const [selectedPrintRange, setSelectedPrintRange] = useState({ start: 1, end: 1 }) 
  const [showPrintModal, setShowPrintModal] = useState(false) 
  
  // States for CSV import functionality
  const [importModalOpen, setImportModalOpen] = useState(false)
  const [csvHeaders, setCsvHeaders] = useState([])
  const [csvRecords, setCsvRecords] = useState([])
  const [columnMapping, setColumnMapping] = useState({})
  const [importProgress, setImportProgress] = useState({ current: 0, total: 0, status: '' })
  const [importResult, setImportResult] = useState(null)
  const [isImporting, setIsImporting] = useState(false)
  const [importController, setImportController] = useState(null)
  
  const importInputRef = useRef(null)
  const navigate = useNavigate()
  const location = useLocation()

  const apiBaseUrl = useMemo(() => {
    return baseUrlHook || process.env.REACT_APP_API_URL || ""
  }, [baseUrlHook])

  const getApiHeaders = () => {
    return authHeadersHook ? authHeadersHook() : (() => {
      const token = localStorage.getItem("token")
      const headers = { Accept: "application/json" }
      if (token) headers.Authorization = `Bearer ${token}`
      return headers
    })()
  }

  // Gestion des paramètres URL au chargement
  useEffect(() => {
    const params = new URLSearchParams(location.search)
    const searchParam = params.get("search") || ""
    const typeTiersParam = params.get("type_tiers") || ""
    
    setSearch(searchParam)
    setAppliedSearch(searchParam)
    
    // Initialisation du filtre type_tiers depuis l'URL
    if (typeTiersParam) {
      setSelectedTypeTiers(typeTiersParam)
    } else {
      setSelectedTypeTiers("")
    }
    
    setPage(1)
  }, [location.search])

  // --- FONCTION DE CHARGEMENT PRINCIPALE (CORRIGÉ) ---
  const fetchClients = async () => {
    // Ne pas réinitialiser loading à true pour éviter le flickering
    setError("");
    try {
      const params = new URLSearchParams();
      
      // Recherche
      if (appliedSearch.trim()) params.append("search", appliedSearch.trim());
      
      // Tri
      if (sort?.key) params.append("sort", sort.key);
      if (sort?.dir) params.append("dir", sort.dir);
      
      // Pagination
      params.append("page", String(page));
      params.append("per_page", String(perPage));
      
      // Filtrage par type_tiers
      if (selectedTypeTiers) {
        params.append("type_tiers", selectedTypeTiers);
        console.log('Filtre type_tiers appliqué :', selectedTypeTiers);
      } else {
        console.log('Aucun filtre type_tiers appliqué');
      }
      
      console.log('Appel API :', `${apiBaseUrl}/api/tiers?${params.toString()}`);
      
      const response = await fetch(`${apiBaseUrl}/api/tiers?${params.toString()}`, {
        headers: getApiHeaders(),
      });

      if (!response.ok) {
        throw new Error("Échec du chargement des clients");
      }

      const payload = await response.json();
      const data = payload?.data ?? [];

      setItems(Array.isArray(data) ? data : []);
      setPagination({
        current_page: payload?.current_page ?? 1,
        last_page: payload?.last_page ?? 1,
        total: payload?.total ?? data.length,
      });
    } catch (e) {
      setError(e.message || "Erreur inconnue lors du chargement");
      setItems([]); // Vider la liste en cas d'erreur
    } finally {
      setLoading(false);
    }
  }

  // --- EXPORT EXCEL (CORRIGÉ) ---
  const exportExcel = async () => {
    try {
      const params = new URLSearchParams()
      if (appliedSearch.trim()) params.append("search", appliedSearch.trim())
      if (sort?.key) params.append("sort", sort.key)
      if (sort?.dir) params.append("dir", sort.dir)
      params.append("per_page", "1000")
      
      // Correction ici aussi - toujours envoyer le paramètre type_tiers
      if (selectedTypeTiers) {
        params.append("type_tiers", selectedTypeTiers)
      }

      const response = await fetch(`${apiBaseUrl}/api/tiers/export-with-details?${params.toString()}`, {
        headers: getApiHeaders(),
      })

      if (!response.ok) {
        const errorText = await response.text();
        console.error('API Error:', response.status, errorText);
        throw new Error(`Export Excel impossible pour le moment (Status: ${response.status})`)
      }

      const payload = await response.json()
      const data = payload?.data ?? []
      
      // Export all fields from the details, not just grid columns
      const allFieldHeaders = [
        'id', 'numero_compte', 'nom_raison_sociale', 'bp', 'ville', 'pays', 
        'adresse_geo_1', 'adresse_geo_2', 'telephone', 'email', 'categorie', 
        'n_contribuable', 'type_tiers', 'date_creation', 'montant_facture', 
        'montant_paye', 'credit', 'motif', 'etablissement', 'service', 
        'nom_signataire'
      ];
      
      const worksheet = XLSX.utils.json_to_sheet(data.map(row => {
        const formattedRow = {};
        allFieldHeaders.forEach(field => {
          let value = row[field];
          
          if (field === 'date_creation') {
            value = formatDateDDMMYYYY(value);
          } else if (['montant_facture', 'montant_paye', 'credit'].includes(field)) {
            value = Number(value || 0);
          } else {
            value = value ?? '';
          }
          formattedRow[field] = value;
        });
        return formattedRow;
      }));

      const colWidths = allFieldHeaders.map(field => ({
        wch: Math.max(field.length, ...data.map(row => String(row[field] ?? "").length))
      }))
      worksheet['!cols'] = colWidths

      const workbook = XLSX.utils.book_new()
      XLSX.utils.book_append_sheet(workbook, worksheet, "Clients")

      const fileName = `clients_${new Date().toISOString().slice(0, 10)}.xlsx`
      XLSX.writeFile(workbook, fileName)
    } catch (e) {
      alert(e.message || "Erreur inconnue lors de l'export Excel")
    }
  }
  
  const handlePrint = () => {
    const totalPages = Math.ceil(pagination.total / printPerPage)
    setSelectedPrintRange({ start: 1, end: Math.min(5, totalPages) })
    setShowPrintModal(true)
  }
  
  // --- IMPRESSION (CORRIGÉE) ---
  const executePrint = async () => {
    try {
      const params = new URLSearchParams()
      if (appliedSearch.trim()) params.append("search", appliedSearch.trim())
      if (sort?.key) params.append("sort", sort.key)
      if (sort?.dir) params.append("dir", sort.dir)
      
      params.append("per_page", "2500") 

      // Correction ici aussi - toujours envoyer le paramètre type_tiers
      if (selectedTypeTiers) {
        params.append("type_tiers", selectedTypeTiers)
      }

      const response = await fetch(`${apiBaseUrl}/api/tiers?${params.toString()}`, {
        headers: getApiHeaders(),
      })

      if (!response.ok) {
        throw new Error("Erreur lors de la récupération des données pour l'impression")
      }

      const payload = await response.json()
      const allData = payload?.data ?? []

      const startIndex = (selectedPrintRange.start - 1) * printPerPage
      const endIndex = selectedPrintRange.end * printPerPage
      
      const printedItems = allData.slice(startIndex, endIndex)

      if (printedItems.length === 0) {
        alert("Aucune donnée à imprimer dans cette plage.")
        return
      }

      const iframe = document.createElement('iframe');
      
      iframe.style.position = 'fixed';
      iframe.style.right = '0';
      iframe.style.bottom = '0';
      iframe.style.width = '0';
      iframe.style.height = '0';
      iframe.style.border = '0';
      
      document.body.appendChild(iframe);

      const doc = iframe.contentWindow.document;
      doc.write(`
        <html>
          <head>
            <title>Impression des clients</title>
            <style>
              body { font-family: Arial, sans-serif; }
              table { border-collapse: collapse; width: 100%; }
              th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
              th { background-color: #f2f2f2; }
              @media print {
                @page { size: A4; margin: 1cm; }
                body { margin: 1cm; }
              }
            </style>
          </head>
          <body>
            <h2>Liste des clients</h2>
            <p>Imprimé le: ${new Date().toLocaleDateString()}</p>
            <table>
              <thead>
                <tr>
                  ${Columns.map(col => `<th>${col.label}</th>`).join('')}
                </tr>
              </thead>
              <tbody>
                ${printedItems.map(item => `
                  <tr>
                    ${Columns.map(col => `<td>${item[col.key] || ''}</td>`).join('')}
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </body>
        </html>
      `);
      doc.close();

      setTimeout(() => {
        iframe.contentWindow.focus();
        iframe.contentWindow.print();
        
        setTimeout(() => {
          document.body.removeChild(iframe);
          setShowPrintModal(false);
        }, 1000);
      }, 500);

    } catch (e) {
      alert(e.message || "Erreur lors de la préparation de l'impression");
    }
  }
  
  const handleImportClick = () => {
    importInputRef.current?.click()
  }

  const handleCancelImport = () => {
    if (importController) {
      importController.abort()
    }
    setIsImporting(false)
    setImportModalOpen(false)
    setCsvHeaders([])
    setCsvRecords([])
    setColumnMapping({})
    setImportProgress({ current: 0, total: 0, status: '' })
    setImportResult(null)
  }

  // --- LOGIQUE D'IMPORT CSV (INCHANGÉE MAIS NÉCESSAIRE) ---
  const readFileAsTextWithEncoding = (file, encoding) => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.onload = () => {
        let result = reader.result
        if (typeof result === 'string' && result.charCodeAt(0) === 0xFEFF) {
          result = result.slice(1)
        }
        resolve(result)
      }
      reader.onerror = () => reject(reader.error)
      reader.readAsText(file, encoding)
    })
  }

  const parseCSV = async (file) => {
    try {
      let text;
      try {
        text = await readFileAsTextWithEncoding(file, 'utf-8');
      } catch (utf8Error) {
        text = await new Promise((resolve, reject) => {
          const reader = new FileReader();
          reader.onload = () => resolve(reader.result);
          reader.onerror = () => reject(reader.error);
          reader.readAsText(file);
        });
      }
      
      if (text.charCodeAt(0) === 0xFEFF) {
        text = text.slice(1);
      }
      
      const separator = text.includes(';') ? ';' : ',';
      
      const lines = [];
      let currentLine = '';
      let inQuotes = false;
      
      for (let i = 0; i < text.length; i++) {
        const char = text[i];
        const nextChar = text[i + 1] || '';
        
        if (char === '"' && !inQuotes) {
          inQuotes = true;
        } else if (char === '"' && nextChar === '"') {
          currentLine += '"';
          i++; 
        } else if (char === '"' && inQuotes) {
          inQuotes = false;
        } else if ((char === '\n' || (char === '\r' && nextChar === '\n')) && !inQuotes) {
          if (char === '\r') {
            i++; 
          }
          lines.push(currentLine);
          currentLine = '';
        } else {
          currentLine += char;
        }
      }
      
      if (currentLine.trim().length > 0) {
        lines.push(currentLine);
      }
      
      if (lines.length === 0) {
        return { headers: [], records: [] };
      }
      
      const headers = lines[0].split(separator).map(h => {
        let cleaned = h.trim().replace(/^"(.*)"$/, '$1');
        return cleaned;
      });
      
      const records = lines.slice(1).map(line => {
        return line.split(separator).map(field => {
          let cleaned = field.trim().replace(/^"(.*)"$/, '$1');
          return cleaned;
        });
      });
      
      return { headers, records };
    } catch (error) {
      console.error('Error parsing CSV:', error);
      throw new Error('Impossible de lire le fichier CSV.');
    }
  };

  const handleFileChange = async (e) => {
    const file = e.target.files && e.target.files[0]
    if (!file) return
    
    try {
      const { headers, records } = await parseCSV(file)
      if (!headers.length || !records.length) throw new Error('CSV vide ou invalide')

      const autoMapping = {}
      headers.forEach(header => {
        const normalizedHeader = header.toLowerCase().replace(/[^a-z0-9éèêëàáâãäåòóôõöøìíîïùúûüÿñç]/g, '')
        if (normalizedHeader.includes('nom') && normalizedHeader.includes('tiers')) {
          autoMapping['nom_raison_sociale'] = header
        } else if (normalizedHeader.includes('type') && !normalizedHeader.includes('tiers')) {
          autoMapping['categorie'] = header
        } else if (normalizedHeader.includes('adresse') && normalizedHeader.includes('geo')) {
          autoMapping['adresse_geo_1'] = header
        } else if (normalizedHeader.includes('boite') || normalizedHeader.includes('bp')) {
          autoMapping['bp'] = header
        } else if (normalizedHeader.includes('ville')) {
          autoMapping['ville'] = header
        } else if (normalizedHeader.includes('telephone') || normalizedHeader.includes('tel')) {
          autoMapping['telephone'] = header
        } else if (normalizedHeader.includes('date') && normalizedHeader.includes('creation')) {
          autoMapping['date_creation'] = header
        } else if (normalizedHeader.includes('signataire')) {
          autoMapping['nom_signataire'] = header
        } else if ((normalizedHeader.includes('general') && normalizedHeader.includes('n')) || 
                   normalizedHeader.includes('numero') || 
                   normalizedHeader.includes('compte')) {
          autoMapping['numero_compte'] = header
        } else if (normalizedHeader.includes('type') && normalizedHeader.includes('tiers')) {
          autoMapping['type_tiers'] = header
        }
      })

      setCsvHeaders(headers)
      setCsvRecords(records)
      setColumnMapping(autoMapping)
      setImportModalOpen(true)
      
    } catch (err) {
      alert(err.message || 'Erreur lors de la lecture du fichier CSV')
    } finally {
      if (importInputRef.current) importInputRef.current.value = ""
    }
  }

  const handleImportConfirm = async () => {
    try {
      setIsImporting(true)
      
      const controller = new AbortController()
      setImportController(controller)
      
      const mappedData = csvRecords.map((row, index) => {
        const mappedRow = {}
        Object.keys(columnMapping).forEach(field => {
          const csvColumn = columnMapping[field]
          if (csvColumn) {
            const columnIndex = csvHeaders.indexOf(csvColumn)
            if (columnIndex !== -1 && row[columnIndex]) {
              mappedRow[field] = row[columnIndex]
            }
          }
        })
        return mappedRow
      }).filter(row => Object.keys(row).length > 0)
      
      setImportProgress({ 
        current: 0, 
        total: mappedData.length, 
        status: `Préparation de l'importation de ${mappedData.length} enregistrements...` 
      })
      
      const token = localStorage.getItem("token")
      const headers = { 
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      }
      if (token) headers['Authorization'] = `Bearer ${token}`
      
      const batchSize = 50
      let importedCount = 0
      const errors = []
      
      for (let i = 0; i < mappedData.length; i += batchSize) {
        if (controller.signal.aborted) break
        
        const batch = mappedData.slice(i, i + batchSize)
        
        try {
          const response = await fetch(`${apiBaseUrl}/api/tiers/import-csv`, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({ 
              data: batch,
              duplicate_action: 'update'
            }),
            signal: controller.signal
          })
          
          if (controller.signal.aborted) break
          
          if (!response.ok) {
            const errorData = await response.json()
            throw new Error(`Import échoué: ${errorData.message || response.statusText}`)
          }
          
          const result = await response.json()
          importedCount += result.created + result.updated
          
          setImportProgress({ 
            current: Math.min(i + batchSize, mappedData.length), 
            total: mappedData.length, 
            status: `Importation en cours... ${importedCount} enregistrements traités` 
          })
          
          if (result.errors && result.errors.length > 0) {
            errors.push(...result.errors)
          }
        } catch (batchError) {
          if (batchError.name === 'AbortError') break
          console.error('Erreur lors de l\'importation du lot:', batchError)
          errors.push(`Lot ${Math.floor(i/batchSize) + 1}: ${batchError.message}`)
        }
      }
      
      setImportResult({ 
        created: importedCount,
        updated: 0,
        skipped: 0,
        errors: errors
      })
      
      if (!controller.signal.aborted) {
        setImportProgress({ 
          current: mappedData.length, 
          total: mappedData.length, 
          status: `Importation terminée! ${importedCount} enregistrements traités${errors.length > 0 ? `, ${errors.length} erreurs` : ''}` 
        })
      }
      
      if (errors.length === 0 && !controller.signal.aborted) {
        setTimeout(() => {
          setImportModalOpen(false)
          setIsImporting(false)
          setCsvHeaders([])
          setCsvRecords([])
          setColumnMapping({})
          setImportProgress({ current: 0, total: 0, status: '' })
          setImportResult(null)
          fetchClients()
        }, 2000)
      } else if (!controller.signal.aborted) {
        setIsImporting(false)
      }
      
    } catch (err) {
      console.error('Erreur d\'importation:', err)
      setIsImporting(false)
      setImportProgress({ current: 0, total: 0, status: `Erreur: ${err.message}` })
    }
  }

  // --- TRI SIMPLIFIÉ (CORRIGÉ) ---
  const handleHeaderSort = (key) => {
    setPage(1)
    setSort((current) => {
      // Si on reclique sur la même colonne, on inverse l'ordre
      if (current.key === key) {
        return { key, dir: current.dir === "asc" ? "desc" : "asc" }
      }
      // Sinon on trie par cette nouvelle colonne en ascendant
      return { key, dir: "asc" }
    })
  }

  const resetFilters = () => {
    setSearch("")
    setAppliedSearch("")
    setSelectedTypeTiers("")
    setSort({ key: "numero_compte", dir: "desc" })
    setPage(1)
    
    // Mettre à jour l'URL en supprimant les paramètres de filtre
    const params = new URLSearchParams(location.search);
    params.delete("search");
    params.delete("type_tiers");
    navigate(`${location.pathname}?${params.toString()}`, { replace: true });
  }

  // --- DÉCLENCHEMENT DE LA RECHERCHE ---
  // C'est ce useEffect qui relance fetchClients quand selectedTypeTiers change
  useEffect(() => {
    // Ajout d'un délai pour éviter les appels multiples rapides
    const handler = setTimeout(() => {
      fetchClients()
    }, 100)
    
    return () => clearTimeout(handler)
  }, [page, perPage, sort, selectedTypeTiers, appliedSearch])

  return (
    <div className="dashboard-stats">
      <button
        className="icon-button"
        onClick={() => resetFilters()}
        aria-label="Réinitialiser"
        style={{ marginBottom: 8, color: "red" }}
      >
        <ArrowLeft size={18} />
      </button>

      <h2 className="stats-title">Grille des comptes clients</h2>

      <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 12, flexWrap: "wrap" }}>
        <input
          placeholder="Rechercher un client..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              setPage(1)
              setAppliedSearch(e.target.value.trim())
            }
          }}
          className="search-input"
          style={{ maxWidth: 260 }}
        />
        
        {/* --- MENU DÉROULANT (CORRIGÉ) --- */}
        <select
          className="search-input"
          value={selectedTypeTiers}
          onChange={(e) => {
            const newTypeTiers = e.target.value;
            setSelectedTypeTiers(newTypeTiers);
            setPage(1);
            
            // Mettre à jour l'URL avec le nouveau filtre
            const params = new URLSearchParams(location.search);
            if (newTypeTiers) {
              params.set("type_tiers", newTypeTiers);
            } else {
              params.delete("type_tiers");
            }
            navigate(`${location.pathname}?${params.toString()}`, { replace: true });
          }}
          style={{ minWidth: 220 }}
        >
          <option value="">Tous les types</option>
          {DEFAULT_CATEGORIES.map((c) => (
            <option key={c} value={c}>{c}</option>
          ))}
        </select>
        
        <button
          className="submit-button"
          onClick={() => {
            setPage(1)
            setAppliedSearch(search.trim())
            
            // Mettre à jour l'URL avec le terme de recherche
            const params = new URLSearchParams(location.search);
            if (search.trim()) {
              params.set("search", search.trim());
            } else {
              params.delete("search");
            }
            navigate(`${location.pathname}?${params.toString()}`, { replace: true });
          }}
        >
          <Search size={16} style={{ marginRight: 6 }} /> Rechercher
        </button>
        <Can permission="create_clients">
          <button className="submit-button" onClick={() => navigate('/dashboard?tab=credit&view=NewClient')}>
            <Plus size={16} style={{ marginRight: 6 }} /> Nouveau compte client
          </button>
        </Can>
       
        <Can permission="view_clients">
          <button className="submit-button" onClick={exportExcel}>
            <Download size={16} style={{ marginRight: 6 }} /> Exporter Excel
          </button>
        </Can>
        <Can permission="view_clients">
          <button className="submit-button" onClick={handlePrint}>
            <Printer size={16} style={{ marginRight: 6 }} /> Imprimer
          </button>
        </Can>
        <Can permission="create_clients" condition={user && (user.role && (user.role.name === 'admin' || user.role.name === 'super_admin'))}>
          <button className="submit-button" onClick={handleImportClick}>
            <Upload size={16} style={{ marginRight: 6 }} /> Importer CSV
          </button>
        </Can>
        <Can permission="create_clients">
          <input ref={importInputRef} type="file" accept=".csv,text/csv" style={{ display: "none" }} onChange={handleFileChange} />
        </Can>
      </div>

      {error && <div className="error-message">{error}</div>}

      {loading ? (
        <div>Chargement...</div>
      ) : (
        <div className="table-wrap">
          <table className="table-basic">
            <thead>
              <tr>
                {Columns.map((col) => {
                  const isSortable = [
                    "id", 
                    "numero_compte", 
                    "nom_raison_sociale", 
                    "bp", 
                    "ville", 
                    "pays", 
                    "categorie",
                    "type_tiers"
                  ].includes(col.key)

                  const isActive = sort.key === col.key
                  const arrow = isActive ? (sort.dir === "asc" ? " ↑" : " ↓") : ""
                  return (
                    <th
                      key={col.key}
                      style={{
                        textAlign: "left",
                        padding: 8,
                        borderBottom: "1px solid #e5e7eb",
                        whiteSpace: "nowrap",
                        cursor: isSortable ? "pointer" : "default",
                        backgroundColor: isActive ? "#f3f4f6" : "transparent"
                      }}
                      onClick={() => isSortable && handleHeaderSort(col.key)}
                    >
                      {col.label}
                      {arrow}
                    </th>
                  )
                })}
              </tr>
            </thead>
            <tbody>
              {items.length === 0 ? (
                <tr>
                  <td colSpan={Columns.length} style={{ padding: 16, textAlign: "center", color: "#6b7280" }}>
                    Aucun compte client trouvé avec les critères actuels.
                  </td>
                </tr>
              ) : (
                items.map((row) => (
                  <tr 
                    key={row.id ?? row.nom_raison_sociale}
                    onClick={() => navigate(`/clients/${row.id}`)}
                    style={{ cursor: "pointer" }}
                    className="clickable-row"
                  >
                    {Columns.map((col) => (
                      <td key={col.key} style={{ padding: 8, borderBottom: "1px solid #f3f4f6" }}>
                        {row?.[col.key] ?? ""}
                      </td>
                    ))}
                  </tr>
                ))
              )}
            </tbody>
            <tfoot>
              <tr>
                <td colSpan={Columns.length} style={{ textAlign: "center", padding: "0.75rem", backgroundColor: "#f9fafb", borderTop: "2px solid #e5e7eb" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "1rem" }}>
                    <div style={{ fontWeight: 500, color: "#374151" }}>
                      Total: {pagination.total || 0} client{pagination.total !== 1 ? 's' : ''}
                    </div>
                    <Pagination
                      currentPage={pagination.current_page || page}
                      totalPages={pagination.last_page || 1}
                      totalItems={pagination.total || 0}
                      itemsPerPage={perPage}
                      onPageChange={(newPage) => setPage(newPage)}
                      onItemsPerPageChange={(newPerPage) => {
                        setPerPage(newPerPage)
                        setPage(1)
                      }}
                      itemsPerPageOptions={[10, 20, 50, 100]}
                      showItemsPerPage={true}
                      showTotal={true}
                    />
                  </div>
                </td>
              </tr>
            </tfoot>
          </table>
        </div>
      )}

      {/* Modale d'importation CSV */}
      {importModalOpen && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0, 0, 0, 0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div style={{ backgroundColor: 'white', borderRadius: 8, padding: 24, maxWidth: '90vw', maxHeight: '90vh', overflow: 'auto', boxShadow: '0 10px 25px rgba(0, 0, 0, 0.2)', position: 'relative' }}>
            <button aria-label="Fermer" onClick={() => setImportModalOpen(false)} style={{ position: 'absolute', top: 8, right: 8, border: 'none', background: 'transparent', cursor: 'pointer', padding: 4, color: 'red', lineHeight: 0 }}>
              <X size={20} />
            </button>
            <h3 style={{ marginTop: 0, marginBottom: 20 }}>Importation CSV des clients</h3>
            
            <div style={{ marginBottom: 20 }}>
              <h4>Colonnes détectées dans le fichier CSV :</h4>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 16 }}>
                {csvHeaders.map((header, index) => (
                  <span key={index} style={{ backgroundColor: '#f3f4f6', padding: '4px 8px', borderRadius: 4, fontSize: '12px', border: '1px solid #d1d5db' }}>
                    {header}
                  </span>
                ))}
              </div>
            </div>

            <div style={{ marginBottom: 20 }}>
              <h4>Mapping des colonnes :</h4>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                {[
                  { key: 'numero_compte', label: 'Numéro de compte' },
                  { key: 'nom_raison_sociale', label: 'Nom / Raison sociale (Nom tiers)' },
                  { key: 'categorie', label: 'Catégorie (Type)' },
                  { key: 'adresse_geo_1', label: 'Adresse géographique 1' },
                  { key: 'bp', label: 'Boîte postale' },
                  { key: 'ville', label: 'Ville' },
                  { key: 'telephone', label: 'Téléphone' },
                  { key: 'date_creation', label: 'Date de création' },
                  { key: 'nom_signataire', label: 'Nom du signataire' },
                  { key: 'type_tiers', label: 'Type tiers' }
                ].map(field => (
                  <div key={field.key} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <label style={{ minWidth: 180, fontSize: '14px' }}>{field.label}:</label>
                    <select 
                      value={columnMapping[field.key] || ''} 
                      onChange={(e) => setColumnMapping(prev => ({ ...prev, [field.key]: e.target.value }))}
                      style={{ flex: 1, padding: '4px 8px', border: '1px solid #d1d5db', borderRadius: 4 }}
                    >
                      <option value="">-- Non mappé --</option>
                      {csvHeaders.map(header => (<option key={header} value={header}>{header}</option>))}
                    </select>
                  </div>
                ))}
              </div>
            </div>

            {csvRecords.length > 0 && (
              <div style={{ marginBottom: 20 }}>
                <h4>Aperçu des données (3 premières lignes) :</h4>
                <div style={{ overflow: 'auto', maxHeight: 200, border: '1px solid #d1d5db', borderRadius: 4 }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                    <thead>
                      <tr style={{ backgroundColor: '#f9fafb' }}>
                        {csvHeaders.map((header, index) => (<th key={index} style={{ padding: '4px 8px', border: '1px solid #d1d5db', textAlign: 'left' }}>{header}</th>))}
                      </tr>
                    </thead>
                    <tbody>
                      {csvRecords.slice(0, 3).map((row, rowIndex) => (
                        <tr key={rowIndex}>
                          {row.map((cell, cellIndex) => (
                            <td key={cellIndex} style={{ padding: '4px 8px', border: '1px solid #d1d5db' }}>{cell}</td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {importProgress.total > 0 && (
              <div style={{ marginBottom: 20 }}>
                <h4>Progression de l'importation :</h4>
                <div style={{ backgroundColor: '#f3f4f6', borderRadius: 4, padding: 12 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                    <span>{importProgress.status}</span>
                    <span>{importProgress.current} / {importProgress.total}</span>
                  </div>
                  <div style={{ backgroundColor: '#e5e7eb', borderRadius: 4, height: 8 }}>
                    <div style={{ backgroundColor: '#10b981', height: '100%', borderRadius: 4, width: `${(importProgress.current / importProgress.total) * 100}%`, transition: 'width 0.3s ease' }} />
                  </div>
                </div>
              </div>
            )}

            {importResult && (
              <div style={{ marginBottom: 20, padding: 12, backgroundColor: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: 4 }}>
                <h4>Résultat de l'importation :</h4>
                <p>
                  {importResult.created} clients créés, {importResult.updated} mis à jour, {importResult.skipped} ignorés
                  {importResult.errors && importResult.errors.length > 0 && (
                    <span>, {importResult.errors.length} erreurs</span>
                  )}
                </p>
              </div>
            )}

            {importResult && importResult.errors && importResult.errors.length > 0 && (
              <div style={{ marginBottom: 20, padding: 12, backgroundColor: '#fef2f2', border: '1px solid #fecaca', borderRadius: 4 }}>
                <h4>Erreurs d'importation :</h4>
                <div style={{ maxHeight: 200, overflowY: 'auto' }}>
                  {importResult.errors.slice(0, 10).map((error, index) => (
                    <div key={index} style={{ fontSize: '12px', color: '#dc2626', marginBottom: '4px' }}>
                      {error}
                    </div>
                  ))}
                  {importResult.errors.length > 10 && (
                    <div style={{ fontSize: '12px', color: '#dc2626', marginTop: '4px' }}>
                      ... et {importResult.errors.length - 10} autres erreurs
                    </div>
                  )}
                </div>
              </div>
            )}

            <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end' }}>
              <button onClick={handleCancelImport} style={{ padding: '8px 16px', border: '1px solid #d1d5db', borderRadius: 4, backgroundColor: 'white', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px' }}><X size={16} style={{ marginRight: 6 }} /> Annuler</button>
              <button
                onClick={handleImportConfirm}
                disabled={isImporting}
                style={{ padding: '8px 16px', border: 'none', borderRadius: 4, backgroundColor: isImporting ? '#9ca3af' : '#3b82f6', color: 'white', cursor: isImporting ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', gap: '8px' }}
              >
                {isImporting && (<div style={{ width: '16px', height: '16px', border: '2px solid #ffffff', borderTop: '2px solid transparent', borderRadius: '50%', animation: 'spin 1s linear infinite' }} />)}
                {isImporting ? 'Importation en cours...' : <><Upload size={16} style={{ marginRight: 6 }} /> Importer</>}
              </button>
            </div>
          </div>
        </div>
      )}
      
      {/* Modale de sélection de plage d'impression */}
      {showPrintModal && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0, 0, 0, 0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div style={{ backgroundColor: 'white', borderRadius: 8, padding: 24, maxWidth: '90vw', maxHeight: '90vh', overflow: 'auto', boxShadow: '0 10px 25px rgba(0, 0, 0, 0.2)', position: 'relative' }}>
            <button aria-label="Fermer" onClick={() => setShowPrintModal(false)} style={{ position: 'absolute', top: 8, right: 8, border: 'none', background: 'transparent', cursor: 'pointer', padding: 4, color: 'red', lineHeight: 0 }}>
              <X size={20} />
            </button>
            <h3 style={{ marginTop: 0, marginBottom: 20 }}>Sélection de la plage d'impression</h3>
            
            <div style={{ marginBottom: 20 }}>
              <p>Nombre total de pages disponibles : {Math.ceil(pagination.total / printPerPage)}</p>
              <p>Nombre total d'éléments : {pagination.total}</p>
            </div>
            
            <div style={{ marginBottom: 20, display: 'flex', gap: 20 }}>
              <div>
                <label>Page de début :</label>
                <input 
                  type="number" 
                  min="1" 
                  max={Math.ceil(pagination.total / printPerPage)}
                  value={selectedPrintRange.start}
                  onChange={(e) => setSelectedPrintRange(prev => ({ ...prev, start: parseInt(e.target.value) || 1 }))}
                  style={{ width: '100px', padding: '4px 8px', border: '1px solid #d1d5db', borderRadius: 4, marginLeft: '8px' }}
                />
              </div>
              <div>
                <label>Page de fin :</label>
                <input 
                  type="number" 
                  min="1" 
                  max={Math.ceil(pagination.total / printPerPage)}
                  value={selectedPrintRange.end}
                  onChange={(e) => setSelectedPrintRange(prev => ({ ...prev, end: parseInt(e.target.value) || 1 }))}
                  style={{ width: '100px', padding: '4px 8px', border: '1px solid #d1d5db', borderRadius: 4, marginLeft: '8px' }}
                />
              </div>
            </div>
            
            <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end' }}>
              <button onClick={() => setShowPrintModal(false)} style={{ padding: '8px 16px', border: '1px solid #d1d5db', borderRadius: 4, backgroundColor: 'white', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px' }}><X size={16} style={{ marginRight: 6 }} /> Annuler</button>
              <button
                onClick={executePrint}
                style={{ padding: '8px 16px', border: 'none', borderRadius: 4, backgroundColor: '#3b82f6', color: 'white', cursor: 'pointer' }}
              >
                <Printer size={16} style={{ marginRight: 6 }} /> Imprimer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default ClientsGrid