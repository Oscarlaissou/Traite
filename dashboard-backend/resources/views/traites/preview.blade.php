<?php 
  $organizationSetting = \App\Models\OrganizationSetting::first();
  $logoUrl = $organizationSetting && $organizationSetting->logo ? url('storage/' . $organizationSetting->logo) : asset('images/LOGO.png');

?>

<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Aperçu – Traites</title>
  <meta name="csrf-token" content="{{ csrf_token() }}" />
  <style>
    body { background: #f3f4f6; margin: 0; font-family: Arial, sans-serif; }
    /* Marges d'impression pour navigateur et moteurs PDF */
    @page { size: A4; margin: 12mm; }
  
    .toolbar {
      top: 0;
      display: flex;
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
      gap: 10px;
      padding: 10px 16px;
      position: sticky;
      bottom: 0;
      z-index: 50;
    }

    /* reverted layout wrapper */

    .toolbar-left {
      display: flex;
      flex-direction: column;
      align-items: center;
      text-align: center;
      width: 100%;
      gap: 6px;
      margin: 0 auto;
    }

    .toolbar-left img {
      height: 40px;
      object-fit: contain;
      max-width: 100%;
    }
    .toolbar-left .message { color: #4b5563; font-size: 12px; }

    .toolbar-right {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .toolbar-right input[type="email"] {
      padding: 8px 10px;
      border: 1px solid #e5e7eb;
      border-radius: 6px;
      font-size: 14px;
      width: 260px;
    }

    .toolbar button {
      background: #111827;
      color: #fff;
      border: none;
      border-radius: 6px;
      padding: 8px 14px;
      cursor: pointer;
      transition: background 0.2s ease-in-out;
    }

    .toolbar button:hover {
      background: #374151;
    }

    .toolbar .hint {
      color: #4b5563;
      font-size: 13px;
    }

    .preview-wrapper {
      padding: 20px;
    }

    .page {
      background: #fff;
      box-shadow: 0 1px 2px rgba(0,0,0,0.06), 0 1px 1px rgba(0,0,0,0.04);
      border-radius: 8px;
      overflow: hidden;
    }

    .pager-footer {
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
      gap: 10px;
      padding: 10px 16px;
      /* border-top: 1px solid #e5e7eb;
      background: #fff; */
      position: sticky;
      bottom: 0;
      z-index: 50;
    }
    .pager-footer .pager { display: inline-flex; gap: 6px; align-items: center; }
    .pager-footer .btn { background: #fff; color: #111827; border: 1px solid #e5e7eb; border-radius: 6px; padding: 6px 10px; cursor: pointer; }
    .pager-footer .btn:hover { background: #f3f4f6; }
    .pager-footer .btn.active { background: #111827; color: #fff; border-color: #111827; }
    .pager-footer .btn:disabled { background: #f3f4f6; color: #9ca3af; cursor: not-allowed; }
    .pager-footer .print { background: #111827; color: #fff; border: none; border-radius: 6px; padding: 6px 12px; cursor: pointer; margin-left: 8px; }
    .pager-footer .cancel { background: #fff; color: #111827; border: 1px solid #e5e7eb; border-radius: 6px; padding: 6px 12px; cursor: pointer; }
    .pager-footer .print:hover { background: #374151; }
    .pager-footer .cancel:hover { background: #f3f4f6; }


    /* Media queries pour responsive design */
    @media (max-width: 768px) {
      .toolbar {
        padding: 8px 12px;
        flex-direction: column;
        gap: 8px;
      }
      .toolbar-left img {
        height: 40px;
      }
      .toolbar-left .message {
        font-size: 11px;
      }
      .preview-wrapper {
        padding: 10px;
      }
      .pager-footer {
        padding: 8px 12px;
        flex-direction: column;
        gap: 8px;
      }
      .pager-footer .pager {
        flex-wrap: wrap;
        justify-content: center;
      }
      .pager-footer .btn {
        padding: 4px 8px;
        font-size: 12px;
      }
    }

    @media (max-width: 480px) {
      .toolbar-left img {
        height: 30px;
      }
      .toolbar-left .message {
        font-size: 10px;
      }
      .preview-wrapper {
        padding: 5px;
      }
      .pager-footer .btn {
        padding: 3px 6px;
        font-size: 11px;
      }
    }

    @media print {
      .toolbar { display: none; }
      .pager-footer { display: none; }
      body { background: #fff; }
      .page { box-shadow: none; break-after: page; display: block !important; }
    }
  </style>
</head>
<body>
  <div class="toolbar">
    <div class="toolbar-left">
<img src="{{ \App\Models\OrganizationSetting::first()?->logo ? url('storage/' . \App\Models\OrganizationSetting::first()->logo) : asset('images/LOGO.png') }}" 
     alt="Logo" 
     style="height: 60px; object-fit: contain; max-width: 100%;" />
      <span class="message">Aperçu de toutes les traites</span>
    </div>
    <div class="toolbar-right"></div>
  </div>


  <div class="preview-wrapper">
    @foreach ($pages as $idx => $p)
      <div class="page" data-index="{{ $idx+1 }}" style="display: {{ $idx === 0 ? 'block' : 'none' }};">
        <?php 
          // Ensure ville is set when rendering the print view
          $printData = $p;
          if (!isset($printData['ville'])) {
              $printData['ville'] = 'Douala';
          }
          echo view('traites.print', $printData)->render(); 
        ?>
      </div>
    @endforeach
  </div>

  <div class="pager-footer">
    <div class="pager" id="pagerNumbers">
      <button class="btn" id="prevBtn">Précédent</button>
      @for ($i = 1; $i <= count($pages); $i++)
        <button class="btn {{ $i === 1 ? 'active' : '' }}" data-page="{{ $i }}">{{ $i }}</button>
      @endfor
      <button class="btn" id="nextBtn">Suivant</button>
    </div>
    <div style="display:flex; gap:8px; align-items:center;">
      <button class="cancel" onclick="cancelPreview()">Annuler</button>
      <button class="print" onclick="window.print()">Imprimer</button>
     
      <button class="print" id="emailBtn" onclick="downloadAndEmail()">Transférer par mail</button>
    </div>
  </div>

  <script>
    (function(){
      const pages = Array.from(document.querySelectorAll('.page'));
      const total = pages.length;
      let current = 1;
      const prevBtn = document.getElementById('prevBtn');
      const nextBtn = document.getElementById('nextBtn');
      const pager = document.getElementById('pagerNumbers');

      function render(){
        pages.forEach(p => { p.style.display = 'none'; });
        const active = pages.find(p => Number(p.dataset.index) === current);
        if (active) active.style.display = 'block';
        prevBtn.disabled = current <= 1;
        nextBtn.disabled = current >= total;
        // Active button state
        pager.querySelectorAll('[data-page]').forEach(btn => {
          const p = Number(btn.getAttribute('data-page'));
          if (p === current) btn.classList.add('active'); else btn.classList.remove('active');
        });
      }
      prevBtn.addEventListener('click', () => { if (current > 1) { current--; render(); } });
      nextBtn.addEventListener('click', () => { if (current < total) { current++; render(); } });
      pager.querySelectorAll('[data-page]').forEach(btn => {
        btn.addEventListener('click', () => { current = Number(btn.getAttribute('data-page')); render(); });
      });
      render();
    })();

    function cancelPreview(){
      // Try to close if opened by script
      window.close();
      // Fallback after a tick if not closed
      setTimeout(function(){
        if (!document.hidden) {
          if (document.referrer) {
            window.location.href = document.referrer;
          } else if (history.length > 1) {
            history.back();
          } else {
            window.location.href = '/';
          }
        }
      }, 100);
    }

    async function downloadScreenshotPdf(){
      const downloadBtn = document.getElementById('downloadBtn');
      const originalText = downloadBtn.textContent;
      
      // Afficher l'état de chargement
      downloadBtn.textContent = 'Génération en cours...';
      downloadBtn.disabled = true;
      downloadBtn.style.opacity = '0.7';
      
      const url = '/print/traites/{{ $traiteId }}/screenshot.pdf';
      try {
        const response = await fetch(url, { credentials: 'same-origin' });
        if (!response.ok) throw new Error('HTTP ' + response.status);
        const blob = await response.blob();
        const link = document.createElement('a');
        const objectUrl = URL.createObjectURL(blob);
        link.href = objectUrl;
        link.download = 'traites_{{ $traiteId }}.pdf';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(objectUrl);
        
        // Succès
        downloadBtn.textContent = 'Téléchargé !';
        setTimeout(() => {
          downloadBtn.textContent = originalText;
          downloadBtn.disabled = false;
          downloadBtn.style.opacity = '1';
        }, 2000);
      } catch (e) {
        // Erreur
        downloadBtn.textContent = 'Erreur - Réessayer';
        setTimeout(() => {
          downloadBtn.textContent = originalText;
          downloadBtn.disabled = false;
          downloadBtn.style.opacity = '1';
        }, 3000);
        
        // Message d'erreur plus informatif
        let errorMessage = 'Téléchargement du PDF impossible: ' + e.message;
        if (e.message.includes('HTTP 500')) {
          errorMessage = 'Erreur serveur: Le service de génération PDF est temporairement indisponible. Veuillez réessayer dans quelques minutes.';
        } else if (e.message.includes('HTTP 404')) {
          errorMessage = 'Erreur: Le fichier PDF demandé n\'a pas été trouvé.';
        } else if (e.message.includes('Failed to fetch')) {
          errorMessage = 'Erreur de connexion: Impossible de contacter le serveur. Vérifiez votre connexion internet.';
        }
        
        alert(errorMessage);
      }
    }

    // Fonction pour télécharger et ouvrir l'application de messagerie externe
    async function downloadAndEmail() {
      const emailBtn = document.getElementById('emailBtn');
      const originalText = emailBtn.textContent;
      
      // Afficher l'état de chargement
      emailBtn.textContent = 'Génération PDF...';
      emailBtn.disabled = true;
      emailBtn.style.opacity = '0.7';
      
      try {
        // D'abord télécharger le PDF
        const url = '/print/traites/{{ $traiteId }}/screenshot.pdf';
        const response = await fetch(url, { credentials: 'same-origin' });
        if (!response.ok) throw new Error('HTTP ' + response.status);
        const blob = await response.blob();
        
        // Créer le lien de téléchargement et déclencher le téléchargement
        const link = document.createElement('a');
        const objectUrl = URL.createObjectURL(blob);
        link.href = objectUrl;
        link.download = 'traites_{{ $traiteId }}.pdf';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(objectUrl);
        
        // Attendre un court délai puis ouvrir l'application de messagerie
        setTimeout(() => {
          emailBtn.textContent = 'Ouverture application mail...';
          
          // Créer le lien mailto avec le PDF en pièce jointe
          const subject = encodeURIComponent('Traites {{ $traiteNumero ?? "" }}');
          const body = encodeURIComponent(`Bonjour,

Veuillez trouver ci-joint la traite {{ $traiteNumero ?? "" }}.

Cordialement.`);
          
          // Ouvrir l'application de messagerie externe
          const mailtoLink = `mailto:?subject=${subject}&body=${body}`;
          window.open(mailtoLink, '_blank');
          
          // Restaurer le bouton
          setTimeout(() => {
            emailBtn.textContent = originalText;
            emailBtn.disabled = false;
            emailBtn.style.opacity = '1';
          }, 1000);
          
        }, 1000);
        
      } catch (e) {
        // Erreur
        emailBtn.textContent = 'Erreur - Réessayer';
        setTimeout(() => {
          emailBtn.textContent = originalText;
          emailBtn.disabled = false;
          emailBtn.style.opacity = '1';
        }, 3000);
        
        let errorMessage = 'Téléchargement du PDF impossible: ' + e.message;
        if (e.message.includes('HTTP 500')) {
          errorMessage = 'Erreur serveur: Le service de génération PDF est temporairement indisponible.';
        } else if (e.message.includes('HTTP 404')) {
          errorMessage = 'Erreur: Le fichier PDF demandé n\'a pas été trouvé.';
        } else if (e.message.includes('Failed to fetch')) {
          errorMessage = 'Erreur de connexion: Impossible de contacter le serveur.';
        }
        
        alert(errorMessage);
      }
    }

  </script>
</body>
</html>