@php
    use Illuminate\Support\Str;
    $formatCurrency = function ($value) {
        if ($value === null || $value === '') {
            return '';
        }
        return number_format((float) $value, 0, ',', ' ');
    };
    $category = $tier->categorie ?? '';
    $isCategory = function (string $value) use ($category) {
        return Str::lower(trim($category)) === Str::lower(trim($value)) ? 'X' : '□';
    };
    $purchaseTitle = !empty($purchaseTitle ?? '') ? $purchaseTitle : ($demande->motif ?? '');
    $purchaseTitle = Str::upper(trim($purchaseTitle));
    $registrationCity = Str::upper(trim($registrationCity ?? 'DLA'));
    $signatureCity = $registrationCity; // UNIQUEMENT ICI
    $signatureDate = $signatureDate ?? now()->format('d/m/Y');
@endphp

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Demande d'Ouverture d'un Compte Tiers</title>
    <style>
        /* === STYLE ÉCRAN (inchangé) === */
        body {
            font-family: Arial, sans-serif;
            font-size: 11pt;
            background-color: #f4f4f4;
            color: #000;
        }
        .container {
            width: 850px;
            margin: 20px auto;
            padding: 15px;
            /* background-color: #fff; */
        }
        .main-title {
            border: 1px solid #000;
            text-align: center;
            font-weight: bold;
            font-size: 14pt;
            padding: 8px;
            margin-bottom: 20px;
        }
        .section-title {
            text-align: center;
            font-weight: bold;
            font-size: 12pt;
            margin-top: 15px;
            margin-bottom: 5px;
        }
        .purchase-title {
            border: 1px solid #000;
            text-align: center;
            font-weight: bold;
            padding: 8px;
            margin: 20px 0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 10px;
        }
        td {
            border: 1px solid #000;
            padding: 4px 8px;
            vertical-align: middle;
        }
        .bold-value { font-weight: bold; }
        .info-table td:first-child { width: 25%; }
        .checkbox-table { margin: 15px 0; }
        .checkbox-table td { width: 25%; }
        .checkbox { font-size: 14pt; font-weight: bold; }
        .complementary-table td:nth-child(1),
        .complementary-table td:nth-child(2) { width: 25%; }
        .emitter-table td:first-child { width: 25%; }
        .footer-table { margin-top: 10px; }
        .footer-table td { height: 30px; text-align: left; }
        .footer-table .value-cell {
            text-align: center;
            font-weight: bold;
            font-size: 12pt;
            height: 40px;
            vertical-align: middle;
            border-top: none;
        }
        .signature-cell {
            width: 25%;
            vertical-align: top;
            text-align: left;
            padding-top: 6px;
        }
        .blank-row {
            height: 80px;
            border-top: none;
            border-bottom: 1px solid black;
            border-left: 1px solid black;
            border-right: 1px solid black;
        }

        /* === IMPRESSION : SEULEMENT LA BORDURE HAUT SIGNATURE SUPPRIMÉE === */
        @media print {
            @page {
                size: A4 portrait;
                margin: 10mm 12mm 10mm 12mm ;
            }

            html, body {
                margin: 0 ;
                padding: 0 ;
               
                background: #fff ;
                font-size: 10.3pt ;
                line-height: 1.38 ;
            }

            .container {
                width: 780px;
              
                max-width: none ;
                margin: 0 ;
                padding: 14px 16px ;
                /* min-height: 20vh ; */
                display: flex;
                flex-direction: column;
                justify-content: space-between;
                box-sizing: border-box;
                page-break-after: avoid ;
            }


            .content-wrapper {
                flex: 1;
                display: flex;
                flex-direction: column;
                justify-content: space-between;
            }

            .main-title {
                font-size: 13.5pt ;
                padding: 7px ;
                margin-bottom: 16px ;
                margin-top: 40px;
            }

            .section-title {
                font-size: 11.5pt ;
                margin: 12px 0 5px ;
            }

            .purchase-title {
                padding: 7px ;
                margin: 16px 0 ;
                font-size: 11.5pt ;
            }

            table {
                margin-bottom: 8px ;
                font-size: 10pt ;
            }

            td {
                padding: 3.5px 7px ;
            }

            .checkbox-table {
                margin: 10px 0 ;
            }

            .footer-table {
                margin-top: 12px ;
                page-break-inside: avoid ;
            }

            .footer-table td {
                height: 28px ;
                font-size: 10.2pt ;
            }

            .value-cell {
                font-size: 11.5pt ;
                height: 36px ;
                /* On garde la bordure du bas des montants */
                padding-top: 40px 
            }

            .signature-cell {
                padding-top: 10px ;
                font-size: 10.2pt ;
            }

            /* UNIQUEMENT LA BORDURE HAUT DE LA ZONE SIGNATURE SUPPRIMÉE */
            .blank-row {
                height: 120px ;
                border-top: none ;     /* ← SUPPRIMÉ ICI */
                border-bottom: 1px solid black ;
                border-left: 1px solid black ;
                border-right: 1px solid black ;
                padding-top: 10px ;
            }

            .footer-wrapper {
                margin-top: auto;
            }

            * {
                page-break-inside: avoid ;
            }
            .container, .content-wrapper, table, tr, td {
                page-break-inside: avoid ;
                page-break-after: avoid ;
            }
        }
    </style>
</head>
<body>

<!-- === ÉCRAN : affichage normal === -->
<div class="container" >
    <div class="main-title">Demande d'Ouverture d'un Compte Tiers</div>

    <div class="section-title">Identification du Tiers</div>
    <table class="info-table">
        <tr><td>Nom ou Raison Sociale</td><td class="bold-value">{{ $tier->nom_raison_sociale ?? '' }}</td></tr>
        <tr><td>BP</td><td class="bold-value">{{ $tier->bp ?? '' }}</td></tr>
        <tr><td>Ville</td><td class="bold-value">{{ $tier->ville ?? '' }}</td></tr>
        <tr><td>Pays</td><td class="bold-value">{{ $tier->pays ?? '' }}</td></tr>
        <tr><td>Adresse Géographique 1</td><td>{{ $tier->adresse_geo_1 ?? '' }}</td></tr>
        <tr><td>Adresse Géographique 2</td><td>{{ $tier->adresse_geo_2 ?? '' }}</td></tr>
        
        <tr><td>Téléphone</td><td>{{ $tier->telephone ?? '' }}</td></tr>
        
        <tr><td>E Mail</td><td>{{ $tier->email ?? '' }}</td></tr>
    </table>

    <table class="checkbox-table">
        <tr>
            <td>Sté Privées Hors Grp<br><span class="checkbox">{{ $isCategory('Sté Privées Hors Grp') }}</span></td>
            <td>Société Groupe<br><span class="checkbox">{{ $isCategory('Société Groupe') }}</span></td>
            <td>Individuel<br><span class="checkbox">{{ $isCategory('Individuel') }}</span></td>
            <td>Personnel Groupe<br><span class="checkbox">{{ $isCategory('Personnel Groupe') }}</span></td>
        </tr>
        <tr>
            <td>Administration<br><span class="checkbox">{{ $isCategory('Administration') }}</span></td>
            <td>Collectivité locale<br><span class="checkbox">{{ $isCategory('Collectivité locale') }}</span></td>
            <td>Entreprise Publique<br><span class="checkbox">{{ $isCategory('Entreprise Publique') }}</span></td>
            <td>Société de financement<br><span class="checkbox">{{ $isCategory('Société de financement') }}</span></td>
        </tr>
    </table>

    <div class="section-title">Renseignements Complémentaires.</div>
    <table class="complementary-table">
        <tr><td>Type d'entreprises</td><td>N° Contribuable</td><td class="bold-value">{{ $tier->n_contribuable ?? '' }}</td></tr>
        <!-- <tr><td>Sté Groupe</td><td>N° Contribuable</td><td></td></tr>
        <tr><td>Individuels</td><td>Employeur</td><td></td></tr>
        <tr><td>Personnel Groupe</td><td>Filiale</td><td></td></tr>
        <tr><td>Administration :</td><td>Ordonnateur</td><td></td></tr>
        <tr><td>Collectivités Locales</td><td>Ordonnateur</td><td></td></tr>
        <tr><td>Entreprises Publiques</td><td>N° Contribuable</td><td></td></tr> -->
    </table>

    <div class="purchase-title">{{ $purchaseTitle }}</div>

    <div class="section-title">Émetteur de la demande.</div>
    <table class="emitter-table">
        <tr><td>Société</td><td class="bold-value">{{ $demande->societe ?? ($companyName ?? 'CFAO MOBILITY CAMEROON') }}</td></tr>
        <tr><td>Établissement</td><td class="bold-value">{{ $demande->etablissement ?? '' }}</td></tr>
        <tr><td>Service</td><td class="bold-value">{{ $demande->service ?? '' }}</td></tr>
        <tr><td>Nom du Signataire</td><td class="bold-value">{{ $demande->nom_signataire ?? '' }}</td></tr>
    </table>

    <table class="footer-table">
        <tr>
            <td>Montant facturé</td>
            <td>Montant payé</td>
            <td>Crédit</td>
            <td rowspan="2" class="signature-cell">
                {{ $signatureCity }} le {{ $signatureDate }}<br>
                <strong>Signature</strong>
            </td>
        </tr>
        <tr>
            <td class="value-cell">{{ $formatCurrency($demande->montant_facture ?? null) }}</td>
            <td class="value-cell">{{ $formatCurrency($demande->montant_paye ?? null) }}</td>
            <td class="value-cell">{{ $formatCurrency($demande->credit ?? null) }}</td>
        </tr>
        <tr>
            <td colspan="4" class="blank-row">&nbsp;</td>
        </tr>
    </table>
</div>

<!-- === IMPRESSION : version propre === -->
<div class="container" style="display: none;">
    <div class="content-wrapper">
        <div>
            <div class="main-title">Demande d'Ouverture d'un Compte Tiers</div>

            <div class="section-title">Identification du Tiers</div>
            <table class="info-table">
                <tr><td>Nom ou Raison Sociale</td><td class="bold-value">{{ $tier->nom_raison_sociale ?? '' }}</td></tr>
                <tr><td>BP</td><td class="bold-value">{{ $tier->bp ?? '' }}</td></tr>
                <tr><td>Ville</td><td class="bold-value">{{ $tier->ville ?? '' }}</td></tr>
                <tr><td>Pays</td><td class="bold-value">{{ $tier->pays ?? '' }}</td></tr>
                <tr><td>Adresse Géographique 1</td><td>{{ $tier->adresse_geo_1 ?? '' }}</td></tr>
                <tr><td>Adresse Géographique 2</td><td>{{ $tier->adresse_geo_2 ?? '' }}</td></tr>
               
                <tr><td>Téléphone</td><td>{{ $tier->telephone ?? '' }}</td></tr>
               
                <tr><td>E Mail</td><td>{{ $tier->email ?? '' }}</td></tr>
            </table>

            <table class="checkbox-table">
                <tr>
                    <td>Sté Privées Hors Grp<br><span class="checkbox">{{ $isCategory('Sté Privées Hors Grp') }}</span></td>
                    <td>Société Groupe<br><span class="checkbox">{{ $isCategory('Société Groupe') }}</span></td>
                    <td>Individuel<br><span class="checkbox">{{ $isCategory('Individuel') }}</span></td>
                    <td>Personnel Groupe<br><span class="checkbox">{{ $isCategory('Personnel Groupe') }}</span></td>
                </tr>
                <tr>
                    <td>Administration<br><span class="checkbox">{{ $isCategory('Administration') }}</span></td>
                    <td>Collectivité locale<br><span class="checkbox">{{ $isCategory('Collectivité locale') }}</span></td>
                    <td>Entreprise Publique<br><span class="checkbox">{{ $isCategory('Entreprise Publique') }}</span></td>
                    <td>Administration Privée<br><span class="checkbox">{{ $isCategory('Administration Privée') }}</span></td>
                </tr>
            </table>

            <div class="section-title">Renseignements Complémentaires.</div>
            <table class="complementary-table">
                <tr><td>Type d'entreprises</td><td>N° Contribuable</td><td class="bold-value">{{ $tier->n_contribuable ?? '' }}</td></tr>
                <!-- <tr><td>Sté Groupe</td><td>N° Contribuable</td><td></td></tr>
                <tr><td>Individuels</td><td>Employeur</td><td></td></tr>
                <tr><td>Personnel Groupe</td><td>Filiale</td><td></td></tr>
                <tr><td>Administration :</td><td>Ordonnateur</td><td></td></tr>
                <tr><td>Collectivités Locales</td><td>Ordonnateur</td><td></td></tr>
                <tr><td>Entreprises Publiques</td><td>N° Contribuable</td><td></td></tr> -->
            </table>

            <div class="purchase-title">{{ $purchaseTitle }}</div>

            <div class="section-title">Émetteur de la demande.</div>
            <table class="emitter-table">
                <tr><td>Société</td><td class="bold-value">{{ $demande->societe ?? ($companyName ?? 'CFAO MOBILITY CAMEROON') }}</td></tr>
                <tr><td>Établissement</td><td class="bold-value">{{ $demande->etablissement ?? '' }}</td></tr>
                <tr><td>Service</td><td class="bold-value">{{ $demande->service ?? '' }}</td></tr>
                <tr><td>Nom du Signataire</td><td class="bold-value">{{ $demande->nom_signataire ?? '' }}</td></tr>
            </table>
        </div>

        <div class="footer-wrapper">
            <table class="footer-table">
                <tr>
                    <td>Montant facturé</td>
                    <td>Montant payé</td>
                    <td>Crédit</td>
                    <td rowspan="2" class="signature-cell">
                        {{ $signatureCity }} le {{ $signatureDate }}<br>
                        <strong>Signature</strong>
                    </td>
                </tr>
                <tr>
                    <td class="value-cell">{{ $formatCurrency($demande->montant_facture ?? null) }}</td>
                    <td class="value-cell">{{ $formatCurrency($demande->montant_paye ?? null) }}</td>
                    <td class="value-cell">{{ $formatCurrency($demande->credit ?? null) }}</td>
                </tr>
                <tr>
                    <td colspan="4" class="blank-row">&nbsp;</td>
                </tr>
            </table>
        </div>
    </div>
</div>

<script>
    window.addEventListener('beforeprint', () => {
        document.querySelectorAll('.container')[0].style.display = 'none';
        document.querySelectorAll('.container')[1].style.display = 'block';
    });
    window.addEventListener('afterprint', () => {
        document.querySelectorAll('.container')[0].style.display = 'block';
        document.querySelectorAll('.container')[1].style.display = 'none';
    });
</script>

</body>
</html>