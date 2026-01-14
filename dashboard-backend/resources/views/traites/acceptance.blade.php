<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document Comptable - Acceptation</title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
    
    <style>
        :root {
            --primary-color: #1a2c4e;
            --accent-color: #2c5aa0;
            --border-color: #d0d0d0;
            --paper-bg: #ffffff;
            --text-gray: #555;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            background-color: #f5f5f5;
            display: flex;
            justify-content: center;
            padding: 40px 20px;
            font-family: 'Roboto', sans-serif;
            color: var(--primary-color);
        }

        .page {
            width: 210mm;
            min-height: 297mm;
            background-color: var(--paper-bg);
            padding: 50px 60px;
            box-shadow: 0 2px 20px rgba(0,0,0,0.1);
            position: relative;
        }

        /* Print button */
        .print-button {
            position: absolute;
            top: 10px;
            right: 20px;
            padding: 8px 16px;
            background-color:#b91c1c;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }

        /* En-tête */
        .header-top {
            display: flex;
            justify-content: flex-end;
            margin-bottom: 30px;
        }

        .date-loc {
            font-size: 14px;
            color: var(--text-gray);
        }

        h1 {
            text-align: center;
            font-size: 22px;
            font-weight: 500;
            margin: 30px 0 50px 0;
            line-height: 1.6;
            color: var(--primary-color);
        }

        /* Informations principales */
        .info-section {
            margin-bottom: 40px;
        }

        .info-row {
            display: flex;
            margin-bottom: 12px;
            font-size: 15px;
        }

        .info-label {
            font-weight: 500;
            min-width: 150px;
            color: var(--text-gray);
        }

        .info-value {
            font-weight: 400;
            flex: 1;
        }

        /* Tableau */
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 8px;
            font-size: 14px;
        }

        th {
            background-color: #f8f9fa;
            font-weight: 500;
            padding: 12px 10px;
            text-align: center;
            border: 1px solid var(--border-color);
        }

        td {
            padding: 12px 10px;
            text-align: center;
            border: 1px solid var(--border-color);
        }

        tbody tr:last-child {
            background-color: #f8f9fa;
            font-weight: 500;
        }

        /* Section sous le tableau */
        .below-table {
            display: flex;
            font-size: 14px;
            margin-top: 5px;
        }

        .below-col-1 { width: 15%; }
        .below-col-2 { width: 25%; }
        .below-col-3 { width: 25%; text-align: center; }
        .below-col-4 { width: 35%; text-align: center; }

        .info-item-label {
            font-weight: 700;
            font-size: 16px;
            color: var(--primary-color);
        }

        /* Section comptable */
        .journal-entry {
            margin: 40px 0;
            padding: 30px 0;
            border-top: 2px solid var(--primary-color);
            border-bottom: 2px solid var(--primary-color);
            position: relative;
        }

        .accounting-container {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 40px;
        }

        .accounting-left {
            display: flex;
            flex-direction: column;
            gap: 20px;
            font-size: 16px;
        }

        .accounting-line {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .account-type {
            font-weight: 500;
            min-width: 30px;
        }

        .account-number {
            font-family: 'Courier New', monospace;
            font-weight: 400;
        }

        .arrow {
            font-size: 60px;
            color: var(--primary-color);
            font-weight: 200;
            line-height: 1;
        }

        .amount-large {
            font-size: 24px;
            font-weight: 500;
            color: var(--primary-color);
        }

        .agos-note {
            text-align: center;
            margin-top: 30px;
            font-size: 14px;
           
        }

        /* Pied de page */
        .footer-section {
            margin-top: 60px;
            text-align: center;
        }

        .footer-title {
            font-size: 16px;
            font-weight: 500;
            line-height: 1.6;
            color: var(--primary-color);
        }

        .signature-area {
            margin-top: 80px;
            text-align: right;
            padding-right: 40px;
        }

        .signature-line {
            display: inline-block;
            border-top: 1px solid var(--primary-color);
            min-width: 200px;
            padding-top: 5px;
            margin-top: 60px;
            font-size: 13px;
            color: var(--text-gray);
        }

        @media print {
            body {
                background-color: #fff;
                padding: 0;
            }
            
            .page {
                box-shadow: none;
                padding: 50px 60px;
            }
            
            .print-button {
                display: none;
            }
        }
    </style>
</head>
<body>

    <div class="page">
        <!-- Print button -->
        <button class="print-button" onclick="window.print()">Imprimer</button>

        <!-- Date -->
        <div class="header-top">
            <div class="date-loc">
                {{ $ville ?? '' }}, le {{ $current_date_long ?? '' }}
            </div>
        </div>

        <!-- Titre -->
        <h1>
            Acceptation de {{ $nombre_traites ?? '' }} Traite(s) à l'{{ strtolower($decision ?? '') }}<br>
            de {{ $nom_raison_sociale ?: '' }}
        </h1>

        <!-- Informations principales -->
        <div class="info-section">
            <div class="info-row">
                <div class="info-label">Montant :</div>
                <div class="info-value">{{ $montant_formatted ?? '' }}</div>
            </div>
            <div class="info-row">
                <div class="info-label">Domiciliation :</div>
                <div class="info-value">{{ $domiciliation ?? '' }}</div>
            </div>
            <div class="info-row">
                <div class="info-label">Compte :</div>
                <div class="info-value">{{ $rib ?? '' }}</div>
            </div>
        </div>

        <!-- Tableau des traites -->
        <table>
            <thead>
                <tr>
                    <th style="width: 15%;">N° Ordre</th>
                    <th style="width: 25%;">N° Traite</th>
                    <th style="width: 25%;">Échéance</th>
                    <th style="width: 35%;">Montants</th>
                </tr>
            </thead>
            <tbody>
                @foreach($traites as $traite)
                <tr>
                    <td>{{ $traite['numero_ordre'] }}</td>
                    <td>{{ $traite['numero'] }}</td>
                    <td>{{ $traite['echeance'] }}</td>
                    <td>{{ $traite['montant_formatted'] }}</td>
                </tr>
                @endforeach
                <tr>
                    <td></td>
                    <td></td>
                    <td>Total</td>
                    <td>{{ $total_general_formatted }}</td>
                </tr>
            </tbody>
        </table>

        <!-- Informations additionnelles -->
        <div class="below-table">
            <div class="below-col-1"></div>
            <div class="below-col-2"></div>
            <div class="below-col-3" style="padding-top: 18px;">{{ $current_date ?? '' }}</div>
            <div class="below-col-4">
            </div>
        </div>
<!-- Section comptable -->
        <div class="journal-entry">
            <div style="text-align: left; margin-bottom: 15px; padding-left: 40px;">
                <span style=" font-weight: 500; font-size: 16px;">{{ $branch_department ?? '' }}</span>
            </div>
            <div class="accounting-container">
                <div class="accounting-left">
                    <div class="accounting-line">
                        <span class="account-type">Débit</span>
                        <span class="account-number">413 0000</span>
                    </div>
                    <div class="accounting-line">
                        <span class="account-type">Crédit</span>
                        <span class="account-number">{{ $credit_account ?? '' }}</span>
                    </div>
                </div>
                
                <div class="arrow">›</div>
                
                <div class="amount-large">
                    {{ $montant_formatted ?? '' }}
                </div>
            </div>
            <div style="text-align: center; margin-top: 15px;">
                <span style=" font-weight: 500; font-size: 16px;">Agios au {{ $agos_type ?? '' }}</span>
            </div>
        </div>
        <!-- Pied de page -->
        <div class="footer-section">
            <div class="footer-title">
                Acceptation de {{ $nombre_traites ?? '' }} traite(s) à l'{{ strtolower($decision ?? '') }}<br>
                de {{ $nom_raison_sociale?: '' }}
            </div>
        </div>
    </div>

</body>
</html>