<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Lettre de Change</title>
<style>
    body { 
        font-family: 'Times New Roman', Times, serif; 
        font-size: 13px; 
        color: #000; 
        background-color: #f0f0f0; 
        display: flex; 
        justify-content: center; 
        padding: 0; 
        margin: 0; 
    }
    .container { width: 100%; max-width: 850px; min-height: 950px; /* Hauteur augmentée */ background-color: #fff; padding: 28px 20px; box-sizing: border-box; margin: 20px; }
    .flex-container { display: flex; justify-content: space-between; gap: 0; }
    .header { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 15px; position: relative; }
    .header-left { font-family: 'Roboto', sans-serif; z-index: 10; position: relative; padding-right: 50px; text-align: center; }
    .header-center { position: relative; flex-grow: 1; text-align: center; }
    .header-right { display: flex; gap: 7px; width: 65%; z-index: 1; }
    .header-right .boxed-info { border: 1px solid #000; padding: 8px 12px; display: flex;  gap: 12px; white-space: nowrap; font-size: 14px; min-width: 200px; align-items: center; text-align: center;}
 
    .double-line-container { position: absolute; top: 20px; left: 0; height: 14px; }
    .double-line { width: 240px; height: 5px; border-top: 1px solid black; border-bottom: 1px solid black; margin: 15px; margin-left: 5px; }
    .double-line-spacer { position: absolute; top: 7px; left: 0; width: 200px; height: 1px; border-top: 1px solid transparent; margin: 0; }
    .main-content { align-items: flex-start; }
    .left-column { width: 55%; padding-right: 30px; text-align: center; margin-top: 20px; display: flex; flex-direction: column; align-items: center; }
    .right-column { width: 100%; margin-top: 20px; }
    h2 { font-family: 'Roboto', sans-serif; font-size: 15px; font-weight: 700; margin-top: 12px; margin-bottom: 6px; letter-spacing: 1px; }
    .section-line { border-bottom: 1px solid #000; margin: 7px 0 4px 0; width: 82%; padding-top: 30px; padding-bottom: 25px; }
    .avaliste-line { display: flex; align-items: center; width: 100%; margin-bottom: 5px; }
    .avaliste-line span { margin-right: 6px; padding-top: 10px; font-size: 12px; }
    .avaliste-line div { flex-grow: 1; border-bottom: 1px solid black; margin-top: 20px; padding-bottom: 10px; }
    .boxed-area { border: 1px solid #000; padding: 7px 2px; height: 108px; margin-top: 5px; position: relative; text-align: center; }
    .boxed-area .label {  font-family: 'Roboto', sans-serif; font-size: 14px; margin-top: 0; }
    .boxed-area .value { margin-top: 4px;  font-size: 13px; }
    .signature-area { text-align: left; margin-top: 0; margin-left: 4px; }
    .signature-box { border: 1px solid #000; width: 90px; height: 17px; line-height: 17px; margin-top: 5px; padding: 0; text-align: center; font-size: 13px; }
    .signature-caption { font-size: 11px; margin-top: 1px; width: 90%; max-width: 360px; line-height: 1.2; padding-top: 8px; text-align: center; margin-left: auto; margin-right: auto; }
    hr.dotted-separator { border: none; border-top: 2px dotted #000; margin: 20px 0 7px 0; }
    /* Ajustement des colonnes du bas */
    .domiciliation-left-column { width: 60%; }
    .correspondence-section { width: 38%; border-left: 1px dotted #000; padding-left: 15px; font-size: 12px; }
    /* Ajout d'espace entre les paragraphes de la section de droite */
    .correspondence-section p { line-height: 1.4; margin-bottom: 25px; }
    .lettre-de-change { border-collapse: collapse; width: 95%; font-size: 13px; table-layout: fixed; margin-top: 0; }
    .lettre-de-change td { border: 1px solid black; padding: 2px 4px; text-align: center; vertical-align: top; font-size: 13px; }
    .center-text { text-align: center; }
    .bold-text { font-weight: bold; }
    .long-text { text-align: left; line-height: 1.1; }
    /* Ajout d'espace entre les paragraphes pour occuper l'espace */
    .long-text p { margin-bottom: 14px; }
    .payment-text-block { text-align: left; margin-bottom: 12px; }
    .single-line { border: none; border-top: 1px solid black; margin-right: 40px; margin-left: 45px; height: 0; }
    .footer-line { border: none; border-top: 1px solid black; margin-top: 6px; margin-left: 30px; width: 250px; }
    .money { white-space: nowrap; font-variant-numeric: tabular-nums; }

    /* Media queries pour responsive design */
    @media (max-width: 768px) {
        body { padding: 5px; }
        .container { padding: 15px 10px; min-height: auto; }
        .header { flex-direction: column; align-items: center; gap: 10px; }
        .header-left { padding-right: 0; }
        .header-right { width: 100%; justify-content: center; flex-wrap: wrap; }
        .header-right .boxed-info { min-width: 150px; font-size: 12px; }
        .main-content { flex-direction: column; }
        .left-column { width: 100%; padding-right: 0; }
        .right-column { width: 100%; }
        .flex-container { flex-direction: column; gap: 10px; }
        .domiciliation-left-column { width: 100%; }
        .correspondence-section { width: 100%; border-left: none; border-top: 1px dotted #000; padding-left: 0; padding-top: 10px; }
        .lettre-de-change { font-size: 11px; }
        .lettre-de-change td { padding: 1px 2px; font-size: 11px; }
        .boxed-area { width: 100% !important; margin-bottom: 10px; }
        .signature-area { width: 100%; text-align: center; }
    }

    @media (max-width: 480px) {
        .container { padding: 10px 5px; }
        .header-right .boxed-info { min-width: 120px; font-size: 11px; padding: 6px 8px; }
        .lettre-de-change { font-size: 10px; }
        .lettre-de-change td { padding: 1px; font-size: 10px; }
        .boxed-area { height: auto; padding: 5px; }
        .signature-box { width: 70px; height: 15px; font-size: 11px; }
        .signature-caption { font-size: 8px; }
        .double-line { width: 200px; }
        .single-line { margin-right: 20px; margin-left: 25px; }
        .footer-line { width: 200px; }
    }

    @media print {
        body { 
            padding: 0; 
            background-color: #fff; 
            margin: 0; 
            zoom: 90%;
        }
        .container { 
            width: 100%; 
            max-width: none; 
            box-shadow: none; 
            padding: 28px 20px; 
            margin: 0; 
        }
    }

</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div class="header-left">{{ $rangeText }}</div>
        <div class="double-line-container">
            <div class="double-line"></div>
            <div class="double-line-spacer"></div>
        </div>
        <div class="header-center">
            <strong>{{ $ville }} Le <span class="highlight-yellow">{{ $date_emission }}</span></strong>
        </div>
        <div class="header-right">
            <div class="boxed-info">
                <span>ECHEANCE AU :</span>
                <span class="highlight-yellow">{{ $echeance }}</span>
            </div>
            <div class="boxed-info">
                <span>B.P.F.</span>
                <span class="highlight-green money">{{ $montant_tranche }}</span>
            </div>
        </div>
    </div>
    <div class="main-content flex-container">
        <div class="left-column">
            <h2>ACCEPTATION</h2>
            <p>Accepté, somme, date et agios</p>
            <div class="section-line"></div>
            <h2 style="margin-top: 10px;">AVAL</h2>
            <p class="signature-caption" style="margin-top: 60px;font-size: 8.5px;">Signature de l'avaliste précédée de la mention - bon pour<br> Aval en garantie de ... (nom du tiré) - écrite de sa main</p>
        </div>
        <div class="right-column">
            <div class="payment-text-block">
                <p>VEUILLEZ PAYER CONTRE CETTE LETTRE DE CHANGE A L'ORDRE DE <br> <strong>{{ $companyName ?? 'CFAO MOBILITY CAMEROON' }}</strong></p>
                <p>LA SOMME DE FRANCS &nbsp;&nbsp; <span class="highlight-green">{{ $montant_tranche_words }}</span></p>
            </div>
            <div class="avaliste-line"><span></span><div></div></div>
            <div class="avaliste-line"><span>Avaliste :</span><div></div></div>
            <div class="flex-container" style="align-items: flex-start; margin-top: 5px;">
                <div class="boxed-area" style="width: 190px;">
                    <div class="label" style="font-weight: bold;">TIRE</div>
                    <div class="value">{{ $nom_raison_sociale }}</div>
                    <div class="label" style="margin-top: 7px;font-weight: bold;">DOMICILIATION</div>
                    <div class="value">{{ $domiciliation }}</div>
                </div>
                <div class="signature-area">
                    <p style="text-align: left;padding-right: 25px;">SIGNATURE DU TIREUR</p>
                    <div class="signature-box" style="text-align: center; padding-bottom:4px;">Timbre</div>
                </div>
            </div>
        </div>
    </div>
    <div><p style="font-weight: bold; margin: 2px 0;">N° : </p></div>
    <hr class="dotted-separator" />
    <h2 style="padding-left: 48px;">AVIS DE DOMICILIATION</h2>
    <div class="flex-container" style="margin-top: 7px;">
        <div class="domiciliation-left-column">
            <table class="lettre-de-change">
                <tbody>
                    <tr>
                        <td colspan="2" class="center-text bold-text" style="font-size: 12px;">DU TIRE</td>
                        <td colspan="2" class="center-text bold-text" style="font-size: 12px;">A BANQUE DOMICILIATAIRE</td>
                    </tr>
                    <tr>
                        <td colspan="2" class="center-text table-value" style="height:30px;">{{ $nom_raison_sociale }}</td>
                        <td colspan="2" class="center-text table-value">{{ $domiciliation }}</td>
                    </tr>
                    <tr>
                        <td rowspan="2" style="width:18%; border-left: none; border-right: none;"></td>
                        <td colspan="2" rowspan="2" class="center-text" style="vertical-align: middle;">
                            <span class="bold-text">N° Compte</span><br>
                            <span class="table-value">{{ $rib }}</span>
                        </td>
                        <td rowspan="2" style="width:18%; border-left: none; border-right: none;"></td>
                    </tr>
                    <tr></tr>
                    <tr>
                        <td class="bold-text" style="text-align: center;">LETTRE DE CHANGE :</td>
                        <td class="center-text bold-text">N°</td>
                        <td class="center-text bold-text">ECHEANCE</td>
                        <td class="center-text bold-text">Montant Francs</td>
                    </tr>
                    <tr>
                        <td></td>
                        <td style="height:16px;"></td>
                        <td class="center-text highlight-yellow">{{ $echeance }}</td>
                        <td class="center-text highlight-green money">{{ $montant_tranche }}</td>
                    </tr>
                </tbody>
            </table>
            <div class="long-text" style="margin-top: 15px;">
                <p>Tiré par &nbsp; <span class="highlight-pink">{{ $companyName ?? 'CFAO MOBILITY CAMEROON' }}</span></p>
                <hr class="single-line" />
                <p>Messieurs,</p>
                <p>Nous avons domicilié à vos guichets l'effet ci-dessus désigné et nous vous prions de bien vouloir, à son échéance, le payer à vue par le débit de notre compte.</p>
                <p>Nous précisons que cet effet est irrévocable et que le bénéficiaire a accepté un paiement différé de sa créance en raison même de cette irrévocabilité.</p>
                <p>Veuillez agréer, Messieurs, nos salutations distinguées.</p>
            </div>
            <!-- Marge supérieure augmentée pour pousser le contenu vers le bas -->
            <div class="flex-container" style="margin-top: 40px; justify-content: flex-start; align-items: baseline;">
                <div>
                    Le &nbsp;&nbsp; <span class="highlight-yellow">{{ $date_emission_text_long }}</span>
                    <hr class="footer-line" />
                </div>
                <div style="margin-left: 30px;">(Signature du tiré)</div>
            </div>
        </div>
        <div class="correspondence-section">
            <p>M.</p>
            <p>Nous avons l'honneur de vous présenter une lettre de change et un avis de domiciliation s'y rapportant.</p>
            <p>Après y avoir inscrit le nom de votre banque et le N° de votre compte, veuillez bien revêtir les deux documents de vos acceptations et signatures, et nous les retourner dans les meilleurs délais.</p>
            <p>Nous vous en remercions d'avance et vous prions d'agréer nos salutations les plus distinguées.</p>
        </div>
    </div>
</div>
</body>
</html>