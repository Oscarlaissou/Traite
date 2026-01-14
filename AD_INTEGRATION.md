# Intégration de l'authentification Active Directory

Ce document explique comment configurer l'authentification Active Directory (AD) dans l'application en conservant les rôles existants.

## Configuration requise

### 1. Extension PHP LDAP

Assurez-vous que l'extension LDAP est activée dans votre installation PHP :

```bash
# Sur Ubuntu/Debian
sudo apt-get install php-ldap
sudo systemctl restart apache2  # ou php-fpm

# Sur Windows
# Décommentez cette ligne dans votre php.ini
extension=ldap
```

### 2. Variables d'environnement

Ajoutez les variables suivantes à votre fichier `.env` :

```env
# Active Directory Configuration
AD_LDAP_HOST=10.68.5.129
AD_LDAP_PORT=389
AD_BASE_DN=DC=domaine,DC=com  # Optionnel, selon votre configuration AD
AD_DOMAIN=Cfaocorp
AD_DEFAULT_ROLE=utilisateur
AD_AUTH_ENABLED=true
```

## Fonctionnalités

### Authentification

- L'application tente d'abord d'authentifier l'utilisateur via AD
- Si l'authentification AD échoue, elle retombe sur l'authentification locale
- Les utilisateurs AD sont automatiquement créés dans la base de données locale

### Gestion des rôles

- Les utilisateurs AD reçoivent un rôle par défaut défini par `AD_DEFAULT_ROLE`
- Possibilité de synchroniser les rôles en fonction des groupes AD (à configurer dans le service)
- Les rôles et permissions sont conservés comme avant

### Informations utilisateur

- L'application peut récupérer des informations supplémentaires depuis AD (nom complet, email, groupes)
- Ces informations peuvent être utilisées pour une gestion plus fine des droits

## Configuration avancée

### Mapping des groupes AD vers les rôles

Dans le fichier `app/Services/LdapService.php`, vous pouvez configurer le mapping des groupes AD vers les rôles de l'application dans la méthode `syncUserRoles` :

```php
$adGroupToRole = [
    'CN=Administrateurs' => 'admin',
    'CN=Gestionnaires' => 'gestionnaire',
    'CN=Utilisateurs' => 'utilisateur',
    // Ajoutez d'autres mappings selon vos besoins
];
```

## Processus d'authentification

1. L'utilisateur entre ses identifiants
2. L'application tente l'authentification via AD
3. Si succès :
   - Vérifie si l'utilisateur existe dans la base locale
   - Crée l'utilisateur s'il n'existe pas
   - Attribue un rôle par défaut ou synchronise à partir des groupes AD
   - Génère un token API
4. Si échec AD :
   - Tente l'authentification locale standard
5. Retourne les informations de l'utilisateur avec ses rôles et permissions

## Points importants

- Les rôles existants sont entièrement conservés
- Les permissions fonctionnent comme avant
- L'authentification est transparente pour l'utilisateur
- L'application continue à fonctionner même si le serveur AD est inaccessible (retombe sur l'authentification locale)