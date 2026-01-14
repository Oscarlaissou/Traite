<?php

return [
    /*
    |--------------------------------------------------------------------------
    | LDAP Configuration
    |--------------------------------------------------------------------------
    |
    | Les paramètres de configuration pour l'authentification Active Directory
    |
    */

    // Adresse du serveur LDAP/AD
    'host' => env('AD_LDAP_HOST', '10.68.5.129'),

    // Port du serveur LDAP
    'port' => env('AD_LDAP_PORT', 389),

    // Base DN pour la recherche d'utilisateurs
    'base_dn' => env('AD_BASE_DN', ''),

    // Domaine AD
    'domain' => env('AD_DOMAIN', 'Cfaocorp'),

    // Rôle par défaut pour les nouveaux utilisateurs AD
    'default_role' => env('AD_DEFAULT_ROLE', 'utilisateur'),

    // Activer l'authentification AD (sinon utiliser l'authentification locale)
    'enabled' => env('AD_AUTH_ENABLED', true),

    // Compte de service pour les opérations d'administration (vérification d'existence)
    'service_user' => env('AD_SERVICE_USER', null),
    'service_password' => env('AD_SERVICE_PASSWORD', null),
];