# Fonctionnalité de Déconnexion Automatique

## Description

Cette fonctionnalité implémente un système de déconnexion automatique après 24 heures d'inactivité pour l'application. Elle vise à résoudre les problèmes d'erreurs fetch dues à des tokens d'authentification expirés.

## Fonctionnalités implémentées

1. **Détection d'inactivité** : Le système surveille les actions de l'utilisateur (clics, déplacements de souris, frappes au clavier, défilement, etc.)
2. **Déconnexion automatique** : L'utilisateur est automatiquement déconnecté après 24 heures d'inactivité
3. **Gestion des erreurs de fetch** : En cas d'erreur d'authentification (code 401), l'utilisateur est déconnecté automatiquement
4. **Intégration transparente** : Le composant SessionTimeout est intégré dans l'application principale sans affecter l'expérience utilisateur

## Composants modifiés

1. **SessionTimeout.jsx** : Nouveau composant qui gère le minuteur d'inactivité
2. **App.jsx** : Intégration du composant SessionTimeout
3. **useAuth.jsx** : Ajout de la fonction handleFetchError pour gérer les erreurs d'authentification
4. **ClientApprovalHistory.jsx** : Utilisation de la nouvelle fonction de gestion d'erreur
5. **ClientsHistoriquePage.jsx** : Utilisation de la nouvelle fonction de gestion d'erreur et correction de l'état des activités

## Configuration

La durée d'inactivité est configurée à 24 heures (24 * 60 * 60 * 1000 ms) dans la constante `INACTIVITY_TIMEOUT` du composant SessionTimeout.

## Utilisation

Le système fonctionne automatiquement une fois intégré. Lorsqu'un utilisateur est inactif pendant plus de 24 heures, il est automatiquement déconnecté et redirigé vers la page de connexion.

En cas d'erreurs de fetch dues à des tokens expirés, l'utilisateur est également déconnecté automatiquement et redirigé vers la page de connexion.