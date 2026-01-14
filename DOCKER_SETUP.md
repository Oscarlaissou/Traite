# Docker Setup Guide

Ce guide explique comment dockeriser votre application avec Docker Desktop.

## Prérequis

- Docker Desktop installé sur votre machine
- Docker Compose installé (normalement inclus avec Docker Desktop)

## Structure du projet

Votre projet est divisé en deux parties principales :
- `dashboard-backend` : Application Laravel (API)
- `dashboard-frontend` : Application React

## Démarrage rapide

1. Ouvrez un terminal dans le répertoire racine de votre projet
2. Exécutez la commande suivante :

```bash
docker-compose up -d
```

Cela démarrera :
- Une base de données MySQL
- L'API Laravel sur le port 8000
- L'interface React sur le port 3000

## Accès à l'application

- Frontend : http://localhost:3000
- Backend API : http://localhost:8000
- Base de données : localhost:3306 (accessible depuis votre machine hôte)

## Configuration de l'application

Lors du premier démarrage, l'application va :
- Créer automatiquement la base de données
- Générer la clé d'application Laravel
- Exécuter les migrations
- Construire les fichiers statiques du frontend

## Commandes utiles

- `docker-compose up -d` : Démarrer les services en arrière-plan
- `docker-compose down` : Arrêter et supprimer les conteneurs
- `docker-compose logs -f` : Voir les logs des services
- `docker-compose exec backend bash` : Accéder au conteneur backend
- `docker-compose exec db mysql -u projet_traite_user -p projet_traite` : Accéder à la base de données

## Variables d'environnement

Le fichier `.env` est généré automatiquement à partir de `.env.example` lors du démarrage du conteneur backend.

## Dépannage

Si vous rencontrez des problèmes :
1. Assurez-vous que les ports 3000, 8000 et 3306 ne sont pas utilisés
2. Vérifiez les logs avec `docker-compose logs`
3. Redémarrez les services avec `docker-compose restart`

## Persistance des données

Les données de la base de données sont persistantes grâce à un volume Docker (`db_data`).