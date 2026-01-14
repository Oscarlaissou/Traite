# Intégration GitHub

Ce document explique comment intégrer votre projet avec GitHub et utiliser les fonctionnalités de CI/CD.

## Initialisation du dépôt

1. Créez un nouveau dépôt sur GitHub
2. Dans votre terminal, allez dans le répertoire de votre projet
3. Exécutez les commandes suivantes :

```bash
git init
git add .
git commit -m "Initial commit with Docker configuration"
git branch -M main
git remote add origin https://github.com/VOTRE_COMPTE_GITHUB/NOM_DU_DEPOT.git
git push -u origin main
```

## Configuration des secrets GitHub

Pour que le workflow GitHub Actions fonctionne correctement, vous devez configurer les secrets suivants dans les paramètres de votre dépôt GitHub :

1. Allez dans `Settings` > `Secrets and variables` > `Actions`
2. Ajoutez les secrets suivants :
   - `DOCKERHUB_USERNAME` : Votre nom d'utilisateur Docker Hub
   - `DOCKERHUB_TOKEN` : Votre token d'accès Docker Hub (généré dans les paramètres de votre compte Docker Hub)

## Workflow CI/CD

Le workflow défini dans `.github/workflows/docker-deploy.yml` :
- Se déclenche lors des pushes sur les branches `main` et `master`
- Construit automatiquement les images Docker pour le backend et le frontend
- Pousse les images sur Docker Hub
- Tag les images avec le tag `latest`

## Déploiement en production

Pour déployer en production, utilisez le fichier `docker-compose.prod.yml` :

```bash
docker-compose -f docker-compose.prod.yml up -d
```

## Processus de développement

1. Faites vos modifications localement
2. Committez et poussez vers GitHub
3. Le workflow CI/CD se déclenche automatiquement
4. Les nouvelles images sont construites et poussées sur Docker Hub
5. Vous pouvez ensuite déployer les nouvelles versions sur votre serveur

## Bonnes pratiques

- Utilisez des tags spécifiques pour les déploiements en production
- Gardez vos secrets sécurisés dans les paramètres de votre dépôt
- Utilisez des branches pour le développement et fusionnez dans `main` pour la production