#!/bin/sh

# Attendre que la base de données soit prête
sleep 10

# Vérifier si le fichier .env existe, sinon le créer à partir de .env.example
if [ ! -f .env ]; then
    cp .env.example .env
fi

# Mettre à jour les variables d'environnement dans le fichier .env
sed -i "s|^APP_KEY=.*|APP_KEY=base64:REwknq/OCULg8owvGnCITDJlJdr/JPFrgvWigTIGZsw=|" .env
sed -i "s|^DB_HOST=.*|DB_HOST=db|" .env
sed -i "s|^DB_PORT=.*|DB_PORT=3306|" .env
sed -i "s|^DB_DATABASE=.*|DB_DATABASE=traite|" .env
sed -i "s|^DB_USERNAME=.*|DB_USERNAME=root|" .env
sed -i "s|^DB_PASSWORD=.*|DB_PASSWORD=root_password|" .env
sed -i "s|^FRONTEND_URL=.*|FRONTEND_URL=http://localhost:3000|" .env || echo 'FRONTEND_URL=http://localhost:3000' >> .env

# S'assurer que les dossiers de stockage ont les bonnes permissions
chown -R www-data:www-data /var/www/html/storage /var/www/html/bootstrap/cache
chmod -R 775 /var/www/html/storage /var/www/html/bootstrap/cache

# Générer la clé de l'application
php artisan key:generate --force

# Nettoyer et recréer la configuration
php artisan config:clear
php artisan config:cache

# Démarrer PHP-FPM
exec php-fpm