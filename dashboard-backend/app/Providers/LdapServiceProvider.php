<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Hash;
use App\Models\User;

class LdapServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register()
    {
        //
    }

    /**
     * Bootstrap services.
     */
    public function boot()
    {
        //
    }

    /**
     * Authenticate user against Active Directory
     */
    public function authenticate($username, $password)
    {
        // Configuration du serveur AD
        $ldapHost = env('AD_LDAP_HOST', '10.68.5.129');
        $ldapPort = env('AD_LDAP_PORT', 389);
        $baseDn = env('AD_BASE_DN', '');
        $domain = env('AD_DOMAIN', 'Cfaocorp');
        
        // Format du nom d'utilisateur pour AD
        $userDn = $domain . '\\' . $username;
        
        // Connexion au serveur LDAP
        $connection = ldap_connect($ldapHost, $ldapPort);
        
        if (!$connection) {
            \Log::error('Impossible de se connecter au serveur LDAP', [
                'host' => $ldapHost, 
                'port' => $ldapPort
            ]);
            return false;
        }
        
        // Configurer les options LDAP
        ldap_set_option($connection, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($connection, LDAP_OPT_REFERRALS, 0);
        
        // Tenter la liaison avec les identifiants fournis
        $bind = @ldap_bind($connection, $userDn, $password);
        
        if ($bind) {
            // Authentification réussie
            ldap_unbind($connection);
            return true;
        } else {
            // Authentification échouée
            $error = ldap_error($connection);
            \Log::error('Échec de l\'authentification LDAP', [
                'username' => $username,
                'error' => $error,
                'errno' => ldap_errno($connection)
            ]);
            ldap_unbind($connection);
            return false;
        }
    }

    /**
     * Create or update user in database after successful AD authentication
     */
    public function createUser($username, $password)
    {
        // Vérifier si l'utilisateur existe dans notre base de données
        $user = User::where('username', $username)->first();
        
        if (!$user) {
            // Créer un utilisateur dans notre base de données s'il n'existe pas
            $user = User::create([
                'username' => $username,
                'password' => Hash::make($password), // On stocke le mot de passe hashé même si on utilise AD
                'role_id' => null, // Peut être défini plus tard via un processus d'attribution de rôle
            ]);
        }
        
        return $user;
    }
}