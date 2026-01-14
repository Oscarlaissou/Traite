<?php

namespace App\Services;

use Illuminate\Support\Facades\Hash;
use App\Models\User;
use App\Models\Role;
use Illuminate\Support\Facades\Log;

class LdapService
{
    /**
     * Authenticate user against Active Directory
     */
    public function authenticate($username, $password)
    {
        // Vérifier si l'authentification AD est activée
        if (!config('ldap.enabled', true)) {
            return false;
        }

        // Vérifier si l'extension LDAP est disponible
        if (!function_exists('ldap_connect')) {
            Log::error('L\'extension LDAP n\'est pas disponible sur ce serveur');
            return false;
        }

        // Vérifier si l'extension LDAP est vraiment fonctionnelle
        $ldapFunctions = ['ldap_connect', 'ldap_bind', 'ldap_search', 'ldap_get_entries', 'ldap_error', 'ldap_errno'];
        foreach ($ldapFunctions as $function) {
            if (!function_exists($function)) {
                Log::error("La fonction LDAP {$function} n'est pas disponible");
                return false;
            }
        }

        // Configuration du serveur AD
        $ldapHost = config('ldap.host');
        $ldapPort = config('ldap.port');
        $baseDn = config('ldap.base_dn');
        $domain = config('ldap.domain');
        
        // Format du nom d'utilisateur pour AD
        $userDn = $domain . '\\' . $username;
        
        // Connexion au serveur LDAP
        $connection = ldap_connect($ldapHost, $ldapPort);
        
        if (!$connection) {
            Log::error('Impossible de se connecter au serveur LDAP', [
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
            Log::error('Échec de l\'authentification LDAP', [
                'username' => $username,
                'error' => $error,
                'errno' => ldap_errno($connection)
            ]);
            ldap_unbind($connection);
            return false;
        }
    }

    /**
     * Get user information from AD
     */
    public function getUserInfo($username, $password)
    {
        // Vérifier si l'extension LDAP est disponible
        if (!function_exists('ldap_connect')) {
            Log::error('L\'extension LDAP n\'est pas disponible sur ce serveur');
            return null;
        }

        $ldapHost = config('ldap.host');
        $ldapPort = config('ldap.port');
        $baseDn = config('ldap.base_dn');
        $domain = config('ldap.domain');
        
        $userDn = $domain . '\\' . $username;
        
        $connection = ldap_connect($ldapHost, $ldapPort);
        
        if (!$connection) {
            return null;
        }
        
        ldap_set_option($connection, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($connection, LDAP_OPT_REFERRALS, 0);
        
        $bind = @ldap_bind($connection, $userDn, $password);
        
        if ($bind) {
            // Rechercher l'utilisateur dans AD pour obtenir des informations supplémentaires
            $searchFilter = "(sAMAccountName={$username})";
            $result = ldap_search($connection, $baseDn, $searchFilter);
            $entries = ldap_get_entries($connection, $result);
            
            ldap_unbind($connection);
            
            if ($entries['count'] > 0) {
                $userEntry = $entries[0];
                return [
                    'username' => $username,
                    'email' => $userEntry['mail'][0] ?? null,
                    'displayName' => $userEntry['displayname'][0] ?? null,
                    'memberOf' => $userEntry['memberof'] ?? []
                ];
            }
        }
        
        ldap_unbind($connection);
        return null;
    }

    /**
     * Check if user exists in AD without authentication
     */
    public function userExistsInAd($username)
    {
        // Vérifier si l'extension LDAP est disponible
        if (!function_exists('ldap_connect')) {
            Log::error('L\'extension LDAP n\'est pas disponible sur ce serveur');
            return false;
        }

        $ldapHost = config('ldap.host');
        $ldapPort = config('ldap.port');
        $baseDn = config('ldap.base_dn');
        $domain = config('ldap.domain');
        
        // Pour vérifier l'existence sans mot de passe, nous devons utiliser un compte de service
        $serviceUser = config('ldap.service_user');
        $servicePassword = config('ldap.service_password');
        
        if (!$serviceUser || !$servicePassword) {
            Log::error('Les identifiants du compte de service AD ne sont pas configurés');
            return false;
        }
        
        $connection = ldap_connect($ldapHost, $ldapPort);
        
        if (!$connection) {
            Log::error('Impossible de se connecter au serveur LDAP', ['host' => $ldapHost, 'port' => $ldapPort]);
            return false;
        }
        
        ldap_set_option($connection, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($connection, LDAP_OPT_REFERRALS, 0);
        
        // Se connecter avec le compte de service
        $serviceUserDn = $domain . '\\' . $serviceUser;
        $bind = @ldap_bind($connection, $serviceUserDn, $servicePassword);
        
        if (!$bind) {
            Log::error('Échec de l\'authentification du compte de service LDAP');
            ldap_unbind($connection);
            return false;
        }
        
        // Rechercher l'utilisateur spécifié
        $searchFilter = "(sAMAccountName={$username})";
        $result = ldap_search($connection, $baseDn, $searchFilter);
        $entries = ldap_get_entries($connection, $result);
        
        ldap_unbind($connection);
        
        return $entries['count'] > 0;
    }

    /**
     * Create or update user in database after successful AD authentication
     */
    public function createUser($username, $password, $userInfo = null)
    {
        // Vérifier si l'utilisateur existe dans notre base de données
        $user = User::where('username', $username)->first();
        
        if (!$user) {
            // Créer un utilisateur dans notre base de données s'il n'existe pas
            $user = User::create([
                'username' => $username,
                'password' => null, // Ne pas stocker le mot de passe pour les utilisateurs AD
                'role_id' => $this->getDefaultRoleId(), // Attribuer un rôle par défaut
                'is_ad_user' => true, // Marquer comme utilisateur AD
            ]);
        } else {
            // Ne mettre à jour que si nécessaire (si ce n'est pas déjà un utilisateur AD)
            if (!$user->is_ad_user) {
                $user->update([
                    'password' => null, // Ne pas stocker le mot de passe pour les utilisateurs AD
                    'is_ad_user' => true,
                ]);
            }
        }
        
        return $user;
    }

    /**
     * Get default role ID for new AD users
     */
    private function getDefaultRoleId()
    {
        // Vous pouvez configurer un rôle par défaut pour les utilisateurs AD
        $defaultRoleName = config('ldap.default_role');
        
        $role = Role::where('name', $defaultRoleName)->first();
        
        if (!$role) {
            // Si le rôle par défaut n'existe pas, utiliser le premier rôle disponible
            $role = Role::first();
        }
        
        return $role ? $role->id : null;
    }

    /**
     * Synchronize user roles based on AD group membership
     */
    public function syncUserRoles($user, $userInfo = null)
    {
        if (!$userInfo || !isset($userInfo['memberOf'])) {
            return;
        }
        
        // Mapping des groupes AD vers les rôles de l'application
        $adGroupToRole = [
            'CN=Administrateurs' => 'admin',
            'CN=Gestionnaires' => 'gestionnaire',
            'CN=Utilisateurs' => 'utilisateur',
            // Ajoutez d'autres mappings selon vos besoins
        ];
        
        // Charger tous les rôles une seule fois
        $allRoles = \App\Models\Role::all()->keyBy('name');
        
        foreach ($userInfo['memberOf'] as $group) {
            foreach ($adGroupToRole as $adGroup => $roleName) {
                if (strpos($group, $adGroup) !== false) {
                    $role = $allRoles->get($roleName);
                    if ($role) {
                        // Ne mettre à jour que si le rôle est différent
                        if ($user->role_id !== $role->id) {
                            $user->update(['role_id' => $role->id]);
                        }
                        break;
                    }
                }
            }
        }
    }
}