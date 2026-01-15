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
        if (!config('ldap.enabled', true)) return false;

        if (!function_exists('ldap_connect')) {
            Log::error('L\'extension LDAP n\'est pas disponible');
            return false;
        }

        $ldapHost = config('ldap.host');
        $ldapPort = config('ldap.port');
        $domain = config('ldap.domain');
        
        // AJUSTEMENT : Format UPN (identifiant@domaine) pour plus de stabilité
        $userDn = $username . '@' . $domain;
        
        $connection = @ldap_connect($ldapHost, $ldapPort);
        if (!$connection) return false;
        
        ldap_set_option($connection, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($connection, LDAP_OPT_REFERRALS, 0);
        
        $bind = @ldap_bind($connection, $userDn, $password);
        
        if ($bind) {
            ldap_unbind($connection);
            return true;
        } else {
            Log::error('Échec auth LDAP', ['user' => $userDn, 'error' => ldap_error($connection)]);
            ldap_unbind($connection);
            return false;
        }
    }

    /**
     * Get user information from AD
     */
    public function getUserInfo($username, $password)
    {
        if (!function_exists('ldap_connect')) return null;

        $ldapHost = config('ldap.host');
        $ldapPort = config('ldap.port');
        $baseDn = config('ldap.base_dn');
        $domain = config('ldap.domain');
        
        // AJUSTEMENT : Format UPN
// Remplace l'ancienne ligne par celle-ci (plus intelligente) :
$userDn = str_contains($username, '@') ? $username : $username . '@' . config('ldap.domain');        
        $connection = @ldap_connect($ldapHost, $ldapPort);
        if (!$connection) return null;
        
        ldap_set_option($connection, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($connection, LDAP_OPT_REFERRALS, 0);
        
        $bind = @ldap_bind($connection, $userDn, $password);
        
        if ($bind) {
            $searchFilter = "(sAMAccountName={$username})";
            // AJUSTEMENT : On supprime l'erreur si l'objet n'est pas trouvé
            $result = @ldap_search($connection, $baseDn, $searchFilter);
            
            if ($result) {
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
        }
        
        @ldap_unbind($connection);
        return null;
    }

    /**
     * Check if user exists in AD without authentication (Requires Service User)
     */
    public function userExistsInAd($username)
    {
        if (!function_exists('ldap_connect')) return false;

        $serviceUser = config('ldap.service_user');
        $servicePassword = config('ldap.service_password');
        
        if (!$serviceUser || !$servicePassword) return false;
        
        $connection = @ldap_connect(config('ldap.host'), config('ldap.port'));
        if (!$connection) return false;
        
        ldap_set_option($connection, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($connection, LDAP_OPT_REFERRALS, 0);
        
        $serviceDn = $serviceUser . '@' . config('ldap.domain');
        $bind = @ldap_bind($connection, $serviceDn, $servicePassword);
        
        if ($bind) {
            $result = @ldap_search($connection, config('ldap.base_dn'), "(sAMAccountName={$username})");
            $entries = ldap_get_entries($connection, $result);
            ldap_unbind($connection);
            return $entries['count'] > 0;
        }
        
        return false;
    }

    public function createUser($username, $password, $userInfo = null)
    {
        $user = User::where('username', $username)->first();
        
        if (!$user) {
            $user = User::create([
                'username' => $username,
                'password' => null,
                'role_id' => $this->getDefaultRoleId(),
                'is_ad_user' => true,
            ]);
        } else if (!$user->is_ad_user) {
            $user->update(['password' => null, 'is_ad_user' => true]);
        }
        
        return $user;
    }

    private function getDefaultRoleId()
    {
        $role = Role::where('name', config('ldap.default_role'))->first();
        return $role ? $role->id : (Role::first() ? Role::first()->id : null);
    }

    public function syncUserRoles($user, $userInfo = null)
    {
        if (!$userInfo || !isset($userInfo['memberOf'])) return;
        
        $adGroupToRole = [
            'CN=Administrateurs' => 'admin',
            'CN=Gestionnaires' => 'gestionnaire',
            'CN=Utilisateurs' => 'utilisateur',
        ];
        
        $allRoles = Role::all()->keyBy('name');
        
        foreach ($userInfo['memberOf'] as $group) {
            foreach ($adGroupToRole as $adGroup => $roleName) {
                if (strpos($group, $adGroup) !== false) {
                    $role = $allRoles->get($roleName);
                    if ($role) {
                        if ($user->role_id !== $role->id) {
                            $user->update(['role_id' => $role->id]);
                        }
                        return; // On s'arrête au premier rôle trouvé
                    }
                }
            }
        }
    }
}