<?php

namespace App\Services;

use Illuminate\Support\Facades\Log;

class LdapService
{
    public function authenticate($username, $password)
    {
        if (!config('ldap.enabled', true)) return false;

        $ldapHost = config('ldap.host');
        $ldapPort = config('ldap.port');
        $domain = config('ldap.domain');
        
        // Format UPN (identifiant@domaine)
        $userDn = str_contains($username, '@') ? $username : $username . '@' . $domain;
        
        $connection = @ldap_connect($ldapHost, $ldapPort);
        if (!$connection) return false;
        
        ldap_set_option($connection, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($connection, LDAP_OPT_REFERRALS, 0);
        
        $bind = @ldap_bind($connection, $userDn, $password);
        
        if ($bind) {
            @ldap_unbind($connection);
            return true;
        }

        @ldap_unbind($connection);
        return false;
    }

    public function getUserInfo($username, $password)
    {
        $ldapHost = config('ldap.host');
        $ldapPort = config('ldap.port');
        $baseDn = config('ldap.base_dn');
        $domain = config('ldap.domain');
        
        $userDn = str_contains($username, '@') ? $username : $username . '@' . $domain;
        
        $connection = @ldap_connect($ldapHost, $ldapPort);
        if (!$connection) return null;
        
        ldap_set_option($connection, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($connection, LDAP_OPT_REFERRALS, 0);
        
        if (@ldap_bind($connection, $userDn, $password)) {
            $cleanUsername = explode('@', $username)[0];
            $searchFilter = "(sAMAccountName=$cleanUsername)";
            $result = @ldap_search($connection, $baseDn, $searchFilter);
            
            if ($result) {
                $entries = ldap_get_entries($connection, $result);
                if ($entries['count'] > 0) {
                    return [
                        'email' => $entries[0]['mail'][0] ?? null,
                        'displayName' => $entries[0]['displayname'][0] ?? null,
                    ];
                }
            }
        }
        return null;
    }
}