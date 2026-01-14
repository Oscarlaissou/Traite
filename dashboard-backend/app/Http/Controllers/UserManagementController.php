<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use App\Models\Role;
use App\Services\LdapService;
use Illuminate\Support\Facades\Auth;

class UserManagementController extends Controller
{
    protected $ldapService;

    public function __construct(LdapService $ldapService)
    {
        $this->ldapService = $ldapService;
    }

    // Méthode pour créer un utilisateur AD
    public function createAdUser(Request $request)
    {
        $request->validate([
            'username' => 'required|string|unique:users,username',
            'role_id' => 'required|exists:roles,id',
        ]);

        // Vérifier si l'utilisateur existe dans AD
        $userExists = $this->ldapService->userExistsInAd($request->username);
        
        if (!$userExists) {
            return response()->json([
                'success' => false,
                'message' => 'L\'utilisateur n\'existe pas dans Active Directory.'
            ], 400);
        }

        // Créer l'utilisateur dans la base locale
        $user = User::create([
            'username' => $request->username,
            'password' => Hash::make('temp_password'), // Mot de passe temporaire, ne sera pas utilisé pour les utilisateurs AD
            'role_id' => $request->role_id,
            'is_ad_user' => true,
        ]);

        return response()->json([
            'success' => true,
            'message' => 'Utilisateur AD créé avec succès',
            'user' => $user
        ]);
    }

    // Méthode pour vérifier si un utilisateur existe dans AD
    public function checkAdUser(Request $request)
    {
        $request->validate([
            'username' => 'required|string',
            'password' => 'required|string',
        ]);

        $adAuthSuccess = $this->ldapService->authenticate($request->username, $request->password);
        
        if ($adAuthSuccess) {
            $userInfo = $this->ldapService->getUserInfo($request->username, $request->password);
            return response()->json([
                'success' => true,
                'user_info' => $userInfo
            ]);
        } else {
            return response()->json([
                'success' => false,
                'message' => 'Identifiants incorrects ou utilisateur inexistant dans AD.'
            ], 400);
        }
    }
}