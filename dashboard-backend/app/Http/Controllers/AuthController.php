<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use App\Services\LdapService;

class AuthController extends Controller
{
    protected $ldapService;

    public function __construct(LdapService $ldapService)
    {
        $this->ldapService = $ldapService;
    }

    public function login(Request $request)
    {
        $request->validate([
            'username' => 'required|string',
            'password' => 'required|string',
        ]);

        // 1. RECHERCHE DE L'UTILISATEUR DANS LA BASE LOCALE
        // Si l'utilisateur n'est pas déjà créé par l'admin, on refuse tout de suite.
        $user = User::where('username', $request->username)->first();

        if (!$user) {
            return response()->json([
                'success' => false,
                'message' => 'Accès refusé. Votre compte doit être autorisé par un administrateur.'
            ], 403);
        }

        // 2. AUTHENTIFICATION
        if ($user->is_ad_user) {
            // Utilisateur marqué comme AD : on vérifie contre le serveur LDAP
            $adAuthSuccess = $this->ldapService->authenticate($request->username, $request->password);
            
            if (!$adAuthSuccess) {
                return response()->json([
                    'success' => false,
                    'message' => 'Identifiants Active Directory incorrects.'
                ], 401);
            }
            
            // Mise à jour optionnelle des infos (email/nom) sans toucher au rôle
            $userInfo = $this->ldapService->getUserInfo($request->username, $request->password);
            if ($userInfo) {
                $user->update(['email' => $userInfo['email'] ?? $user->email]);
            }
        } else {
            // Utilisateur local (ex: super admin) : on vérifie le mot de passe en base
            if (!Hash::check($request->password, $user->password)) {
                return response()->json([
                    'success' => false,
                    'message' => 'Mot de passe local incorrect.'
                ], 401);
            }
        }

        // 3. GENERATION DU TOKEN (Connexion réussie)
        // On charge le rôle qui a été attribué manuellement lors de la création
        $user->load(['roleModel.permissions']);
        $token = $user->createToken('auth-token')->plainTextToken;

        return response()->json([
            'success' => true,
            'token' => $token,
            'user' => [
                'id' => $user->id,
                'username' => $user->username,
                'role' => $user->roleModel ? $user->roleModel->name : null,
            ],
            'permissions' => $user->getPermissions(),
        ]);
    }

    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();
        return response()->json(['message' => 'Déconnexion réussie']);
    }
}