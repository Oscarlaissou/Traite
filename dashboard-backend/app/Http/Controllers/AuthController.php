<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use Illuminate\Support\Facades\Log;
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

        // Essayer d'abord l'authentification AD
        $adAuthSuccess = $this->ldapService->authenticate($request->username, $request->password);
        
        if ($adAuthSuccess) {
            // L'utilisateur s'est authentifié avec succès via AD
            // Récupérer les informations de l'utilisateur depuis AD
            $userInfo = $this->ldapService->getUserInfo($request->username, $request->password);
            
            // Créer ou mettre à jour l'utilisateur dans la base de données
            $user = $this->ldapService->createUser($request->username, $request->password, $userInfo);
            
            // Synchroniser les rôles basés sur les groupes AD si les informations sont disponibles
            if ($userInfo) {
                $this->ldapService->syncUserRoles($user, $userInfo);
            }

            // Charger la relation role avec ses permissions
            $user->load(['roleModel.permissions']);

            $token = $user->createToken('auth-token')->plainTextToken;

            return response()->json([
                'success' => true,
                'token' => $token,
                'user' => [
                    'id' => $user->id,
                    'username' => $user->username,
                    'role_id' => $user->role_id,
                    'role' => $user->roleModel ? [
                        'id' => $user->roleModel->id,
                        'name' => $user->roleModel->name,
                        'description' => $user->roleModel->description,
                    ] : null,
                ],
                'permissions' => $user->getPermissions(),
            ]);
        } else {
            // Si l'authentification AD échoue, essayer l'authentification locale
            $user = User::where('username', $request->username)->first();

            // Si c'est un utilisateur AD, on ne devrait pas arriver ici normalement
            if ($user && $user->is_ad_user) {
                return response()->json([
                    'success' => false,
                    'message' => 'Cet utilisateur utilise l\'authentification Active Directory. Veuillez vérifier vos identifiants.'
                ], 401);
            }

            if (!$user || !Hash::check($request->password, $user->password)) {
                return response()->json([
                    'success' => false,
                    'message' => 'Nom d\'utilisateur ou mot de passe incorrect.'
                ], 401);
            }

            // Charger la relation role avec ses permissions
            $user->load(['roleModel.permissions']);

            $token = $user->createToken('auth-token')->plainTextToken;

            return response()->json([
                'success' => true,
                'token' => $token,
                'user' => [
                    'id' => $user->id,
                    'username' => $user->username,
                    'role_id' => $user->role_id,
                    'role' => $user->roleModel ? [
                        'id' => $user->roleModel->id,
                        'name' => $user->roleModel->name,
                        'description' => $user->roleModel->description,
                    ] : null,
                ],
                'permissions' => $user->getPermissions(),
            ]);
        }
    }

    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();
        return response()->json(['message' => 'Déconnexion réussie']);
    }

    public function user(Request $request)
    {
        $user = $request->user();
        
        // Charger la relation role avec ses permissions
        $user->load(['roleModel.permissions']);
        
        return response()->json([
            'user' => [
                'id' => $user->id,
                'username' => $user->username,
                'role_id' => $user->role_id,
                'role' => $user->roleModel ? [
                    'id' => $user->roleModel->id,
                    'name' => $user->roleModel->name,
                    'description' => $user->roleModel->description,
                ] : null,
            ],
            'permissions' => $user->getPermissions(),
        ]);
    }
}