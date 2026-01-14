<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Models\Role;
use App\Models\Permission;
use App\Models\OrganizationSetting;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;

class UserController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        $users = User::select('id', 'username', 'role', 'role_id', 'ville', 'is_ad_user', 'created_at', 'updated_at')
                     ->with('roleModel') // Charger uniquement la relation de rôle sans les permissions
                     ->get();
        return response()->json($users);
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        // Vérifier s'il y a déjà un super_admin et si on essaie d'en créer un autre
        if ($request->role === 'super_admin' && User::where('role', 'super_admin')->exists()) {
            return response()->json(['error' => 'Il ne peut y avoir qu\'un seul super administrateur'], 400);
        }
        
        $request->validate([
            'username' => 'required|string|max:255|unique:users',
            'password' => $request->boolean('is_ad_user') ? 'nullable' : 'required|string|min:8',
            'role' => 'required|string|in:traites_manager,clients_manager,admin,super_admin',
            'ville' => 'nullable|string|max:255',
            'is_ad_user' => 'boolean',
        ]);

        // Map role name to role_id
        $role = Role::where('name', $request->role)->first();
        $roleId = $role ? $role->id : null;

        // Prepare user data
        $userData = [
            'username' => $request->username,
            'role' => $request->role,
            'role_id' => $roleId,
            'ville' => $request->ville,
            'is_ad_user' => $request->boolean('is_ad_user', false),
        ];

        // Only include password if not AD user or if password is provided
        if (!$request->boolean('is_ad_user') && !empty($request->password)) {
            $userData['password'] = Hash::make($request->password);
        }

        $user = User::create($userData);

        return response()->json($user, 201);
    }

    /**
     * Display the specified resource.
     */
    public function show(string $id)
    {
        $user = User::findOrFail($id);
        return response()->json($user);
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, string $id)
    {
        $user = User::findOrFail($id);
        
        // Vérifier s'il y a déjà un super_admin et si on essaie d'en créer un autre
        if ($request->role === 'super_admin' && User::where('role', 'super_admin')->where('id', '!=', $id)->exists()) {
            return response()->json(['error' => 'Il ne peut y avoir qu\'un seul super administrateur'], 400);
        }

        $request->validate([
            'username' => ['required', 'string', 'max:255', Rule::unique('users')->ignore($user->id)],
            'password' => $request->boolean('is_ad_user') ? 'nullable' : 'nullable|string|min:8',
            'role' => 'required|string|in:traites_manager,clients_manager,admin,super_admin',
            'ville' => 'nullable|string|max:255',
            'is_ad_user' => 'boolean',
        ]);

        // Map role name to role_id
        $role = Role::where('name', $request->role)->first();
        $roleId = $role ? $role->id : null;

        $userData = [
            'username' => $request->username,
            'role' => $request->role,
            'role_id' => $roleId,
            'ville' => $request->ville,
            'is_ad_user' => $request->boolean('is_ad_user', $user->is_ad_user),
        ];
        
        // Only update password if provided and user is not AD user
        if ($request->filled('password') && !$request->boolean('is_ad_user')) {
            $userData['password'] = Hash::make($request->password);
        } elseif ($request->filled('is_ad_user') && $request->boolean('is_ad_user')) {
            // If user is marked as AD user, remove the password
            $userData['password'] = null;
        }

        $user->update($userData);
        
        // Si le rôle a changé, supprimer les permissions directes pour utiliser celles du rôle
        if ($user->wasChanged('role') || $user->wasChanged('role_id')) {
            // Supprimer toutes les permissions directes
            $user->directPermissions()->detach();
            
            Log::info('User role changed, cleared direct permissions', [
                'user_id' => $user->id,
                'new_role' => $request->role
            ]);
        }

        return response()->json($user);
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(string $id)
    {
        $user = User::findOrFail($id);
        
        // Prevent deleting super admin
        if ($user->role === 'super_admin') {
            return response()->json(['error' => 'Cannot delete the super administrator'], 400);
        }
        
        $user->delete();
        
        return response()->json(['message' => 'User deleted successfully']);
    }
    
    /**
     * Get all permissions
     */
    public function getPermissions()
    {
        $permissions = Permission::all();
        return response()->json($permissions);
    }
    
    /**
     * Get user permissions
     */
    public function getUserPermissions(string $id)
    {
        $user = User::findOrFail($id);
        $permissions = $user->getPermissions();
        
        // Log the permissions for debugging
        Log::info('Getting user permissions', [
            'user_id' => $id,
            'permissions' => $permissions
        ]);
        
        return response()->json($permissions);
    }
    
    /**
     * Update user permissions
     */
    public function updateUserPermissions(Request $request, string $id)
    {
        $user = User::findOrFail($id);
        
        $request->validate([
            'permissions' => 'required|array',
            'permissions.*' => 'string|exists:permissions,name'
        ]);
        
        // Log the incoming permissions for debugging
        Log::info('Updating user permissions', [
            'user_id' => $id,
            'incoming_permissions' => $request->permissions
        ]);
        
        // Set user permissions
        $user->setPermissions($request->permissions);
        
        // Get updated permissions to confirm
        $updatedPermissions = $user->getPermissions();
        
        Log::info('User permissions updated', [
            'user_id' => $id,
            'updated_permissions' => $updatedPermissions
        ]);
        
        return response()->json([
            'message' => 'Permissions updated successfully',
            'permissions' => $updatedPermissions
        ]);
    }
    
    /**
     * Get organization settings
     */
    public function getOrganizationSettings()
    {
        $settings = OrganizationSetting::first();
        
        if (!$settings) {
            // Créer une entrée vide si elle n'existe pas
            $settings = OrganizationSetting::create([
                'name' => null,
                'logo' => null
            ]);
        }
        
        // Retourner l'URL complète du logo
        $response = [
            'id' => $settings->id,
            'name' => $settings->name,
            'logo' => $settings->logo ? url('storage/' . $settings->logo) : null,
            'created_at' => $settings->created_at,
            'updated_at' => $settings->updated_at
        ];
        
        return response()->json($response);
    }
    
    /**
     * Update organization settings
     */
    public function updateOrganizationSettings(Request $request)
    {
        try {
            $request->validate([
                'name' => 'nullable|string|max:255',
                'logo' => 'nullable|image|mimes:jpeg,png,jpg,gif,svg|max:2048'
            ]);
            
            // Récupérer ou créer les paramètres
            $settings = OrganizationSetting::first();
            if (!$settings) {
                $settings = new OrganizationSetting();
            }
            
            // Mettre à jour le nom
            if ($request->has('name')) {
                $settings->name = $request->name;
            }
            
            // Gérer l'upload du logo
            if ($request->hasFile('logo')) {
                // Supprimer l'ancien logo si il existe
                if ($settings->logo && Storage::disk('public')->exists($settings->logo)) {
                    Storage::disk('public')->delete($settings->logo);
                }
                
                // Stocker le nouveau logo
                $logoPath = $request->file('logo')->store('logos', 'public');
                $settings->logo = $logoPath;
            }
            
            $settings->save();
            
            // Retourner l'URL complète du logo
            $response = [
                'id' => $settings->id,
                'name' => $settings->name,
                'logo' => $settings->logo ? url('storage/' . $settings->logo) : null,
                'created_at' => $settings->created_at,
                'updated_at' => $settings->updated_at
            ];
            
            return response()->json($response);
        } catch (\Exception $e) {
            Log::error('Error updating organization settings: ' . $e->getMessage(), [
                'exception' => $e,
                'request_data' => $request->all()
            ]);
            
            return response()->json([
                'error' => 'Failed to update organization settings',
                'message' => $e->getMessage()
            ], 500);
        }
    }
    
    /**
     * Get user notifications
     */
    public function getNotifications(Request $request)
    {
        $user = $request->user();
        $notifications = $user->notifications()->orderBy('created_at', 'desc')->get();
        
        return response()->json($notifications);
    }
    
    /**
     * Mark notification as read and delete it
     */
    public function markNotificationAsRead(Request $request, $id)
    {
        $user = $request->user();
        $notification = $user->notifications()->where('id', $id)->first();
        
        if ($notification) {
            // Delete the notification instead of just marking it as read
            $notification->delete();
            return response()->json(['message' => 'Notification deleted']);
        }
        
        return response()->json(['error' => 'Notification not found'], 404);
    }
}