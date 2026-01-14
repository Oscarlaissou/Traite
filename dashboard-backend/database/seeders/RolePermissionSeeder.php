<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use App\Models\Role;
use App\Models\Permission;

class RolePermissionSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        // Récupérer toutes les permissions
        $permissions = Permission::all()->pluck('id', 'name')->toArray();
        
        // Rôles et leurs permissions
        $roles = [
            'super_admin' => [
                'access_dashboard',
                'view_traites',
                'create_traites',
                'edit_traites',
                'delete_traites',
                'view_clients',
                'create_clients',
                'edit_clients',
                'delete_clients',
                'manage_company_info',
                'manage_users',
                'manage_pending_clients', // Super admin a accès aux clients en attente
            ],
            'admin' => [
                'access_dashboard',
                'view_traites',
                'create_traites',
                'edit_traites',
                'delete_traites',
                'view_clients',
                'create_clients',
                'edit_clients',
                'delete_clients',
                'manage_pending_clients', // Admin a accès aux clients en attente
            ],
            'traites_manager' => [
                'access_dashboard',
                'view_traites',
                'create_traites',
                'edit_traites',
                'delete_traites',
            ],
            'clients_manager' => [
                'access_dashboard',
                'view_clients',
                'create_clients',
                'edit_clients',
                'delete_clients',
                // Pas de permission 'manage_pending_clients' pour les gestionnaires de clients
            ],
        ];

        foreach ($roles as $roleName => $rolePermissions) {
            // Créer ou mettre à jour le rôle
            $role = Role::updateOrCreate(
                ['name' => $roleName],
                ['description' => ucfirst(str_replace('_', ' ', $roleName))]
            );
            
            // Attacher les permissions au rôle
            $permissionIds = array_intersect_key($permissions, array_flip($rolePermissions));
            $role->permissions()->sync(array_values($permissionIds));
        }
    }
}