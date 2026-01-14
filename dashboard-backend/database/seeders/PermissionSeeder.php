<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use App\Models\Permission;

class PermissionSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        // Permissions existantes
        $permissions = [
            ['name' => 'access_dashboard', 'description' => 'Accéder au tableau de bord'],
            ['name' => 'view_traites', 'description' => 'Voir les traites'],
            ['name' => 'create_traites', 'description' => 'Créer des traites'],
            ['name' => 'edit_traites', 'description' => 'Modifier des traites'],
            ['name' => 'delete_traites', 'description' => 'Supprimer des traites'],
            ['name' => 'view_clients', 'description' => 'Voir les clients'],
            ['name' => 'create_clients', 'description' => 'Créer des clients'],
            ['name' => 'edit_clients', 'description' => 'Modifier des clients'],
            ['name' => 'delete_clients', 'description' => 'Supprimer des clients'],
            ['name' => 'manage_company_info', 'description' => 'Gérer les informations de l\'entreprise'],
            ['name' => 'manage_users', 'description' => 'Gérer les utilisateurs'],
            // Nouvelle permission pour gérer les clients en attente
            ['name' => 'manage_pending_clients', 'description' => 'Gérer les clients en attente'],
        ];

        foreach ($permissions as $permissionData) {
            Permission::updateOrCreate(
                ['name' => $permissionData['name']],
                $permissionData
            );
        }
    }
}