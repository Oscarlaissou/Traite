<?php
namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\User;
use Illuminate\Support\Facades\Hash;

class UserSeeder extends Seeder
{
    public function run()
    {
        // Utilisateur Admin
        User::create([
            'username' => 'admin',
            'password' => Hash::make('admin'),
            'role' => 'admin',
            'ville' => 'Douala'
        ]);

        // Utilisateur Test
        User::create([
            'username' => 'testuser',
            'password' => Hash::make('password123'),
            'role' => 'user',
            'ville' => 'Yaoundé'
        ]);

        // Utilisateur Manager
        User::create([
            'username' => 'manager',
            'password' => Hash::make('password123'),
            'role' => 'manager',
            'ville' => 'Bafoussam'
        ]);
    }
}