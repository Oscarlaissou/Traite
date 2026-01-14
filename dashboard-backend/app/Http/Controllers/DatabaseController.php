<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class DatabaseController extends Controller
{
    public function checkConnection()
    {
        try {
            $connection = DB::connection()->getPdo();
            $config = DB::connection()->getConfig();  // Récupère toute la config d'un coup

            $databaseName = $config['database'] ?? 'Non défini';  // Valeur par défaut si manquant
            $driver = $config['driver'] ?? 'Inconnu';
            $host = $config['host'] ?? 'Inconnu';
            $version = $connection->getAttribute(\PDO::ATTR_SERVER_VERSION);

            return response()->json([
                'connected' => true,
                'details' => [
                    'driver' => $driver,
                    'database' => $databaseName,
                    'host' => $host,
                    'version' => $version,
                ]
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'connected' => false,
                'details' => [
                    'error' => $e->getMessage()
                ]
            ], 500);
        }
    }
}