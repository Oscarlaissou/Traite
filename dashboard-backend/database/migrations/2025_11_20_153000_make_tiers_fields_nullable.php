<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('tiers', function (Blueprint $table) {
            $table->string('numero_compte', 20)->nullable()->change();
            $table->string('bp', 20)->nullable()->change();
            $table->string('adresse_geo_1', 100)->nullable()->change();
            $table->string('adresse_geo_2', 100)->nullable()->change();
            $table->string('telephone', 20)->nullable()->change();
            $table->string('email', 100)->nullable()->change();
            $table->string('n_contribuable', 20)->nullable()->change();
        });
    }

    public function down(): void
    {
        Schema::table('tiers', function (Blueprint $table) {
            $table->string('numero_compte', 20)->change();
            $table->string('bp', 20)->change();
            $table->string('adresse_geo_1', 100)->change();
            $table->string('adresse_geo_2', 100)->change();
            $table->string('telephone', 20)->change();
            $table->string('email', 100)->change();
            $table->string('n_contribuable', 20)->change();
        });
    }
};