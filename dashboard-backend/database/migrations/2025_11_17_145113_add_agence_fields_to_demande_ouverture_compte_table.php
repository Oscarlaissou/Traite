<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('demande_ouverture_compte', function (Blueprint $table) {
            $table->string('etablissement', 255)->nullable()->after('motif');
            $table->string('service', 255)->nullable()->after('etablissement');
            $table->string('nom_signataire', 255)->nullable()->after('service');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('demande_ouverture_compte', function (Blueprint $table) {
            $table->dropColumn(['etablissement', 'service', 'nom_signataire']);
        });
    }
};
