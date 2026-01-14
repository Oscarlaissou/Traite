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
            // Check if the old fields exist before trying to drop them
            if (Schema::hasColumn('demande_ouverture_compte', 'etablissement')) {
                $table->dropColumn('etablissement');
            }
            
            if (Schema::hasColumn('demande_ouverture_compte', 'service')) {
                $table->dropColumn('service');
            }
            
            if (Schema::hasColumn('demande_ouverture_compte', 'nom_signataire')) {
                $table->dropColumn('nom_signataire');
            }
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('demande_ouverture_compte', function (Blueprint $table) {
            $table->string('etablissement', 255)->nullable();
            $table->string('service', 255)->nullable();
            $table->string('nom_signataire', 255)->nullable();
        });
    }
};