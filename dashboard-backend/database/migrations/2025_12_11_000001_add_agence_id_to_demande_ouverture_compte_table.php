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
            $table->unsignedBigInteger('agence_id')->nullable()->after('motif');
            
            // Add foreign key constraint if agence table exists
            if (Schema::hasTable('agence')) {
                $table->foreign('agence_id')->references('id')->on('agence')->onDelete('set null');
            }
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('demande_ouverture_compte', function (Blueprint $table) {
            $table->dropForeign(['agence_id']);
            $table->dropColumn('agence_id');
        });
    }
};