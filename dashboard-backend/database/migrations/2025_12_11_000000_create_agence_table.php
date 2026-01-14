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
        Schema::create('agence', function (Blueprint $table) {
            $table->id();
            $table->string('code', 50)->unique()->nullable();
            $table->string('etablissement', 255);
            $table->string('service', 255)->nullable();
            $table->string('nom_signataire', 255)->nullable();
            $table->string('societe', 255)->nullable();
            $table->timestamps();
            
            $table->index(['etablissement', 'service', 'nom_signataire']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('agence');
    }
};