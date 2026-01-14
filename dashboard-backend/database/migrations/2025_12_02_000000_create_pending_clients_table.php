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
        Schema::create('pending_clients', function (Blueprint $table) {
            $table->id();
            $table->string('numero_compte', 100)->nullable();
            $table->string('nom_raison_sociale', 255);
            $table->string('bp', 255)->nullable();
            $table->string('ville', 255)->nullable();
            $table->string('pays', 255)->nullable();
            $table->string('adresse_geo_1', 255)->nullable();
            $table->string('adresse_geo_2', 255)->nullable();
            $table->string('telephone', 50)->nullable();
            $table->string('email', 255)->nullable();
            $table->string('categorie', 255);
            $table->string('n_contribuable', 100)->nullable();
            $table->string('type_tiers', 50);
            
            // Champs Demande d'ouverture de compte
            $table->date('date_creation')->nullable();
            $table->decimal('montant_facture', 15, 2)->nullable();
            $table->decimal('montant_paye', 15, 2)->nullable();
            $table->decimal('credit', 15, 2)->nullable();
            $table->text('motif')->nullable();
            $table->string('etablissement', 255)->nullable();
            $table->string('service', 255)->nullable();
            $table->string('nom_signataire', 255)->nullable();
            
            $table->unsignedBigInteger('created_by')->nullable();
            $table->foreign('created_by')->references('id')->on('users')->nullOnDelete();
            
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('pending_clients');
    }
};