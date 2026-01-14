<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('traites', function (Blueprint $table) {
            $table->id();
            $table->string('numero', 100);
            $table->unsignedInteger('nombre_traites');
            $table->date('echeance');
            $table->date('date_emission');
            $table->decimal('montant', 15, 2);
            $table->string('nom_raison_sociale', 255);
            $table->string('domiciliation_bancaire', 255)->nullable();
            $table->string('rib', 50)->nullable();
            $table->string('motif', 500)->nullable();
            $table->text('commentaires')->nullable();
            $table->string('statut', 50)->default('Non échu');
            $table->timestamps();

            $table->index(['numero']);
            $table->index(['statut']);
            $table->index(['echeance']);
            $table->index(['date_emission']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('traites');
    }
};


