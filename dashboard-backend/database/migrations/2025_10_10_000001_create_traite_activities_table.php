<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('traite_activities', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('traite_id');
            $table->unsignedBigInteger('user_id')->nullable();
            $table->string('action', 50); // Création, Modification, Suppression
            $table->json('changes')->nullable();
            $table->timestamps();

            $table->foreign('traite_id')->references('id')->on('traites')->onDelete('cascade');
            $table->foreign('user_id')->references('id')->on('users')->nullOnDelete();

            $table->index(['traite_id']);
            $table->index(['user_id']);
            $table->index(['action']);
            $table->index(['created_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('traite_activities');
    }
};


