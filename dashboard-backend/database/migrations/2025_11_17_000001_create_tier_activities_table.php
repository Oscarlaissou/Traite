<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('tier_activities', function (Blueprint $table) {
            $table->id();
            $table->integer('tier_id');
            $table->unsignedBigInteger('user_id')->nullable();
            $table->string('action', 50); // Création, Modification, Suppression
            $table->json('changes')->nullable();
            $table->timestamps();

            $table->foreign('tier_id')->references('id')->on('tiers')->onDelete('cascade');
            $table->foreign('user_id')->references('id')->on('users')->nullOnDelete();

            $table->index(['tier_id']);
            $table->index(['user_id']);
            $table->index(['action']);
            $table->index(['created_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('tier_activities');
    }
};
