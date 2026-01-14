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
        Schema::table('client_approvals', function (Blueprint $table) {
            // Make tier_id nullable to allow keeping approval records
            $table->unsignedBigInteger('tier_id')->nullable()->change();
            
            // Drop the existing foreign key constraint
            $table->dropForeign(['tier_id']);
            
            // Add the foreign key constraint without cascade delete
            $table->foreign('tier_id')->references('id')->on('pending_clients')->onDelete('set null');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('client_approvals', function (Blueprint $table) {
            // Drop the foreign key constraint
            $table->dropForeign(['tier_id']);
            
            // Make tier_id not nullable again
            $table->unsignedBigInteger('tier_id')->nullable(false)->change();
            
            // Add back the original foreign key constraint with cascade delete
            $table->foreign('tier_id')->references('id')->on('pending_clients')->onDelete('cascade');
        });
    }
};