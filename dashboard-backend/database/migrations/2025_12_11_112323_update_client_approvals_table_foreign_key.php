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
            // Drop the existing foreign key constraint
            $table->dropForeign(['tier_id']);
            
            // Add the correct foreign key constraint referencing pending_clients
            $table->foreign('tier_id')->references('id')->on('pending_clients')->onDelete('cascade');
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
            
            // Add back the original foreign key constraint referencing tiers
            $table->foreign('tier_id')->references('id')->on('tiers')->onDelete('cascade');
        });
    }
};