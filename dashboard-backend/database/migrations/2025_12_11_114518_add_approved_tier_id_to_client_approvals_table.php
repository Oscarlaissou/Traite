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
            $table->unsignedBigInteger('approved_tier_id')->nullable()->after('tier_id');
            $table->foreign('approved_tier_id')->references('id')->on('tiers')->onDelete('cascade');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('client_approvals', function (Blueprint $table) {
            $table->dropForeign(['approved_tier_id']);
            $table->dropColumn('approved_tier_id');
        });
    }
};