<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class TierActivity extends Model
{
    use HasFactory;

    protected $table = 'tier_activities';

    protected $guarded = [];

    protected $casts = [
        'changes' => 'array',
    ];

    public function tier()
    {
        return $this->belongsTo(Tier::class);
    }

    public function user()
    {
        return $this->belongsTo(User::class);
    }
}
