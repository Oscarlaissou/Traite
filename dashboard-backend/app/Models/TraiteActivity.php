<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class TraiteActivity extends Model
{
    use HasFactory;

    protected $table = 'traite_activities';

    protected $guarded = [];

    protected $casts = [
        'changes' => 'array',
    ];

    public function traite()
    {
        return $this->belongsTo(Traite::class);
    }

    public function user()
    {
        return $this->belongsTo(User::class);
    }
}


