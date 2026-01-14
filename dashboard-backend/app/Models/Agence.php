<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Agence extends Model
{
    protected $table = 'agence';

    protected $fillable = [
        'code',
        'etablissement',
        'service',
        'nom_signataire',
        'societe',
    ];

    protected $casts = [
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];
}