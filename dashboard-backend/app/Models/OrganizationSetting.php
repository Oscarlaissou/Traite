<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class OrganizationSetting extends Model
{
    protected $fillable = ['name', 'logo'];
    
    protected $table = 'organization_settings';
}