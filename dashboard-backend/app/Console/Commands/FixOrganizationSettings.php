<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Models\OrganizationSetting;

class FixOrganizationSettings extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'organization:fix-settings';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Fix organization settings in the database';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $this->info('Checking organization settings...');
        
        $settings = OrganizationSetting::first();
        
        if (!$settings) {
            $this->info('No organization settings found. Creating new record...');
            $settings = new OrganizationSetting();
            $settings->name = '';
            $settings->logo = '';
            $settings->save();
            $this->info('Created new organization settings record with ID: ' . $settings->id);
        } else {
            $this->info('Found organization settings with ID: ' . $settings->id);
            $this->info('Name: ' . ($settings->name === null ? 'NULL' : '"' . $settings->name . '"'));
            $this->info('Logo: ' . ($settings->logo ?: 'NULL'));
            
            // Fix any potential issues
            $updated = false;
            if ($settings->name === null) {
                $settings->name = '';
                $this->info('Fixed null name to empty string');
                $updated = true;
            }
            
            if ($settings->logo === null) {
                $settings->logo = '';
                $this->info('Fixed null logo to empty string');
                $updated = true;
            }
            
            if ($updated) {
                $settings->save();
                $this->info('Settings record updated');
            } else {
                $this->info('No changes needed');
            }
        }
        
        $this->info('Organization settings check completed.');
    }
}