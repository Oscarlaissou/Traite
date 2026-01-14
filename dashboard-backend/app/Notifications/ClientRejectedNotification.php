<?php

namespace App\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class ClientRejectedNotification extends Notification
{
    use Queueable;

    protected $clientName;
    protected $reason;
    protected $clientId;

    /**
     * Create a new notification instance.
     */
    public function __construct($clientName, $reason = null, $clientId = null)
    {
        $this->clientName = $clientName;
        $this->reason = $reason;
        $this->clientId = $clientId;
    }

    /**
     * Get the notification's delivery channels.
     *
     * @return array<int, string>
     */
    public function via(object $notifiable): array
    {
        return ['database'];
    }

    /**
     * Get the array representation of the notification.
     *
     * @return array<string, mixed>
     */
    public function toArray(object $notifiable): array
    {
        $message = "Le client \"{$this->clientName}\" a été rejeté.";
        if ($this->reason) {
            $message .= " Raison: {$this->reason}";
        }

        return [
            'message' => $message,
            'type' => 'client_rejected',
            'client_name' => $this->clientName,
            'reason' => $this->reason,
            'client_id' => $this->clientId,
            'created_at' => now(),
        ];
    }
}