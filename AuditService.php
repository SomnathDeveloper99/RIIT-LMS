<?php

namespace App\Services;

use App\Models\AuditLog;
use Illuminate\Support\Facades\Request;

class AuditService
{
    /**
     * Record an authoritative security, academic, or financial audit event.
     */
    public static function log(
        string $action,
        ?string $entityType = null,
        ?int $entityId = null,
        ?array $oldValues = null,
        ?array $newValues = null,
        ?int $userId = null
    ): AuditLog {
        // Sanitize sensitive fields from logs (passwords, tokens, OTPs, CVVs)
        $sanitize = function (?array $data) {
            if (!$data) return null;
            $sensitiveKeys = ['password', 'password_confirmation', 'token', 'otp', 'delivery_otp', 'cvv', 'card_number'];
            foreach ($sensitiveKeys as $key) {
                if (isset($data[$key])) {
                    $data[$key] = '[REDACTED]';
                }
            }
            return $data;
        };

        return AuditLog::create([
            'user_id' => $userId ?? auth()->id(),
            'action' => $action,
            'entity_type' => $entityType,
            'entity_id' => $entityId,
            'old_values' => $sanitize($oldValues),
            'new_values' => $sanitize($newValues),
            'ip_address' => Request::ip(),
            'user_agent' => Request::userAgent(),
            'created_at' => now(),
        ]);
    }
}
