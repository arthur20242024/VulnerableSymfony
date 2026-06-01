<?php

namespace App\Services;

use Psr\Log\LoggerInterface;

class Analytics
{
    public function __construct(
        private readonly bool $trackingEnabled,
        private readonly LoggerInterface $logger
    )
    {
    }

    /**
     * #VULNERABILITY: Intended vulnerable request (SSRF + RCE in the referer header)
     */
    public function track(): void
    {
    	if (!$this->trackingEnabled) {
            return;
    	}

    	$referer = $_SERVER['HTTP_REFERER'] ?? null;
    	if (!$referer || !$this->validate($referer)) {
            return;
    	}

    	// Vérification que l'URL est bien HTTP/HTTPS et pas interne
    	$parsed = parse_url($referer);
    	if (!isset($parsed['scheme']) || !in_array($parsed['scheme'], ['http', 'https'])) {
            return;
        }
        $host = $parsed['host'] ?? '';
        // Bloquer les adresses internes
        if (preg_match('/^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|localhost)/i', $host)) {
            return;
        }

        $this->logger->info('Referer tracked: ' . $referer);
    }

    public function validate(string $url): bool
    {
        return filter_var($url, FILTER_VALIDATE_URL) !== false;
    }
}
