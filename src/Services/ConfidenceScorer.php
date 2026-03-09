<?php

namespace JayAnta\ThreatDetection\Services;

class ConfidenceScorer
{
    private array $attackTools = [
        'sqlmap', 'nikto', 'nmap', 'acunetix', 'nessus', 'openvas',
        'nuclei', 'metasploit', 'w3af', 'havij', 'masscan', 'zgrab',
        'burp', 'zap',
    ];

    /**
     * @param array  $matches        [label, threatLevel, sourceTag] tuples
     * @param string $sensitivityMode 'strict'|'balanced'|'relaxed'
     * @return array{score: int, label: string}
     */
    public function calculate(
        array $matches,
        array $contextWeights = [],
        bool $hasAttackToolUA = false,
        string $sensitivityMode = 'balanced'
    ): array {
        if (empty($matches)) {
            return ['score' => 0, 'label' => 'low'];
        }

        $score = 0;

        // Base score
        $score += 20;

        // Extra matches (capped at 3)
        $extraMatches = min(count($matches) - 1, 3);
        $score += $extraMatches * 15;

        // High-severity bonus
        foreach ($matches as [$label, $level, $source]) {
            if ($level === 'high') {
                $score += 15;
                break;
            }
        }

        // Context weight bonus
        foreach ($matches as [$label, $level, $source]) {
            $weight = $contextWeights[$label] ?? 1.0;
            if ($weight > 1.0) {
                $score += 10;
                break;
            }
        }

        // Attack tool user-agent bonus
        if ($hasAttackToolUA) {
            $score += 25;
        }

        // Sensitivity mode adjustment
        $score += match ($sensitivityMode) {
            'strict' => 10,
            'relaxed' => -10,
            default => 0,
        };

        // Clamp to 0-100
        $score = max(0, min(100, $score));

        return [
            'score' => $score,
            'label' => $this->scoreToLabel($score),
        ];
    }

    public function isAttackToolUserAgent(string $userAgent): bool
    {
        $ua = strtolower($userAgent);

        foreach ($this->attackTools as $tool) {
            if (str_contains($ua, $tool)) {
                return true;
            }
        }

        return false;
    }

    public function scoreToLabel(int $score): string
    {
        return match (true) {
            $score >= 76 => 'very_high',
            $score >= 51 => 'high',
            $score >= 26 => 'medium',
            default => 'low',
        };
    }
}
