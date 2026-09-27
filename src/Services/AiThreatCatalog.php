<?php

namespace JayAnta\ThreatDetection\Services;

/**
 * Which logged threats are AI-related, and which kind.
 *
 * The dashboard and API show these apart from classic web attacks, because
 * the two need different responses and different people: an injection in a
 * search box goes to whoever owns that code, while someone enumerating
 * `/v1/models` is hunting for model infrastructure the app may not know it
 * exposes.
 *
 * ── How a row is classified ────────────────────────────────────────────────
 *
 * By its exact stored `type`, against the labels the AI packs ship with.
 * Nothing new is stored and no column is added, so it applies to rows logged
 * before this existed, and a query can use the type index with `IN`. The two
 * packs are read whether or not they are currently switched on: a row logged
 * last week while the pack was enabled is still an AI-infrastructure probe
 * today.
 *
 * The limit, stated rather than hidden: an operator who gives one of the
 * pack's paths their own label in `probe_tracking.paths` has replaced the
 * pack's entry, so that row carries their label and is not counted here.
 *
 * ── What is deliberately *not* here ────────────────────────────────────────
 *
 * Mutation chains, clusters and identity verdicts are AI-*indicative*
 * analyses, not logged rows, and the dashboard shows them in the AI section
 * as analyses. An injection that a mutation chain later links to automation
 * is still an injection, and relabelling it would hide it from whoever
 * triages injections.
 */
class AiThreatCatalog
{
    public const FAMILY_INFRASTRUCTURE = 'ai_infrastructure_probe';

    public const FAMILY_LLM_INJECTION = 'llm_injection';

    /**
     * Every stored `type` this package counts as AI-related, mapped to its
     * family.
     *
     * @return array<string, string>
     */
    public function types(): array
    {
        $types = [];

        foreach ((array) config('threat-detection.probe_tracking.ai_infrastructure.paths', []) as $definition) {
            $label = $this->probeLabel($definition);

            if ($label !== null) {
                $types["[probe] {$label}"] = self::FAMILY_INFRASTRUCTURE;
            }
        }

        foreach ((array) config('threat-detection.llm_log_safety.patterns', []) as $entry) {
            $label = is_string($entry) ? $entry : (is_array($entry) ? ($entry['label'] ?? null) : null);

            // Stored exactly as configured — custom-pattern labels are not
            // trimmed on the way in, so they are not trimmed here either.
            if (is_string($label) && $label !== '') {
                $types["[custom] {$label}"] = self::FAMILY_LLM_INJECTION;
            }
        }

        return $types;
    }

    /** @return array<int, string> */
    public function typeList(): array
    {
        return array_keys($this->types());
    }

    public function familyOf(?string $type): ?string
    {
        return is_string($type) ? ($this->types()[$type] ?? null) : null;
    }

    public function isAi(?string $type): bool
    {
        return $this->familyOf($type) !== null;
    }

    /**
     * The probe label as ProbeDetectorService stores it: trimmed, and absent
     * when empty or malformed.
     */
    private function probeLabel(mixed $definition): ?string
    {
        $label = is_string($definition)
            ? $definition
            : (is_array($definition) && is_string($definition['label'] ?? null) ? $definition['label'] : '');

        $label = trim($label);

        return $label === '' ? null : $label;
    }
}
