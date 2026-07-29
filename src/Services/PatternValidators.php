<?php

namespace JayAnta\ThreatDetection\Services;

/**
 * Named post-match validators.
 *
 * A regex alone can't express every constraint — a 12-digit run is not an
 * Aadhaar number unless it also passes the Verhoeff checksum, and a 16-digit
 * run is not a card number unless it passes Luhn. A pattern label can be
 * mapped to one of these validators (config: pattern_validators); a regex hit
 * then only counts as a detection when at least one matched value passes.
 *
 * Validators are referenced by name (a plain string), never a closure, so the
 * config stays compatible with `config:cache`.
 */
class PatternValidators
{
    /**
     * Whether the value clears the named validator. An unknown name never
     * suppresses a hit — the caller fails open (and warns) on a typo, so a
     * misconfigured validator can't silently disable a detection pattern.
     */
    public static function passes(string $name, string $value): bool
    {
        return match ($name) {
            'luhn' => self::luhn($value),
            'verhoeff' => self::verhoeff($value),
            default => true,
        };
    }

    public static function known(string $name): bool
    {
        return in_array($name, ['luhn', 'verhoeff'], true);
    }

    /**
     * The Luhn checksum used by every major card scheme, so random 16-digit
     * values (order ids, tracking numbers) are not mistaken for a card number.
     * Non-digits (spaces, dashes) are stripped before checking.
     */
    private static function luhn(string $value): bool
    {
        $digits = (string) preg_replace('/\D/', '', $value);

        if (strlen($digits) < 12) {
            return false;
        }

        $sum = 0;
        $double = false;

        for ($i = strlen($digits) - 1; $i >= 0; $i--) {
            $n = (int) $digits[$i];

            if ($double && ($n *= 2) > 9) {
                $n -= 9;
            }

            $sum += $n;
            $double = !$double;
        }

        return $sum % 10 === 0;
    }

    /**
     * The Verhoeff checksum used by Aadhaar numbers. It detects all
     * single-digit errors and adjacent transpositions, so arbitrary 12-digit
     * runs (timestamps, EAN barcodes, order ids) are not mistaken for an
     * Aadhaar number. Non-digits are stripped before checking.
     */
    private static function verhoeff(string $value): bool
    {
        $digits = (string) preg_replace('/\D/', '', $value);

        if ($digits === '') {
            return false;
        }

        // Multiplication table of the dihedral group D5.
        static $d = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
            [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
            [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
            [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
            [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
            [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
            [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
            [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
            [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
        ];

        // Position-dependent permutation table.
        static $p = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
            [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
            [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
            [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
            [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
            [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
            [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
        ];

        $c = 0;
        $reversed = strrev($digits);

        for ($i = 0, $len = strlen($reversed); $i < $len; $i++) {
            $c = $d[$c][$p[$i % 8][(int) $reversed[$i]]];
        }

        return $c === 0;
    }
}