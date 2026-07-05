<?php

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 public-sector-dev-crew

declare(strict_types=1);

namespace Lotse\Musterung;

use Jose\Component\Core\JWKSet;

/**
 * Statischer {@see JwksProviderInterface}: hält je Issuer einen fest hinterlegten {@see JWKSet}. Für Tests
 * (synthetische Schlüssel) und für Dev-Deployments mit vorab bekannten, nicht-rotierenden JWKS. Da nichts
 * über HTTP bezogen wird, ist {@see refreshed()} identisch zu {@see jwkSetFor()} — es gibt keinen frischen
 * Bezug.
 *
 * ⚠️ REVIEW-GATE: kein produktiver JWKS-Bezug. Produktiv löst der {@see CachingHttpJwksProvider} die JWKS
 * über den Discovery-/`jwks_uri`-Endpunkt des Issuers auf und unterstützt echte Schlüssel-Rotation.
 */
final readonly class StaticJwksProvider implements JwksProviderInterface
{
    /**
     * @param array<string, JWKSet> $keySetsByIssuer Issuer-URL → JWKSet
     */
    public function __construct(
        private array $keySetsByIssuer,
    ) {
    }

    public function jwkSetFor(string $issuer): JWKSet
    {
        return $this->keySetsByIssuer[$issuer]
            ?? throw new \RuntimeException('No static JWKS configured for the requested issuer.');
    }

    public function refreshed(string $issuer): JWKSet
    {
        // Statisch: kein frischer Bezug möglich — derselbe Satz. Rotation wäre neue Konfiguration.
        return $this->jwkSetFor($issuer);
    }
}
