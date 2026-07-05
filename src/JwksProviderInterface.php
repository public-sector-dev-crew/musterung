<?php

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 public-sector-dev-crew

declare(strict_types=1);

namespace Lotse\Musterung;

use Jose\Component\Core\JWKSet;

/**
 * Liefert den JWKS-Schlüsselsatz (RFC 7517) eines OIDC-Issuers für die Token-Signaturprüfung. Bewusst ein
 * **musterung-interner** Port (nicht rigg): sein Rückgabetyp ist das `Jose\Component\Core\JWKSet` der
 * JWT-Bibliothek, die außerhalb dieses Packages nicht sichtbar sein soll (rigg bleibt zero-dependency).
 *
 * {@see refreshed()} erzwingt einen Neu-Bezug (ohne Cache) — der `kid`-Rotations-Pfad aus ADR-0025 §2:
 * scheitert die Signaturprüfung, weil der Issuer seinen Schlüssel rotiert hat, lädt der Verifier die JWKS
 * einmal frisch und prüft erneut.
 */
interface JwksProviderInterface
{
    /**
     * @param string $issuer die (bereits allowlist-geprüfte) OIDC-Issuer-URL
     *
     * @throws \RuntimeException wenn für den Issuer keine JWKS bezogen werden kann (fail-closed)
     */
    public function jwkSetFor(string $issuer): JWKSet;

    /**
     * Erzwingt einen frischen JWKS-Bezug unter Umgehung des Caches (Schlüssel-Rotation).
     *
     * @throws \RuntimeException wenn für den Issuer keine JWKS bezogen werden kann (fail-closed)
     */
    public function refreshed(string $issuer): JWKSet;
}
