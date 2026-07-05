<?php

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 public-sector-dev-crew

declare(strict_types=1);

namespace Lotse\Musterung;

use Jose\Component\Core\JWKSet;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Produktions-geformter {@see JwksProviderInterface}: bezieht den JWKS-Schlüsselsatz (RFC 7517) eines OIDC-
 * Issuers über dessen `jwks_uri` per HTTPS und cached ihn PSR-6-konform mit `max-age=86400` (ADR-0025 §2:
 * „`kid`-Rotation via JWKS mit Cache-Control: max-age=86400"). Löst den {@see StaticJwksProvider} für den
 * produktiven Pfad ab.
 *
 * **`kid`-Rotation:** rotiert der Issuer seinen Signaturschlüssel, schlägt die Signaturprüfung im
 * {@see WebTokenOidcVerifier} zunächst fehl; dieser ruft dann {@see refreshed()}, das den Cache **umgeht** und
 * die JWKS frisch lädt — der neue `kid` wird sichtbar, ohne auf den TTL-Ablauf zu warten.
 *
 * ⚠️ REVIEW-GATE: der `jwks_uri` je Issuer ist Deployment-Konfiguration (leer = kein Issuer akzeptiert,
 * fail-closed). Produktiv gehören dazu die echten IdP-Endpunkte (z. B. Keycloak
 * `…/realms/<realm>/protocol/openid-connect/certs`) samt TLS-Verifikation/Timeouts; optional die
 * Auto-Auflösung via OIDC-Discovery (`…/.well-known/openid-configuration`) statt einer festen Abbildung.
 * Fehlerpfade sind fail-closed und tragen kein Schlüsselmaterial.
 */
final class CachingHttpJwksProvider implements JwksProviderInterface
{
    /**
     * @param array<string, string> $jwksUriByIssuer Issuer-URL → JWKS-Endpunkt (`jwks_uri`)
     * @param int                   $cacheTtlSeconds Cache-Lebensdauer (ADR-0025 §2: 86400)
     */
    public function __construct(
        private readonly HttpClientInterface $http,
        private readonly CacheItemPoolInterface $cache,
        private readonly array $jwksUriByIssuer,
        private readonly int $cacheTtlSeconds = 86400,
    ) {
    }

    public function jwkSetFor(string $issuer): JWKSet
    {
        return $this->load($issuer, false);
    }

    public function refreshed(string $issuer): JWKSet
    {
        // `kid`-Rotation: Cache umgehen und frisch laden.
        return $this->load($issuer, true);
    }

    private function load(string $issuer, bool $bypassCache): JWKSet
    {
        $jwksUri = $this->jwksUriByIssuer[$issuer] ?? null;
        if (null === $jwksUri) {
            // Unbekannter/nicht-konfigurierter Issuer → fail-closed (kein blindes Vertrauen).
            throw new \RuntimeException('No jwks_uri configured for the requested OIDC issuer.');
        }

        $cacheItem = $this->cache->getItem($this->cacheKey($issuer));
        if (!$bypassCache && $cacheItem->isHit()) {
            $cached = $cacheItem->get();
            if (\is_string($cached) && '' !== $cached) {
                return $this->parse($cached);
            }
        }

        $json = $this->fetch($jwksUri);
        $jwkSet = $this->parse($json);

        $cacheItem->set($json)->expiresAfter($this->cacheTtlSeconds);
        $this->cache->save($cacheItem);

        return $jwkSet;
    }

    private function fetch(string $jwksUri): string
    {
        try {
            // getContent() wirft bei non-2xx (HttpExceptionInterface) — fail-closed.
            return $this->http->request('GET', $jwksUri)->getContent();
        } catch (HttpExceptionInterface $e) {
            throw new \RuntimeException('Failed to fetch the OIDC JWKS from the issuer.', 0, $e);
        }
    }

    private function parse(string $json): JWKSet
    {
        try {
            return JWKSet::createFromJson($json);
        } catch (\Throwable $e) {
            throw new \RuntimeException('The fetched OIDC JWKS is not a valid key set.', 0, $e);
        }
    }

    private function cacheKey(string $issuer): string
    {
        // PSR-6-sicherer, kollisionsfreier Schlüssel (kein reserviertes Zeichen aus der Issuer-URL).
        return 'lotse.musterung.oidc_jwks.'.hash('sha256', $issuer);
    }
}
