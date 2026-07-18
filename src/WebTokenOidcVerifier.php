<?php

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 public-sector-dev-crew

declare(strict_types=1);

namespace Lotse\Musterung;

use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Lotse\Rigg\Auth\OidcTokenVerifierInterface;
use Lotse\Rigg\Auth\OidcVerificationException;
use Lotse\Rigg\Auth\VerifiedOidcClaims;
use Psr\Clock\ClockInterface;

/**
 * Produktions-geformter OIDC-Token-Verifier auf Basis von `web-token/jwt-library` (v4), der die
 * Pflicht-Härtungen aus ADR-0025 §2 (RFC 8725 JWT-BCP) **fail-closed** durchsetzt:
 *
 * 1. Nur `[ES256, ES384, EdDSA]` im *protected* Header (BSI TR-03116-4); `alg: none`/RS256 → Ablehnung.
 * 2. Signatur gegen die Issuer-JWKS; scheitert sie, wird die JWKS **einmal** frisch geladen (`kid`-Rotation).
 * 3. `iss` gegen die Allowlist, `exp` Pflicht + nicht abgelaufen, vorhandenes `nbf` eingehalten,
 *    `iat` plausibel, Pflicht-Claims präsent.
 * 4. `aud` gegen die konfigurierte Audience-Liste (string **oder** array-`aud`).
 *
 * Die JWT-Bibliothek ist hier gekapselt; nach außen liefert der Verifier den vendor-neutralen
 * {@see VerifiedOidcClaims} (aus dem rigg-`Auth/`-Block). Jeder Fehlerpfad wirft {@see OidcVerificationException}
 * mit generischer, credential-freier Meldung.
 *
 * ⚠️ REVIEW-GATE: produktiv braucht es echte IdP-Discovery/JWKS (siehe {@see JwksProviderInterface}),
 * tenant-spezifische Audience-Listen und ggf. Sender-Constrained-Tokens (mTLS/DPoP, ADR-0025 §4). Der
 * Kryptopfad selbst ist hier vollständig und getestet.
 */
final class WebTokenOidcVerifier implements OidcTokenVerifierInterface
{
    /** @var non-empty-list<string> */
    private const array ALLOWED_ALGORITHMS = ['ES256', 'ES384', 'EdDSA'];

    private const array MANDATORY_CLAIMS = ['iss', 'sub', 'aud', 'exp', 'iat'];

    private readonly JWSVerifier $jwsVerifier;
    private readonly CompactSerializer $serializer;
    private readonly HeaderCheckerManager $headerChecker;
    private readonly ClaimCheckerManager $claimChecker;

    /** @var list<string> */
    private readonly array $allowedIssuers;

    /** @var list<string> */
    private readonly array $allowedAudiences;

    /**
     * @param list<string> $allowedIssuers   zugelassene OIDC-Issuer (`iss`)
     * @param list<string> $allowedAudiences zugelassene Audiences (`aud`)
     */
    public function __construct(
        private readonly JwksProviderInterface $jwks,
        ClockInterface $clock,
        array $allowedIssuers,
        array $allowedAudiences,
    ) {
        $this->jwsVerifier = new JWSVerifier(new AlgorithmManager([new ES256(), new ES384(), new EdDSA()]));
        $this->serializer = new CompactSerializer();
        // Alg-Allowlist im PROTECTED Header (true) — `alg: none`/RS256 sind fail-closed nicht enthalten.
        $this->headerChecker = new HeaderCheckerManager(
            [new AlgorithmChecker(self::ALLOWED_ALGORITHMS, true)],
            [new JWSTokenSupport()],
        );
        $this->claimChecker = new ClaimCheckerManager([
            new IssuedAtChecker($clock),
            new ExpirationTimeChecker($clock),
            new NotBeforeChecker($clock),
            new IssuerChecker($allowedIssuers),
        ]);
        $this->allowedIssuers = $allowedIssuers;
        $this->allowedAudiences = $allowedAudiences;
    }

    public function verify(string $rawToken): VerifiedOidcClaims
    {
        $jws = $this->parse($rawToken);

        // 1. Header: Algorithmus muss in der Allowlist stehen (fängt `alg: none`/RS256 vor jeder Krypto).
        try {
            $this->headerChecker->check($jws, 0, ['alg']);
        } catch (\Throwable $e) {
            throw OidcVerificationException::disallowedAlgorithm();
        }

        $claims = $this->decodePayload($jws);

        // 2. `iss` (noch unverifiziert) nur zur JWKS-Auswahl lesen + gegen die Allowlist grob vorprüfen.
        $issuer = $this->issuerForKeySelection($claims);

        // 3. Signatur gegen die Issuer-JWKS prüfen (mit `kid`-Rotations-Reload). Ab hier ist der Payload echt.
        $kid = $this->kid($jws);
        $this->verifySignatureOrThrow($jws, $issuer, $kid);

        // 4. Claims validieren: exp/iat/iss + Pflicht-Claims (jetzt auf verifiziertem Payload).
        try {
            $this->claimChecker->check($claims, self::MANDATORY_CLAIMS);
        } catch (\Throwable $e) {
            throw OidcVerificationException::invalidClaims($e);
        }

        // 5. Audience gegen die Liste (string oder array) — separat, da mehrere Audiences zulässig sind.
        $audience = $this->matchAudience($claims);

        return new VerifiedOidcClaims(
            $this->requireString($claims, 'sub'),
            $this->requireString($claims, 'iss'),
            $audience,
            $this->requireInt($claims, 'iat'),
            $this->requireInt($claims, 'exp'),
            $this->extractRoles($claims),
            $this->optionalString($claims, 'organization_id'),
        );
    }

    private function parse(string $rawToken): JWS
    {
        if ('' === $rawToken) {
            throw OidcVerificationException::malformed();
        }
        try {
            return $this->serializer->unserialize($rawToken);
        } catch (\Throwable $e) {
            throw OidcVerificationException::malformed($e);
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function decodePayload(JWS $jws): array
    {
        $payload = $jws->getPayload();
        if (null === $payload) {
            throw OidcVerificationException::malformed();
        }
        try {
            $decoded = json_decode($payload, true, 8, \JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw OidcVerificationException::malformed($e);
        }
        if (!\is_array($decoded)) {
            throw OidcVerificationException::malformed();
        }

        // Auf string-Keys normalisieren (JWT-Claims sind string-benannt) — ergibt array<string, mixed>.
        $claims = [];
        foreach ($decoded as $key => $value) {
            if (\is_string($key)) {
                $claims[$key] = $value;
            }
        }

        return $claims;
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function issuerForKeySelection(array $claims): string
    {
        $issuer = $claims['iss'] ?? null;
        if (!\is_string($issuer) || !\in_array($issuer, $this->allowedIssuers, true)) {
            throw OidcVerificationException::invalidClaims();
        }

        return $issuer;
    }

    private function kid(JWS $jws): ?string
    {
        $kid = $jws->getSignature(0)->getProtectedHeader()['kid'] ?? null;

        return \is_string($kid) ? $kid : null;
    }

    private function verifySignatureOrThrow(JWS $jws, string $issuer, ?string $kid): void
    {
        $jwkset = $this->loadJwkSet($issuer, false);

        // `kid`-Rotation: fehlt der referenzierte Schlüssel im Satz, einmal frisch laden.
        if (null !== $kid && null === $jwkset->selectKey('sig', null, ['kid' => $kid])) {
            $jwkset = $this->loadJwkSet($issuer, true);
            if (null === $jwkset->selectKey('sig', null, ['kid' => $kid])) {
                throw OidcVerificationException::unknownSigningKey();
            }
        }

        if ($this->jwsVerifier->verifyWithKeySet($jws, $jwkset, 0)) {
            return;
        }

        // Fehlschlag evtl. wegen veralteten Caches → einmal frisch laden und erneut prüfen.
        if ($this->jwsVerifier->verifyWithKeySet($jws, $this->loadJwkSet($issuer, true), 0)) {
            return;
        }

        throw OidcVerificationException::invalidSignature();
    }

    private function loadJwkSet(string $issuer, bool $refresh): \Jose\Component\Core\JWKSet
    {
        try {
            return $refresh ? $this->jwks->refreshed($issuer) : $this->jwks->jwkSetFor($issuer);
        } catch (\Throwable $e) {
            throw OidcVerificationException::jwksUnavailable($e);
        }
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function matchAudience(array $claims): string
    {
        $aud = $claims['aud'] ?? null;
        if (\is_string($aud)) {
            $tokenAudiences = [$aud];
        } elseif (\is_array($aud)) {
            $tokenAudiences = [];
            foreach ($aud as $candidate) {
                if (!\is_string($candidate) || '' === $candidate) {
                    throw OidcVerificationException::invalidClaims();
                }
                $tokenAudiences[] = $candidate;
            }
        } else {
            throw OidcVerificationException::invalidClaims();
        }

        foreach ($tokenAudiences as $candidate) {
            if (\in_array($candidate, $this->allowedAudiences, true)) {
                return $candidate;
            }
        }

        throw OidcVerificationException::invalidClaims();
    }

    /**
     * @param array<string, mixed> $claims
     *
     * @return list<string>
     */
    private function extractRoles(array $claims): array
    {
        $roles = $claims['roles'] ?? null;
        if (!\is_array($roles)) {
            return [];
        }

        return array_values(array_filter($roles, static fn (mixed $r): bool => \is_string($r) && '' !== $r));
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function requireString(array $claims, string $key): string
    {
        $value = $claims[$key] ?? null;
        if (!\is_string($value) || '' === $value) {
            throw OidcVerificationException::invalidClaims();
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function requireInt(array $claims, string $key): int
    {
        $value = $claims[$key] ?? null;
        if (!\is_int($value)) {
            throw OidcVerificationException::invalidClaims();
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function optionalString(array $claims, string $key): ?string
    {
        $value = $claims[$key] ?? null;

        return \is_string($value) && '' !== $value ? $value : null;
    }
}
