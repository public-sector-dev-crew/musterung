<?php

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 public-sector-dev-crew
//
// NUR SYNTHETISCHE TESTDATEN (R3) — alle Schlüssel/Tokens werden im Test frisch erzeugt.

declare(strict_types=1);

namespace Lotse\Musterung\Tests\Unit;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Lotse\Musterung\JwksProviderInterface;
use Lotse\Musterung\StaticJwksProvider;
use Lotse\Musterung\WebTokenOidcVerifier;
use Lotse\Rigg\Auth\OidcVerificationException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

#[CoversClass(WebTokenOidcVerifier::class)]
#[CoversClass(StaticJwksProvider::class)]
final class WebTokenOidcVerifierTest extends TestCase
{
    private const string ISSUER = 'https://idp.test.local/realms/musterung';
    private const string AUDIENCE = 'lotse-sams';
    private const string NOW = '2026-07-05T12:00:00+00:00';

    private JWK $ecPrivate;
    private JWK $okpPrivate;
    private JWK $rsaPrivate;
    private MockClock $clock;

    protected function setUp(): void
    {
        $this->ecPrivate = JWKFactory::createECKey('P-256', ['kid' => 'ec-1', 'use' => 'sig', 'alg' => 'ES256']);
        $this->okpPrivate = JWKFactory::createOKPKey('Ed25519', ['kid' => 'okp-1', 'use' => 'sig', 'alg' => 'EdDSA']);
        $this->rsaPrivate = JWKFactory::createRSAKey(2048, ['kid' => 'rsa-1', 'use' => 'sig', 'alg' => 'RS256']);
        $this->clock = new MockClock(new \DateTimeImmutable(self::NOW));
    }

    public function testVerifiesValidEs256Token(): void
    {
        $verified = $this->verifier()->verify($this->sign($this->ecPrivate, 'ES256', $this->claims()));

        self::assertSame('operator-sub-42', $verified->subject);
        self::assertSame(self::ISSUER, $verified->issuer);
        self::assertSame(self::AUDIENCE, $verified->audience);
        self::assertSame(['lotse.operator'], $verified->roles);
        self::assertSame('org-ulid-synthetic', $verified->organizationId);
        self::assertTrue($verified->hasRole('lotse.operator'));
    }

    public function testVerifiesValidEdDsaToken(): void
    {
        self::assertSame('operator-sub-42', $this->verifier()->verify($this->sign($this->okpPrivate, 'EdDSA', $this->claims()))->subject);
    }

    public function testAcceptsArrayAudienceWhenOneMatches(): void
    {
        $token = $this->sign($this->ecPrivate, 'ES256', $this->claims(['aud' => ['other-service', self::AUDIENCE]]));

        self::assertSame(self::AUDIENCE, $this->verifier()->verify($token)->audience);
    }

    public function testRejectsAlgNone(): void
    {
        $header = $this->b64url((string) json_encode(['alg' => 'none', 'typ' => 'JWT']));
        $payload = $this->b64url((string) json_encode($this->claims()));

        $this->assertRejected($header.'.'.$payload.'.');
    }

    public function testRejectsRs256EvenWithValidSignature(): void
    {
        $this->assertRejectedWith('disallowed_algorithm', $this->sign($this->rsaPrivate, 'RS256', $this->claims()));
    }

    public function testRejectsExpiredToken(): void
    {
        $this->assertRejectedWith('invalid_claims', $this->sign($this->ecPrivate, 'ES256', $this->claims(['exp' => $this->ts('-1 minute')])));
    }

    public function testRejectsMissingExpClaim(): void
    {
        $claims = $this->claims();
        unset($claims['exp']);

        $this->assertRejectedWith('invalid_claims', $this->sign($this->ecPrivate, 'ES256', $claims));
    }

    public function testRejectsNotYetValidToken(): void
    {
        $this->assertRejectedWith('invalid_claims', $this->sign($this->ecPrivate, 'ES256', $this->claims(['nbf' => $this->ts('+1 minute')])));
    }

    public function testRejectsWrongAudience(): void
    {
        $this->assertRejectedWith('invalid_claims', $this->sign($this->ecPrivate, 'ES256', $this->claims(['aud' => 'some-other-service'])));
    }

    public function testRejectsMalformedAudienceArray(): void
    {
        $this->assertRejectedWith('invalid_claims', $this->sign($this->ecPrivate, 'ES256', $this->claims(['aud' => [self::AUDIENCE, 42]])));
    }

    public function testRejectsUnknownIssuer(): void
    {
        $this->assertRejectedWith('invalid_claims', $this->sign($this->ecPrivate, 'ES256', $this->claims(['iss' => 'https://evil.example/realms/x'])));
    }

    public function testRejectsUnknownKid(): void
    {
        $foreign = JWKFactory::createECKey('P-256', ['kid' => 'not-in-jwks', 'use' => 'sig', 'alg' => 'ES256']);

        $this->assertRejectedWith('unknown_signing_key', $this->sign($foreign, 'ES256', $this->claims()));
    }

    public function testRejectsSignatureFromForeignKeyWithKnownKid(): void
    {
        $foreign = JWKFactory::createECKey('P-256', ['kid' => 'ec-1', 'use' => 'sig', 'alg' => 'ES256']);

        $this->assertRejectedWith('invalid_signature', $this->sign($foreign, 'ES256', $this->claims()));
    }

    public function testRejectsWhenJwksCannotBeLoaded(): void
    {
        $unavailableJwks = new class implements JwksProviderInterface {
            public function jwkSetFor(string $issuer): JWKSet
            {
                throw new \RuntimeException('Synthetic JWKS outage.');
            }

            public function refreshed(string $issuer): JWKSet
            {
                throw new \RuntimeException('Synthetic JWKS outage.');
            }
        };
        $verifier = new WebTokenOidcVerifier($unavailableJwks, $this->clock, [self::ISSUER], [self::AUDIENCE]);

        try {
            $verifier->verify($this->sign($this->ecPrivate, 'ES256', $this->claims()));
            self::fail('Erwartete OidcVerificationException bei nicht verfügbarer JWKS.');
        } catch (OidcVerificationException $e) {
            self::assertSame('jwks_unavailable', $e->reason);
            self::assertInstanceOf(\RuntimeException::class, $e->getPrevious());
        }
    }

    public function testRejectsMalformedToken(): void
    {
        $this->assertRejectedWith('malformed', 'not-a-jwt');
    }

    public function testRejectsEmptyToken(): void
    {
        $this->assertRejectedWith('malformed', '');
    }

    private function verifier(): WebTokenOidcVerifier
    {
        $jwks = new JWKSet([$this->ecPrivate->toPublic(), $this->okpPrivate->toPublic()]);

        return new WebTokenOidcVerifier(new StaticJwksProvider([self::ISSUER => $jwks]), $this->clock, [self::ISSUER], [self::AUDIENCE]);
    }

    /**
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    private function claims(array $overrides = []): array
    {
        return array_merge([
            'iss' => self::ISSUER,
            'sub' => 'operator-sub-42',
            'aud' => self::AUDIENCE,
            'iat' => $this->ts('-10 seconds'),
            'exp' => $this->ts('+15 minutes'),
            'roles' => ['lotse.operator'],
            'organization_id' => 'org-ulid-synthetic',
        ], $overrides);
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function sign(JWK $key, string $alg, array $claims): string
    {
        $builder = new JWSBuilder(new AlgorithmManager([new ES256(), new ES384(), new EdDSA(), new RS256()]));
        $kid = $key->get('kid');
        $header = ['alg' => $alg, 'kid' => \is_string($kid) ? $kid : ''];
        $jws = $builder->create()->withPayload((string) json_encode($claims))->addSignature($key, $header)->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }

    private function assertRejectedWith(string $reason, string $token): void
    {
        try {
            $this->verifier()->verify($token);
            self::fail('Erwartete OidcVerificationException mit reason "'.$reason.'", aber keine geworfen.');
        } catch (OidcVerificationException $e) {
            self::assertSame($reason, $e->reason);
        }
    }

    private function assertRejected(string $token): void
    {
        $this->expectException(OidcVerificationException::class);
        $this->verifier()->verify($token);
    }

    private function ts(string $modifier): int
    {
        return (new \DateTimeImmutable(self::NOW))->modify($modifier)->getTimestamp();
    }

    private function b64url(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }
}
