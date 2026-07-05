<?php

// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 public-sector-dev-crew
//
// NUR SYNTHETISCHE TESTDATEN (R3) — JWKS/Schlüssel im Test frisch erzeugt, kein echter IdP.

declare(strict_types=1);

namespace Lotse\Musterung\Tests\Unit;

use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Lotse\Musterung\CachingHttpJwksProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

#[CoversClass(CachingHttpJwksProvider::class)]
final class CachingHttpJwksProviderTest extends TestCase
{
    private const string ISSUER = 'https://idp.test.local/realms/musterung';
    private const string JWKS_URI = 'https://idp.test.local/realms/musterung/protocol/openid-connect/certs';

    private string $jwksJson;

    protected function setUp(): void
    {
        $public = JWKFactory::createECKey('P-256', ['kid' => 'k1', 'use' => 'sig', 'alg' => 'ES256'])->toPublic();
        $this->jwksJson = (string) json_encode(new JWKSet([$public]));
    }

    public function testFetchesAndParsesJwksForConfiguredIssuer(): void
    {
        $jwkSet = $this->provider($this->jwksHttp())->jwkSetFor(self::ISSUER);

        self::assertSame(1, $jwkSet->count());
        self::assertNotNull($jwkSet->selectKey('sig', null, ['kid' => 'k1']));
    }

    public function testCachesAcrossCalls(): void
    {
        $http = $this->jwksHttp();
        $provider = $this->provider($http);

        $provider->jwkSetFor(self::ISSUER);
        $provider->jwkSetFor(self::ISSUER);

        self::assertSame(1, $http->getRequestsCount(), 'der zweite Zugriff kommt aus dem PSR-6-Cache (max-age 86400)');
    }

    public function testRefreshedBypassesCacheForKidRotation(): void
    {
        $http = $this->jwksHttp();
        $provider = $this->provider($http);

        $provider->jwkSetFor(self::ISSUER); // 1 (füllt Cache)
        $provider->refreshed(self::ISSUER); // 2 (umgeht Cache — kid-Rotation)

        self::assertSame(2, $http->getRequestsCount());
    }

    public function testUnknownIssuerFailsClosed(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->provider($this->jwksHttp())->jwkSetFor('https://evil.example/realms/x');
    }

    public function testFetchErrorFailsClosed(): void
    {
        $http = new MockHttpClient(static fn (): MockResponse => new MockResponse('nope', ['http_code' => 500]));

        $this->expectException(\RuntimeException::class);
        $this->provider($http)->jwkSetFor(self::ISSUER);
    }

    public function testInvalidJwksFailsClosed(): void
    {
        $http = new MockHttpClient(static fn (): MockResponse => new MockResponse('kein-json'));

        $this->expectException(\RuntimeException::class);
        $this->provider($http)->jwkSetFor(self::ISSUER);
    }

    private function provider(MockHttpClient $http): CachingHttpJwksProvider
    {
        return new CachingHttpJwksProvider($http, new ArrayAdapter(), [self::ISSUER => self::JWKS_URI]);
    }

    private function jwksHttp(): MockHttpClient
    {
        $json = $this->jwksJson;

        return new MockHttpClient(static fn (): MockResponse => new MockResponse($json));
    }
}
