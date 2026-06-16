<?php

namespace Icinga\Module\Otc;

use Icinga\Application\Logger;
use Icinga\Exception\QueryException;

/**
 * OtcClient – authenticates against OTC IAM (Keystone v3) and fetches
 * resources from any service endpoint found in the service catalog.
 *
 * No external dependencies – uses PHP's built-in cURL extension only.
 */
class OtcClient
{
    /** @var string */
    private $iam_url;
    private $username;
    private $password;
    private $domain;
    private $project;
    private $auth_type;

    /** @var string|null  current bearer token */
    private $token = null;

    /** @var int|null  Unix timestamp when the token expires */
    private $expires = null;

    /** @var array  Keystone service catalog from the last auth response */
    private $catalog = [];

    /** @var string|null  project UUID resolved during auth */
    private $project_id = null;

    /** @var array  cURL options applied to every request */
    private $curl_opts = [];

    public function __construct(
        $iam_url,
        $username,
        $password,
        $domain,
        $project,
        $auth_type   = 'password',
        $proxy       = '',
        $con_timeout = 0,
        $timeout     = 0
    ) {
        $this->iam_url   = rtrim($iam_url, '/');
        $this->username  = $username;
        $this->password  = $password;
        $this->domain    = $domain;
        $this->project   = $project;
        $this->auth_type = $auth_type;

        $this->curl_opts = [
            CURLOPT_CONNECTTIMEOUT => (int) $con_timeout,
            CURLOPT_TIMEOUT        => (int) $timeout,
        ];
        if ($proxy !== '') {
            $this->curl_opts[CURLOPT_PROXY] = $proxy;
        }
    }

    // ── authentication ────────────────────────────────────────────────────────

    /**
     * Dispatch to password or AK/SK authentication.
     */
    private function authenticate()
    {
        if ($this->auth_type === 'aksk') {
            $this->authenticateAkSk();
        } else {
            $this->authenticatePassword();
        }
    }

    /**
     * Return the host (without default port) extracted from iam_url.
     * Used as the Host header value for AK/SK request signing.
     */
    private function iamHost()
    {
        $parsed = parse_url($this->iam_url);
        $host   = $parsed['host'];
        $port   = $parsed['port'] ?? null;
        $scheme = $parsed['scheme'] ?? 'https';
        $default = ($scheme === 'https') ? 443 : 80;
        if ($port !== null && $port !== $default) {
            $host .= ':' . $port;
        }
        return $host;
    }

    /**
     * Build the SDK-HMAC-SHA256 signed headers for an OTC API request.
     *
     * @param  string $method  HTTP method (uppercase)
     * @param  string $host    Host header value (from iamHost())
     * @param  string $path    Absolute URI path, e.g. /v3/auth/tokens
     * @param  string $body    Raw request body
     * @return array  Associative array of headers to send
     */
    private function buildAkSkHeaders($method, $host, $path, $body)
    {
        $datetime = gmdate('Ymd\THis\Z');

        $hdrs = [
            'content-type' => 'application/json',
            'host'         => $host,
            'x-sdk-date'   => $datetime,
        ];
        ksort($hdrs);

        $canon_hdrs  = '';
        $signed_list = [];
        foreach ($hdrs as $k => $v) {
            $canon_hdrs    .= $k . ':' . $v . "\n";
            $signed_list[] = $k;
        }
        $signed_headers = implode(';', $signed_list);

        $canon_req = implode("\n", [
            $method,
            $path,
            '',                          // canonical query string
            $canon_hdrs,
            $signed_headers,
            hash('sha256', $body),
        ]);

        $str_to_sign = implode("\n", [
            'SDK-HMAC-SHA256',
            $datetime,
            hash('sha256', $canon_req),
        ]);

        $signature = hash_hmac('sha256', $str_to_sign, $this->password);

        return [
            'Content-Type'  => 'application/json',
            'Host'          => $host,
            'X-Sdk-Date'    => $datetime,
            'Authorization' => sprintf(
                'SDK-HMAC-SHA256 Access=%s, SignedHeaders=%s, Signature=%s',
                $this->username,
                $signed_headers,
                $signature
            ),
        ];
    }

    /**
     * Authenticate with OTC AK/SK credentials (SDK-HMAC-SHA256 request signing).
     * The signed request is sent to the standard Keystone v3 token endpoint.
     * On success the X-Subject-Token and service catalog are stored.
     */
    private function authenticateAkSk()
    {
        Logger::info('OTC: authenticating (AK/SK) against ' . $this->iam_url);

        $host = $this->iamHost();
        $path = '/v3/auth/tokens';
        $body = json_encode([
            'auth' => [
                'identity' => [
                    'methods'  => ['hw_ak_sk'],
                    'hw_ak_sk' => [
                        'access' => ['key' => $this->username],
                        'secret' => ['key' => $this->password],
                    ],
                ],
                'scope' => [
                    'project' => ['name' => $this->project],
                ],
            ],
        ]);

        $headers      = $this->buildAkSkHeaders('POST', $host, $path, $body);
        $http_headers = [];
        foreach ($headers as $k => $v) {
            $http_headers[] = $k . ': ' . $v;
        }

        $ch = curl_init($this->iam_url . $path);
        curl_setopt_array($ch, $this->curl_opts + [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $body,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_HTTPHEADER     => $http_headers,
        ]);

        $raw      = curl_exec($ch);
        $http     = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $hdr_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $err      = curl_error($ch);
        curl_close($ch);

        if ($err) {
            throw new QueryException('OTC AK/SK auth cURL error: ' . $err);
        }
        if ($http !== 201) {
            throw new QueryException(sprintf(
                'OTC AK/SK auth failed (HTTP %d): %s',
                $http,
                substr($raw, $hdr_size)
            ));
        }

        $raw_headers = substr($raw, 0, $hdr_size);
        if (!preg_match('/^X-Subject-Token:\s*(\S+)/mi', $raw_headers, $m)) {
            throw new QueryException('OTC AK/SK auth: X-Subject-Token missing from response');
        }
        $this->token = $m[1];

        $data = json_decode(substr($raw, $hdr_size), true);
        $this->expires    = strtotime($data['token']['expires_at'] ?? '+1 hour');
        $this->catalog    = $data['token']['catalog']        ?? [];
        $this->project_id = $data['token']['project']['id'] ?? null;

        Logger::info(sprintf(
            'OTC: authenticated via AK/SK, project_id=%s, token valid until %s',
            $this->project_id,
            date('c', $this->expires)
        ));
    }

    /**
     * Perform a Keystone v3 password-auth with project scope.
     * Stores the X-Subject-Token, the service catalog and the project ID.
     */
    private function authenticatePassword()
    {
        Logger::info('OTC: authenticating (password) against ' . $this->iam_url);

        $body = json_encode([
            'auth' => [
                'identity' => [
                    'methods'  => ['password'],
                    'password' => [
                        'user' => [
                            'domain'   => ['name' => $this->domain],
                            'name'     => $this->username,
                            'password' => $this->password,
                        ],
                    ],
                ],
                'scope' => [
                    'project' => ['name' => $this->project],
                ],
            ],
        ]);

        $ch = curl_init($this->iam_url . '/v3/auth/tokens');
        curl_setopt_array($ch, $this->curl_opts + [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $body,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,           // include response headers
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        ]);

        $raw      = curl_exec($ch);
        $http     = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $hdr_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $err      = curl_error($ch);
        curl_close($ch);

        if ($err) {
            throw new QueryException('OTC auth cURL error: ' . $err);
        }
        if ($http !== 201) {
            throw new QueryException(sprintf(
                'OTC auth failed (HTTP %d): %s',
                $http,
                substr($raw, $hdr_size)
            ));
        }

        // The token itself lives in the response header, not the body
        $headers = substr($raw, 0, $hdr_size);
        if (!preg_match('/^X-Subject-Token:\s*(\S+)/mi', $headers, $m)) {
            throw new QueryException('OTC auth: X-Subject-Token missing from response');
        }
        $this->token = $m[1];

        $data = json_decode(substr($raw, $hdr_size), true);
        $this->expires    = strtotime($data['token']['expires_at'] ?? '+1 hour');
        $this->catalog    = $data['token']['catalog']        ?? [];
        $this->project_id = $data['token']['project']['id'] ?? null;

        Logger::info(sprintf(
            'OTC: authenticated as %s, project_id=%s, token valid until %s',
            $this->username,
            $this->project_id,
            date('c', $this->expires)
        ));
    }

    private function tokenExpired()
    {
        return $this->token === null
            || $this->expires === null
            || $this->expires <= time();
    }

    private function ensureToken()
    {
        if ($this->tokenExpired()) {
            $this->authenticate();
        }
    }

    // ── service catalog ───────────────────────────────────────────────────────

    /**
     * Return the public endpoint URL for the requested service type.
     * The {project_id} placeholder in OTC URLs is replaced automatically.
     *
     * @param  string $service_type  e.g. "compute", "network", "volumev2"
     * @param  string $region        optional region filter, e.g. "eu-de"
     * @return string
     * @throws QueryException when no matching endpoint is found
     */
    public function getEndpoint($service_type, $region = '')
    {
        $this->ensureToken();

        foreach ($this->catalog as $service) {
            if (($service['type'] ?? '') !== $service_type) {
                continue;
            }
            foreach ($service['endpoints'] as $ep) {
                if ($ep['interface'] !== 'public') {
                    continue;
                }
                $ep_region = $ep['region_id'] ?? $ep['region'] ?? '';
                if ($region !== '' && $ep_region !== $region) {
                    continue;
                }
                $url = $ep['url'];
                if ($this->project_id !== null) {
                    $url = str_replace('{project_id}', $this->project_id, $url);
                }
                return rtrim($url, '/');
            }
        }

        throw new QueryException(sprintf(
            'OTC: no public endpoint for service_type "%s" (region: "%s"). '
            . 'Available types in catalog: %s',
            $service_type,
            $region,
            implode(', ', array_unique(array_column($this->catalog, 'type')))
        ));
    }

    // ── resource fetching ─────────────────────────────────────────────────────

    /**
     * GET a URL with the current token.
     * Automatically follows OpenStack's next-link pagination so all pages
     * are returned as a flat list of raw response arrays.
     *
     * @param  string $url
     * @return array  array of decoded JSON response bodies (one per page)
     * @throws QueryException on cURL or HTTP errors
     */
    public function get($url)
    {
        $this->ensureToken();

        $pages   = [];
        $current = $url;

        while ($current !== null) {
            $ch = curl_init($current);
            curl_setopt_array($ch, $this->curl_opts + [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HTTPHEADER     => [
                    'X-Auth-Token: ' . $this->token,
                    'Content-Type: application/json',
                ],
            ]);

            $raw  = curl_exec($ch);
            $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $err  = curl_error($ch);
            curl_close($ch);

            if ($err) {
                throw new QueryException('OTC API cURL error: ' . $err);
            }
            if ($http < 200 || $http >= 300) {
                throw new QueryException(sprintf(
                    'OTC API error (HTTP %d) for %s: %s',
                    $http,
                    $current,
                    $raw
                ));
            }

            $data    = json_decode($raw, true);
            $pages[] = $data;
            $current = $this->nextLink($data);
        }

        return $pages;
    }

    // ── response parsing ──────────────────────────────────────────────────────

    /**
     * Extract the resource list from all response pages.
     *
     * OpenStack services wrap their lists in a top-level key, e.g.
     *   {"servers": [...]}  or  {"networks": [...]}
     *
     * This method finds that key automatically – it picks the top-level entry
     * that is a non-empty indexed array (ignoring *_links arrays).
     * Resources from all pages are merged into one flat list.
     *
     * @param  array $pages  as returned by get()
     * @return array
     */
    public function extractResources(array $pages)
    {
        $merged = [];

        foreach ($pages as $page) {
            $best_key   = null;
            $best_count = 0;

            foreach ($page as $key => $value) {
                // Skip pagination helper arrays like "servers_links"
                if (substr($key, -6) === '_links') {
                    continue;
                }
                // We want an indexed (list) array with at least one element
                if (!is_array($value) || empty($value) || !isset($value[0])) {
                    continue;
                }
                if (count($value) > $best_count) {
                    $best_key   = $key;
                    $best_count = count($value);
                }
            }

            if ($best_key !== null) {
                $merged = array_merge($merged, $page[$best_key]);
            }
        }

        return $merged;
    }

    /**
     * Return the top-level keys of the first resource as column names.
     * These are the fields available for Icinga Director sync rules.
     *
     * @param  array $resources  as returned by extractResources()
     * @return array
     */
    public function extractColumns(array $resources)
    {
        if (empty($resources)) {
            return [];
        }
        return array_keys($resources[0]);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /**
     * Return the "next" href from an OpenStack *_links array, or null.
     *
     * @param  array $data
     * @return string|null
     */
    private function nextLink(array $data)
    {
        foreach ($data as $key => $value) {
            if (substr($key, -6) !== '_links' || !is_array($value)) {
                continue;
            }
            foreach ($value as $link) {
                if (isset($link['rel']) && $link['rel'] === 'next') {
                    return $link['href'];
                }
            }
        }
        return null;
    }
}
