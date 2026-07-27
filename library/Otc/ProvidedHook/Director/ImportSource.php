<?php

namespace Icinga\Module\Otc\ProvidedHook\Director;

use Icinga\Module\Director\Hook\ImportSourceHook;
use Icinga\Module\Director\Web\Form\QuickForm;
use Icinga\Module\Otc\OtcClient;
use Icinga\Application\Logger;
use Icinga\Exception\ConfigurationError;

require_once dirname(__DIR__, 2) . '/OtcClient.php';

class ImportSource extends ImportSourceHook
{
    /** @var OtcClient|null */
    private $client = null;

    /** @var array  raw resource arrays from the last fetchData() call */
    private $resources = [];

    /**
     * Authenticate against OTC, resolve the service endpoint from the catalog,
     * fetch all resource pages and return them as an array of stdClass objects.
     *
     * When the setting `enrich_subnet_names` is truthy the `addresses` field of
     * every compute resource is re-keyed from opaque network UUIDs to
     * human-readable names derived from:
     *   1. Subnet CIDR lookup (fast, no extra API calls per server)
     *   2. Fallback: per-server Ports API → subnet_id → subnet_name
     *      (works in Shared VPCs where CIDR ranges overlap across projects)
     *
     * Only servers with more than one NIC are enriched; single-NIC servers
     * keep the UUID key and the modifier falls back to "first" automatically.
     *
     * This allows a downstream PropertyModifierIpBySubnetName modifier to
     * reliably select a specific NIC by name pattern (e.g. "*mgmt*").
     */
    public function fetchData()
    {
        $this->client = new OtcClient(
            $this->getSetting('iam_url'),
            $this->getSetting('username'),
            $this->getSetting('password'),
            $this->getSetting('domain', ''),
            $this->getSetting('project'),
            $this->getSetting('auth_type', 'password'),
            $this->getSetting('proxy', ''),
            (int) $this->getSetting('con_timeout', 0),
            (int) $this->getSetting('timeout', 0)
        );

        $service_type  = $this->getSetting('service_type');
        $resource_path = '/' . ltrim($this->getSetting('resource_path'), '/');
        $region        = $this->getSetting('region', '');

        $endpoint = $this->client->getEndpoint($service_type, $region);
        $url      = $endpoint . $resource_path;

        Logger::info('OTC ImportSource: fetching ' . $url);

        $pages           = $this->client->get($url);
        $this->resources = $this->client->extractResources($pages);

        if (empty($this->resources)) {
            Logger::warning('OTC ImportSource: no resources returned from ' . $url);
            return [];
        }

        // Optionally enrich addresses with subnet/network names
        if ($this->isTrue($this->getSetting('enrich_subnet_names', ''))) {
            try {
                $networkEndpoint = $this->client->getEndpoint('network', $region);

                // OTC/Huawei Cloud VPC: the service catalog often returns a bare
                // host URL (https://vpc.eu-de.otc.t-systems.com) without a version
                // prefix.  The Neutron-compatible API requires /v2.0/.
                // Auto-detect: if the path component is empty or just '/', append /v2.0.
                $catalogPath = parse_url($networkEndpoint, PHP_URL_PATH);
                if (empty($catalogPath) || $catalogPath === '/') {
                    $networkApiPath  = '/' . ltrim($this->getSetting('network_api_path', 'v2.0'), '/');
                    $networkEndpoint = $networkEndpoint . $networkApiPath;
                    Logger::info('OTC ImportSource: bare network endpoint detected, appended ' . $networkApiPath);
                }

                Logger::info('OTC ImportSource: starting enrichment, network endpoint: ' . $networkEndpoint);

                // Tier 1: CIDR matching (fast, single-tenant only)
                $subnets = [];
                try {
                    $subnetPages = $this->client->get($networkEndpoint . '/subnets');
                    $subnets     = $this->client->extractResources($subnetPages);
                    Logger::info(sprintf('OTC ImportSource: CIDR enrichment with %d subnet(s)', count($subnets)));
                } catch (\Exception $e) {
                    Logger::warning('OTC ImportSource: subnet listing unavailable: ' . $e->getMessage());
                }

                // Tier 2: Network UUID → name (Shared VPC fallback)
                $networkPages = $this->client->get($networkEndpoint . '/networks');
                $networks     = $this->client->extractResources($networkPages);
                Logger::info(sprintf('OTC ImportSource: networks enrichment with %d network(s)', count($networks)));

                // Tier 2+3: Per-server enrichment via CIDR (fast) then Ports API (fallback).
                // In Shared VPC we MUST query ports per device, not all ports at once.
                $resources = &$this->resources;
                foreach ($resources as &$resource) {
                    if (empty($resource['id'])) {
                        continue;
                    }
                    $serverId = $resource['id'];

                    // Skip if already enriched (no raw UUID keys left)
                    $hasUuidKey = false;
                    if (!empty($resource['addresses']) && is_array($resource['addresses'])) {
                        foreach (array_keys($resource['addresses']) as $key) {
                            if (preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $key)) {
                                $hasUuidKey = true;
                                break;
                            }
                        }
                    }
                    if (!$hasUuidKey) {
                        continue; // already enriched
                    }

                    // Count total IPs across all network keys.
                    // With a single NIC the UUID key is irrelevant – the modifier
                    // falls back to "first" anyway, so enrichment buys nothing.
                    $totalIps = 0;
                    foreach ($resource['addresses'] as $addrList) {
                        $totalIps += count((array) $addrList);
                    }
                    if ($totalIps <= 1) {
                        continue; // single NIC – no enrichment needed
                    }

                    try {
                        $ipToSubnetName  = [];  // ip_address  → subnet_name  (precise, per IP)
                        $macToSubnetName = [];  // mac_address → subnet_name  (fallback)
                        $subnetIdCache   = [];  // subnet_id   → subnet_name  (avoids duplicate API calls)


                        // --- Tier 1: CIDR pre-matching (no extra API calls) ---
                        // Match every IP in this server's addresses against the
                        // already-fetched $subnets list.  Avoids per-server ports
                        // API calls when all IPs resolve via CIDR (single-tenant).
                        if (!empty($subnets) && !empty($resource['addresses']) && is_array($resource['addresses'])) {
                            foreach ($resource['addresses'] as $addrList) {
                                foreach ((array) $addrList as $addrObj) {
                                    $addrArr = (array) $addrObj;
                                    $ip = $addrArr['addr'] ?? null;
                                    if ($ip === null || isset($ipToSubnetName[$ip])) {
                                        continue;
                                    }
                                    foreach ($subnets as $subnet) {
                                        $subnet = (array) $subnet;
                                        if (isset($subnet['cidr'], $subnet['name'])
                                            && $this->ipInCidr($ip, $subnet['cidr'])
                                        ) {
                                            $ipToSubnetName[$ip] = $subnet['name'];
                                            $debugMap[$ip] = [
                                                'subnet_name' => $subnet['name'],
                                                'method'      => 'cidr',
                                            ];
                                            break;
                                        }
                                    }
                                }
                            }
                            Logger::info(sprintf(
                                'OTC ImportSource: server %s – CIDR resolved %d IP(s)',
                                $serverId, count($ipToSubnetName)
                            ));
                        }

                        // Collect all IPs for this server to find unresolved ones
                        $allIps = [];
                        if (!empty($resource['addresses']) && is_array($resource['addresses'])) {
                            foreach ($resource['addresses'] as $addrList) {
                                foreach ((array) $addrList as $addrObj) {
                                    $ip = ((array) $addrObj)['addr'] ?? null;
                                    if ($ip !== null) {
                                        $allIps[$ip] = true;
                                    }
                                }
                            }
                        }
                        $unresolvedIps = array_diff_key($allIps, $ipToSubnetName);

                        // --- Tier 2: Ports API (only for IPs CIDR could not resolve) ---
                        // OTC Cloud ports carry subnet info in the `fixed_ips` array
                        // (each entry: {subnet_id, ip_address}), not a top-level field.
                        if (!empty($unresolvedIps)) {
                            $serverPortUrl = $networkEndpoint . '/ports?device_id=' . $serverId;
                            Logger::info('OTC ImportSource: fetching ports for server ' . $serverId . ' via ' . $serverPortUrl);
                            $serverPortPages = $this->client->get($serverPortUrl);
                            $serverPorts     = $this->client->extractResources($serverPortPages);
                            Logger::info(sprintf('OTC ImportSource: server %s has %d port(s)', $serverId, count($serverPorts)));

                            foreach ($serverPorts as $port) {
                                $port = (array) $port;

                                if (!isset($port['mac_address'], $port['fixed_ips'])) {
                                    Logger::info(sprintf(
                                        'OTC ImportSource: server %s – port missing mac_address or'
                                        . ' fixed_ips, skipping. Available keys: [%s]',
                                        $serverId, implode(', ', array_keys($port))
                                    ));
                                    continue;
                                }

                                $mac      = $port['mac_address'];
                                $fixedIps = (array) $port['fixed_ips'];

                                Logger::info(sprintf(
                                    'OTC ImportSource: server %s – port mac=%s has %d fixed_ip(s)',
                                    $serverId, $mac, count($fixedIps)
                                ));

                                foreach ($fixedIps as $fixedIp) {
                                    $fixedIp  = (array) $fixedIp;
                                    $subnetId = $fixedIp['subnet_id'] ?? null;
                                    $ipAddr   = $fixedIp['ip_address'] ?? null;

                                    if ($subnetId === null) {
                                        Logger::info(sprintf(
                                            'OTC ImportSource: server %s mac=%s – fixed_ip entry'
                                            . ' has no subnet_id, skipping. Keys: [%s]',
                                            $serverId, $mac, implode(', ', array_keys($fixedIp))
                                        ));
                                        continue;
                                    }

                                    // If this IP was already resolved via CIDR, just populate
                                    // the MAC fallback and skip another API call.
                                    if ($ipAddr !== null && isset($ipToSubnetName[$ipAddr])) {
                                        $macToSubnetName[$mac] = $ipToSubnetName[$ipAddr];
                                        continue;
                                    }

                                    // Resolve subnet_id → subnet_name (cached).
                                    //
                                    // GET /subnets/{uuid} returns {"subnet": {...}} (singular
                                    // wrapper), NOT a list.  extractResources() expects an indexed
                                    // array and returns [] for detail responses – use direct key
                                    // access instead.
                                    if (!isset($subnetIdCache[$subnetId])) {
                                        try {
                                            $detailUrl    = $networkEndpoint . '/subnets/' . $subnetId;
                                            Logger::info(
                                                'OTC ImportSource: fetching subnet detail for '
                                                . $subnetId . ' via ' . $detailUrl
                                            );
                                            $detailPages  = $this->client->get($detailUrl);
                                            $detailSubnet = $detailPages[0]['subnet'] ?? null;
                                            if ($detailSubnet !== null && isset($detailSubnet['name'])) {
                                                $subnetIdCache[$subnetId] = $detailSubnet['name'];
                                                Logger::info(
                                                    'OTC ImportSource: subnet_id ' . $subnetId
                                                    . ' → subnet_name "' . $detailSubnet['name'] . '"'
                                                );
                                            } else {
                                                $subnetIdCache[$subnetId] = $subnetId;
                                                Logger::info(
                                                    'OTC ImportSource: subnet_id ' . $subnetId
                                                    . ' – no name returned, keeping UUID as name'
                                                );
                                            }
                                        } catch (\Exception $e) {
                                            Logger::warning(
                                                'OTC ImportSource: subnet detail lookup failed for '
                                                . $subnetId . ': ' . $e->getMessage()
                                            );
                                            $subnetIdCache[$subnetId] = $subnetId;
                                        }
                                    }

                                    $subnetName = $subnetIdCache[$subnetId];

                                    // Per-IP mapping (1:1 – one IP belongs to exactly one subnet)
                                    if ($ipAddr !== null) {
                                        $ipToSubnetName[$ipAddr] = $subnetName;
                                        $debugMap[$ipAddr] = [
                                            'mac'         => $mac,
                                            'subnet_id'   => $subnetId,
                                            'subnet_name' => $subnetName,
                                            'method'      => 'ports-api',
                                        ];
                                        Logger::info(sprintf(
                                            'OTC ImportSource: server %s – RESOLVED'
                                            . ' mac=%s  ip=%s  subnet_id=%s  subnet_name=%s',
                                            $serverId, $mac, $ipAddr, $subnetId, $subnetName
                                        ));
                                    }

                                    // MAC fallback: last fixed_ip wins when multiple exist per port
                                    $macToSubnetName[$mac] = $subnetName;
                                }
                            }
                        }

                        Logger::info(sprintf(
                            'OTC ImportSource: server %s – ip→subnet map: %s',
                            $serverId, json_encode($ipToSubnetName)
                        ));

                        // Enrich addresses: prefer ip→subnet (precise), fall back to mac→subnet
                        if (isset($resource['addresses']) && is_array($resource['addresses'])) {
                            if (!empty($ipToSubnetName)) {
                                Logger::info(sprintf(
                                    'OTC ImportSource: enriching server %s with %d ip→subnet mapping(s)',
                                    $serverId, count($ipToSubnetName)
                                ));
                                $this->enrichResourceAddresses($resource, $macToSubnetName, $networks, $ipToSubnetName);
                            } elseif (!empty($macToSubnetName)) {
                                Logger::info(sprintf(
                                    'OTC ImportSource: enriching server %s with %d mac→subnet'
                                    . ' mapping(s) (ip fallback)',
                                    $serverId, count($macToSubnetName)
                                ));
                                $this->enrichResourceAddresses($resource, $macToSubnetName, $networks);
                            }
                        }


                    } catch (\Exception $e) {
                        Logger::warning('OTC ImportSource: ports lookup failed for server ' . $serverId . ': ' . $e->getMessage());
                    }
                }
                unset($resource);
            } catch (\Exception $e) {
                Logger::warning('OTC ImportSource: address enrichment failed – ' . $e->getMessage());
            }
        }

        return array_map(function ($r) {
            return (object) $r;
        }, $this->resources);
    }

    /**
     * Settings form shown in Icinga Director under
     * Automation → Import Source → add.
     */
    public static function addSettingsFormFields(QuickForm $form)
    {
        $form->addElement('text', 'iam_url', [
            'label'       => 'IAM URL',
            'required'    => true,
            'description' => 'Keystone v3 IAM base URL, e.g. https://iam.eu-de.otc.t-systems.com',
        ]);

        $form->addElement('select', 'auth_type', [
            'label'        => 'Authentication Type',
            'required'     => true,
            'multiOptions' => [
                'password' => 'Username / Password',
                'aksk'     => 'Access Key / Secret Key (AK/SK)',
            ],
            'value'       => 'password',
        ]);

        $form->addElement('text', 'username', [
            'label'       => 'Username / Access Key (AK)',
            'required'    => true,
            'description' => 'IAM username for password auth, or Access Key (AK) for AK/SK auth.',
        ]);

        $form->addElement('password', 'password', [
            'label'       => 'Password / Secret Key (SK)',
            'required'    => true,
            'description' => 'IAM password for password auth, or Secret Key (SK) for AK/SK auth.',
        ]);

        $form->addElement('text', 'domain', [
            'label'       => 'Domain Name',
            'required'    => false,
            'description' => 'OTC account domain, e.g. OTC0000123456. Required for password auth; not used for AK/SK.',
        ]);

        $form->addElement('text', 'project', [
            'label'       => 'Project / Region',
            'required'    => true,
            'description' => 'Project name (usually the region), e.g. eu-de',
        ]);

        $form->addElement('text', 'region', [
            'label'       => 'Region Filter (optional)',
            'description' => 'Filter service catalog by region, e.g. eu-de. Leave empty to accept the first matching endpoint.',
        ]);

        $form->addElement('text', 'service_type', [
            'label'       => 'Service Type',
            'required'    => true,
            'description' => 'OpenStack / OTC service catalog type, e.g. compute, network',
        ]);

        $form->addElement('text', 'resource_path', [
            'label'       => 'Resource Path',
            'required'    => true,
            'description' => 'Path relative to the service endpoint, e.g. /servers/detail  /networks  /loadbalancers  /zones',
        ]);

        $form->addElement('select', 'enrich_subnet_names', [
            'label'       => 'Enrich addresses with subnet/network names',
            'description' => 'Re-key the addresses map from network UUIDs to subnet names via CIDR lookup, '
                            . 'falling back to the Ports API when CIDR is ambiguous (Shared VPC). '
                            . 'Requires a network endpoint in the service catalog. '
                            . 'Enable for compute resources to allow key-pattern IP selection.',
            'value'       => 'false',
            'multiOptions' => [
                'false' => 'No',
                'true'  => 'Yes',
            ],
        ]);

        $form->addElement('text', 'network_api_path', [
            'label'       => 'Network API Path Prefix',
            'required'    => false,
            'value'       => 'v2.0',
            'description' => 'Version prefix appended to the network endpoint when the service catalog '
                           . 'does not include it (OTC/Huawei Cloud VPC returns a bare host URL). '
                           . 'Default: v2.0  →  https://vpc.../v2.0/subnets',
        ]);

        $form->addElement('text', 'proxy', [
            'label'       => 'HTTP Proxy',
            'description' => 'Optional proxy URL, e.g. http://proxy.example.com:3128',
        ]);

        $form->addElement('text', 'con_timeout', [
            'label'       => 'Connect Timeout (s)',
            'description' => 'cURL connect timeout in seconds; 0 = no limit',
            'value'       => '0',
        ]);

        $form->addElement('text', 'timeout', [
            'label'       => 'Request Timeout (s)',
            'description' => 'cURL request timeout in seconds; 0 = no limit',
            'value'       => '0',
        ]);
    }

    /**
     * Columns are derived from the union of all top-level keys across all
     * returned resources.  No hardcoding – every field the API returns is
     * available automatically.
     */
    public function listColumns()
    {
        if ($this->client === null) {
            return ['placeholder: run a preview to discover columns'];
        }
        return $this->client->extractColumns($this->resources);
    }

    public static function getDefaultKeyColumnName()
    {
        return 'id';
    }

    public function getName()
    {
        return 'OTC';
    }

    // ── private helpers ───────────────────────────────────────────────────────

    /**
     * Enrich a single resource's addresses using ip→subnet_name (preferred)
     * and mac→subnet_name (fallback) mappings from the per-server ports lookup.
     *
     * Resolution order per address entry:
     *   1. ip_address  → subnet_name  (precise: 1 IP = 1 subnet)
     *   2. mac_address → subnet_name  (fallback: last fixed_ip wins per port)
     *   3. network UUID → network name (via /networks)
     *   4. networkKey:ip              (last resort)
     *
     * @param array $resource         modified in-place
     * @param array $macToSubnetName  mac_address → subnet_name
     * @param array $networks         for UUID → name fallback
     * @param array $ipToSubnetName   ip_address  → subnet_name (optional, preferred)
     */
    private function enrichResourceAddresses(array &$resource, array $macToSubnetName, array $networks, array $ipToSubnetName = []): void
    {
        $networkMap = [];
        foreach ($networks as $net) {
            if (isset($net['id'], $net['name'])) {
                $networkMap[$net['id']] = $net['name'];
            }
        }

        $enriched = [];
        foreach ($resource['addresses'] as $networkKey => $addrList) {
            foreach ((array) $addrList as $addrObj) {
                $addrArr = (array) $addrObj;
                $mac  = $addrArr['OS-EXT-IPS-MAC:mac_addr'] ?? null;
                $ip   = $addrArr['addr'] ?? null;
                $name = null;

                // Tier 1: IP-based mapping (1:1 – most precise)
                if ($ip !== null && isset($ipToSubnetName[$ip])) {
                    $name = $ipToSubnetName[$ip];
                }

                // Tier 2: MAC-based mapping fallback
                if ($name === null && $mac !== null && isset($macToSubnetName[$mac])) {
                    $name = $macToSubnetName[$mac];
                }

                // Tier 3: Network UUID → network name
                if ($name === null && isset($networkMap[$networkKey])) {
                    $name = $networkMap[$networkKey];
                }

                // Final fallback: keep UUID + IP so the data is not lost
                if ($name === null) {
                    $name = $networkKey . ':' . $ip;
                }

                if (!isset($enriched[$name])) {
                    $enriched[$name] = [];
                }
                $enriched[$name][] = $addrObj;
            }
        }
        $resource['addresses'] = $enriched;
    }

    /**
     * Test whether an IPv4 address falls within a CIDR block.
     *
     * Protected so that test subclasses can expose it via a thin public wrapper.
     *
     * @param string $ip    e.g. "192.0.2.82"
     * @param string $cidr  e.g. "192.0.2.80/28"
     * @return bool
     */
    protected function ipInCidr(string $ip, string $cidr): bool
    {
        $parts  = explode('/', $cidr, 2);
        $prefix = isset($parts[1]) ? (int) $parts[1] : 32;

        $ipLong  = ip2long($ip);
        $netLong = ip2long($parts[0]);

        if ($ipLong === false || $netLong === false) {
            return false;
        }

        // A prefix of 0 means match everything; avoid undefined-behaviour of <<32
        $mask = $prefix === 0 ? 0 : (~0 << (32 - $prefix));

        return ($ipLong & $mask) === ($netLong & $mask);
    }

    /**
     * Return true for common truthy string values ("1", "true", "yes", "on").
     *
     * @param mixed $value
     * @return bool
     */
    private function isTrue($value): bool
    {
        return in_array(strtolower((string) $value), ['1', 'true', 'yes', 'on'], true);
    }
}
