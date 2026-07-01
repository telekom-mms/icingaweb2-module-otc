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
     * every compute resource is re-keyed from opaque network UUIDs (or VPC names)
     * to human-readable subnet names derived from CIDR matching.  This allows a
     * downstream PropertyModifierArrayElementByKeyPattern modifier to reliably
     * select a specific NIC by name pattern (e.g. "*mgmt*") instead of blindly
     * taking the first element.
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

        // Optionally enrich addresses with subnet names (CIDR-based re-keying)
        if ($this->isTrue($this->getSetting('enrich_subnet_names', ''))) {
            try {
                $networkEndpoint = $this->client->getEndpoint('network', $region);
                $subnetPages     = $this->client->get($networkEndpoint . '/subnets');
                $subnets         = $this->client->extractResources($subnetPages);

                Logger::info(sprintf(
                    'OTC ImportSource: enriching addresses with %d subnet name(s)',
                    count($subnets)
                ));

                $this->resources = $this->enrichAddressesWithSubnetNames($this->resources, $subnets);
            } catch (\Exception $e) {
                Logger::warning(
                    'OTC ImportSource: subnet name enrichment failed, addresses remain as-is – '
                    . $e->getMessage()
                );
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
            'description' => 'OpenStack service catalog type, e.g. compute, network',
        ]);

        $form->addElement('text', 'resource_path', [
            'label'       => 'Resource Path',
            'required'    => true,
            'description' => 'Path relative to the service endpoint, e.g. /servers/detail  /networks  /loadbalancers  /zones',
        ]);

        $form->addElement('select', 'enrich_subnet_names', [
            'label'       => 'Enrich addresses with subnet names',
            'description' => 'Re-key the addresses map from network UUIDs to subnet names via CIDR lookup. '
                           . 'Requires a network endpoint in the service catalog. '
                           . 'Enable for compute resources to allow key-pattern IP selection.',
            'value'       => 'false',
            'multiOptions' => [
                'false' => 'No',
                'true'  => 'Yes',
            ],
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
     * Columns are derived from the top-level keys of the first returned resource.
     * No hardcoding – every field the API returns is available automatically.
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
     * Re-key the `addresses` map of each resource from opaque network UUIDs (or
     * VPC names) to the human-readable OTC subnet names that the IPs belong to.
     *
     * Before enrichment a multi-NIC VM looks like:
     *   addresses = {
     *     "791f9f9f-uuid": [
     *       {"addr": "192.0.2.50"},
     *       {"addr": "192.0.2.82"},
     *       {"addr": "192.0.2.66"},
     *     ]
     *   }
     *
     * After enrichment (with subnet CIDRs 192.0.2.48/28 → "example-data-subnet", etc.):
     *   addresses = {
     *     "example-data-subnet": [{"addr": "192.0.2.50"}],
     *     "example-mgmt-subnet": [{"addr": "192.0.2.82"}],
     *     "example-app-subnet":  [{"addr": "192.0.2.66"}],
     *   }
     *
     * IPs that do not fall into any known subnet CIDR are kept under their
     * original network key.
     *
     * @param array $resources  flat list of resource arrays (modified in-place)
     * @param array $subnets    list of subnet arrays each with 'name' and 'cidr'
     * @return array
     */
    private function enrichAddressesWithSubnetNames(array $resources, array $subnets): array
    {
        foreach ($resources as &$resource) {
            if (empty($resource['addresses']) || ! is_array($resource['addresses'])) {
                continue;
            }

            $enriched = [];

            foreach ($resource['addresses'] as $networkKey => $addrList) {
                foreach ((array) $addrList as $addrObj) {
                    $ip         = $addrObj['addr'] ?? null;
                    $subnetName = null;

                    if ($ip !== null) {
                        foreach ($subnets as $subnet) {
                            if (isset($subnet['cidr'], $subnet['name'])
                                && $this->ipInCidr($ip, $subnet['cidr'])
                            ) {
                                $subnetName = $subnet['name'];
                                break;
                            }
                        }
                    }

                    // Each IP gets its own key; unknown IPs fall back to the
                    // original network key (suffixed with the IP to avoid collisions).
                    $key             = $subnetName ?? ($networkKey . ':' . ($ip ?? 'unknown'));
                    $enriched[$key]  = [$addrObj];
                }
            }

            $resource['addresses'] = $enriched;
        }

        unset($resource);
        return $resources;
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
