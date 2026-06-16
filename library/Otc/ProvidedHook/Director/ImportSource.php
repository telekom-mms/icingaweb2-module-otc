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
}
