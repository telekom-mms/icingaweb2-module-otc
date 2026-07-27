<?php

namespace Icinga\Module\Otc\PropertyModifier;

use Icinga\Module\Director\Hook\PropertyModifierHook;
use Icinga\Module\Director\Web\Form\QuickForm;
use InvalidArgumentException;

/**
 * Get IP by Subnet Name
 *
 * Scans the enriched `addresses` map (subnet_name => [addrObj, ...]) returned
 * by the OTC Import Source and returns the IP address of the first NIC whose
 * subnet name matches the configured pattern (glob wildcards supported,
 * e.g. *mgmt*, subnet-prod-01).
 *
 * Prerequisites:
 *   - The OTC Import Source must have "Enrich subnet names" enabled so that
 *     the `addresses` keys are human-readable subnet names instead of opaque
 *     network UUIDs.
 *
 * Use case:
 *   A server has 3 NICs in subnets subnet-mgmt, subnet-data, subnet-backup.
 *   Set Subnet Name to "*mgmt*" to extract the management IP automatically.
 */
class PropertyModifierIpBySubnetName extends PropertyModifierHook
{
    public function getName()
    {
        return 'Get IP by Subnet Name';
    }

    public function hasArraySupport()
    {
        return true;
    }

    public static function addSettingsFormFields(QuickForm $form)
    {
        $form->addElement('text', 'subnet_name', [
            'label'       => 'Subnet Name',
            'required'    => true,
            'description' => 'Subnet name or glob pattern matched against the enriched address keys '
                           . '(e.g. *mgmt*, subnet-prod-01). '
                           . 'Requires "Enrich subnet names" to be enabled on the OTC Import Source.',
        ]);

        $form->addElement('select', 'when_missing', [
            'label'       => 'When not available',
            'required'    => true,
            'value'       => 'null',
            'description' => 'What should happen when no NIC matches the subnet name?',
            'multiOptions' => [
                'null'  => 'Return NULL',
                'first' => 'Fall back to first available IP',
                'fail'  => 'Let the whole Import Run fail',
            ],
        ]);
    }

    /**
     * @param  array|\stdClass|mixed $value  Enriched addresses map (subnet_name => [addrObj, ...]).
     * @return string|null                   IP address string of the matching NIC.
     */
    public function transform($value)
    {
        if ($value instanceof \stdClass) {
            $value = (array) $value;
        }

        if (! is_array($value)) {
            return $this->handleMissing($value);
        }

        $pattern = (string) $this->getSetting('subnet_name', '*');

        foreach ($value as $subnetName => $addrList) {
            if (! fnmatch($pattern, (string) $subnetName)) {
                continue;
            }

            // Found matching subnet – return the first IP address
            $list = is_array($addrList) ? $addrList : (array) $addrList;
            foreach ($list as $addrObj) {
                $obj = is_array($addrObj) ? $addrObj : (array) $addrObj;
                if (isset($obj['addr'])) {
                    return (string) $obj['addr'];
                }
            }
        }

        return $this->handleMissing($value);
    }

    /**
     * @param  mixed $value  Original addresses array (used to build error message).
     * @return null
     */
    private function handleMissing($value)
    {
        switch ($this->getSetting('when_missing', 'null')) {
            case 'first':
                // Return the very first IP regardless of subnet
                if (is_array($value)) {
                    foreach ($value as $addrList) {
                        $list = is_array($addrList) ? $addrList : (array) $addrList;
                        foreach ($list as $addrObj) {
                            $obj = is_array($addrObj) ? $addrObj : (array) $addrObj;
                            if (isset($obj['addr'])) {
                                return (string) $obj['addr'];
                            }
                        }
                    }
                }
                return null;

            case 'fail':
                throw new InvalidArgumentException(sprintf(
                    'No NIC with subnet name matching "%s" found. Available subnets: [%s]',
                    $this->getSetting('subnet_name'),
                    is_array($value)
                        ? implode(', ', array_keys($value))
                        : '(no addresses or not enriched)'
                ));

            case 'null':
            default:
                return null;
        }
    }
}
