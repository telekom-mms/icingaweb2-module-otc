<?php

namespace Icinga\Module\Otc\PropertyModifier;

use Icinga\Module\Director\Hook\PropertyModifierHook;
use Icinga\Module\Director\Web\Form\QuickForm;
use InvalidArgumentException;

/**
 * PropertyModifierArrayElementByKeyPattern
 *
 * Selects the value of the first array key that matches a given glob pattern
 * (e.g. "*mgmt*").  Designed for use with the OTC `addresses` field after
 * enrichAddressesWithSubnetNames() has re-keyed the map from opaque UUIDs to
 * human-readable subnet names.
 *
 * Settings
 * --------
 * key_pattern   Glob pattern matched against each array key, e.g. "*mgmt*"
 * when_missing  What to do when no key matches:
 *                 "null"  – return null (default)
 *                 "first" – fall back to the first array element
 *                 "fail"  – throw InvalidArgumentException
 *
 * Full modifier chain to extract a specific NIC's IP
 * ---------------------------------------------------
 * 1. PropertyModifierArrayElementByKeyPattern  key_pattern=*mgmt*  when_missing=first
 *    addresses  →  [['addr' => '10.x.x.x', ...]]
 * 2. PropertyModifierArrayElementByPosition    position_type=first
 *    addresses  →  ['addr' => '10.x.x.x', ...]
 * 3. PropertyModifierArrayElementByPosition    position_type=keyname  position=addr
 *    addresses  →  ip_address = "10.x.x.x"
 */
class PropertyModifierArrayElementByKeyPattern extends PropertyModifierHook
{
    public function getName()
    {
        return 'Get Array Element by Key Pattern';
    }

    public function hasArraySupport()
    {
        return true;
    }

    public static function addSettingsFormFields(QuickForm $form)
    {
        $form->addElement('text', 'key_pattern', [
            'label'       => 'Key Pattern',
            'required'    => true,
            'description' => 'Glob pattern matched against array keys (e.g. *mgmt*, *transit*). '
                           . 'The value of the first matching key is returned.',
        ]);

        $form->addElement('select', 'when_missing', [
            'label'       => 'When not available',
            'required'    => true,
            'value'       => 'null',
            'description' => 'What should happen when no key matches the pattern?',
            'multiOptions' => [
                'null'  => 'Return NULL',
                'first' => 'Fall back to first element',
                'fail'  => 'Let the whole Import Run fail',
            ],
        ]);
    }

    /**
     * @param array|\stdClass|mixed $value
     * @return mixed|null
     */
    public function transform($value)
    {
        if ($value instanceof \stdClass) {
            $value = (array) $value;
        }

        if (! is_array($value)) {
            return $this->handleMissing($value);
        }

        $pattern = (string) $this->getSetting('key_pattern', '*');

        foreach ($value as $key => $element) {
            if (fnmatch($pattern, (string) $key)) {
                return $element;
            }
        }

        return $this->handleMissing($value);
    }

    /**
     * @param mixed $value  the original value (used for fallback / error message)
     * @return mixed|null
     */
    private function handleMissing($value)
    {
        switch ($this->getSetting('when_missing', 'null')) {
            case 'first':
                if (is_array($value) && ! empty($value)) {
                    return array_shift($value);
                }
                return null;

            case 'fail':
                throw new InvalidArgumentException(sprintf(
                    'No key matching pattern "%s" found in [%s]',
                    $this->getSetting('key_pattern'),
                    implode(', ', is_array($value) ? array_keys($value) : [])
                ));

            case 'null':
            default:
                return null;
        }
    }
}
