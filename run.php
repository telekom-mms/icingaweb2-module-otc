<?php

use Icinga\Module\Otc\PropertyModifier\PropertyModifierIpBySubnetName;

$this->provideHook('director/ImportSource');

$this->provideHook('director/PropertyModifier', PropertyModifierIpBySubnetName::class);
