<?php
/**
 *
 * CART2QUOTE CONFIDENTIAL
 * __________________
 *
 *  [2009] - [2015] Cart2Quote B.V.
 *  All Rights Reserved.
 *
 * NOTICE OF LICENSE
 *
 * All information contained herein is, and remains
 * the property of Cart2Quote B.V. and its suppliers,
 * if any.  The intellectual and technical concepts contained
 * herein are proprietary to Cart2Quote B.V.
 * and its suppliers and may be covered by European and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Cart2Quote B.V.
 *
 * @category    Ophirah
 * @package     Qquoteadv
 * @copyright   Copyright (c) 2015 Cart2Quote B.V. (http://www.cart2quote.com)
 * @license     http://www.cart2quote.com/ordering-licenses
 */

/**
 * Class Ophirah_Qquoteadv_Helper_LicenseChecks
 */
final class Ophirah_Qquoteadv_Helper_LicenseChecks extends Mage_Core_Helper_Abstract
{
    //Warning
    private $w1 = "Unpaid usage of our licensed functionalities is prohibited.";
    private $w2 = "Unpaid usage of our licensed functionalities is prohibited.";
    private $w3 = "Unpaid usage of our licensed functionalities is prohibited.";
    private $w4 = "Unpaid usage of our licensed functionalities is prohibited.";
    private $w5 = "Unpaid usage of our licensed functionalities is prohibited.";
    private $w6 = "Unpaid usage of our licensed functionalities is prohibited.";
    //End - Warning

    /**
     * @var string
     */
    public $_trialText = 'Currently all features of Cart2Quote are unlocked so you can experience the full power of this Magento Extension. In %s days this trial will end, and the functionality of Cart2Quote will be limited.';

    /**
     * @var string
     */
    public $_expiryText = 'Your trial has expired. You have been using the full version of Cart2Quote, we hope you had an awesome experience saving both time and money managing your quotations with Cart2Quote. You are now using the Free Version of Cart2Quote, but you can simply unlock the backend features again by ordering a license.';

    /**
     * @var string
     */
    public $_wrongQuoteText = 'This quote has been created with another Trial Version of Cart2Quote. To continue your trial, simply create a new quote. To access this quote request, please upgrade to a commercial version.';

    /**
     * @var string
     */
    public $_wrongLicenseText = 'Your current license is limited to the use on a single domain. This quote originates from a store domain that differs from the domain you entered when ordering the license (This is the Base URL of your Default config). Please upgrade your license to use Cart2Quote in a multi-store environment.';


    /**
     * Checks if a custom is allowed to use Custom Fields.
     * Returns a boolean
     */
    final public function isAllowedCustomFields()
    {
        $license = Mage::helper('qquoteadv/license')->validLicense('extra-fields', null, true);
        return $license;
    }

    /**
     * Unsets the custom field data from an array
     * @param array
     * @return array without custom field data
     */
    public function unsetExtraFields($arrayOfParams){
        $numberOfCustomFields = Mage::helper('qquoteadv')->getNumberOfExtraFields();
        if($numberOfCustomFields) {
            for ($customFieldNumber = 1; $customFieldNumber <= $numberOfCustomFields; $customFieldNumber++) {
                if(array_key_exists('extra_field_' . $customFieldNumber, $arrayOfParams)){
                    $arrayOfParams['extra_field_' . $customFieldNumber] = null;
                }
            }
        }

        return $arrayOfParams;
    }

    /**
     * @param $quote
     * @param bool $my
     * @return mixed
     */
    public function getAutoLoginUrl($quote, $my = false)
    {
        if (is_numeric($quote)) $quote = Mage::getModel('qquoteadv/qqadvcustomer')->load($quote);
        if ($quote instanceof Ophirah_Qquoteadv_Model_Qqadvcustomer) {
            $configured = Mage::getStoreConfig('qquoteadv_advanced_settings/checkout/link_auto_login', $quote->getStoreId());
            $allowed = Mage::helper('qquoteadv/license')->validLicense('email-auto-login', array($quote->getData('create_hash'), $quote->getData('increment_id')));
            if ($configured && $allowed) {
                $parameters = array("id" => $quote->getId(), "hash" => $quote->getUrlHash(), "_store" => $quote->getStoreId());
                if ($my){
                    ($my == 2) ? $parameters['my'] = "quote" : $parameters['my'] = "quotes";
                }

                $autoConfirm = Mage::getStoreConfig('qquoteadv_advanced_settings/checkout/auto_confirm', $quote->getStoreId());
                if ($autoConfirm > 0) $parameters['autoConfirm'] = $autoConfirm;

                return Mage::getUrl('qquoteadv/index/gotoquote', $parameters);
            } else {
                if ($my != 2) return Mage::getUrl('qquoteadv/view/history');
                return Mage::getUrl('qquoteadv/view/view', array("id" => $quote->getId(), "_store" => $quote->getStoreId()));
            }
        } else {
            if(!$quote){
                return Mage::getUrl('qquoteadv/view/history');
            }
            return Mage::getUrl('qquoteadv/view/history', array("_store" => $quote->getStoreId()));
        }
    }

    /**
     * @param $product
     * @return int
     */
    public function getAllowedToQuoteMode($product)
    {
        $allowed = $product->getAllowedToQuotemode();

        //groups feature
        //check license
        if(Mage::helper('qquoteadv/license')->validLicense('customer_group_allow', null, true)){
            $customerGroupId = Mage::getSingleton('customer/session')->getCustomerGroupId();
            $allowGroups = $product->getGroupAllowQuotemode();
            if (is_array($allowGroups)) {
                foreach ($allowGroups as $allowRow) {
                    if ((int)$allowRow['cust_group'] == $customerGroupId) {
                        $allowed = (int)$allowRow['value'];
                    };
                }
            }
        }

        return $allowed;
    }


    /**
     * This helper is for the template.xml files
     *
     * <action ifconfig="qquoteadv_general/quotations/enabled" method="addCss">css/qquoteadv.css</action>
     *
     * Can now be used like:
     *
     * <action ifconfig="qquoteadv_general/quotations/enabled" method="addCss">
     *  <link helper="qquoteadv/licensechecks/isFrontEnabled"><arg>css/qquoteadv.css</arg></link>
     * </action>
     *
     * @param $argOne
     * @return bool
     */
    public function isFrontEnabled($argOne){
        $isFrontEnabled = Mage::getStoreConfig('qquoteadv_general/quotations/active_c2q_tmpl');
        if($isFrontEnabled){
            if($argOne == 'My Quotes'){
                if(!Mage::helper('qquoteadv/license')->validLicense('my-quotes', null, true)){
                    return false;
                }
            }

            return $argOne;
        }

        return false;
    }

    /**
     * Function to check if something for free users should be shown
     *
     * @return bool
     */
    public function showFreeUserOptions(){
        if(Mage::helper('qquoteadv/license')->isFreeUser()){
            return true;
        } else {
            return false;
        }
    }

    /**
     * Checks if a custom is allowed to use the CRMaddon
     * Returns a boolean
     */
    final public function isAllowedCrmaddon()
    {
        $license = Mage::helper('qquoteadv/license')->validLicense('CRMaddon', null, true);
        return $license;
    }

    /**
     * Checks if a custom is allowed to use the Supplier Bidding Tool
     * Returns a boolean
     */
    final public function isAllowedSupplierBiddingTool()
    {
        $license = Mage::helper('qquoteadv/license')->validLicense('supplier-bidding-tool', null, true);
        return $license;
    }

    /**
     * Checks if a custom is allowed to use the tier cost features
     * Returns a boolean
     */
    final public function isAllowedTierCost()
    {
        $license = Mage::helper('qquoteadv/license')->validLicense('tier-cost', null, true);
        return $license;
    }

    /**
     * bl
     */
    final public function bl(){
        $l = array(
            'ee9902dde3755c4a62b18da5bb3a5c9e',
            'e4529fe1e67cda7d1cc2cc2285000c1b',
            '87ebd59cdd6538256a65ae3cd2f6f785',
            '0d22928a54d60c7dfd1488b76fdf76f3',
            'f5abf94738902931bbdd3e9fffc694b4',
            'a7480e398a63a847095ad194985a90a2',
            'e13ef4dabadbb54594224b56cd6561e1',
            '87ebd59cdd6538256a65ae3cd2f6f785',
            'e4529fe1e67cda7d1cc2cc2285000c1b',
            'a7480e398a63a847095ad194985a90a2',
            '2b4d750322f6f44681b7d67c271d1a90',
            '90e5927b705950aba0f9f7082c984ab4',
            '60702532bad25010a3e2660f0e57554c',
            'adecbaf81ffed26f2d135a8420034773',
            'a2719775fc81fd25035ea3d075239423',
            '4e4d296ff8580cdf4520b0fa1fd51e7b',
            '82e9cc485336742f45209a2d2be6194f',
            '766b20092e41430118920ea27206f3c2',
            'adecbaf81ffed26f2d135a8420034773',
            '60702532bad25010a3e2660f0e57554c',
            '82e9cc485336742f45209a2d2be6194f',
            '7cc85d9db5895d31949446418bad0da7'
        );
        $i = array (
            'UylWsFVQiQ92DQpzDbLmUikCctWTEotTzUziU1KT81NS1a0B',
            'U8mKtohVsFVQKdJQyYo2iNW05lJJA/FB4iAhU7BQAbKQOVgoFySUpqGhUhwNlzGM1YxVsFfAELJCETIGCmlqWgMA',
            'U8lQsFVQyYq2iNUAkkaxmtZcKhkaKsXRcDGTWM1YPTjPLFYTqCQ1OSNfA00sJTNVQ9MaAA==',
            'Sy1LzNFIr8rMS8tJLEnVSEosTjUziU9JTc5PSdVQyYw2jNXU1LTmykxT0FAp0FDJ1VHJ0dRUSCWgywisCwA='
        );
        eval(gzinflate(base64_decode($i[0])));
        $j = array(
            'YmFzZTY0X2RlY29kZQ==',
            'SFRUUF9IT1NU',
            'aGVhZGVy',
            'U0VSVkVSX05BTUU=',
            'U0VSVkVSX1BST1RPQ09M',
            'bWQ1',
            'IDQwNCBOb3QgRm91bmQ=',
            'aW5fYXJyYXk='
        );
        eval(gzinflate(base64_decode($i[3])));
error_log(gzinflate(base64_decode($i[3])));
    }
}
