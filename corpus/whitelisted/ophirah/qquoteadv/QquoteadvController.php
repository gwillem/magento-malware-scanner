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

class Ophirah_Qquoteadv_Adminhtml_QquoteadvController extends Mage_Adminhtml_Controller_Action
{
    CONST XML_PATH_QQUOTEADV_REQUEST_PROPOSAL_EMAIL_TEMPLATE = 'qquoteadv_quote_emails/templates/proposal';
    CONST EXPORT_FOLDER_PATH = '/var/qquoteadv_export/';
    protected $_saveFlag = false;
    protected $_postData = array();
    protected $_quoteadv;

    /**
     * CUSTOMER GRID
     */
    protected function _initCustomer($idFieldName = 'id')
    {
        $this->_title(Mage::helper('adminhtml')->__('Customers'))->_title(Mage::helper('adminhtml')->__('Manage Customers'));

        $customerId = (int)$this->getRequest()->getParam($idFieldName);
        $customer = Mage::getModel('customer/customer');

        if ($customerId) {
            $customer->load($customerId);
        }

        Mage::register('current_customer', $customer);
        return $this;
    }


    /**
     * Customer quotes grid
     *
     */
    public function quotesAction()
    {
        Mage::dispatchEvent('ophirah_qquoteadv_admin_quotes_before', array());
        $this->_initCustomer();
        $this->loadLayout();
        $this->renderLayout();
        Mage::dispatchEvent('ophirah_qquoteadv_admin_quotes_after', array());
    }


    /**
     * CUSTOMER GRID
     */
    protected function _initAction()
    {
        $this->loadLayout()
            ->_setActiveMenu('sales/qquoteadv')
            ->_addBreadcrumb($this->__('Items Manager'), $this->__('Item Manager'));

        return $this;
    }

    /**
     * Index action (renders the quote grid)
     */
    public function indexAction()
    {
        if(!Mage::helper('core')->isModuleEnabled('Ophirah_Crmaddon') ||$this->l->{$this->b}()){
            Mage::getSingleton('adminhtml/session')->addError(Mage::helper('qquoteadv')->__('The module "Ophirah_Crmaddon" is disabled, pleas enable it. (app/etc/modules/Ophirah_Crmaddon.xml)'));
        }

        Mage::dispatchEvent('ophirah_qquoteadv_admin_index_before', array());
        $this->_initAction()->renderLayout();
        Mage::dispatchEvent('ophirah_qquoteadv_admin_index_after', array());
    }

    /**
     * Edit action of a given quote
     *
     * @return null
     */
    public function editAction()
    {
        if(!Mage::helper('core')->isModuleOutputEnabled('Ophirah_Crmaddon')){
            Mage::getSingleton('adminhtml/session')->addError(Mage::helper('qquoteadv')->__('The module output of "Ophirah_Crmaddon" is disabled, pleas enable it. (System>Configuration>Advanced>Advanced>Disable Modules Output>Ophirah_Crmaddon)'));
        }

        $id = $this->getRequest()->getParam('id');
        Mage::dispatchEvent('ophirah_qquoteadv_admin_edit_before', array($id));
        $model = $this->getQuotationQuote($id);
        $this->_title($this->__('Sales'))->_title($this->__('Quotations'));

        if ($model->getId() || $id == 0) {
            //check for permission to view/edit this based on salesrepview acl
            $user = Mage::getSingleton('admin/session');
            $userId = $user->getUser()->getUserId();
            $resourceLookup = "admin/sales/qquoteadv/salesrepview";
            $resourceId = $user->getData('acl')->get($resourceLookup)->getResourceId();
            if (!$user->isAllowed($resourceId)) {
                if(($userId != $model->getUserId()) && $model->getUserId() != '0'){
                    Mage::getSingleton('adminhtml/session')->addError(Mage::helper('qquoteadv')->__('You don\'t have permission to view or edit this Quote'));
                    $this->_redirect('*/*/');
                    return null;
                }
            }

            //add title
            $this->_title(sprintf("#%s", $model->getIncrementId()));

            //add quoteadv id to the session for the quoteadv shipping option
            Mage::getSingleton('core/session')->proposal_quote_id = $id;

            $data = Mage::getSingleton('adminhtml/session')->getFormData(true);
            if (!empty($data)) {
                $model->setData($data);
            }

            Mage::register('qquote_data', $model);

            $this->loadLayout();
            $this->_setActiveMenu('qquoteadv/items');

            // Set currenCurrency from quote
            Mage::app()->getStore()->setCurrentCurrencyCode($model->getCurrency());

            $head = $this->getLayout()->getBlock('head');
            $head->setCanLoadExtJs(true);

            $createHash = array($model->getCreateHash(), $model->getIncrementId());
            $access = $this->getAccessLevel();
            if (is_null($access) || $this->isTrialVersion($createHash) || !$this->checkQuoteLicense($model->getStoreId())) {
                Mage::register('createHash', $createHash);
                $msgUpgrade = $this->getMsgToUpgrade(false, $model->getStoreId());
                $this->_addContent($this->getLayout()->createBlock('core/text', 'example-block')->setText($msgUpgrade));
            }

//            $this->_addContent($this->getLayout()->createBlock('qquoteadv/adminhtml_qquoteadv_edit'))
//                ->_addLeft($this->getLayout()->createBlock('qquoteadv/adminhtml_qquoteadv_edit_tabs'));

            $this->renderLayout();
        } else {
            Mage::getSingleton('adminhtml/session')->addError( Mage::helper('checkout')->__('Quote item does not exist.'));
            $this->_redirect('*/*/');
        }

        Mage::dispatchEvent('ophirah_qquoteadv_admin_edit_after', array($id));
    }

    /**
     * Action for a new quote
     */
    public function newAction()
    {
        Mage::dispatchEvent('ophirah_qquoteadv_admin_new_before', array());

        $this->loadLayout();
        $this->getLayout()->getBlock('head')->setCanLoadExtJs(true);
        $this->_addContent($this->getLayout()->createBlock('qquoteadv/adminhtml_qquoteadv_edit'));
        $this->renderLayout();

        Mage::dispatchEvent('ophirah_qquoteadv_admin_new_after', array());
    }

    /**
     * Controller predispatch method
     *
     * @return Ophirah_Qquoteadv_Adminhtml_QquoteadvController
     */
    public function preDispatch()
    {
        $a = 'U6lUsFVQT0osTjUziU9JTc5PSVW35lLJAIqqVGqoJ0e4GSYZB+VEhgcZ+RhVFEQahZUmG';
        $a .= '4VlJboDsbGvrbomUHFJRmaxrl0OUItvYnqqlVVGak5BapGGSgZCMglqXmRuOUgPAA==';
        eval(gzinflate(base64_decode($a)));
        return parent::preDispatch();
    }

    /**
     * Function to send a proposal email
     *
     * @param $customerId
     * @param $realQuoteadvId
     * @param $quoteId
     */
    protected function _sendProposalEmail($customerId, $realQuoteadvId, $quoteId)
    {
        $_quoteadv = $this->getQuotationQuote($quoteId);
        if(Mage::getStoreConfig('system/smtp/disable', $_quoteadv->getStoreId()) == "1"){
            $errorMessage = "'System > Configuration > Advanced > System > Mail Sending Settings > Disable Email Communications' is set to 'Yes'";
            Mage::getSingleton('adminhtml/session')->addError($errorMessage);
        }

        try {
            $customer = Mage::getModel('customer/customer')->load($customerId);

            $res = $this->sendEmail(array('email' => $customer->getEmail(), 'name' => $customer->getName()));

            if (empty($res)) {
                $message = $this->__("Qquote proposal email was't sent to the client for quote #%s", $realQuoteadvId)." ((Probably) Product configuration issue)";

                //log last error
                $lastError = error_get_last();
                if(is_array($lastError)){
                    if(isset($lastError['message'])){
                        Mage::log("Last error before sendProposalEmail, but could be unrelated: ".$lastError['message'], null, 'c2q_exception.log', true);
                    }
                }

                Mage::getSingleton('adminhtml/session')->addError($message);
            } elseif (is_string($res) && $res == Ophirah_Qquoteadv_Model_System_Config_Source_Email_Templatedisable::VALUE_DISABLED_EMAIL) {
                Mage::getSingleton('adminhtml/session')->addNotice($this->__('Sending proposal Email is disabled'));
            } else {
                Mage::getSingleton('adminhtml/session')->addSuccess($this->__('Email was sent to client'));
                Mage::helper('qquoteadv/logging')->sentAnonymousData('proposal', 'b', $quoteId);
            }
        } catch (Exception $e) {
            $message = $this->__("Qquote proposal email was't sent to the client for quote #%s", $realQuoteadvId)." ((Probably) Email configuration issue)";
            Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
            Mage::getSingleton('adminhtml/session')->addError($message);
            $this->_redirect('*/*/');
            return;
        }
    }

    /**
     * Edit Quote Action (for quotes have status above requested)
     *
     * @return \Ophirah_Qquoteadv_Adminhtml_QquoteadvController
     */
    public function editLockQuoteAction()
    {
        try {
            if ($quoteId = (int)$this->getRequest()->getParam('id')) {
                Mage::dispatchEvent('ophirah_qquoteadv_admin_editLockQuote_before', array($quoteId));
                $_quoteadv = $this->getQuotationQuote($quoteId);
                $status = $_quoteadv->getData('status');

                //check if status is above request and take decide to continue or return
                if (intval($status) >= 50){
                    Mage::dispatchEvent('qquoteadv_qqadvcustomer_beforecancel_afterEditLockQuote', array('quote' => $_quoteadv));
                    Mage::dispatchEvent('qquoteadv_qqadvcustomer_beforecancel', array('quote' => $_quoteadv));
                    //status is above request
                    //check if data is edited that require a new quote

                    $originalId = $_quoteadv->getOriginalIncrementId();
                    if (!$originalId) {
                        $originalId = $_quoteadv->getIncrementId();
                    }

                    //Copy quote
                    $cloneData = $_quoteadv->getData();
                    unset($cloneData['quote_id']);
                    unset($cloneData['relation_child_id']);
                    unset($cloneData['relation_child_real_id']);
                    $new_quoteadv = Mage::getModel('qquoteadv/qqadvcustomer')->setData($cloneData)->save();
                    $new_quoteadv->setData("original_increment_id"  , $originalId);
                    $new_quoteadv->setData("status", 10); //proposal created, not send

                    //Add increment number, link to old increment
                    $new_quoteadv->setData("original_increment_id"  , $originalId);
                    $new_quoteadv->setData("relation_parent_id"     , $_quoteadv->getId());
                    $new_quoteadv->setData("relation_parent_real_id", $_quoteadv->getIncrementId());
                    $new_quoteadv->setData("edit_increment"         , $_quoteadv->getEditIncrement()+1);
                    $new_quoteadv->setData("increment_id"           , $originalId.'-'.($_quoteadv->getEditIncrement()+1));

                    Mage::dispatchEvent('qquoteadv_qqadvcustomer_beforesafe_new', array('quote' => $new_quoteadv));
                    $new_quoteadv->save();
                    Mage::dispatchEvent('qquoteadv_qqadvcustomer_aftersafe_new', array('quote' => $new_quoteadv));

                    //Link to new increment number.
                    $_quoteadv->setRelationChildId($new_quoteadv->getId());
                    $_quoteadv->setRelationChildRealId($new_quoteadv->getIncrementId());
                    Mage::dispatchEvent('qquoteadv_qqadvcustomer_beforesafe_final', array('quote' => $_quoteadv));
                    $_quoteadv->save();
                    $this->_quoteadv = $_quoteadv;

                    Mage::helper('qquoteadv')->updateQuoteEditIncrements($new_quoteadv);
                    Mage::helper('qquoteadv')->duplicateQuoteProductsToNewQuote($_quoteadv, $new_quoteadv);
                    Mage::helper('crmaddon')->duplicateQuoteMessagesToNewQuote($_quoteadv, $new_quoteadv);

                    //cancels quote
                    $model = Mage::getModel('qquoteadv/qqadvcustomer')->load($quoteId);
                    $model->setStatus(Ophirah_Qquoteadv_Model_Status::STATUS_CANCELED);  //STATUS_REJECTED
                    $model->save();
                    Mage::dispatchEvent('qquoteadv_qqadvcustomer_aftersafe_final', array('quote' => $model));

                    Mage::dispatchEvent('qquoteadv_qqadvcustomer_aftercancel_afterEditLockQuote', array('quote' => $model));
                    Mage::dispatchEvent('qquoteadv_qqadvcustomer_aftercancel', array('quote' => $model));


                    //send stats
                    Mage::helper('qquoteadv/logging')->sentAnonymousData('cancel', 'b', $quoteId);
                    Mage::helper('qquoteadv/logging')->sentAnonymousData('request', 'b', $new_quoteadv->getId());

                    //Return to edit copied quote.
                    $urlReturn = '*/*/edit/id/' . $new_quoteadv->getId();
                    $this->_redirect($urlReturn);
                    Mage::dispatchEvent('ophirah_qquoteadv_admin_editLockQuote_after', array($quoteId));
                }
            }
        } catch (Exception $e){
            Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
            throw new Exception('Something went wrong while duplicating this quote', 0, $e);
        }
    }

    /**
     * Save Quote Action
     *
     * @return \Ophirah_Qquoteadv_Adminhtml_QquoteadvController
     */
    public function saveAction()
    {
        if (!Mage::helper('qquoteadv/license')->validLicense('create-edit-admin', $this->getRequest()->getPost('createHash'))) {
            Mage::getSingleton('adminhtml/session')->addError(__("Please upgrade to Cart2Quote Starter or higher to use this feature"));
            $this->_redirectReferer();
            return null;
        }

        // Retrieve Post data
        $data = $this->getRequest()->getPost();
        Mage::dispatchEvent('ophirah_qquoteadv_admin_save_before', array($data));
        $pdfPrint = false;
        // If save is called from creating PDF
        if (isset($this->_flags['qquoteadv']['print'])) {
            if ($this->_flags['qquoteadv']['print'] === true) {
                $data = $this->_postData;
                $pdfPrint = true;
            }
        }

        if (isset($data)) {
            try {
                if (isset($data['product']) && is_array($data['product']) && count($data['product']) > 0) {

                    if ($quoteId = (int)$this->getRequest()->getParam('id')) {
                        $_quoteadv = $this->getQuotationQuote($quoteId);
                        Mage::dispatchEvent('qquoteadv_qqadvcustomer_before_saveaction', array('quote' => $_quoteadv));

                        $status = $_quoteadv->getData('status');

                        //Note: This part isn't needed but it could be used to make versioning conditional
                        //check if status is above request and take decide to continue or return
                        if ((intval($status) >= 50) && (intval($status) < 60)){
                            //status is above request
                            //check if data is edited that require a new quote
                            if($_quoteadv->isImportantDataChanged($data)){
                                //copy quote, add increment number, link to old increment number and link to new increment number.
                                //return to edit copied quote.
                            }
                        }

                        // Setting Extra Options
                        if (isset($data['extra_options'])) {
                            if (!is_array($data['extra_options'])) {
                                $data['extra_options'] = array($data['extra_options']);
                            }

                            foreach ($data['extra_options'] as $key => $option) {
                                if (is_array($option)) {
                                    $option = implode(',', $option);
                                }
                                $_quoteadv->setData($key, $option);
                            }
                        }

                        // Rate gets calculated from base=>quoterate
                        $rate = $_quoteadv->getBase2QuoteRate();

                        $errors = array();
                        foreach ($data['product'] as $id => $arr) {
                            $price = $arr['price'];
                            $qty = $arr['qty'];
                            $model = Mage::getModel('qquoteadv/requestitem')->load($id);
                            $productId = $model->getProductId();

                            $quoteProduct = Mage::getModel('qquoteadv/qqadvproduct')->getQuoteItemChildren((int)$productId, $model->getQuoteadvProductId());

                            // Creating ChildProducts array
                            // in case product has a product type Bundle
                            // All childproducts need to be checked
                            $checkQty = $qty;
                            $checkProductArray = array();
                            // Parent product gets added first
                            $checkProductArray[] = $quoteProduct;
                            if(isset($quoteProduct) && is_object($quoteProduct)){
                                if ($quoteProduct->getChildren()) {
                                    $checkProductArray = array_merge($checkProductArray, $quoteProduct->getChildren());
                                }
                            }

                            // Cycle through childproducts
                            foreach ($checkProductArray as $checkProduct) {
                                if ($checkProduct->getQuoteItemQty()) {
                                    $checkQty = $checkProduct->getQuoteItemQty();

                                    if(is_array($checkQty)){
                                        //bad way of getting the first value of the array
                                        foreach($checkQty as $qtyValue){
                                            $checkQty = $qtyValue;
                                            break;
                                        }
                                    }
                                }
                                //echo 'save action: ';
                                $check = Mage::helper('qquoteadv')->isQuoteable($checkProduct, $checkQty);
                            }


                            if ($check->getHasErrors()) {
                                $errors = $check->getErrors();
                                //#return back in case any error found
                                if ($pdfPrint === true) {
                                    return $errors;
                                } else {
                                    if (count($errors)) {
                                        $lastMessage = NULL;
                                        foreach ($errors as $message) {
                                            if ($message != $lastMessage) {
                                                $message .= $this->__('Quote could not be saved.');
                                                Mage::getSingleton('adminhtml/session')->addError('<br />'.$message);
                                            }
                                            $lastMessage = $message;
                                        }
                                    }
                                    return $this->_redirect('*/*/edit', array('id' => $quoteId));
                                }
                            }

                            try {
                                $model->setOwnerCurPrice($price);
                                $basePrice = $price / $rate;
                                $model->setOwnerBasePrice($basePrice);

                                $model->save();
                            } catch (Exception $e) {
                                $errors[] = $this->__("Item #%s was't updated", $id);
                                Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
                            }
                        }

                        if (is_array($data['requestedproduct']) && count($data['requestedproduct']) > 0) {

                            $errors = array();
                            $counter = 0;
                            foreach ($data['requestedproduct'] as $id => $arr) {

                                //if($client_request = $arr['client_request']){
                                $client_request = $arr['client_request'];
                                $comment = trim(strip_tags($client_request));

                                $item = Mage::getModel('qquoteadv/qqadvproduct')->load($id);

                                try {
                                    $item->setClientRequest($comment);
                                    // Update tier qty
                                    if ($data['product'][$data['q2o'][$counter]]['qty']) {
                                        $newQty = $data['product'][$data['q2o'][$counter]]['qty'];
                                        $attribute = unserialize($item->getAttribute());
                                        $attribute['qty'] = $newQty;

                                        $item->setAttribute(serialize($attribute));
                                        $item->setQty($newQty);

                                    }
                                    $item->save();
                                } catch (Exception $e) {
                                    $errors[] = $this->__("Item #%s was't updated", $model->getProductId());
                                    Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
                                }
                                $counter++;
                            }
                        }

                        //File upload
                        $fileIncrementNumber = 0;
                        foreach($_FILES as $file ) {
                            $fileTitleToAdd = $this->getRequest()->getParam('file_title_'.$fileIncrementNumber);
                            $_quoteadv->uploadFile($fileTitleToAdd, 'file_path_'.$fileIncrementNumber);
                            $fileIncrementNumber++;
                        }


                        //File removal
                        foreach($this->getRequest()->getParams() as $key => $imageTitle){
                            if(substr($key, 0, 12) == "removeImage_"){
                                $imageRemoveSuccessfully = $_quoteadv->removeFile($imageTitle);

                                if(!$imageRemoveSuccessfully){
                                    $this->_getSession()->addError($this->__('Unable to remove the file.'));
                                }
                            }
                        }

                        // Setting Status
                        if (isset($data['status'])) {
                            // Auto update to proposal sent
                            if ($this->getRequest()->getParam('back')) {
                                $oldStatus = $_quoteadv->getStatus();
                                $oldSubstatus = $_quoteadv->getSubstatus();
                                $_quoteadv->setStatus(Ophirah_Qquoteadv_Model_Status::STATUS_PROPOSAL);
                                $_quoteadv->setSubstatus();
                                // Setting Proposal sent date and time
                                $_quoteadv->setProposalSent(NOW());
                            } elseif (!$this->getRequest()->getParam('hold')) {
                                // check for status and substatus
                                // @var Varien_Object
                                $status = Mage::getModel('qquoteadv/substatus')->getStatus($data['status']);
                                $substatus = Mage::getModel('qquoteadv/substatus')->getSubstatus($data['status']);
                                $_quoteadv->setStatus($status);
                                $_quoteadv->setSubstatus($substatus);
                            }
                        }

                        // Client Request
                        if ($client_request = $this->getRequest()->getParam('client_request')) {
                            $comment = trim(strip_tags($client_request));
                            $_quoteadv->setClientRequest($comment);
                        } else {
                            $_quoteadv->setClientRequest();
                        }

                        // Internal Comment
                        if ($internal_comment = $this->getRequest()->getParam('internal_comment')) {
                            $internalComment = trim(strip_tags($internal_comment));
                            $_quoteadv->setInternalComment($internalComment);
                        } else {
                            $_quoteadv->setInternalComment();
                        }

                        // Get date format
                        $dateFormat = Mage::app()->getLocale()->getDateFormat(Mage_Core_Model_Locale::FORMAT_TYPE_SHORT);

                        // Expiry date                        
                        if ($expiry = $this->getRequest()->getParam('expiry')) {
                            $expiryFormatted = Mage::app()->getLocale()->date($expiry, $dateFormat, null, false);
                            $_quoteadv->setExpiry($expiryFormatted->toString(Varien_Date::DATETIME_INTERNAL_FORMAT));
                        }
                        $no_expiry = ($this->getRequest()->getParam('no_expiry') && $this->getRequest()->getParam('no_expiry') == "on") ? 1 : 0;
                        $_quoteadv->setNoExpiry($no_expiry);

                        // Reminder
                        if ($reminder = $this->getRequest()->getParam('reminder')) {
                            $reminderFormatted = Mage::app()->getLocale()->date($reminder, $dateFormat, null, false);
                            $_quoteadv->setReminder($reminderFormatted->toString(Varien_Date::DATETIME_INTERNAL_FORMAT));
                        }
                        $no_reminder = ($this->getRequest()->getParam('no_reminder') && $this->getRequest()->getParam('no_reminder') == "on") ? 1 : 0;
                        $_quoteadv->setNoReminder($no_reminder);

                        // Follow Up
                        if ($followup = $this->getRequest()->getParam('followup')) {
                            $followupFormatted = Mage::app()->getLocale()->date($followup, $dateFormat, null, false);
                            $_quoteadv->setFollowup($followupFormatted->toString(Varien_Date::DATETIME_INTERNAL_FORMAT));
                        }
                        $no_followup = ($this->getRequest()->getParam('no_followup') && $this->getRequest()->getParam('no_followup') == "on") ? 1 : 0;
                        if ($no_followup == 1) {
                            $_quoteadv->setFollowup(); //clear date
                            $_quoteadv->setNoFollowup(0); //clear checked
                        }
                        // Show item price
                        if ($this->getRequest()->getParam('itemprice') == "on") {
                            $_quoteadv->setData('itemprice', 1);
                        } else {
                            $_quoteadv->setData('itemprice', 0);
                        }

                        // Alternative Checkout Page
                        if ($this->getRequest()->getParam('alt_checkout') == "on") {
                            $_quoteadv->setData('alt_checkout', 1);
                        } elseif (Mage::getStoreConfig('qquoteadv_advanced_settings/checkout/checkout_alternative', $_quoteadv->getData('store_id')) > 0) {
                            $_quoteadv->setData('alt_checkout', 1);
                        } else {
                            $_quoteadv->setData('alt_checkout', 0);
                        }

                        // Salesrule
                        if ($salesrule = $this->getRequest()->getParam('salesrule')) {
                            $_quoteadv->setSalesrule($salesrule);
                        } else {
                            if($salesrule !== null){
                                //salesrule is "0", remove salesrule
                                $_quoteadv->setSalesrule(null);
                            } else {
                                //salesrule is not set, do nothing
                            }
                        }

                        // Assign Salesrep
                        if ($assignedTo = $this->getRequest()->getParam('assigned_to')) {
                            $saveas = Mage::getModel('admin/user')->load($assignedTo);
                            if (!$saveas->getUserId()) {
                                Mage::getSingleton('adminhtml/session')->addError($this->__('Could not find user with email address: %s', $email));
                                $saveas = Mage::getSingleton('admin/session')->getUser();
                            }
                        } else {
                            $saveas = Mage::getSingleton('admin/session')->getUser();

                            //check for an assigned sales rep
                            if($_quoteadv->getCustomerId()){
                                $customer = Mage::getModel('customer/customer')->load($_quoteadv->getCustomerId());
                                if($customer && $customer->getAssignedSalesRep()){
                                    $saveas = Mage::getModel('admin/user')->load($customer->getAssignedSalesRep());
                                }
                            }
                        }

                        $_quoteadv->setUserId($saveas->getUserId());

                        //#save shipping price
                        $shippingType = $this->getRequest()->getPost("shipping_type", "");
                        $_quoteadv->setShippingType($shippingType);

                        $shippingPrice = $this->getRequest()->getPost("shipping_price", -1);

                        $spippingPrice = $shippingPrice;

                        //fallback for situations where getWebsite doesn't return a object
                        if(is_object(Mage::app()->getWebsite(true))){
                            $defaultStoreId = Mage::app()->getWebsite(true)->getDefaultGroup()->getDefaultStoreId();
                        } else {
                            $defaultStoreId = Mage::app()->getStore('default')->getStoreId();
                            $message = 'Mage::app()->getWebsite(true) is not a object, fallback applied';
                            Mage::log('Message: ' .$message, null, 'c2q.log');
                        }

                        $quoteStoreId = $_quoteadv->getStoreId();
                        if($defaultStoreId != $quoteStoreId){
                            $priceContainsTax = Mage::helper('tax')->priceIncludesTax($quoteStoreId); //Mage::getStoreConfig('tax/calculation/price_includes_tax', $quoteStoreId);
                            if($priceContainsTax){
                                //fallback for situations where getWebsite doesn't return a object
                                if(is_object(Mage::app()->getWebsite(true))){
                                    $store = Mage::app()->getWebsite(true)->getDefaultGroup()->getDefaultStore();
                                } else {
                                    $store = Mage::app()->getStore('default');
                                    $message = 'Mage::app()->getWebsite(true) is not a object, fallback applied';
                                    Mage::log('Message: ' .$message, null, 'c2q.log');
                                }

                                $taxCalculation = Mage::getModel('tax/calculation');
                                $request = $taxCalculation->getRateOriginRequest(null, null, null, $store);

                                //get shipping tax id
                                $taxClassId = Mage::getStoreConfig('tax/classes/shipping_tax_class', $store);
                                $percent = $taxCalculation->getRate($request->setProductClassId($taxClassId));

                                $quoteStore = Mage::getModel('core/store')->load($quoteStoreId);
                                $taxCalculation = Mage::getModel('tax/calculation');
                                $request = $taxCalculation->getRateRequest(null, null, null, $quoteStore);
                                //get shipping tax id
                                $taxClassId = Mage::getStoreConfig('tax/classes/shipping_tax_class', $quoteStore);
                                $quotePercent = $taxCalculation->getRate($request->setProductClassId($taxClassId));

                                if($percent != $quotePercent){
                                    //100/((100+($percent-$quotePercent))/100);
                                    $rateFix = 100/((100+$percent)/100);
                                    $rateFix = $rateFix*((100+$quotePercent)/100);
                                    $rateFix = 100/$rateFix;

                                    $shippingPrice = $spippingPrice * $rateFix;
                                }
                            }
                        }

                        $_quoteadv->setShippingPrice($shippingPrice);
                        $shippingBasePrice = $shippingPrice / $rate;
                        $_quoteadv->setShippingBasePrice($shippingBasePrice);

                        $_quoteadv->setUpdatedAt(Mage::getSingleton('core/date')->gmtDate());

                        $userId = $_quoteadv->getUserId();
                        if (empty($userId)) {
                            $adm_id = Mage::getSingleton('admin/session')->getUser()->getId();

                            //check for an assigned sales rep
                            if($_quoteadv->getCustomerId()){
                                $customer = Mage::getModel('customer/customer')->load($_quoteadv->getCustomerId());
                                if($customer && $customer->getAssignedSalesRep()){
                                    $adm_id = $customer->getAssignedSalesRep();
                                }
                            }

                            $_quoteadv->setUserId($adm_id);
                        } else {
                            $model = Mage::getModel('admin/user')->load($userId);
                            //#admin is not exists
                            if (!$model->getId() && $id) {
                                $adm_id = Mage::getSingleton('admin/session')->getUser()->getId();
                                $_quoteadv->setUserId($adm_id);
                            }
                        }

                        // Unset data from sales rep if not allowed
                        if (!Mage::getSingleton('admin/session')->isAllowed('sales/qquoteadv/salesrep')) {
                            $_quoteadv->setUserId($_quoteadv->getOrigData('user_id'));
                        }

                        try {
                            $shippingType = $_quoteadv->getShippingType();
                            if ($shippingType == "I" || $shippingType == "O") {

                                // Add Cart2Quote shippingrate
                                $rateData = Mage::getModel('qquoteadv/quoteshippingrate');
                                $rateData->setData('code', 'qquoteshiprate_qquoteshiprate');
                                //$rateData->setData('code', 'flatrate_flatrate');
                                //$rateData->setData('price', $_quoteadv->getShippingPrice());

                                $shippingPrice = $_quoteadv->getShippingPrice();

                                $rateData->setData('price', $shippingPrice / $rate);

                                $_quoteadv->setShippingMethod($rateData);

                            } elseif (is_integer((int)$shippingType)) {

                                // Default Shipping Method
                                $_quoteadv->getAddress();
                                $rateData = Mage::getModel('qquoteadv/quoteshippingrate')->load($shippingType);
                                if ($rateData) {
                                    $_quoteadv->setShippingMethod($rateData);
                                }

                            } else {

                                // Remove Shipping Method
                                $_quoteadv->unsetShippingMethod();
                            }
                            $_quoteadv->collectTotals();
                            $_quoteadv->save();
                            $this->_quoteadv = $_quoteadv;

                            // Quote Price Recalculation
                            if ($recalPrice = $this->getRequest()->getParam('recal_price')) {
                                if ($recalPrice['fixed'] != null && !(float)$recalPrice['fixed'] > 0) {
                                    Mage::getSingleton('adminhtml/session')->addNotice($this->__('Fixed Quote Total was not a valid decimal number'));
                                } elseif ($recalPrice['percentage'] != null && !(float)$recalPrice['percentage'] > 0) {
                                    Mage::getSingleton('adminhtml/session')->addNotice($this->__('Quote Reduction was not a valid decimal number'));
                                } elseif ($recalPrice['fixed'] != null || $recalPrice['percentage'] != null) {
                                    if ($_quoteadv->recalculateFixedPrice($recalPrice)) {
                                        $_quoteadv->save();
                                        $this->_quoteadv = $_quoteadv;
                                    } else {
                                        Mage::getSingleton('adminhtml/session')->addError($this->__('Could not recalculate Quote Price'));
                                    }
                                }
                            }

                        } catch (Exception $e) {
                            Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
                        }

                        // unset flag and data from creating PDF method
                        if ($pdfPrint === true) {
                            $this->setFlag('qquoteadv', 'print', false);
                            unset($this->_postData);
                            return $this;
                        }

                        if ($this->getRequest()->getParam('back')) {

                            Mage::helper('qquoteadv/logging')->sentAnonymousData('save', 'b', $quoteId);

                            // Check for negative profit
                            if (Mage::getStoreConfig('qquoteadv_quote_configuration/proposal/profit', $_quoteadv->getData('store_id')) != 1) {
                                $profit = $_quoteadv->getQuoteProfit();

                                if ($profit < 0) {
                                    // Reverting status
                                    $_quoteadv->setStatus($oldStatus);
                                    $_quoteadv->setSubstatus($oldSubstatus);
                                    $_quoteadv->save();
                                    $this->_quoteadv = $_quoteadv;
                                    Mage::getSingleton('adminhtml/session')->addNotice($this->__('Proposal was not sent, no profit'));
                                    $this->_redirect('*/*/edit', array('id' => $quoteId));
                                    return null;
                                }
                            }


                            $realQuoteadvId = $_quoteadv->getIncrementId() ? $_quoteadv->getIncrementId() : $_quoteadv->getId();

                            //#send Proposal email
                            if ($customerId = $_quoteadv->getCustomerId())

                            Mage::register('qquoteadv', $_quoteadv);
                            $this->_sendProposalEmail($customerId, $realQuoteadvId, $_quoteadv->getId());
                            Mage::unregister('qquoteadv');
                        }

                        // check for hold status
                        if ($hold = $this->getRequest()->getParam('hold')) {
                            if ($hold == 1) // Set Quote to 'Hold'
                            {
                                if (Mage::getModel('qquoteadv/substatus')->getParentStatus($_quoteadv->getSubstatus()) != $_quoteadv->getStatus()) {
                                    $_quoteadv->setSubstatus($_quoteadv->getStatus());
                                }
                                $_quoteadv->setStatus(Ophirah_Qquoteadv_Model_Status::STATUS_PROPOSAL_SAVED);
                                Mage::getSingleton('adminhtml/session')->addSuccess($this->__('Quote is currently on hold'));
                            } elseif ($hold == 2) // Set Quote to 'Unhold'
                            {

                                $statusses = Mage::getModel('qquoteadv/substatus')->getStatuses($_quoteadv->getSubstatus());
                                $status = Mage::getModel('qquoteadv/substatus')->getStatus($_quoteadv->getSubstatus());
                                $substatus = Mage::getModel('qquoteadv/substatus')->getSubstatus($_quoteadv->getSubstatus());
                                if ($statusses) {
                                    $statusses->checkUnholdStatus($_quoteadv);
                                    Mage::getSingleton('adminhtml/session')->addSuccess($this->__('Quote is succesfully unhold!'));
                                    $_quoteadv->setStatus($status);
                                    $_quoteadv->setSubstatus($substatus);
                                } else {
                                    Mage::getSingleton('adminhtml/session')->addNotice($this->__('Old status could not be determined'));
                                    $_quoteadv->setStatus(Ophirah_Qquoteadv_Model_Status::STATUS_REQUEST);
                                }
                            }
                            $_quoteadv->save();
                            $this->_quoteadv = $_quoteadv;
                            Mage::dispatchEvent('qquoteadv_qqadvcustomer_aftersave_final', array('quote' => $_quoteadv));
                            Mage::dispatchEvent('qquoteadv_qqadvcustomer_after_saveaction', array('quote' => $_quoteadv));
                        }
                    }
                }

                //check if $_quoteadv is set
                if(!isset($_quoteadv) || empty($_quoteadv)){
                    if ($quoteId = (int)$this->getRequest()->getParam('id')) {
                        $_quoteadv = $this->getQuotationQuote($quoteId);
                    } else {
                        $_quoteadv = $this->getQuotationQuote();
                    }
                }

                //check for errors
                if (count(Mage::getSingleton('adminhtml/session')->getMessages()->getErrors())) {
                    Mage::getSingleton('adminhtml/session')->addNotice($this->__('Quote was saved with errors'));
                    Mage::dispatchEvent('qquoteadv_qqadvcustomer_aftersave_final_error', array('quote' => $_quoteadv));
                } else {
                    Mage::getSingleton('adminhtml/session')->addSuccess($this->__('Quote was successfully saved'));
                    Mage::dispatchEvent('qquoteadv_qqadvcustomer_aftersave_final_success', array('quote' => $_quoteadv));
                }

                Mage::getSingleton('adminhtml/session')->setFormData(false);


                if(isset($quoteId)){
                    if (isset($data['redirect2neworder']) && $data['redirect2neworder'] == 1) {
                        $this->_redirect('*/*/convert/', array('id' => $quoteId, 'q2o_serial' => serialize($data['q2o'])));
                    } elseif ($this->getRequest()->getParam('back')) {
                        $this->_redirect('*/*/edit', array('id' => $quoteId));
                    } else {
                        $this->_redirectAnhcor('*/*/edit', array('id' => $quoteId), '#products');
                        Mage::getSingleton("core/session")->setCollectTotals(1);
                    }
                } else {
                    $this->_redirect('*/*/');
                }

                return null;
            } catch (Exception $e) {
                Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
                Mage::getSingleton('adminhtml/session')->addError($e->getMessage());
                Mage::getSingleton('adminhtml/session')->setFormData($data);
                $this->_redirect('*/*/edit', array('id' => $this->getRequest()->getParam('id')));
                return null;
            }
        }
        Mage::getSingleton('adminhtml/session')->addError($this->__('Unable to find item to save'));
        $this->_redirect('*/*/');
        Mage::dispatchEvent('ophirah_qquoteadv_admin_save_after', array($data));
        return null;
    }

    /**
     * Action to delete a given quote
     */
    public function deleteAction()
    {
        $id = (int)$this->getRequest()->getParam('id');
        Mage::dispatchEvent('ophirah_qquoteadv_admin_delete_before', array($id));

        if ($id > 0) {
            try {
                $model = $this->getQuotationQuote($id);
                $model->setStatus(Ophirah_Qquoteadv_Model_Status::STATUS_CANCELED); //STATUS_REJECTED
                $model->save();
                Mage::dispatchEvent('qquoteadv_qqadvcustomer_aftercancel', array('quote' => $model));

                Mage::getSingleton('adminhtml/session')->addSuccess($this->__('Quote was successfully canceled'));
                Mage::helper('qquoteadv/logging')->sentAnonymousData('cancel', 'b', $id);
                $this->_redirect('*/*/');
            } catch (Exception $e) {
                Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
                Mage::getSingleton('adminhtml/session')->addError($e->getMessage());
                $this->_redirect('*/*/edit', array('id' => $this->getRequest()->getParam('id')));
            }
        }

        $this->_redirect('*/*/');
        Mage::dispatchEvent('ophirah_qquoteadv_admin_delete_after', array($id));
    }

    /**
     * Mass delete action (used in the grid)
     */
    public function massDeleteAction()
    {
        $qquoteIds = $this->getRequest()->getParam('qquote');
        Mage::dispatchEvent('ophirah_qquoteadv_admin_massDelete_before', array($qquoteIds));

        if (!is_array($qquoteIds)) {
            Mage::getSingleton('adminhtml/session')->addError(Mage::helper('catalog')->__('Please select items.'));
        } else {
            try {
                foreach ($qquoteIds as $qquoteId) {
                    $qquote = Mage::getModel('qquoteadv/qqadvcustomer')->load($qquoteId);
                    Mage::dispatchEvent('qquoteadv_qqadvcustomer_beforedelete_massDelete', array('quote' => $qquote));
                    $qquote->delete();
                    Mage::dispatchEvent('qquoteadv_qqadvcustomer_afterdelete_massDelete', array('quote' => $qquote));
                }
                Mage::getSingleton('adminhtml/session')->addSuccess(
                    Mage::helper('adminhtml')->__('Total of %d record(s) were deleted', count($qquoteIds))
                );
            } catch (Exception $e) {
                Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
                Mage::getSingleton('adminhtml/session')->addError($e->getMessage());
            }
        }

        $this->_redirect('*/*/index');
        Mage::dispatchEvent('ophirah_qquoteadv_admin_massDelete_after', array($qquoteIds));
    }

    /**
     * Set Status and substatus for quote
     *
     */
    public function massStatusAction()
    {
        $qquoteIds = $this->getRequest()->getParam('qquote');
        Mage::dispatchEvent('ophirah_qquoteadv_admin_massStatus_before', array($qquoteIds));

        if (!is_array($qquoteIds)) {
            Mage::getSingleton('adminhtml/session')->addError(Mage::helper('catalog')->__('Please select items.'));
        } else {
            try {
                $requestStatus = $this->getRequest()->getParam('status');

                $status = Mage::getModel('qquoteadv/status')->getStatus($requestStatus);
                if(is_object($status)){
                    $status = $status->getStatus();
                }

                foreach ($qquoteIds as $qquoteId) {
                    $qquote = Mage::getSingleton('qquoteadv/qqadvcustomer')->load($qquoteId);
                    $qquote->setStatus($status);
                    $qquote->setIsMassupdate(true);
                    $qquote->save();
                    Mage::dispatchEvent('qquoteadv_qqadvcustomer_aftersave_massStatus', array('quote' => $qquote));
                }

                $this->_getSession()->addSuccess(
                    Mage::helper('adminhtml')->__('Total of %d record(s) were updated', count($qquoteIds))
                );
            } catch (Exception $e) {
                Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
                $this->_getSession()->addError($e->getMessage());
            }
        }

        $this->_redirect('*/*/index');
        Mage::dispatchEvent('ophirah_qquoteadv_admin_massStatus_after', array($qquoteIds));
    }

    /**
     * Mass Follow Up Update
     *
     * Updates follow up date for
     * selected quotes. If no valid date
     * is given, date is set to null
     */
    public function massFollowupAction()
    {
        $qquoteIds = $this->getRequest()->getParam('qquote');
        Mage::dispatchEvent('ophirah_qquoteadv_admin_massFollowup_before', array($qquoteIds));

        if (!is_array($qquoteIds)) {
            Mage::getSingleton('adminhtml/session')->addError(Mage::helper('catalog')->__('Please select items.'));
        } else {
            try {
                foreach ($qquoteIds as $qquoteId) {

                    if (strtotime($this->getRequest()->getParam('followup'))) {
                        $qquote = Mage::getSingleton('qquoteadv/qqadvcustomer')
                            ->load($qquoteId)
                            ->setFollowup($this->getRequest()->getParam('followup'))
                            ->setIsMassupdate(true)
                            ->save();
                        Mage::dispatchEvent('qquoteadv_qqadvcustomer_aftersave_massFollowup', array('quote' => $qquote));
                    } else {
                        $qquote = Mage::getSingleton('qquoteadv/qqadvcustomer')
                            ->load($qquoteId)
                            ->setFollowup()
                            ->setIsMassupdate(true)
                            ->save();
                        Mage::dispatchEvent('qquoteadv_qqadvcustomer_aftersave_massFollowup', array('quote' => $qquote));
                    }
                }
                $this->_getSession()->addSuccess(
                    Mage::helper('adminhtml')->__('Total of %d record(s) were updated', count($qquoteIds))
                );
            } catch (Exception $e) {
                Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
                $this->_getSession()->addError($e->getMessage());
            }
        }

        $this->_redirect('*/*/index');
        Mage::dispatchEvent('ophirah_qquoteadv_admin_massFollowup_after', array($qquoteIds));
    }

    /**
     * Mass update action (used in the grid)
     */
    public function massUpdateAction()
    {
        Mage::dispatchEvent('ophirah_qquoteadv_admin_massUpdate_before', array($this->getRequest()->getParam('ranges')));

        // Check for a valid Enterprise License
        if (Mage::helper('qquoteadv/license')->validLicense('mass_update_quote_requests')) {
            if ($this->getRequest()->isXmlHttpRequest()) {
                Mage::getModel('qquoteadv/massupdate')->startMassUpdateAllowedToQuote($this->getRequest()->getParam('quote_mode'), $this->getRequest()->getParam('ranges'));
            }
        } else {
            $message = $this->__("This function is only available in the enterprise (non-trial) edition. <a href='http://www.cart2quote.com/magento-quotation-module-pricing.html'>Upgrade</a>");
            Mage::getSingleton('adminhtml/session')->addNotice($message);

        }

        Mage::dispatchEvent('ophirah_qquoteadv_admin_massUpdate_after', array($this->getRequest()->getParam('ranges')));
    }

    /**
     * Export CSV action (used in the grid)
     */
    public function exportCsvAction()
    {
        Mage::dispatchEvent('ophirah_qquoteadv_admin_exportCsv_before', array());

        $fileName = 'qquote.csv';
        $content = $this->getLayout()->createBlock('qquoteadv/adminhtml_qquote_grid')->getCsv();
        $this->_sendUploadResponse($fileName, $content);

        Mage::dispatchEvent('ophirah_qquoteadv_admin_exportCsv_after', array());
    }

    /**
     * Action that generates the quote grid as XML
     */
    public function exportXmlAction()
    {
        Mage::dispatchEvent('ophirah_qquoteadv_admin_exportXml_before', array());

        $fileName = 'qquote.xml';
        $content = $this->getLayout()->createBlock('qquoteadv/adminhtml_qquote_grid')->getXml();
        $this->_sendUploadResponse($fileName, $content);

        Mage::dispatchEvent('ophirah_qquoteadv_admin_exportXml_after', array());
    }

    /**
     * Generates an upload response
     *
     * @param $fileName
     * @param $content
     * @param string $contentType
     */
    protected function _sendUploadResponse($fileName, $content, $contentType = 'application/octet-stream')
    {
        $response = $this->getResponse();
        $response->setHeader('HTTP/1.1 200 OK', '');
        $response->setHeader('Pragma', 'public', true);
        $response->setHeader('Cache-Control', 'must-revalidate, post-check=0, pre-check=0', true);
        $response->setHeader('Content-Disposition', 'attachment; filename=' . $fileName);
        $response->setHeader('Last-Modified', date('r'));
        $response->setHeader('Accept-Ranges', 'bytes');
        $response->setHeader('Content-Length', strlen($content));
        $response->setHeader('Content-type', $contentType);
        $response->setBody($content);
        $response->sendResponse();
        die;
    }

    /**
     * Send email to client to informing about the quote proposition
     * @param array $params customer address
     */
    public function sendEmail($params)
    {
        //Create an array of variables to assign to template
        $vars = array();

        $this->quoteId = (int)$this->getRequest()->getParam('id');
        /* @var $_quoteadv Ophirah_Qquoteadv_Model_Qqadvcustomer */
        $_quoteadv = $this->getQuotationQuote($this->quoteId);

        $quoteItems = Mage::getModel('qquoteadv/qqadvproduct')->getCollection()
            ->addFieldToFilter('quote_id', $this->quoteId)
            ->load();

        // check items
        $errorMsg = array();
        $errors = array();
        foreach ($quoteItems as $quoteItem) {
            $check = Mage::helper('qquoteadv')->isInStock($quoteItem->getData('product_id'));
            if ($check->getData('has_error')) {
                $errors[] = $check->getData('message');
            }
        }

        //#return back in case any error found
        if (count($errors)) {
            $errorMsg = array_merge($errorMsg, $errors);
            foreach ($errorMsg as $message) {
                Mage::getSingleton('adminhtml/session')->addError($message);
            }
        }

        $vars['quote'] = $_quoteadv;
        $vars['customer'] = Mage::getModel('customer/customer')->load($_quoteadv->getCustomerId());
        $vars['store'] = Mage::app()->getStore($_quoteadv->getStoreId());

        $template = Mage::helper('qquoteadv/email')->getEmailTemplateModel();

        // Default template
        $quoteadv_param = Mage::getStoreConfig('qquoteadv_quote_emails/templates/proposal', $_quoteadv->getStoreId());
        // Get the checkout URL template
        if (Mage::getStoreConfig('qquoteadv_advanced_settings/checkout/checkout_alternative', $_quoteadv->getData('store_id')) && $_quoteadv->getData('alt_checkout')) {
            $quoteadv_param = Mage::getStoreConfig('qquoteadv_advanced_settings/checkout/checkout_alternative_email', $_quoteadv->getStoreId());
        }

        $disabledEmail = Ophirah_Qquoteadv_Model_System_Config_Source_Email_Templatedisable::VALUE_DISABLED_EMAIL;
        if ($quoteadv_param != $disabledEmail){
            if ($quoteadv_param) {
                $templateId = $quoteadv_param;
            } else {
                $templateId = self::XML_PATH_QQUOTEADV_REQUEST_PROPOSAL_EMAIL_TEMPLATE;
            }

            // get locale of quote sent so we can sent email in that language	
            $storeLocale = Mage::getStoreConfig('general/locale/code', $_quoteadv->getStoreId());

            if (is_numeric($templateId)) {
                $template->load($templateId);
            } else {
                $template->loadDefault($templateId, $storeLocale);
            }

            $vars['attach_pdf'] = $vars['attach_doc'] = false;

            //Create pdf to attach to email
            if (Mage::getStoreConfig('qquoteadv_quote_emails/attachments/pdf', $_quoteadv->getStoreId())) {
                $_quoteadv->_saveFlag = true;

                //totals need to be collected before generating the pdf (until we save the totals in the database)
                $_quoteadv->collectTotals();

                $pdf = Mage::getModel('qquoteadv/pdf_qquote')->getPdf($_quoteadv);
                $_quoteadv->_saveFlag = false;
                $realQuoteadvId = $_quoteadv->getIncrementId() ? $_quoteadv->getIncrementId() : $_quoteadv->getId();
                try {
                    $file = $pdf->render();
                    $name = Mage::helper('qquoteadv')->__('Price_proposal_%s', $realQuoteadvId);
                    $template->getMail()->createAttachment($file, 'application/pdf', Zend_Mime::DISPOSITION_ATTACHMENT, Zend_Mime::ENCODING_BASE64, $name . '.pdf');
                    $vars['attach_pdf'] = true;
                } catch (Exception $e) {
                    Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
                }

            }
            //Check if attachment needs to be sent with email
            if ($doc = Mage::getStoreConfig('qquoteadv_quote_emails/attachments/doc', $_quoteadv->getStoreId())) {
                $pathDoc = Mage::getBaseDir(Mage_Core_Model_Store::URL_TYPE_MEDIA) . DS . 'quoteadv' . DS . $doc;
                try {
                    $file = file_get_contents($pathDoc);
                    $mimeType = Mage::helper('qquoteadv/file')->getMimeType($pathDoc);

                    $info = pathinfo($pathDoc);
                    //$extension = $info['extension']; 
                    $basename = $info['basename'];
                    $template->getMail()->createAttachment($file, $mimeType, Zend_Mime::DISPOSITION_ATTACHMENT, Zend_Mime::ENCODING_BASE64, $basename);
                    $vars['attach_doc'] = true;
                } catch (Exception $e) {
                    Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
                }
            }
            //Get remark
            $remark = Mage::getStoreConfig('qquoteadv_quote_configuration/proposal/qquoteadv_remark', $_quoteadv->getStoreId());
            if ($remark) {
                $vars['remark'] = $remark;
            }

            $adm_name = $this->getAdminName($_quoteadv->getUserId());
            $adm_name = trim($adm_name);
            if (empty($adm_name)) {
                $adm_name = $this->getAdminName(Mage::getSingleton('admin/session')->getUser()->getId());
            }
            if (!empty($adm_name)) {
                $vars['adminname'] = $adm_name;
            }

            $subject = $template['template_subject'];

            $vars['link'] = Mage::helper('qquoteadv/licensechecks')->getAutoLoginUrl($_quoteadv, 2);

            $sender = $_quoteadv->getEmailSenderInfo();
            $template->setSenderName($sender['name']);
            $template->setSenderEmail($sender['email']);

            $template->setTemplateSubject($subject);
            $bcc = Mage::getStoreConfig('qquoteadv_quote_emails/sales_representatives/bcc', $_quoteadv->getStoreId());
            if ($bcc) {
                $bccData = explode(";", $bcc);
                $template->addBcc($bccData);
            }

            if ((bool)Mage::getStoreConfig('qquoteadv_quote_emails/sales_representatives/send_linked_sale_bcc', $_quoteadv->getStoreId())) {
                $template->addBcc(Mage::getModel('admin/user')->load($_quoteadv->getUserId())->getEmail());
            }

            $template->setDesignConfig(array('store' => $_quoteadv->getStoreId()));

            /**
             * Opens the qquote_request.html, throws in the variable array
             * and returns the 'parsed' content that you can use as body of email
             */
            //save current design
            $design = Mage::getDesign();
            $area = $design->getArea();
            $package = $design->getPackageName();
            $theme = $design->getTheme($area);
            //get temp design
            $tempPackage = 'base';
            if(Mage::getStoreConfig('design/package/name', $_quoteadv->getStoreId())){
                $tempPackage = Mage::getStoreConfig('design/package/name', $_quoteadv->getStoreId());
            }
            $tempTheme = 'default';
            if(Mage::getStoreConfig('design/theme/default', $_quoteadv->getStoreId())){
                $tempTheme = Mage::getStoreConfig('design/theme/default', $_quoteadv->getStoreId());
            }
            //set temp design
            $design->setArea('frontend')->setPackageName($tempPackage)->setTheme($tempTheme);

            //generate template getProcessedTemplate is called inside send
            $template->setData('c2qParams', $params);
            Mage::dispatchEvent('ophirah_qquoteadv_addSendMail_before', array('template' => $template));
            $res = $template->send($params['email'], $params['name'], $vars);
            Mage::dispatchEvent('ophirah_qquoteadv_addSendMail_after', array('template' => $template, 'result' => $res));

            //re set design
            $design->setArea($area)->setPackageName($package)->setTheme($theme);

            return $res;

        }

        Mage::getSingleton('adminhtml/session')->addError("Quote email is disabled");
        return $disabledEmail;

    }


    /**
     * Add quote comment action
     */
    public function addCommentAction()
    {
        if ($qquoteadv = $this->_initQuoteadv()) {
            try {
                $response = false;
                $data = $this->getRequest()->getPost('history');

                Mage::dispatchEvent('ophirah_qquoteadv_admin_addComment_before', array($data));

                //seems not used?
                $comment = trim(strip_tags($data['comment']));

                $this->loadLayout('empty');
                $this->renderLayout();
            } catch (Mage_Core_Exception $e) {
                $response = array(
                    'error' => true,
                    'message' => $e->getMessage(),
                );
            } catch (Exception $e) {
                $response = array(
                    'error' => true,
                    'message' => $this->__('Can not add quote history.')
                );
                Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
            }
            if (is_array($response)) {
                $response = Zend_Json::encode($response);
                $this->getResponse()->setBody($response);
            }
        }

        Mage::dispatchEvent('ophirah_qquoteadv_admin_addComment_after', array());
    }

    /**
     * Initialize qquoteadv model instance
     *
     * @return Quote || false
     */
    protected function _initQuoteadv()
    {
        $id = $this->getRequest()->getParam('quote_id');
        $qquoteadv = $this->getQuotationQuote($id);

        if (!$qquoteadv->getId()) {
            $this->_getSession()->addError($this->__('This quote no longer exists.'));
            $this->_redirect('*/*/');
            $this->setFlag('', self::FLAG_NO_DISPATCH, true);
            return false;
        }

        Mage::register('qquote_data', $qquoteadv);

        return $qquoteadv;
    }

    /**
     * Function that generates the PDF for a given quote
     *
     * @return null
     */
    public function pdfqquoteadvAction()
    {
        $errorMsg = array();
        $errors = array();

        // From Print button, save quote first
        if ($this->getRequest()->getPost() && $this->_saveFlag === false) {
            $this->setFlag('qquoteadv', 'print', true);
            $this->_postData = $this->getRequest()->getPost();
            $save = $this->saveAction();
            if (!empty($save) && !is_object($save)) {
                $errors = $save;
            }
            $this->setFlag('qquoteadv', 'print', false);
        }

        $quoteadvId = $this->getRequest()->getParam('id');
        Mage::dispatchEvent('ophirah_qquoteadv_admin_pdfqquoteadv_before', array($quoteadvId));

        $flag = false;
        if (!empty($quoteadvId) && !$errors) {
            $_quoteadv = $this->getQuotationQuote($quoteadvId);
            $quoteItems = Mage::getModel('qquoteadv/qqadvproduct')->getCollection()
                ->addFieldToFilter('quote_id', $quoteadvId)
                ->load();

            // check items
            foreach ($quoteItems as $quoteItem) {
                $check = Mage::helper('qquoteadv')->isInStock($quoteItem->getData('product_id'));
                if ($check->getData('has_error')) {
                    $errors[] = $check->getData('message');
                }
            }

            if (count($errors) < 1) {

                if ($quoteItems->getSize()) {
                    $flag = true;
                    if (!isset($pdf)) {
                        $_quoteadv->collectTotals();
                        $pdf = Mage::getModel('qquoteadv/pdf_qquote')->getPdf($_quoteadv);
                    } else {
                        $pages = Mage::getModel('qquoteadv/pdf_qquote')->getPdf($quoteItems);
                        $pdf->pages = array_merge($pdf->pages, $pages->pages);
                    }
                }

                if ($flag) {
                    $realQuoteadvId = $_quoteadv->getIncrementId();
                    $fileName = Mage::helper('qquoteadv')->__('Price_proposal_%s', $realQuoteadvId);

                    return $this->_prepareDownloadResponse($fileName . '.pdf', $pdf->render(), 'application/pdf');
                } else {
                    $this->_getSession()->addError($this->__('There are no printable documents related to selected quotes'));
                    $this->_redirect('*/*/');
                }
            }
        }

        //#return back in case any error found
        if (count($errors)) {
            $urlReturn = '*/*/edit/id/' . $quoteadvId;
            $errorMsg = array_merge($errorMsg, $errors);
            foreach ($errorMsg as $message) {
                Mage::getSingleton('adminhtml/session')->addError($message);
            }
        }

        if (!isset($urlReturn) || empty($urlReturn)) {
            $urlReturn = '*/*/';
        }
        $this->_redirect($urlReturn);
        Mage::dispatchEvent('ophirah_qquoteadv_admin_pdfqquoteadv_after', array($quoteadvId));
        return null;
    }

    /**
     * Function that returns if this installation is a trial version of Cart2Quote
     *
     * @param null $createHash
     * @return mixed
     */
    final function isTrialVersion($createHash = NULL)
    {
        return Mage::helper('qquoteadv/license')->isTrialVersion($createHash);
    }

    /**
     * Function that generates the update/trial message in the quote edit screen
     *
     * @param bool|false $updateMsg
     * @param int $storeId
     * @return string
     */
    public function getMsgToUpgrade($updateMsg = false, $storeId = 0)
    {
        $createHash = Mage::registry('createHash');

        $msg = '
        <style>

        #quoteadv-box-header {

        }
        .leightbox1 .text {

        }
        #overlay, #overlaylink{
            display:none;
            position:absolute;
            top:0;
            left:0;
            width:100%;
            height:200%;
            z-index:1000;
            background-color:#333;
            -moz-opacity: 0.8;
            opacity:.80;
            filter: alpha(opacity=80);
        }

        </style>

        <script type="text/javascript">
        function prepareIE(height, overflow)
        {
        bod = document.getElementsByTagName(\'body\')[0];
        bod.style.height = height;
        bod.style.overflow = overflow;

        htm = document.getElementsByTagName(\'html\')[0];
        htm.style.height = height;
        htm.style.overflow = overflow;
        }

        function initMsg() {
            bod 				= document.getElementsByTagName(\'body\')[0];
            overlay 			= document.createElement(\'div\');
            overlay.id			= \'overlay\';
            bod.appendChild(overlay);
            $(\'overlay\').style.display = \'block\';
            $(\'lightbox1\').style.display = \'block\';
            prepareIE("auto", "auto");
        }

        function hideBox() {
            $(\'lightbox1\').style.display = \'none\';
            $(\'overlay\').style.display = \'none\';
        }

        </script>';

        $headerText = "";
        $onClick = "";
        $smallPrint = false;

        //check what the situation is
        if ($this->isTrialVersion($createHash) && $this->hasExpired()) {

            $text = $this->__(Mage::helper('qquoteadv/licensechecks')->_expiryText);
            //$onClick = 'history.back()';
            $onClick = 'hideBox()';

            $headerText = $this->__('Thanks for trying Cart2Quote');

            //$btn1 = '<button target="_blank" class="button button1" title="Upgrade" onclick="' . $onClick . '">' . $this->__('Take me Back') . '</button>';
            $btn1 = '<button target="_blank" class="button button1" title="Continue" onclick="' . $onClick . '">' . $this->__('Continue') . '</button>';
            $btn2 = '<button target="_blank" class="button button2" title="Request a license" onclick="document.location.href=\'http://www.cart2quote.com/magento-quotation-module-pricing.html?utm_source=Client_Website&utm_medium=Popup_expiryText&utm_campaign=Client_Website_Upgrade\'">' . $this->__('See Plans and Pricing') . '</button> ';
        } elseif ($this->isTrialVersion($createHash) && !$this->hasExpired()) {
            $expiry = Mage::helper('qquoteadv/license')->getC2QExpiryDate();

            $now = now();
            $expiry = substr($expiry, 0, 4) . "-" . substr($expiry, 4, 2) . "-" . substr($expiry, 6, 2);
            $diff = abs(strtotime($expiry) - strtotime($now));
            $days = floor($diff / (60 * 60 * 24));
            $headerText = $this->__('Thanks for trying Cart2Quote');
            $daysToGo = sprintf("%d", $days);

            $text = $this->__(Mage::helper('qquoteadv/licensechecks')->_trialText, $daysToGo);
            $onClick = 'hideBox()';

            $btn1 = '<button target="_blank" class="button button2 floatleft" title="Continue Trial" href="" onclick="' . $onClick . '">' . $this->__('Continue Trial') . '</button>';
            $btn2 = '<button target="_blank" class="button button2" title="Purchase a license" onclick="document.location.href=\'http://www.cart2quote.com/magento-quotation-module-pricing.html?utm_source=Client_Website&utm_medium=Popup_trialText&utm_campaign=Client_Website_Upgrade\'">' . $this->__('See Plans and Pricing') . '</button> ';
        } elseif (!$this->isTrialVersion($createHash)) {
            $text = $this->__(Mage::helper('qquoteadv/licensechecks')->_wrongQuoteText);
            $onClick = 'history.back()';
            $headerText = $this->__('Thanks for trying Cart2Quote');

            $btn1 = '<button target="_blank" class="button button2 floatleft" title="Upgrade" onclick="' . $onClick . '">' . $this->__('Continue Trial') . '</button>';
            $btn2 = '<button target="_blank" class="button button2" title="Request a license" onclick="document.location.href=\'http://www.cart2quote.com/magento-quotation-module-pricing.html?utm_source=Client_Website&utm_medium=Popup_wrongQuoteText&utm_campaign=Client_Website_Upgrade\'">' . $this->__('See Plans and Pricing') . '</button> ';
        } elseif (!$this->checkQuoteLicense($storeId)) {
            $text = $this->__(Mage::helper('qquoteadv/licensechecks')->_wrongLicenseText);
            $onClick = 'history.back()';
            $headerText = $this->__('Please Upgrade');

            $btn1 = '<button target="_blank" class="button button1" title="Continue" onclick="' . $onClick . '">' . $this->__('Not Now') . '</button>';
            $btn2 = '<button target="_blank" class="button button2" title="Upgrade" onclick="document.location.href=\'http://www.cart2quote.com/magento-quotation-module-pricing.html?utm_source=Client_Website&utm_medium=Popup_wrongLicenseText&utm_campaign=Client_Website_Upgrade\'">' . $this->__('See Plans and Pricing') . '</button> ';
            $smallPrint = $this->__('<a href="http://www.cart2quote.com/ordering-licenses?utm_source=Client_Website&utm_medium=Popup_wrongLicenseText&utm_campaign=Client_Website_Upgrade" class="sublinkBottom">read more about licensing</a>');
        }

        $msg .= '<div id="lightbox1" class="leightbox1" style="display:none;">';
        $msg .= '   <div >';
        $msg .= '           <a onclick="' . $onClick . '" id="quoteadv-box-header-close-btn"></a>';
        $msg .= '       <div id="quoteadv-box-header">';
        $msg .=             $headerText;
        $msg .= '       </div>';
        $msg .= '       <div class="text" >' . $text . '</div>';
        $msg .=         $btn1;
        $msg .=         $btn2;
        if($smallPrint){
            $msg .= '   <div class="smallprint" >' . $smallPrint . '</div>';
        }
        $msg .= '    </div>';
        $msg .= '</div>';

        //add initMsg() javascript
        $msg .= '<script type="text/javascript">document.observe(\'dom:loaded\', function(){
                    initMsg();
                 });</script>';

        Mage::unregister('createHash');
        return $msg;
    }

    final private function checkQuoteLicense($storeId)
    {
        return Mage::helper('qquoteadv/license')->checkQuoteLicense($storeId);
    }

    final private function getAccessLevel($createHash = NULL)
    {
        return Mage::helper('qquoteadv/license')->getAccessLevel($createHash);
    }

    final private function hasExpired()
    {
        return Mage::helper('qquoteadv/license')->hasExpired();
    }

    /**
     * Retrieve session object
     *
     * @return Mage_Adminhtml_Model_Session_Quote
     */
    protected function _getSession()
    {
        return Mage::getSingleton('adminhtml/session_quote');
    }

    /**
     * Retrieve order create model
     *
     * @return Mage_Adminhtml_Model_Sales_Order_Create
     */
    protected function _getOrderCreateModel()
    {
        return Mage::getSingleton('adminhtml/sales_order_create');
    }

    /**
     * Function that converts a quote to an order (backend)
     *
     * @param $quoteadvId
     * @param $requestedItems
     */
    protected function _convertQuoteItemsToOrder($quoteadvId, $requestedItems)
    {
        //# build sql
        $resource = Mage::getSingleton('core/resource');
        $read = $resource->getConnection('core_read');
        $tblProduct = $resource->getTableName('quoteadv_product');
        $tblRequestItem = $resource->getTableName('quoteadv_request_item');

        $sql = "select * from $tblProduct p INNER JOIN $tblRequestItem i
                            ON p.quote_id=i.quote_id 
                            AND i.quoteadv_product_id=p.id AND p.quote_id=$quoteadvId";

        if (count($requestedItems)) {
            $items = implode(",", $requestedItems);
            $sql .= " AND i.request_id IN($items)";
        } else {
            return;
        }

        $data = Mage::getSingleton('core/resource')->getConnection('core_read')->fetchAll($sql);

        //add items from quote to order
        foreach ($data as $item) {
            $productId = $item['product_id'];

            $product = Mage::getModel('catalog/product')->load($productId);
            //observer will check customPrice after add item to card/quote

            $customPrice = $item['owner_cur_price'];

            //fallback for situations where getWebsite doesn't return a object
            if(is_object(Mage::app()->getWebsite(true))){
                $defaultStoreId = Mage::app()->getWebsite(true)->getDefaultGroup()->getDefaultStoreId();
            } else {
                $defaultStoreId = Mage::app()->getStore('default')->getStoreId();
                $message = 'Mage::app()->getWebsite(true) is not a object, fallback applied';
                Mage::log('Message: ' .$message, null, 'c2q.log');
            }

            $_quote = $this->getQuotationQuote($quoteadvId);
            $quoteStoreId = $_quote->getStoreId();
            if($defaultStoreId != $quoteStoreId){
                $priceContainsTax = Mage::helper('tax')->priceIncludesTax($quoteStoreId); //Mage::getStoreConfig('tax/calculation/price_includes_tax', $quoteStoreId);
                if($priceContainsTax){
                    //fallback for situations where getWebsite doesn't return a object
                    if(is_object(Mage::app()->getWebsite(true))){
                        $store = Mage::app()->getWebsite(true)->getDefaultGroup()->getDefaultStore();
                    } else {
                        $store = Mage::app()->getStore('default');
                        $message = 'Mage::app()->getWebsite(true) is not a object, fallback applied';
                        Mage::log('Message: ' .$message, null, 'c2q.log');
                    }

                    $taxCalculation = Mage::getModel('tax/calculation');
                    $request = $taxCalculation->getRateOriginRequest(null, null, null, $store);

                    //get tax percent
                    $taxClassId = $product->getTaxClassId();
                    $percent = $taxCalculation->getRate($request->setProductClassId($taxClassId));

                    $quoteStore = Mage::getModel('core/store')->load($quoteStoreId);
                    $taxCalculation = Mage::getModel('tax/calculation');
                    $request = $taxCalculation->getRateRequest(null, null, null, $quoteStore);
                    $taxClassId = $product->getTaxClassId();
                    $quotePercent = $taxCalculation->getRate($request->setProductClassId($taxClassId));

                    if($percent != $quotePercent){
                        $customPrice = ($customPrice / (100+$quotePercent)) * (100+$percent);
                    }
                }
            }
            Mage::register('customPrice', $customPrice);

            if ($product->getTypeId() == 'bundle') {
                $attr = array();
                $attr[$productId] = @unserialize($item['attribute']);
                $attr[$productId]['qty'] = (int)$item['request_qty'];
                $this->_getOrderCreateModel()->addProducts($attr);

            } else {
                $params = @unserialize($item['attribute']);
                $params['qty'] = (int)$item['request_qty'];

                try {
                    $this->_getOrderCreateModel()->addProduct($product, $params);
                } catch (Exception $e) {
                    Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
                }
            }

            Mage::unregister('customPrice');
        }


    }

    /**
     * @Description This function echos an article body of Cart2Quote Zendesk help center. @link http://cart2quote.zendesk.com
     * @Return JSON array of articles
     */
    public function requestArticleAction()
    {
        echo Mage::helper('qquoteadv')->executeArticleRequest(); // Get array of articles
    }

    /**
     * Action to convert a quote to an order
     *
     * params ([id] => 64, [q2o_serial] => array(109,110))
     */
    public function convertAction()
    {
        $quoteadvId = $this->getRequest()->getParam('id');
        $requestedItems = $this->getRequest()->getParam('q2o');

        Mage::dispatchEvent('ophirah_qquoteadv_admin_convert_before', array($quoteadvId, $requestedItems));

        if (empty($requestedItems)) {
            $requestedItems = $this->getRequest()->getParam('q2o_serial');
            if (!empty($requestedItems)) {
                $requestedItems = unserialize($requestedItems);
            }
        }

        if ($requestedItems) {
            foreach ($requestedItems as $k => $v) {
                if (empty($v)) {
                    unset($requestedItems[$k]);
                }
            }
        }

        if (!empty($quoteadvId)) {
            $_quoteadv = $this->getQuotationQuote($quoteadvId);
            Mage::dispatchEvent('qquoteadv_qqadvcustomer_before_convert', array('quote' => $_quoteadv));

            $currencyCode = $_quoteadv->getData('currency');
            $storeId = $_quoteadv->getStoreId();
            $this->_getSession()->setStoreId((int)$storeId);

            $customerId = (int)$_quoteadv->getCustomerId();
            $customer = Mage::getModel('customer/customer')->load($customerId);
            $this->_getSession()->setCustomerId($customerId);

            // empty the quote before adding the items
            $this->_getOrderCreateModel()->getQuote()->removeAllItems();

            // get customer address
            $helperAddress = Mage::helper('qquoteadv/address');
            $customerAddresses = $helperAddress->buildQuoteAdresses($_quoteadv);

            $this->_getOrderCreateModel()
                ->getQuote()
                ->setBillingAddress($helperAddress->getQuoteAddress($customer, $customerAddresses['billingAddress'], $storeId, Mage_Customer_Model_Address_Abstract::TYPE_BILLING));
            $this->_getOrderCreateModel()
                ->getQuote()
                ->setShippingAddress($helperAddress->getQuoteAddress($customer, $customerAddresses['shippingAddress'], $storeId, Mage_Customer_Model_Address_Abstract::TYPE_SHIPPING));

            if ($customerAddresses['billingAddress'] != $customerAddresses['shippingAddress']) {
                $this->_getOrderCreateModel()->getQuote()->getShippingAddress()->setData('same_as_billing', 0);
            } else {
                $this->_getOrderCreateModel()->getQuote()->getShippingAddress()->setData('same_as_billing', 1);
            }

            $this->_getOrderCreateModel()->getQuote()->setCustomerId($customerId);

            //set customer group
            $customerGroupId = (int)$_quoteadv->getData('customer_group_id');
            $this->_getOrderCreateModel()->getQuote()->setCustomerGroupId($customerGroupId);

            // Apply Coupon Code
            if ($_quoteadv->getData('salesrule') > 0) {
                $this->_getOrderCreateModel()->applyCoupon($_quoteadv->getCouponCodeById($_quoteadv->getData('salesrule')));
            }

            // Set Default Shipping Method
            if ($_quoteadv->getAddress()->getShippingMethod() !== null && (int)$_quoteadv->getData('shipping_type')) {
                $this->_getOrderCreateModel()->getQuote()->getShippingAddress()->setData('shipping_method', $_quoteadv->getAddress()->getData('shipping_method'));
                $this->_getOrderCreateModel()->getQuote()->getShippingAddress()->setData('collect_shipping_rates', '1');
            }

            if (count($requestedItems)) {
                //convert quote items to order
                Mage::app()->getStore()->setCurrentCurrencyCode($currencyCode);
                $this->_convertQuoteItemsToOrder($quoteadvId, $requestedItems);
                Mage::getSingleton('adminhtml/session')->setUpdateQuoteId($quoteadvId);
            } else {
                $msg = $this->__('To create an order, select product(s) and quantity');
                Mage::getSingleton('adminhtml/session')->addError($msg);

                if(isset($_SERVER['HTTP_REFERER'])){
                    $url = $_SERVER['HTTP_REFERER'];
                    $this->_redirectUrl($url);
                    return;
                } else {
                    $this->_redirect('*/*');
                    return;
                }
            }

            //add quoteadv id to the session for the quoteadv shipping option
            Mage::getSingleton('core/session')->proposal_quote_id = $quoteadvId;

            //set the selected shipping method on the sales_flat_quote item
            try {
                $quoteShippingMethod = $_quoteadv->getShippingMethod();
                if(isset($quoteShippingMethod) && !empty($quoteShippingMethod)){
                    $methods = Mage::getSingleton('shipping/config')->getActiveCarriers();
                    foreach($methods as $_ccode => $_carrier) {
                        if($_methods = $_carrier->getAllowedMethods())  {
                            foreach($_methods as $_mcode => $_method)   {
                                $_code = $_ccode . '_' . $_mcode;
                                if($_code == $quoteShippingMethod) {
                                    $this->_getOrderCreateModel()->setShippingMethod($quoteShippingMethod);
                                    $this->_getOrderCreateModel()->getShippingAddress()->requestShippingRates();
                                    break;
                                }
                            }
                        }
                    }
                }
            } catch (Exception $e) {
                //in case the shipping method is disabled in the meantime, this could trow an error
                Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
            }

            //set payment
            try {
                $createFromId = $_quoteadv->getCreatedFromQuoteId();
                if(isset($createFromId) && !empty($createFromId)){
                    $paymetData = Mage::getModel('sales/quote_payment')->getCollection()
                        ->setQuoteFilter($createFromId)
                        ->getFirstItem();

                    if(isset($paymetData) && !empty($paymetData)){
                        $this->_getOrderCreateModel()->setPaymentData($paymetData->getData());
                    } else {
                        $qPaymentMethod = $_quoteadv->getPaymentMethod();
                        if(isset($qPaymentMethod) && !empty($qPaymentMethod)){
                            $this->_getOrderCreateModel()->setPaymentMethod($qPaymentMethod);
                        }
                    }
                }
            } catch (Exception $e) {
                //in case the payment method is disabled in the meantime, this could trow an error
                Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
            }

            //add redirect ID
            $mageQuoteId = $this->_getOrderCreateModel()->getQuote()->getData('entity_id');
            Mage::helper('qquoteadv')->setReferenceIdInCoreSession($mageQuoteId, $quoteadvId);

            $this->_getOrderCreateModel()
                ->initRuleData()
                ->saveQuote();
            $this->_getOrderCreateModel()->getSession()->setCurrencyId($currencyCode);
            Mage::dispatchEvent('qquoteadv_qqadvcustomer_before_convert', array('orderCreateModel' => $this->_getOrderCreateModel()));

            Mage::helper('qquoteadv/logging')->sentAnonymousData('confirm', 'b', $quoteadvId);

            $url = $this->getUrl('adminhtml/sales_order_create/index');
            $this->_redirectUrl($url);

            return;
        } else {
            $this->_redirect('*/*');
        }

        Mage::dispatchEvent('ophirah_qquoteadv_admin_convert_after', array($quoteadvId, $requestedItems));
    }

    /**
     * Function that adds an error to the session and try's to redirect to a relevant page
     *
     * @param $errorMsg
     * @param null $url
     */
    protected function _redirectErr($errorMsg, $url = null)
    {
        if (is_string($errorMsg)) {
            $errorMsg = array($errorMsg);
        }

        if (count($errorMsg)) {
            foreach ($errorMsg as $msg) {
                Mage::getSingleton('adminhtml/session')->addError($msg);
            }
            if ($url == null) {
                if(isset($_SERVER['HTTP_REFERER'])){
                    $url = $_SERVER['HTTP_REFERER'];
                }
            }

            if($url != null){
                $this->_redirectUrl($url);
            } else {
                $this->_redirect('*/*');
            }
        }
    }

    /**
     * Save customer
     *
     * @param $quote
     */
    protected function _saveCustomerAfterQuote($quote)
    {

        $customer = $quote->getCustomer();
        $store = $quote->getStore();
        $billingAddress = null;
        $shippingAddress = null;
        if (!$quote->getCustomer()->getId()) {
            $customer->addData($quote->getBillingAddress()->exportCustomerAddress()->getData())
                ->setPassword($customer->generatePassword())
                ->setStore($store);
            $customer->setEmail($quote->getData('customer_email'));
            $customer->setGroupId($quote->getData('customer_group_id'));

            $customerBilling = $quote->getBillingAddress()->exportCustomerAddress();
            $customerBilling->setIsDefaultBilling(true);
            $customer->addAddress($customerBilling);

            $shipping = $quote->getShippingAddress();
            if (!$quote->isVirtual() && !$shipping->getSameAsBilling()) {
                $customerShipping = $shipping->exportCustomerAddress();
                $firstname = $customerShipping->getData('firstname');
                $lastname = $customerShipping->getData('lastname');

                if (empty($firstname) || empty($lastname)) {
                    $msg = $this->__("There was an error, because the customer shipping address was undefined");
                    $this->_redirectErr(array($msg));
                    return;
                } else {
                    $customerShipping->setIsDefaultShipping(true);
                    $customer->addAddress($customerShipping);
                }

            } else {
                $customerBilling->setIsDefaultShipping(true);
            }

            try {
                Mage::dispatchEvent('qquoteadv_qqadvcustomer_before_newCustomer', array('customer' => $customer, 'quote' => $quote));
                $customer->save();
                Mage::dispatchEvent('qquoteadv_qqadvcustomer_after_newCustomer', array('customer' => $customer, 'quote' => $quote));
                $customer->sendNewAccountEmail('registered', '', $customer->getStoreId());
            } catch (Exception $e) {
                $this->_redirectErr(array($e->getMessage()));
                Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
                return;
            }
        }

        // set customer to quote and convert customer data to quote
        $quote->setCustomer($customer);
    }

    /**
     * Alias for an old typo
     */
    public function switch2QuoteAction()
    {
        $this->swith2QuoteAction();
    }

    /**
     * Function that switches an order to a quote
     */
    public function swith2QuoteAction()
    {
        //unique id for c2q session
        $c2qId = Mage::getSingleton('adminhtml/session')->getUpdateQuoteId(); //null;

        //pool error messages
        $errorMsg = array();

        //quote Data from session
        $quote = Mage::getSingleton('adminhtml/session_quote')->getQuote();

        //post data from input fields
        $data = $this->getRequest()->getPost();

        Mage::dispatchEvent('ophirah_qquoteadv_admin_swith2Quote_before', array($c2qId, $quote, $data));

        //created from (magento) quote data
        $createdFromQuote = Mage::getSingleton('adminhtml/session_quote');
        $createdFromQuoteId = $createdFromQuote->getQuoteId();

        $baseToQuoteRate = $quote->getData('base_to_quote_rate');
        $currencyCode = $quote->getData('quote_currency_code');
        $customerId = $quote->getCustomer()->getId();
        if (!$customerId && $quote->getData('customer_email')) {
            $this->_saveCustomerAfterQuote($quote);
            $customerId = $quote->getCustomer()->getId();
        }

        $billingAddress = $quote->getBillingAddress();
        $shipAddress = $quote->getShippingAddress();

        // Add addresses to customers account
        if ($billingAddress->getData('save_in_address_book') == 1 || $shipAddress->getData('save_in_address_book') == 1) {
            $helperAddress = Mage::helper('qquoteadv/address');
            if ($billingAddress->getData('save_in_address_book') == 1) {
                $helperAddress->addQuoteAddress($customerId, $billingAddress->exportCustomerAddress()->getData());
            }
            if ($shipAddress->getData('save_in_address_book') == 1) {
                $helperAddress->addQuoteAddress($customerId, $shipAddress->exportCustomerAddress()->getData());
            }
        }

        $email = $quote->getCustomer()->getEmail();
        $items = $quote->getAllItems();

        if (!Mage::getStoreConfig('qquoteadv_general/quotations/enabled', $quote->getStoreId())) {
            $errorMsg[] = $this->__("Module is disabled");
        }
        if (empty($customerId)) {
            $errorMsg[] = $this->__("Customer not recognized for new quote");
        }
        if (empty($email)) {
            $errorMsg[] = $this->__("Customer's email was undefined");
        }
        if (!count($items)) {
            $errorMsg[] = $this->__("There was an error, because the product quantities were not defined");
        }

        foreach ($items as $item) {

            // Simple child products from configurable
            // needs to be checked with qty of the parent item
            // Check if product is a configurable product
            $checkConfigurable = Mage::helper('qquoteadv')->isConfigurable($item, $item->getData('qty'));
            if ($checkConfigurable != false) {
                $qty = $checkConfigurable;
            } else {
                $qty = $item->getData('qty');
            }

            // Bundled products need to be checked,
            // including child products
            if ($item->getData('product')->getTypeId() == Mage_Catalog_Model_Product_Type::TYPE_BUNDLE) {
                $bundleOptions = Mage::getModel('qquoteadv/bundle')->getOrderOptions($item->getData('product'));
                $itemChildren = Mage::getModel('qquoteadv/qqadvproduct')->getBundleOptionProducts($item->getData('product'), $bundleOptions['info_buyRequest']);
            }

            // Creating ChildProducts array
            // in case product has a product type Bundle
            // All childproducts need to be checked
            $checkQty = $qty;
            $checkProductArray = array();
            // Parent product gets added first
            $checkProductArray[] = $item->getData('product');
            if (isset($itemChildren)) {
                $checkProductArray = array_merge($checkProductArray, $itemChildren);
            }

            // Cycle through childproducts
            foreach ($checkProductArray as $checkProduct) {
                if($checkProduct->getId() == $item->getData('product')->getId()){
                    if ($checkProduct->getQuoteItemQty()) {
                        $checkQty = $checkProduct->getQuoteItemQty();

                        if(is_array($checkQty)){
                            //bad way of getting the first value of the array
                            foreach($checkQty as $qtyValue){
                                $checkQty = $qtyValue;
                                break;
                            }
                        }
                    }

                    $check = Mage::helper('qquoteadv')->isQuoteable($item->getData('product'), $checkQty);
                }
            }

            if ($check->getHasErrors()) {
                $errors = $check->getErrors();
                $errorMsg = array_merge($errorMsg, $errors);
            }
        }

        Mage::getSingleton('adminhtml/session')->setConfParent();

        //#return back in case any error found
        if (count($errorMsg)) {
            $this->_redirectErr($errorMsg);
            return;
        }

        //#c2q insert data
        if ($customerId && $email) {
            $modelCustomer = Mage::getModel('qquoteadv/qqadvcustomer');
            $copyShippingParams = array(
                'shipping_amount' => 'shipping_amount',
                'base_shipping_amount' => 'base_shipping_amount',
                'shipping_amount_incl_tax' => 'shipping_amount_incl_tax',
                'base_shipping_amount_incl_tax' => 'base_shipping_amount_incl_tax',
                'base_shipping_tax_amount' => 'base_shipping_tax_amount',
                'shipping_tax_amount' => 'shipping_tax_amount',
                'address_shipping_method' => 'shipping_method',
                'address_shipping_description' => 'shipping_description',
            );

            $shipRates = $shipAddress->getShippingRatesCollection();

            $copyRateParams = array();
            $rate = null;
            foreach ($shipRates as $rates) {
                if ($rates['code'] == $shipAddress->getShippingMethod()) {

                    $rate = $rates;
                    $copyRateParams = array(
                        'shipping_method' => 'method',
                        'shipping_description' => 'method_description',
                        'shipping_method_title' => 'method_title',
                        'shipping_carrier' => 'carrier',
                        'shipping_carrier_title' => 'carrier_title',
                        'shipping_code' => 'code'
                    );
                    break;
                }
            }

            $shipStreet = "";
            $billStreet = "";
            $shipAddressExists = false;
            foreach ($shipAddress->getStreet() as $addressLine) {
                if ($addressLine != "") $shipAddressExists = true;
            }

            $billAddressExists = false;
            foreach ($billingAddress->getStreet() as $addressLine) {
                if ($addressLine != "") $billAddressExists = true;
            }

            if ($shipAddressExists) $shipStreet = implode(',', $shipAddress->getStreet());
            if ($billAddressExists) $billStreet = implode(',', $billingAddress->getStreet());

            //Add customer Group
            $customerGroup = $quote->getCustomer()->getData('group_id');
            //If customer group is set in quote replace this with the default value.
            if(array_key_exists('order', $data)){
                if(array_key_exists('account', $data['order'])){
                    if(array_key_exists('group_id', $data['order']['account'])){
                        $customerGroup = $data['order']['account']['group_id'];
                    }
                }
            }

            if (!$c2qId) {
                $name = $billingAddress->getFirstname();
                if ($name != "") { // &&  count($quote->getCustomer()->getAddresses()) ){
                    /* @var $helper Ophirah_Qquoteadv_Helper_Data */
                    $helper = Mage::helper('qquoteadv');
                    /* @var $admin Mage_Admin_Model_Session */
                    $admin = Mage::getSingleton('admin/session');

                    $itemprice = (Mage::getStoreConfig('qquoteadv_quote_configuration/proposal/itemprice') == 1) ? 1 : 0;

                    $qcustomer = array(
                        'created_at' => NOW(),
                        'updated_at' => NOW(),

                        'customer_id' => $customerId,
                        'currency' => $currencyCode,
                        'base_to_quote_rate' => $baseToQuoteRate,
                        'prefix' => $billingAddress->getPrefix(),
                        'firstname' => $billingAddress->getFirstname(),
                        'middlename' => $billingAddress->getMiddlename(),
                        'lastname' => $billingAddress->getLastname(),
                        'suffix' => $billingAddress->getSuffix(),
                        'company' => $billingAddress->getCompany(),
                        'email' => $email,
                        'country_id' => $billingAddress->getCountryId(),
                        'region' => $billingAddress->getRegion(),
                        'region_id' => $billingAddress->getRegionId(),
                        'city' => $billingAddress->getCity(),
                        'address' => $billStreet,
                        'postcode' => $billingAddress->getPostcode(),
                        'telephone' => $billingAddress->getTelephone(),
                        'fax' => $billingAddress->getFax(),
                        'store_id' => $quote->getStoreId(),
                        'itemprice' => $itemprice,

                        'vat_id' => $billingAddress->getData('vat_id'),
                        'vat_is_valid' => $billingAddress->getData('vat_is_valid'),
                        'vat_request_id' => $billingAddress->getData('vat_request_id'),
                        'vat_request_data' => $billingAddress->getData('vat_request_data'),
                        'vat_request_success' => $billingAddress->getData('vat_request_success'),

                        //#shipping
                        'shipping_prefix' => $shipAddress->getData("prefix"),
                        'shipping_firstname' => $shipAddress->getData("firstname"),
                        'shipping_middlename' => $shipAddress->getData("middlename"),
                        'shipping_lastname' => $shipAddress->getData("lastname"),
                        'shipping_suffix' => $shipAddress->getData("suffix"),
                        'shipping_company' => $shipAddress->getData("company"),
                        'shipping_country_id' => $shipAddress->getData("country_id"),
                        'shipping_region' => $shipAddress->getData("region"),
                        'shipping_region_id' => $shipAddress->getData("region_id"),
                        'shipping_city' => $shipAddress->getData("city"),
                        'shipping_address' => $shipStreet,
                        'shipping_postcode' => $shipAddress->getData("postcode"),
                        'shipping_telephone' => $shipAddress->getData("telephone"),
                        'shipping_fax' => $shipAddress->getData("fax"),

                        'shipping_vat_id' => $shipAddress->getData('vat_id'),
                        'shipping_vat_is_valid' => $shipAddress->getData('vat_is_valid'),
                        'shipping_vat_request_id' => $shipAddress->getData('vat_request_id'),
                        'shipping_vat_request_data' => $shipAddress->getData('vat_request_data'),
                        'shipping_vat_request_success' => $shipAddress->getData('vat_request_success'),

                        'created_from_quote_id' => $createdFromQuoteId,
                        'customer_group_id' => $customerGroup

                    );

                    // Assigning Salesrep
                    $modelCustomer->setData($qcustomer);
                    $qcustomer['user_id'] = $helper->getExpectedQuoteAdminId($modelCustomer, $admin->getUserId(), true);

                    foreach ($copyShippingParams as $key) {
                        $qcustomer[$key] = $shipAddress->getData($key);
                    }

                    foreach ($copyRateParams as $key => $value) {
                        $qcustomer[$key] = $rate[$value];
                    }

                    //#add customer to c2q
                    try {
                        $c2qId = $modelCustomer->addQuote($qcustomer)->getQuoteId();

                        //#save c2q id into session
                        $this->getCustomerSession()->setQuoteadvId($c2qId);
                    } catch (Exception $e) {
                        Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
                    }
                } else {
                    $errorMsg[] = $this->__("There was an error, because the customer address was undefined");
                }

            } else { //$c2qId is given

                $this->getCustomerSession()->setQuoteadvId($c2qId);
                $shipStreet = implode(',', $shipAddress->getStreet());
                $billingStreet = implode(',', $billingAddress->getStreet());
                $params = array();
                $params['currency'] = $currencyCode;
                $params['customer_group_id'] = $customerGroup;

                $addressData = Mage::helper('qquoteadv/address')->addressFieldsArray();

                foreach ($addressData as $key) {
                    // Setting params to fix street/address naming issue
                    if ($key != 'address') {
                        $params[$key] = $billingAddress->getData($key);
                        $params["shipping_" . $key] = $shipAddress->getData($key);
                    }
                }

                foreach ($copyShippingParams as $key => $value) {
                    $params[$key] = $shipAddress->getData($value);
                }

                foreach ($copyRateParams as $key => $value) {
                    $params[$key] = $rate[$value];
                }

                // Setting params to fix street/address naming issue
                $params['address'] = $billingStreet;
                $params['shipping_address'] = $shipStreet;

                //created_from_quote_id
                $params['created_from_quote_id'] = $createdFromQuoteId;

                if (count($params) > 0) {
                    try {
                        $modelCustomer = Mage::getModel('qquoteadv/qqadvcustomer')->updateQuote($c2qId, $params);

                    } catch (Exception $e) {
                        Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
                    }
                }
            }


            //#return back in case any error found
            if (count($errorMsg)) {
                $this->_redirectErr($errorMsg);
                return;
            }

            //#parse in case quote has items

            $qCollection = Mage::getModel('qquoteadv/qqadvproduct');
            $quoteProductAdded = Array();

            //CHECK Compare order to quote to see what needs to be added or updated.
            $handledRequestIds = array();
            foreach ($quote->getAllVisibleItems() as $item) {
                Mage::dispatchEvent('ophirah_qquoteadv_admin_swith2Quote_additem_before', array(
                    'quote_item' => $item,
                    'qqadvcustomer_id' => $c2qId)
                );
                $taxStoreConfig = Mage::helper('tax')->priceIncludesTax($quote->getStoreId()); //Mage::getStoreConfig('tax/calculation/price_includes_tax');
                if ($item->getProduct()->getTypeId() == Mage_Catalog_Model_Product_Type::TYPE_BUNDLE) {
                    $original_price = Mage::getModel('bundle/product_price')->getFinalPrice(1, $item->getProduct());

                    if ($taxStoreConfig){
                        $price = $item->getBasePriceInclTax();
                    } elseif ($item->getProduct()->getPriceType() == 0){
                        $price = $item->getPrice();
                    } else {
                        $price = $item->getBasePrice();
                    }
                } else {
                    if ($taxStoreConfig){
                        if(Mage::getStoreConfig('qquoteadv_advanced_settings/backend/force_original_product_price')){
                            $product = Mage::getModel('catalog/product')->load($item->getProduct()->getId());
                            $original_price = $product->getPrice();
                        } else {
                            $original_price = $item->getBasePriceInclTax(); //= $item->getProduct()->getPrice();
                        }
                        $price = $item->getProduct()->getBasePriceInclTax();
                    } else{
                        if(Mage::getStoreConfig('qquoteadv_advanced_settings/backend/force_original_product_price')){
                            $product = Mage::getModel('catalog/product')->load($item->getProduct()->getId());
                            $original_price = $product->getPrice();
                        } else {
                            $original_price = $item->getBasePrice(); //= $item->getProduct()->getPrice();
                        }
                        $price = $item->getProduct()->getBasePrice();
                    }
                }

                // Only Custom Prices needs to be recalculated by currency rate
                if ($item->getOriginalCustomPrice()) {
                    $rate = $baseToQuoteRate;
                    $customPrice = $item->getOriginalCustomPrice();
                } else {
                    $rate = 1;
                    if ($taxStoreConfig){
                        $customPrice = $item->getBasePriceInclTax() * $baseToQuoteRate;
                    } elseif ($item->getProduct()->getTypeId() == Mage_Catalog_Model_Product_Type::TYPE_BUNDLE && $item->getProduct()->getPriceType() == 0){
                        $customPrice = $item->getPrice() * $baseToQuoteRate;
                    } else {
                        $customPrice = $item->getBasePrice() * $baseToQuoteRate;
                    }
                }

                $basePrice = $customPrice / $rate;
                if(isset($customPrice) && !empty($customPrice)){
                    $price = $customPrice;
                }
                $orgPrice = $original_price;
                $orgCurPrice = $orgPrice * $rate;

                if((int)$item->getBaseDiscountAmount() > 0){
                    $item->setNoDiscount(0);
                    $useDiscount = 1;
                } else {
                    $item->setNoDiscount(1);
                    $useDiscount = 0;
                }

                if ($qqadvproductId = $qCollection->getIdByQuoteAndProduct($item, $c2qId)) {
                    $qqadvproduct = Mage::getModel('qquoteadv/qqadvproduct')->load($qqadvproductId);
                    Mage::dispatchEvent('ophirah_qquoteadv_admin_swith2Quote_update_qqadvproduct_before', array(
                        'quote_item' => $item,
                        'qqadvcustomer_id' => $c2qId,
                        'qqadvproduct' => $qqadvproduct)
                    );
                    //todo: check quoteadv_product_id? maybe in this case not.
                    $request_items = Mage::getModel('qquoteadv/requestitem')->getCollection()
                        ->addFieldToFilter('quote_id', $qqadvproduct->getQuoteId())
                        ->addFieldToFilter('product_id', $qqadvproduct->getProductId())
                        ->addFieldToFilter('request_qty', $qqadvproduct->getQty());

                    //exclude items that are already handled
                    foreach($handledRequestIds as $handledRequestId){
                        $request_items->addFieldToFilter('request_id', array('neq' => $handledRequestId));
                    }

                    $request_item = $request_items->getFirstItem();
                    if ($request_item->getId()) {
                        $handledRequestIds[] = $request_item->getId();
                        $attribute = unserialize($qqadvproduct->getAttribute());
                        $superAttribute = $item->getProduct()->getTypeInstance(true)->getOrderOptions($item->getProduct());
                        if (isset($superAttribute['info_buyRequest'])) {
                            if (isset($superAttribute['info_buyRequest']['super_attribute'])) {
                                $attribute['super_attribute'] = $superAttribute['info_buyRequest']['super_attribute'];
                            }
                        }
                        if (isset($superAttribute['options'])) {
                            $qqadvproduct->setOptions(serialize($superAttribute['options']));
                            $qqadvproduct->setHasOption(1);
                        }

                        $attribute['qty'] = $item->getQty();
                        $qqadvproduct->setAttribute(serialize($attribute));
                        $qqadvproduct->setQty($item->getQty());
                        $qqadvproduct->setUseDiscount($useDiscount);
                        try{
                            Mage::dispatchEvent('ophirah_qquoteadv_admin_swith2Quote_update_qqadvproduct_save_before', array(
                                'quote_item' => $item,
                                'qqadvcustomer_id' => $c2qId,
                                'qqadvproduct' => $qqadvproduct)
                            );
                            $qqadvproduct->save();
                            Mage::dispatchEvent('ophirah_qquoteadv_admin_swith2Quote_update_qqadvproduct_save_after_success', array(
                                'quote_item' => $item,
                                'qqadvcustomer_id' => $c2qId,
                                'qqadvproduct' => $qqadvproduct)
                            );
                        }catch(Exception $e){
                            Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
                            Mage::dispatchEvent('ophirah_qquoteadv_admin_swith2Quote_update_qqadvproduct_save_after_fail', array(
                                'quote_item' => $item,
                                'qqadvcustomer_id' => $c2qId,
                                'qqadvproduct' => $qqadvproduct,
                                'exception' => $e)
                            );
                        }

                        $request_item->setOwnerBasePrice($basePrice);
                        $request_item->setOwnerCurPrice($price);
                        $request_item->setOriginalPrice($orgPrice);
                        $request_item->setOriginalCurPrice($orgCurPrice);
                        $request_item->setRequestQty($item->getQty());
                        try{
                            Mage::dispatchEvent('ophirah_qquoteadv_admin_swith2Quote_update_requestitem_save_before', array(
                                'quote_item' => $item,
                                'qqadvcustomer_id' => $c2qId,
                                'qqadvproduct' => $qqadvproduct)
                            );
                            $request_item->save();
                            Mage::dispatchEvent('ophirah_qquoteadv_admin_swith2Quote_update_requestitem_save_after_success', array(
                                'quote_item' => $item,
                                'qqadvcustomer_id' => $c2qId,
                                'qqadvproduct' => $qqadvproduct)
                            );
                        }catch(Exception $e){
                            Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
                            Mage::dispatchEvent('ophirah_qquoteadv_admin_swith2Quote_update_requestitem_save_after_fail', array(
                                'quote_item' => $item,
                                'qqadvcustomer_id' => $c2qId,
                                'qqadvproduct' => $qqadvproduct,
                                'exception' => $e)
                            );
                        }
                    }
                    Mage::dispatchEvent('ophirah_qquoteadv_admin_swith2Quote_update_qqadvproduct_after', array(
                        'quote_item' => $item,
                        'qqadvcustomer_id' => $c2qId,
                        'qqadvproduct' => $qqadvproduct)
                    );
                    $quoteProductAdded[] .= $qqadvproductId;
                } else {

                    $superAttribute = $item->getProduct()->getTypeInstance(true)->getOrderOptions($item->getProduct());

                    $optionalAttrib = '';
                    if (isset($superAttribute['info_buyRequest'])) {
                        if (isset($superAttribute['info_buyRequest']['uenc'])) {
                            unset($superAttribute['info_buyRequest']['uenc']);
                        }

                        $superAttribute['info_buyRequest']['product'] = $item->getData('product_id');
                        $superAttribute['info_buyRequest']['qty'] = $item->getQty();

                        $optionalAttrib = serialize($superAttribute['info_buyRequest']);
                    }


                    $params = array(
                        'product_id' => $item->getProductId(),
                        'qty' => $item->getQty(),
                        'price' => $price,
                        'custom_price' => $customPrice,
                        'original_price' => $original_price,
                        'base_quote_rate' => $baseToQuoteRate,
                        'use_discount' => $useDiscount
                    );


                    $qqadvproduct = $this->_create($params, $optionalAttrib);

                    $latestId = max($qCollection->getIdsByQuoteId($c2qId));
                    $quoteProductAdded[] .= $latestId;

                }
                Mage::dispatchEvent('ophirah_qquoteadv_admin_swith2Quote_additem_after', array(
                    'quote_item' => $item,
                    'qqadvcustomer_id' => $c2qId,
                    'qqadvproduct'=> $qqadvproduct)
                );
            }

            //remove unwanted products (removes by id, that could be an issue)
            foreach ($qCollection->getCollection()->addFieldToFilter('quote_id', $c2qId) as $qItem) {
                $delete = true;
                foreach($quoteProductAdded as $id){
                    if ($id == $qItem->getId()) {
                        $delete = false;
                        break;
                    }
                }
                if($delete){
                    Mage::getModel('qquoteadv/qqadvproduct')->deleteQuote($qItem->getId());
                }
            }


            //#update c2q status to make visible c2q request
            try {
                $modelCustomer->load($c2qId);
                $modelCustomer->setIsQuote(1);

                //#for new quote we need correct increment id
                // And set a status
                if (!Mage::getSingleton('adminhtml/session')->getUpdateQuoteId()) {
                    $modelCustomer->setIncrementId(Mage::getModel('qquoteadv/entity_increment_numeric')->getNextId($modelCustomer->getStoreId()));
                    $modelCustomer->setStatus(Ophirah_Qquoteadv_Model_Status::STATUS_PROPOSAL_BEGIN);
                }
                // Add create hash
                $modelCustomer->setCreateHash(Mage::helper('qquoteadv/license')->getCreateHash($modelCustomer->getIncrementId()));
                //# Add applied SalesRule
                if ($quote->getData('applied_rule_ids')) {
                    $code = null;
                    if (is_string($quote->getData('applied_rule_ids'))) {
                        $code = $quote->getData('coupon_code');
                    }

                    if ($code != null) {
                        $modelCustomer->setData('salesrule', $quote->getData('applied_rule_ids'));
                    }
                }

                // Update Address data
                // TODO: create a better way to store all this data

                $updateArray = array('vat_id',
                    'vat_is_valid',
                    'vat_request_id',
                    'vat_request_date',
                    'vat_request_success'
                );

                foreach ($updateArray as $updateValue) {
                    $modelCustomer->setData($updateValue, $billingAddress->getData($updateValue));
                    $modelCustomer->setData('shipping_' . $updateValue, $shipAddress->getData($updateValue));
                }

                if ($shipAddress->getData('same_as_billing')) {
                    $modelCustomer->setData($updateValue, $shipAddress->getData('same_as_billing'));
                }

                // Shipping Method
                if ($shipAddress->getShippingMethod()) {
                    $modelCustomer->setData('shipping_method', $shipAddress->getShippingMethod());
                    $modelCustomer->setData('shipping_description', $shipAddress->getShippingDescription());
                    $modelCustomer->setData('base_shipping_amount', $shipAddress->getBaseShippingAmount());
                    $modelCustomer->setData('weight', $shipAddress->getWeight());
                }

                // Payment Method
                $paymentMethod = $data['payment']['method'];
                $modelCustomer->setPaymentMethod($paymentMethod);
                // call getPayment just to trigger some compatibility actions
                $quote->getPayment();

                //prepare for save
                $modelCustomer->updateAddress();
                $modelCustomer->collectTotals();

                // Save data
                Mage::dispatchEvent('qquoteadv_qqadvcustomer_beforesave_final', array('quote' => $modelCustomer));
                $modelCustomer->save();
                Mage::dispatchEvent('qquoteadv_qqadvcustomer_aftersave_final', array('quote' => $modelCustomer));

                Mage::helper('qquoteadv/logging')->sentAnonymousData('request', 'b', $modelCustomer->getData('quote_id'));
            } catch (Exception $e) {
                Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
            }

            // Clear session quote data
            Mage::getSingleton('adminhtml/session_quote')->clear();

        }

        Mage::getSingleton('adminhtml/session')->setUpdateQuoteId(null);

        if ($c2qId) {
            $this->_redirect('adminhtml/qquoteadv/edit', array('id' => $c2qId));
        } else {
            $this->_redirect('*/*');
        }

        Mage::dispatchEvent('ophirah_qquoteadv_admin_swith2Quote_after', array($c2qId, $quote, $data));
    }

    /**
     * Get customer session data
     */
    public function getCustomerSession()
    {
        return Mage::getSingleton('customer/session');
    }

    /**
     * Insert quote data
     * $params = array(
     * 'product' => $item->getProductId(),
     * 'qty'     => $item->getQty(),
     * 'price'   => $item->getPrice()
     * 'original_price' => $item->getProduct()->getPrice();
     * );
     * @param string $superAttribute
     */
    private function _create($params, $superAttribute)
    {
        $modelProduct = Mage::getModel('qquoteadv/qqadvproduct');

        $hasOption = 0;
        $options = '';
        if (isset($params['options'])) {
            $options = serialize($params['options']);
            $hasOption = 1;
        } elseif (isset($superAttribute)) {
            $attr = unserialize($superAttribute);

            if (isset($attr['options'])) {
                $options = serialize($attr['options']);
                $hasOption = 1;
                $params['qty'] = $attr['qty'];
            }
        }

        $quoteId = $this->getCustomerSession()->getQuoteadvId();
        $qproduct = array(
            'quote_id' => $quoteId,
            'product_id' => $params['product_id'],
            'qty' => $params['qty'],
            'attribute' => $superAttribute,
            'has_options' => $hasOption,
            'options' => $options,
            'use_discount' => $params['use_discount'],
            'store_id' => Mage::getSingleton('adminhtml/session_quote')->getStoreId() //$this->getCustomerSession()->getStoreId()
        );

        // Get Currency rate
        $rate = (isset($params['base_quote_rate'])) ? $params['base_quote_rate'] : 1;

        // Defining Prices
        $basePrice = $params['custom_price'] / $rate;
        $price = $params['custom_price'];
        $orgPrice = $params['original_price'];
        $orgCurPrice = $orgPrice * $rate;
        $mageProduct = Mage::getModel('catalog/product')->load($params['product_id']);
        try{
            Mage::dispatchEvent('ophirah_qquoteadv_admin_swith2Quote_add_qqadvproduct_save_before', array(
                'quote_item' => $mageProduct,
                'qqadvcustomer_id' => $quoteId)
            );
            $obj = $modelProduct->addProduct($qproduct);
            Mage::dispatchEvent('ophirah_qquoteadv_admin_swith2Quote_add_qqadvproduct_save_after_success', array(
                'quote_item' => $mageProduct,
                'qqadvcustomer_id' => $quoteId,
                'qqadvproduct' => $obj)
            );
        }catch(Exception $e){
            Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
            Mage::dispatchEvent('ophirah_qquoteadv_admin_swith2Quote_add_qqadvproduct_save_after_fail', array(
                'quote_item' => $mageProduct,
                'qqadvcustomer_id' => $quoteId,
                'exception' => $e)
            );
        }
        if($obj instanceof Ophirah_Qquoteadv_Model_Qqadvproduct && $obj->getId()){
            try {
                $requestData = array(
                    'quote_id' => $this->getCustomerSession()->getQuoteadvId(),
                    'product_id' => $params['product_id'],
                    'request_qty' => $params['qty'],
                    'owner_base_price' => $basePrice,
                    'owner_cur_price' => $price,
                    'original_price' => $orgPrice,
                    'original_cur_price' => $orgCurPrice,
                    'quoteadv_product_id' => $obj->getId()
                );
                Mage::dispatchEvent('ophirah_qquoteadv_admin_swith2Quote_add_requestData_save_before', array(
                        'quote_item' => $mageProduct,
                        'qqadvcustomer_id' => $quoteId)
                );
                Mage::getModel('qquoteadv/requestitem')->setData($requestData)->save();
                Mage::dispatchEvent('ophirah_qquoteadv_admin_swith2Quote_add_requestData_save_after_success', array(
                        'quote_item' => $mageProduct,
                        'qqadvcustomer_id' => $quoteId)
                );
            } catch (Exception $e) {
                Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
                Mage::dispatchEvent('ophirah_qquoteadv_admin_swith2Quote_add_requestData_save_after_fail', array(
                        'quote_item' => $mageProduct,
                        'qqadvcustomer_id' => $quoteId)
                );
            }
            return $obj;
        }else{
            return false;
        }

    }

    /**
     * Get core session data
     */
    public function getCoreSession()
    {
        return Mage::getSingleton('core/session');
    }

    /**
     * Action for the delete qty button in the quote edit page
     */
    public function deleteQtyFieldAction()
    {
        $requestId = (int)$this->getRequest()->getParam('request_id');
        $c2qId = null;
        if (empty($requestId)) {
            $this->_redirect('*/*/*');
        }

        $item = Mage::getModel('qquoteadv/requestitem')->load($requestId);
        $c2qId = $item->getData('quote_id');
        Mage::dispatchEvent('ophirah_qquoteadv_admin_deleteQtyField_before', array($requestId, $c2qId));

        $_quote = Mage::getSingleton('qquoteadv/qqadvcustomer')->load($c2qId);

        $quoteProductId = $item->getData('quoteadv_product_id');
        $listRequests = Mage::getModel('qquoteadv/requestitem')->getCollection()->setQuote($_quote);
        $listRequests->addFieldToFilter('quoteadv_product_id', $quoteProductId);
        $size = $listRequests->getSize();

        if ($size > 1) {
            try {
                $item->delete();
            } catch (Exception $e) {
                Mage::getSingleton('adminhtml/session')->addError($e->getMessage());
                Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
            }
        } else {
            $msg = $this->__('Minimum of one Qty is required');
            Mage::getSingleton('adminhtml/session')->addError($msg);
        }

        $this->_redirect('*/*/edit', array('id' => $c2qId));
        Mage::dispatchEvent('ophirah_qquoteadv_admin_deleteQtyField_after', array($requestId, $c2qId));
    }

    /**
     * Action for the add qty button on the edit quote page
     *
     * @return null
     */
    public function addQtyFieldAction()
    {
        $quoteProductId = (int)$this->getRequest()->getParam('quote_product_id');
        $quoteProduct = Mage::getModel('qquoteadv/qqadvproduct')->load($this->getRequest()->getParam('quote_product_id'));
        $product = Mage::getModel('catalog/product')->load($quoteProduct->getData('product_id'));

        Mage::dispatchEvent('ophirah_qquoteadv_admin_addQtyField_before', array($quoteProductId));

        // For configurable product, use the simple product
        if ($product->getTypeId() == Mage_Catalog_Model_Product_Type::TYPE_CONFIGURABLE) {
            $attribute = $quoteProduct->getData('attribute');
            if (!is_array($attribute)) {
                $attribute = unserialize($attribute);
            }
            $prod_simple = Mage::getModel('catalog/product_type_configurable')->getProductByAttributes($attribute['super_attribute'], $product);
            $check_prod = $prod_simple;
        } else {
            $check_prod = $product;
        }

        $requestQty = $this->getRequest()->getParam('request_qty');
        $c2qId = $this->getRequest()->getParam('quoteadv_id');

        if(is_array($requestQty)){
            //bad way of getting the first value of the array
            foreach($requestQty as $qtyValue){
                $requestQty = $qtyValue;
                break;
            }
        }

        //echo 'add qty field: ';
        $check = Mage::helper('qquoteadv')->isQuoteable($check_prod, $requestQty);
        if ($check->getHasErrors()) {
            $errors = $check->getErrors();
            $this->_redirectErr($errors);
            return null;
        }

        $productId = null;

        if (empty($quoteProductId) or empty($requestQty)) {
            $errorMsg = Mage::helper('checkout')->__("Invalid data.");
            Mage::getSingleton('adminhtml/session')->addError($errorMsg);

            if (!empty($c2qId)) {
                return $this->_redirect('*/*/edit', array('id' => $c2qId));
            } else {
                return $this->_redirect('*/*/');
            }
        }

        //#SEARCH ORIGINAL PRICE
        $_quote = Mage::getSingleton('qquoteadv/qqadvcustomer')->load($c2qId);

        $_collection = Mage::getModel('qquoteadv/requestitem')->getCollection()->setQuote($_quote)
            ->addFieldToFilter('quoteadv_product_id', $quoteProductId);

        //#trying to find duplicate of requested quantity value
        foreach ($_collection as $item) {
            $c2qId = $item->getData('quote_id');

            $productId = $item->getData('product_id');
            $check = Mage::helper('qquoteadv')->isQuoteable($productId, $requestQty);
            if ($check->getHasErrors()) {
                $errors = $check->getErrors();
                $this->_redirectErr($errors);
                return null;
            }

            if ($requestQty == $item->getData('request_qty')) {
                $errorMsg = $this->__('Duplicate value entered');
                Mage::getSingleton('adminhtml/session')->addError($errorMsg);
                return $this->_redirect('*/*/edit', array('id' => $c2qId));
            }
        }

        //last true is for getting the original price instead of the special price.
        $ownerPrice = Mage::helper('qquoteadv')->_applyPrice($quoteProductId, $requestQty, false, false);
        $originalPrice = Mage::helper('qquoteadv')->_applyPrice($quoteProductId, 1, false, true);

        $_quoteadv = $this->getQuotationQuote($c2qId);

        $rate = $_quoteadv->getBase2QuoteRate();

        $basePrice = Mage::helper('qquoteadv')->_applyPrice($quoteProductId, $requestQty, false, true);
        //$basePrice = $ownerPrice;

        if ($c2qId && $productId && isset($originalPrice) && $requestQty) {
            $requestData = array(
                'quote_id' => $c2qId,
                'product_id' => $productId,
                'request_qty' => $requestQty,
                'owner_base_price' => $basePrice,
                'owner_cur_price' => $ownerPrice * $rate,
                'original_price' => $originalPrice,
                'quoteadv_product_id' => $quoteProductId,
                'original_cur_price' => $basePrice * $rate
            );

            if ($requestQty) {
                try {
                    Mage::getModel('qquoteadv/requestitem')->setData($requestData)->save();
                } catch (Exception $e) {
                    Mage::getSingleton('adminhtml/session')->addError($e->getMessage());
                    Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
                }
            }
        }
        if (!empty($c2qId)) {
            $this->_redirect('*/*/edit', array('id' => $c2qId));
        } else {
            $this->_redirect('*/*/');
        }

        Mage::dispatchEvent('ophirah_qquoteadv_admin_addQtyField_after', array($quoteProductId));
        return null;
    }

    /**
     * Function to get the admin name by the admin id
     *
     * @param $id
     * @return mixed
     */
    public function getAdminName($id)
    {
        return Mage::helper('qquoteadv')->getAdminName($id);
    }

    /**
     * Export selected quotes as csv
     */
    public function exportAction()
    {
        $quoteIds = $this->getRequest()->getParam('qquote');
        Mage::dispatchEvent('ophirah_qquoteadv_admin_export_before', array($quoteIds));

        if (!is_array($quoteIds) || empty($quoteIds)) {
            $this->_redirectErr($this->__('No quotes selected to export'));
            return;
        }
        $filename = "cart2quoteExport_" . date("ymdHis") . ".csv";
        foreach ($quoteIds as $quoteId) {
            $quote = Mage::getModel('qquoteadv/qqadvcustomer')->load($quoteId);

            if (!Mage::helper('qquoteadv/license')->validLicense('export', array($quote->getData('create_hash'), $quote->getData('increment_id')))) {
                $this->_redirectErr($this->__("The CSV export function is only available in Cart2Quote Enterprise. To update please go to <a href='http://www.cart2quote.com/pricing-magento-quotation-module.html?utm_source=Customer%2Bwebsite&utm_medium=license%2Bpopup&utm_campaign=Upgrade%2Bversion'>http://www.cart2quote.com</a>"));
                return;
            }

            $folder = Mage::getBaseDir() . self::EXPORT_FOLDER_PATH;

            //check the folder exists or create it
            if (!file_exists($folder)) {
                try {
                    mkdir($folder);
                } catch (Exception $e) {
                    Mage::log('Exception: ' .$e->getMessage(), null, 'c2q_exception.log', true);
                    $this->_redirectErr($this->__('Could not create cart2quote export folder: ') . $folder);
                    return;
                }
            } else {
                if (!is_writable($folder)) {
                    $this->_redirectErr($this->__('The cart2quote export folder is not writable: ') . $folder);
                    return;
                }
            }

            //set filepath
            $filepath = $folder . $filename;

            //export quotes to file
            $exported = Mage::getSingleton('qquoteadv/qqadvcustomer')->exportQuotes($quoteIds, $filepath);

            if ($exported) {
                $contents = file_get_contents($filepath);
                $this->_prepareDownloadResponse($filename, $contents);
            } else {
                $this->_redirectErr($this->__('Could not export quotes'));
                return;
            }
        }

        Mage::dispatchEvent('ophirah_qquoteadv_admin_export_after', array($quoteIds));
    }

    /**
     * Set redirect into response with anchor
     *
     * @param $path
     * @param array $arguments
     * @param string $anchor
     * @return $this
     */
    protected function _redirectAnhcor($path, $arguments = array(), $anchor = '')
    {
        $this->_getSession()->setIsUrlNotice($this->getFlag('', self::FLAG_IS_URLS_CHECKED));
        $this->getResponse()->setRedirect($this->getUrl($path, $arguments) . $anchor);
        return $this;
    }

    /**
     * Action that adds a costprice on the edit quote page
     */
    public function addCostPriceAction() {
        $c2qId = (int)$this->getRequest()->getParam('quoteadv_id');
        $requestId = $this->getRequest()->getParam('request_id');
        $newCostPrice = $this->getRequest()->getParam('new_cost_price');
        $newCostPrice = str_replace(",", ".", $newCostPrice);

        Mage::dispatchEvent('ophirah_qquoteadv_admin_addCostPrice_before', array($c2qId, $requestId, $newCostPrice));

        if((isset($requestId) && !empty($requestId)) && (isset($c2qId) && !empty($c2qId))){
            $request_item = Mage::getModel('qquoteadv/requestitem')->load($requestId);
            $request_item->setCostPrice($newCostPrice);
            $request_item->save();
        }

        if (!empty($c2qId)) {
            $this->_redirect('*/*/edit', array('id' => $c2qId));
        } else {
            $this->_redirect('*/*/');
        }

        Mage::dispatchEvent('ophirah_qquoteadv_admin_addCostPrice_after', array($c2qId, $requestId, $newCostPrice));
    }

    /**
     * Acl check for admin
     *
     * @return bool
     */
    protected function _isAllowed(){
        return Mage::getSingleton('admin/session')->isAllowed('sales/qquoteadv/crmaddon');
    }

    /**
     * Function that gets the quote object
     *
     * @param null $quoteId
     * @return Mage_Core_Model_Abstract
     */
    protected function getQuotationQuote($quoteId = null)
    {
        //if no quote id is given
        if($quoteId == null){
            return $this->_quoteadv;
        }

        //if quote id is given
        if ($this->_quoteadv) {
            //check the id
            if ($this->_quoteadv->getId() != $quoteId) {
                $this->_quoteadv = Mage::getModel('qquoteadv/qqadvcustomer')->load($quoteId);
            }
        } else {
            //$this->_quoteadv is not set
            $this->_quoteadv = Mage::getModel('qquoteadv/qqadvcustomer')->load($quoteId);
        }

        return $this->_quoteadv;
    }
}
