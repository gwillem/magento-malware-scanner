<?php

/**
 * phpwcms content management system
 *
 * @author Oliver Georgi <og@phpwcms.org>
 * @copyright Copyright (c) 2002-2018, Oliver Georgi
 * @license http://opensource.org/licenses/GPL-2.0 GNU GPL-2
 * @link http://www.phpwcms.org
 *
 **/

// some mod ADS functions only needed in frontend

function renderAds($match) {

	if(empty($match[1])) {
		return '';
	} elseif(!($adID = intval($match[1])))  {
		return '';
	} elseif($GLOBALS['IS_A_BOT']) {
		return '';
	} elseif(BROWSER_OS == 'Other') {
		return '';
	}

	$sql  = 'SELECT * FROM '.DB_PREPEND.'phpwcms_ads_campaign ac ';
	$sql .= 'LEFT JOIN '.DB_PREPEND.'phpwcms_ads_place ap ON ';
	$sql .= 'ap.adplace_id=ac.adcampaign_place ';
	$sql .= 'WHERE ac.adcampaign_place='.$adID.' AND ';
	$sql .= 'ac.adcampaign_status=1 AND ap.adplace_status=1 AND ';
	$sql .= 'ac.adcampaign_datestart < NOW() AND ';
	$sql .= 'ac.adcampaign_dateend > NOW() AND ';
	$sql .= '(ac.adcampaign_maxview=0 OR (ac.adcampaign_maxview > 0 AND ac.adcampaign_maxview >= ac.adcampaign_curview)) AND ';
	$sql .= '(ac.adcampaign_maxclick=0 OR (ac.adcampaign_maxclick > 0 AND ac.adcampaign_maxclick >= ac.adcampaign_curclick))';

	$ads  = _dbQuery($sql);

	if(is_array($ads) && count($ads) ) {

		if(empty($_COOKIE['phpwcmsAdsUserId'])) {

			$ad = $ads[array_rand($ads)];

		} else {

			$ads_userid = $_COOKIE['phpwcmsAdsUserId'];
			while(count($ads)) {

				$ad_index	= array_rand($ads);
				$ad			= $ads[$ad_index];

				if($ad['adcampaign_maxviewuser']) {

					//check how often selected ad was viewed by user
					$sql  = 'SELECT COUNT(*) FROM '.DB_PREPEND.'phpwcms_ads_tracking WHERE ';
					$sql .= 'adtracking_campaignid='.$ad['adcampaign_id'].' AND ';
					$sql .= "adtracking_cookieid="._dbEscape($ads_userid);
					$ads_viewed = _dbQuery($sql, 'COUNT');

					if($ads_viewed <= $ad['adcampaign_maxviewuser']) {
						break;
					} else {
						unset($ads[$ad_index]);
					}

				} else {
					break;
				}

			}
			if(!count($ads)) {
				return '';
			}

		}

	} else {
		return '';
	}

	$ad['adcampaign_data']	= @unserialize($ad['adcampaign_data']);
	$ad['dir']				= PHPWCMS_CONTENT.'ads/'.$ad['adcampaign_id'];
	$ad['content_dir']		= CONTENT_PATH.'ads/'.$ad['adcampaign_id'].'/';
	if($ad['adcampaign_type']!=2 && $ad['adcampaign_type']!=4 && !is_dir($ad['dir'])) {
		return '';
	}
	$ad['dir']			   .= '/';
	if(!empty($ad['adcampaign_data']['css']) && is_file($ad['dir'].$ad['adcampaign_data']['css'])) {
		$GLOBALS['block']['custom_htmlhead'][] = '  <link rel="stylesheet" type="text/css" href="'.$ad['content_dir'].$ad['adcampaign_data']['css'].'"'.HTML_TAG_CLOSE;
	}

	$ad_media	= '';
	$ad_title	= ' title="'.html($ad['adcampaign_data']['title_text'] ? $ad['adcampaign_data']['title_text'] : $ad['adcampaign_data']['url']).'"';
	$ad_alt		= $ad['adcampaign_data']['alt_text'] ? ' alt="'.html_specialchars($ad['adcampaign_data']['alt_text']).'"' : ' alt=""';
	$ad_wxh		= ' style="width:'.$ad['adplace_width'].'px;height:'.$ad['adplace_height'].'px;"';
	$ad_imgsrc	= $ad['content_dir'].$ad['adcampaign_data']['image'];
	$ad_swfsrc	= $ad['content_dir'].$ad['adcampaign_data']['flash'];
	$ad_random	= md5( time().@microtime() );
	$ad_urldata	= '&amp;u='.PHPWCMS_USER_KEY.'&amp;r='.(empty($_SERVER['HTTP_REFERER']) ? '' : urlencode($_SERVER['HTTP_REFERER'])).'&amp;c='.$GLOBALS['aktion'][0].'&amp;a='.$GLOBALS['aktion'][1].'&amp;k='.$ad_random;

	switch($ad['adcampaign_type']) {

		case 0:	//Bild
				if(empty($ad['adcampaign_data']['image']) || !is_file($ad['dir'].$ad['adcampaign_data']['image'])) {
					return '';
				}
				$ad_imgsrc	 = html_specialchars($ad_imgsrc);
				$ad_media	.= '<a href="index.php?adclickval='.$ad['adcampaign_id'].'&amp;url='.urlencode($ad['adcampaign_data']['url']).$ad_urldata.'"';
				$ad_media	.= $ad_title;
				if($ad['adcampaign_data']['target']) {
					$ad_media	.= ' target="'.$ad['adcampaign_data']['target'].'"';
				}
				$ad_media	.= '><img src="'.$ad_imgsrc.'" border="0"'.$ad_wxh.$ad_alt.HTML_TAG_CLOSE.'</a>';
				break;

		case 1:	//Flash
				$ad['adcampaign_data']['url'] = urlencode($ad['adcampaign_data']['url']);
				$ad_flashID  = 'adsBannerFlash'.$adID;
				$ad_so		 = 'adsInnerFlash'.$ad['adcampaign_id'];
				$ad_media	.= '<a href="index.php?adclickval='.$ad['adcampaign_id'].'&amp;url='.$ad['adcampaign_data']['url'].$ad_urldata.'"';
				$ad_media	.= $ad_title;
				if($ad['adcampaign_data']['target']) {
					$ad_media	.= ' target="'.$ad['adcampaign_data']['target'].'"';
				}
				$ad_media	.= ' id="'.$ad_so.'">';
				if(is_file($ad['dir'].$ad['adcampaign_data']['image'])) {
					$ad_media	.= '<img src="'. html_specialchars($ad_imgsrc) .'" border="0"'.$ad_wxh.$ad_alt.HTML_TAG_CLOSE;
				} else {
					$ad_media	.= $ad_title;
				}
				$ad_media	.= '</a>';
				$ad_media    = '<div id="'.$ad_flashID.'">'.$ad_media.'</div>';

				if(!empty($ad['adcampaign_data']['flash']) && is_file($ad['dir'].$ad['adcampaign_data']['flash'])) {

					initSwfObject();

					$ad_urldata	 = urldecode(str_replace('&amp;', '&', $ad_urldata));
					$ad_flash	 = '  <script'.SCRIPT_ATTRIBUTE_TYPE.'>'.LF.SCRIPT_CDATA_START.LF;

					$ad_flash	.= '	var flashvars_'.$ad_so.'	= {clickTag: "'.urlencode('index.php?adclickval='.$ad['adcampaign_id'].'&url='.$ad['adcampaign_data']['url'].$ad_urldata).'", ';
					$ad_flash	.= 'clickTarget: "'.urlencode($ad['adcampaign_data']['target']).'"};' . LF;
					$ad_flash	.= '	var params_'.$ad_so.'		= {wmode: "opaque", autoplay: true, quality: "autohigh", ';
					$ad_flash	.= 'play: true, menu: false, allowscriptaccess: "always", swliveconnect: true, scale: "exactfit"';
					if($ad['adcampaign_data']['bgcolor']) {
						$ad_flash	.= ', bgcolor: "'.$ad['adcampaign_data']['bgcolor'].'"';
					}
					$ad_flash	.= '};' . LF;
					$ad_flash	.= '	var attributes_'.$ad_so.'	= {};' . LF;

					$ad_flash	.= '	swfobject.embedSWF("'.$ad_swfsrc.'", "'.$ad_so.'", ';
					$ad_flash	.= '"'.$ad['adplace_width'].'", "'.$ad['adplace_height'].'", ';
					$ad_flash	.= '"'.$ad['adcampaign_data']['flashversion'].'", false, ';
					$ad_flash	.= 'flashvars_'.$ad_so.', params_'.$ad_so.', attributes_'.$ad_so.');';

					$ad_flash	.= LF.SCRIPT_CDATA_END.LF.'  </script>';

					$GLOBALS['block']['custom_htmlhead'][$ad_so] = $ad_flash;

				}
				break;

		case 2:	//HTML
				if(!empty($ad['adcampaign_data']['html'])) {
					if($ad['adcampaign_data']['bordercolor']) {
						$ad_wxh  = ' style="width:'.($ad['adplace_width']-2).'px;height:'.($ad['adplace_height']-2).'px;';
						$ad_wxh .= 'border:1px solid '.$ad['adcampaign_data']['bordercolor'].';';
					} else {
						$ad_wxh  = ' style="width:'.$ad['adplace_width'].'px;height:'.$ad['adplace_height'].'px;';
					}
					if($ad['adcampaign_data']['bgcolor']) {
						$ad_wxh .= 'background-color:'.$ad['adcampaign_data']['bgcolor'].';';
					}
					$ad_media .= '<div id="adBannerHTML'.$adID.'"'.$ad_wxh.'">';
					$ad_media .= '<a href="index.php?adclickval='.$ad['adcampaign_id'].'&amp;url='.urlencode($ad['adcampaign_data']['url']).$ad_urldata.'"';
					$ad_media .= $ad_title;
					if($ad['adcampaign_data']['target']) {
						$ad_media .= ' target="'.$ad['adcampaign_data']['target'].'"';
					}
					$ad_media .= ' style="width:'.$ad['adplace_width'].'px;height:'.$ad['adplace_height'].'px;display:block;">';
					$ad_media .= $ad['adcampaign_data']['html'] . '</a></div>';
				}

				break;

		case 3:	//Flash Layer
				$ad['adcampaign_data']['url']		= urlencode($ad['adcampaign_data']['url']);
				$ad_flashID  = 'adsBannerFL'.$adID;
				$ad_so		 = 'adsInnerFlash'.$ad['adcampaign_id'];
				if(!empty($ad['adcampaign_data']['flash']) && is_file($ad['dir'].$ad['adcampaign_data']['flash'])) {

					$ad_media    = '<div id="'.$ad_flashID.'" style="width:'.$ad['adplace_width'].'px;height:'.$ad['adplace_height'].'px;display:none;">';
					$ad_media   .= '<div id="'.$ad_so.'"></div></div>';

					initSwfObject();

					$ad_urldata	 = urldecode(str_replace('&amp;', '&', $ad_urldata));


					$ad_flash	 = '  <!--[if gte IE 5]><script type="text/javascript" event="FSCommand(command,args)" for="'.$ad_so.'">';
					$ad_flash	.= $ad_so.'_DoFSCommand(command, args);</script><![endif]-->'.LF;

					$ad_flash	.= '  <script'.SCRIPT_ATTRIBUTE_TYPE.'>'.LF.SCRIPT_CDATA_START.LF;

					$ad_flash	.= '	function '.$ad_so.'_DoFSCommand(command,args){if(command=="adlayerhider")toggleLayerDisplay("'.$ad_flashID.'","none");}'.LF;
					$ad_flash	.= '	function show'.$ad_so.'(){toggleLayerDisplay("'.$ad_flashID.'", "block");}'.LF;

					$ad_flash	.= '	var flashvars_'.$ad_so.'	= {clickTag: "'.urlencode('index.php?adclickval='.$ad['adcampaign_id'].'&current='.$ad_random.'&u='.PHPWCMS_USER_KEY.'&url='.$ad['adcampaign_data']['url']).'", ';
					$ad_flash	.= 'clickTarget: "'.urlencode($ad['adcampaign_data']['target']).'"};' . LF;
					$ad_flash	.= '	var params_'.$ad_so.'		= {wmode: "transparent", autoplay: true, quality: "autohigh", ';
					$ad_flash	.= 'play: true, menu: false, allowscriptaccess: "always", swliveconnect: true, scale: "exactfit"';
					if($ad['adcampaign_data']['bgcolor']) {
						$ad_flash	.= ', bgcolor: "'.$ad['adcampaign_data']['bgcolor'].'"';
					}
					$ad_flash	.= '};' . LF;
					$ad_flash	.= '	var attributes_'.$ad_so.'	= {name: "'.$ad_so.'"};' . LF;

					$ad_flash	.= '	swfobject.embedSWF("'.$ad_swfsrc.'", "'.$ad_so.'", ';
					$ad_flash	.= '"'.$ad['adplace_width'].'", "'.$ad['adplace_height'].'", ';
					$ad_flash	.= '"'.$ad['adcampaign_data']['flashversion'].'", false, ';
					$ad_flash	.= 'flashvars_'.$ad_so.', params_'.$ad_so.', attributes_'.$ad_so.');' . LF;

					$ad_flash	.= '	window.setTimeout("show'.$ad_so.'()", 1000);';

					$ad_flash	.= LF.SCRIPT_CDATA_END.LF.'  </script>';

					$GLOBALS['block']['custom_htmlhead'][$ad_so] = $ad_flash;

				}
				break;

		case 4: //Remote HTML Code
				if(!empty($ad['adcampaign_data']['html'])) {
					$ad_media .= $ad['adcampaign_data']['html'];
				}
				break;

	}

	//set ads tracking image here.
	$GLOBALS['content']['ADS_ALL'][] = $ad['adcampaign_id'];

	return $ad['adplace_prefix'].$ad_media.$ad['adplace_suffix'];

}
