<?php

/*************************************************************************************
   Copyright notice
   
   (c) 2002-2008 Oliver Georgi (oliver@phpwcms.de) // All rights reserved.
 
   This script is part of PHPWCMS. The PHPWCMS web content management system is
   free software; you can redistribute it and/or modify it under the terms of
   the GNU General Public License as published by the Free Software Foundation;
   either version 2 of the License, or (at your option) any later version.
  
   The GNU General Public License can be found at http://www.gnu.org/copyleft/gpl.html
   A copy is found in the textfile GPL.txt and important notices to the license 
   from the author is found in LICENSE.txt distributed with these scripts.
  
   This script is distributed in the hope that it will be useful, but WITHOUT ANY 
   WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
   PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 
   This copyright notice MUST APPEAR in all copies of the script!
*************************************************************************************/

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
			$ads_viewed = 0;
			while(count($ads)) {
				
				$ad_index	= array_rand($ads);
				$ad			= $ads[$ad_index];
				
				if($ad['adcampaign_maxviewuser']) {
				
					//check how often selected ad was viewed by user
					$sql  = 'SELECT COUNT(*) FROM '.DB_PREPEND.'phpwcms_ads_tracking WHERE ';
					$sql .= 'adtracking_campaignid='.$ad['adcampaign_id'].' AND ';
					$sql .= "adtracking_cookieid='".mysql_escape_string($ads_userid)."'";
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
	if($ad['adcampaign_data']['css'] && is_file($ad['dir'].$ad['adcampaign_data']['css'])) {
		$GLOBALS['block']['custom_htmlhead'][] = '  <link rel="stylesheet" type="text/css" href="'.$ad['content_dir'].$ad['adcampaign_data']['css'].'"'.HTML_TAG_CLOSE;
	}

	$ad_media	= '';
	$ad_title	= ' title="'.html_specialchars($ad['adcampaign_data']['title_text'] ? $ad['adcampaign_data']['title_text'] : $ad['adcampaign_data']['url']).'"';
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
				$ad_imgsrc	 = @htmlentities($ad_imgsrc, ENT_QUOTES, PHPWCMS_CHARSET);
				$ad_media	.= '<a href="index.php?adclickval='.$ad['adcampaign_id'].'&amp;url='.urlencode($ad['adcampaign_data']['url']).$ad_urldata.'"';
				$ad_media	.= $ad_title;
				$ad_media	.= $ad['adcampaign_data']['target'] ? ' target="'.$ad['adcampaign_data']['target'].'"' : '';
				$ad_media	.= '>';
				$ad_media	.= '<noscript><img src="'.$ad_imgsrc.'" border="0"'.$ad_wxh.$ad_alt.HTML_TAG_CLOSE.'</noscript>';
				$ad_media	.= '<script type="text/javascript" language="javascript">'.LF.SCRIPT_CDATA_START.LF;
				$ad_media	.= '	document.write(\'<\'+\'img src="'.$ad_imgsrc.'" border="0"'.$ad_wxh.$ad_alt."'+'".HTML_TAG_CLOSE."');";			
				$ad_media	.= LF.SCRIPT_CDATA_END.LF.'</script>';
				$ad_media	.= '</a>';
				break;
		
		case 1:	//Flash
				$ad['adcampaign_data']['url']		= urlencode($ad['adcampaign_data']['url']);
				$ad_flashID  = 'adsBannerFlash'.$adID;
				$ad_so		 = 'ufoFO'.$ad['adcampaign_id'];
				$ad_media	.= '<a href="index.php?adclickval='.$ad['adcampaign_id'].'&amp;url='.$ad['adcampaign_data']['url'].$ad_urldata.'"';
				$ad_media	.= $ad_title;
				$ad_media	.= $ad['adcampaign_data']['target'] ? ' target="'.$ad['adcampaign_data']['target'].'"' : '';
				$ad_media	.= '>';
				if(is_file($ad['dir'].$ad['adcampaign_data']['image'])) {
					$ad_media	.= '<img src="'. @htmlentities($ad_imgsrc, ENT_QUOTES, PHPWCMS_CHARSET) .'" border="0"'.$ad_wxh.$ad_alt.HTML_TAG_CLOSE;
				} else {
					$ad_media	.= $ad_title;
				}
				$ad_media	.= '</a>';
				$ad_media    = '<div id="'.$ad_flashID.'">'.$ad_media.'</div>';
				if(!empty($ad['adcampaign_data']['flash']) && is_file($ad['dir'].$ad['adcampaign_data']['flash'])) {
					
					$GLOBALS['block']['custom_htmlhead']['ufo.js'] = '  <script src="'.TEMPLATE_PATH.'inc_js/ufo/ufo.js" type="text/javascript"></script>';
					$ad_urldata	 = urldecode(str_replace('&amp;', '&', $ad_urldata));
					$ad_flash	 = '';
					$ad_flash	.= '  <script type="text/javascript" language="javascript">'.LF.SCRIPT_CDATA_START.LF;
					
					$ad_flash	.= '  var '.$ad_so.' = { ';
					$ad_flash	.= 'movie:"'.$ad_swfsrc.'", id:"UFO'.$ad_flashID.'", name:"UFO'.$ad_flashID.'", ';
					$ad_flash	.= 'width:"'.$ad['adplace_width'].'", height:"'.$ad['adplace_height'].'", ';
					$ad_flash	.= 'majorversion:"'.$ad['adcampaign_data']['flashversion'].'", build:"0", ';
					$ad_flash	.= 'autoplay:"true", play:"true", scale:"exactfit", quality:"autohigh", ';
					$ad_flash	.= 'wmode:"opaque", menu:"false", allowscriptaccess:"always", swliveconnect:"true", ';
					$ad_flash	.= 'flashvars:"clickTag='.urlencode('index.php?adclickval='.$ad['adcampaign_id'].'&url='.$ad['adcampaign_data']['url'].$ad_urldata).'&clickTarget='.urlencode($ad['adcampaign_data']['target']).'", ';
					if($ad['adcampaign_data']['bgcolor']) {
						$ad_flash	.= 'bgcolor:"'.$ad['adcampaign_data']['bgcolor'].'", ';
					}
					$ad_flash	.= 'xi:"false" };'.LF;
					$ad_flash	.= '  UFO.create('.$ad_so.', "'.$ad_flashID.'");';
					
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
					$ad_media .= $ad['adcampaign_data']['target'] ? ' target="'.$ad['adcampaign_data']['target'].'"' : '';
					$ad_media .= ' style="width:'.$ad['adplace_width'].'px;height:'.$ad['adplace_height'].'px;display:block;">';
					$ad_media .= $ad['adcampaign_data']['html'];
					$ad_media .= '</a></div>';
				}
		
				break;
		
		case 3:	//Flash Layer
				$ad['adcampaign_data']['url']		= urlencode($ad['adcampaign_data']['url']);
				$ad_flashID  = 'adsBannerFL'.$adID;
				$ad_so		 = 'ufoFO'.$ad['adcampaign_id'];
				if(!empty($ad['adcampaign_data']['flash']) && is_file($ad['dir'].$ad['adcampaign_data']['flash'])) {
					
					$GLOBALS['block']['custom_htmlhead']['ufo.js'] = '  <script src="'.TEMPLATE_PATH.'inc_js/ufo/ufo.js" type="text/javascript"></script>';
					
					$ad_urldata	 = urldecode(str_replace('&amp;', '&', $ad_urldata));
					
					$ad_media    = '<div id="'.$ad_flashID.'" style="width:'.$ad['adplace_width'].'px;height:'.$ad['adplace_height'].'px;display:none;"></div>';
					
					$ad_flash	 = '  <!--[if gte IE 5]><script type="text/javascript" event="FSCommand(command,args)" for="UFO'.$ad_flashID.'">';
					$ad_flash	.= 'UFO'.$ad_flashID.'_DoFSCommand(command, args);</script><![endif]-->'.LF;
					
					$ad_flash	.= '  <script type="text/javascript" language="javascript">'.LF.SCRIPT_CDATA_START.LF;
					$ad_flash	.= '    function UFO'.$ad_flashID.'_DoFSCommand(command,args){if(command=="adlayerhider")toggleLayerDisplay("'.$ad_flashID.'","none");}'.LF;
					$ad_flash	.= '    var '.$ad_so.' = { ';
					$ad_flash	.= 'movie:"'.$ad_swfsrc.'", id:"UFO'.$ad_flashID.'", name:"UFO'.$ad_flashID.'", ';
					$ad_flash	.= 'width:"'.$ad['adplace_width'].'", height:"'.$ad['adplace_height'].'", ';
					$ad_flash	.= 'majorversion:"'.$ad['adcampaign_data']['flashversion'].'", build:"0", ';
					$ad_flash	.= 'autoplay:"true", play:"true", scale:"exactfit", quality:"autohigh", ';
					$ad_flash	.= 'wmode:"transparent", menu:"false", allowscriptaccess:"always", swliveconnect:"true", ';
					$ad_flash	.= 'flashvars:"clickTag='.urlencode('index.php?adclickval='.$ad['adcampaign_id'].'&current='.$ad_random.'&u='.PHPWCMS_USER_KEY.'&url='.$ad['adcampaign_data']['url']).'&clickTarget='.urlencode($ad['adcampaign_data']['target']).'", ';
					$ad_flash	.= 'xi:"false" };'.LF;
					$ad_flash	.= '    function show'.$ad_so.'(){toggleLayerDisplay("'.$ad_flashID.'", "block");UFO.create('.$ad_so.', "'.$ad_flashID.'");}'.LF;
					$ad_flash	.= '    window.setTimeout("show'.$ad_so.'()", 5000);';
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


?>