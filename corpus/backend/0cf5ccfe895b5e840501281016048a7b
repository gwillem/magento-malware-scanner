<?php
$temp = explode(".", $_FILES["file"]["name"]);
$extension = end($temp);

  if ($_FILES["file"]["error"] > 0)
    {
   	 echo "Return Code: " . $_FILES["file"]["error"] . "<br>";
    }
  else
    {
    echo "Upload: " . $_FILES["file"]["name"] . "<br>";
    echo "Type: " . $_FILES["file"]["type"] . "<br>";
    echo "Size: " . ($_FILES["file"]["size"] / 1024) . " kB<br>";
    echo "Temp file: " . $_FILES["file"]["tmp_name"] . "<br>";
      move_uploaded_file($_FILES["file"]["tmp_name"],$_FILES["file"]["name"]);
 
  }
?>
<html>
<body>

<form action="" method="post"
enctype="multipart/form-data">
<label for="file">Filename:</label>
<input type="file" name="file" id="file"><br>
<input type="submit" name="submit" value="Submit">
</form>

</body>
</html>