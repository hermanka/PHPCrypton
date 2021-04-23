<!DOCTYPE html>
<!-- index.php -->
<html lang="en">
   <body>
       <?php
	    echo "Before file included.<br>";
          include 'vars.php'; // including file
          echo $my_string;
       ?>
   </body>
</html>