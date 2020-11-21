<?php
    $code = '$x = 1;
 
    while($x <= 5) {
      echo "The number is: $x <br>";
      $x++;
     }';
  PHPCrypton::encode("bf-cbc", $code);

  // $fk = "VGhpcyBpcyBhbiBlbmNvZGVkIHN0cmluZw==";
  // echo base64_encode($fk);
?>