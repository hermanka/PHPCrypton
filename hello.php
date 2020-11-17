<?php
    // for ($i=0; $i<10; $i++) echo(myFunction()."\n");

    // echo "\nsum_everything\n";
    // echo(sum_everything(10,"100",20)."\n");
    // echo "\nout_everything\n";
    // out_everything("echo 'hello'");

    
    // my_function_void();
    // $code = '$x = 1;
 
    // while($x <= 5) {
    //   echo "The number is: $x <br>";
    //   $x++;
    // }';
    // $ciphercode = caesar($code);
    // echo "code : ";
    // echo caesard($ciphercode);
    // echo "ciphercode : " ;
    // echo caesar($code);
    // echo "execute : \n";
    // s_function($ciphercode);

    // PHPCrypton::exec("caesar", $ciphercode);

    // example_function();
    // echo "\n";
    // try_function("ABCD");

    // openssl_encryption
    define('FIRSTKEY','Lk5Uz3slx3BrAghS1aaW5AYgWZRV0tIX5eI0yPchFz4=');
    define('SECONDKEY','EZ44mFi3TlAey1b2w4Y7lVDuqO+SRxGXsa7nctnr/JmMrA2vN6EJhrvdVZbxaQs5jpSe34X3ejFK/o9+Y5c83w==');
    
    $data = "this is a message";
    $first_key = base64_decode(FIRSTKEY);
    $second_key = base64_decode(SECONDKEY);  

    $method = "aes-256-cbc";   
    $iv_length = openssl_cipher_iv_length($method);
    $iv = openssl_random_pseudo_bytes($iv_length);
    $first_encrypted = openssl_encrypt($data,$method,$first_key, OPENSSL_RAW_DATA ,$iv);   
    // $second_encrypted = hash_hmac('sha3-512', $first_encrypted, $second_key, TRUE);
              
    // $output = base64_encode($iv.$second_encrypted.$first_encrypted); 

    echo bin2hex($iv);
    echo "\n";
    echo bin2hex(random_bytes(16));
    echo "\n";
    //   echo "\n";


      // openssl_decryption
  //   $first_key = base64_decode(FIRSTKEY);
  // $second_key = base64_decode(SECONDKEY);           
  // $mix = base64_decode("XfQK1b7h95J2ICihgQbHngNPxN43bZd6xBn9C+I/Fz12EGOSOPJ0cim9XqfXGaNBGhXTgpcJCL0ypGGw1aoN6pSOpYV2jauPuJcNWcwpADo9rKIl0JcmvhNBCCymxT20mhkZUZf/R5iBbtAFVnty2w==");
        
  // $method = "aes-256-cbc";   
  // $iv_length = openssl_cipher_iv_length($method);
            
  // $iv = substr($mix,0,$iv_length);
  // $second_encrypted = substr($mix,$iv_length,64);
  // $first_encrypted = substr($mix,$iv_length+64);
            
  // $data = openssl_decrypt($first_encrypted,$method,$first_key,OPENSSL_RAW_DATA,$iv);
  // $second_encrypted_new = hash_hmac('sha3-512', $first_encrypted, $second_key, TRUE);
    
  // if (hash_equals($second_encrypted,$second_encrypted_new))
  // echo $data;
    
  // return $data;

  // decryption_function("kOY6RIRT5mI7SZ/Up2evixZN7EeRhaNfIDdab8mpSQcHPCD0PBjAMj0fr/NTxcr/legOLKZDI5/ShbPzmgpkZT4C6en2J2zFUq0tWl1XzON9iJdiRfJTpyH9n4T757f+");

  // PHPCrypton::encrypt("aes-256-cbc", "this is a message for my trial with aes algorithm, great!!!");
?>