#include <iostream>
#include <phpcpp.h>
/**
 *  tell the compiler that the get_module is a pure C function
 */
 
using namespace std;


class Cryptix : public Php::Base
{
private:
    /**
     *  Example property
     *  @var    int
     */
    int _value = 0;

public:
    /**
     *  C++ constructor and destructor
     */
    Cryptix() = default;
    virtual ~Cryptix() = default;

    /** 
     *  Static method
     *
     *  A static method also has no 'this' pointer and has
     *  therefore a signature identical to regular functions
     *
     *  @param  params      Parameters passed to the method
     */
     
     
    // sekarang untuk script yang di decrypt harus diawali dan diakhiri dengan tag php
        
    static void decrypt(Php::Parameters &params)
    {
        // @todo add implementation
        std::string type = params[0];
        std::string msg = params[1];
        // if(type=="caesar"){
        //     Php::out << Php::eval(caesar_dec(msg)) << std::endl;
        // } else if (type=="aes-256-cbc"){
            // Php::out << Php::eval(openssl_dec(type, msg)) << std::endl;
            // Php::out << openssl_dec(type, msg) << std::endl;
            

            // add for decrypt from file
            // std::string code = " ?>" +  openssl_dec(type, msg) ;

            // :TODO kondisi jika tidak ada close tag
            std::string plain_code = openssl_dec(type, msg);
            std::string clean_code = Php::call("rtrim", plain_code );

            // get close tag
            std::string end_code = Php::call("substr", clean_code, -2);
            std::string sanitize_code = Php::call("substr", clean_code, 0, -2);

            // standard code is omitting close php tag
            std::string standard_code;
            if(end_code == "?>"){
                // remove closing tag
                standard_code = sanitize_code;
            } else {
                standard_code = clean_code;               
            }

            std::string code = " ?>" + standard_code;
            Php::out << Php::eval(code) << std::endl; 
            // std::string code = " ?>" + standard_code;
            // std::string code = " ?>" + plain_code + "<?php ";
            // Php::out << code << std::endl;
            // Php::out << Php::eval(standard_code) << std::endl;
        // }
    }
    
    static void encrypt(Php::Parameters &params)
    {
        // @todo add implementation
        std::string type = params[0];
        std::string msg = params[1];
        // if(type=="aes-256-cbc"){
            Php::out << openssl_enc(type, msg) << std::endl;
        // }
    }

    // how to call from cli
    // php -r 'PHPCrypton::encodeFile("bf-cbc", "form.php");'

    static void encrypt_file(Php::Parameters &params)
    {
        // @todo add implementation
        std::string type = params[0];
        std::string file = params[1];

        std::string code = Php::call("file_get_contents", file, true);
        // if(type=="aes-256-cbc"){

        //output to terminal
        //Php::out << openssl_enc(type, code) << std::endl;

        std::string enc_code = "<?php PHPCrypton::decode('"+type+"', '"+openssl_enc(type, code)+"'); ?>";
        
        Php::out << Php::call("file_put_contents", file + ".original", code) << std::endl;
        Php::out << Php::call("file_put_contents", file, enc_code) << std::endl;
        // }
    }

    static void decrypt_file(Php::Parameters &params)
    {
        // @todo add implementation
        std::string type = params[0];
        std::string file = params[1];
        
        
        std::string code = Php::call("file_get_contents", file, true);


        std::string extract_code = Php::call("str_replace","<?php PHPCrypton::decode('"+type+"', '","", code); 

        std::string enc_code = Php::call("str_replace","'); ?>","", extract_code);  
        
        

        
        // Php::out << Php::call("file_put_contents", file + ".enc", enc_code) << std::endl;
        // }

            // add for decrypt from file
            // std::string code = " ?>" + openssl_dec(type, msg) + "<?php ";
            // Php::out << openssl_dec(type, enc_code) << std::endl;
            
        Php::out << Php::call("file_put_contents", file + ".dec", openssl_dec(type, enc_code)) << std::endl;
        // }
    }


    static std::string caesar_dec(std::string message){
        int i, key = 5;
        char ch;
        // std::string message = param[0];
        for(i = 0; message[i] != '\0'; ++i){
            ch = message[i];		
                ch = ch - key;			
                message[i] = ch;
        }
        return message;
    }

    static std::string openssl_enc(std::string method, std::string data){
        
        std::string firstkey = "Lk5Uz3slx3BrAghS1aaW5AYgWZRV0tIX5eI0yPchFz4=";
        std::string secondkey = "EZ44mFi3TlAey1b2w4Y7lVDuqO+SRxGXsa7nctnr/JmMrA2vN6EJhrvdVZbxaQs5jpSe34X3ejFK/o9+Y5c83w==";
     
        // std::string data =  params[0];
        std::string first_key = Php::call("base64_decode", firstkey);
        std::string second_key = Php::call("base64_decode", secondkey);
        
        // std::string method = "aes-256-cbc";   
        std::string iv_length = Php::call("openssl_cipher_iv_length", method);
        std::string iv = Php::call("openssl_random_pseudo_bytes", iv_length);

        // more secure pseudo-random in php7+
        //std::string iv = Php::call("random_bytes", iv_length);

        

        Php::Value openssl_raw_data = Php::constant("OPENSSL_RAW_DATA");
        
        std::string first_encrypted = Php::call("openssl_encrypt", data, method, first_key, openssl_raw_data , iv);  
        std::string second_encrypted = Php::call("hash_hmac", "sha3-512", first_encrypted, second_key, true);

        std::string output = Php::call("base64_encode", iv + second_encrypted + first_encrypted);
        return output;
        // Php::out << output << std::endl;
    }

    static std::string openssl_dec(std::string method, std::string cipher){
    // static void aes_dec(Php::Parameters &params){
        
        std::string firstkey = "Lk5Uz3slx3BrAghS1aaW5AYgWZRV0tIX5eI0yPchFz4=";
        std::string secondkey = "EZ44mFi3TlAey1b2w4Y7lVDuqO+SRxGXsa7nctnr/JmMrA2vN6EJhrvdVZbxaQs5jpSe34X3ejFK/o9+Y5c83w==";
        
        std::string first_key = Php::call("base64_decode", firstkey);
        std::string second_key = Php::call("base64_decode", secondkey);

        std::string mix =  Php::call("base64_decode", cipher);
        // std::string method = "aes-256-cbc";   
        int iv_length = Php::call("openssl_cipher_iv_length", method);
        std::string iv = Php::call("substr", mix, 0, iv_length);

        
        std::string second_encrypted = Php::call("substr", mix, iv_length, 64);
        std::string first_encrypted = Php::call("substr", mix, iv_length+64);

        
        Php::Value openssl_raw_data = Php::constant("OPENSSL_RAW_DATA");
        
        std::string data = Php::call("openssl_decrypt", first_encrypted, method, first_key, openssl_raw_data, iv);  

        std::string second_encrypted_new = Php::call("hash_hmac", "sha3-512", first_encrypted, second_key, true);

        if(Php::call("hash_equals", second_encrypted, second_encrypted_new))
        {
            return data;
        } else {
            return "0";
        }

        // if(Php::call("hash_equals", second_encrypted, second_encrypted_new))
        // {
        //     Php::out << data << std::endl;
        // } else {
        //     Php::out << false << std::endl;
        // }
    }

};


// below is old function before modulated
void encryption_function()
{

    // create an object (this will also call __construct())
    // Php::Object time("DateTime", "now");

    // call a method on the datetime object
    // Php::out << time.call("format", "Y-m-d H:i:s") << std::endl;

    // second parameter is a callback function
    // Php::Value callback = params[1];

    // call the callback function
    // callback("some","parameter");

    // in PHP it is possible to create an array with two parameters, the first
    // parameter being an object, and the second parameter should be the name
    // of the method, we can do that in PHP-CPP too
    // Php::Array time_format({time, "format"});

    // call the method that is stored in the array
    // Php::out << time_format("Y-m-d H:i:s") << std::endl;

    std::string firstkey = "Lk5Uz3slx3BrAghS1aaW5AYgWZRV0tIX5eI0yPchFz4=";
    std::string secondkey = "EZ44mFi3TlAey1b2w4Y7lVDuqO+SRxGXsa7nctnr/JmMrA2vN6EJhrvdVZbxaQs5jpSe34X3ejFK/o9+Y5c83w==";

    std::string data = "this is a message";
    std::string first_key = Php::call("base64_decode", firstkey);
    std::string second_key = Php::call("base64_decode", secondkey);
    
    std::string method = "aes-256-cbc";   
    std::string iv_length = Php::call("openssl_cipher_iv_length", method);
    std::string iv = Php::call("openssl_random_pseudo_bytes", iv_length);

    Php::Value openssl_raw_data = Php::constant("OPENSSL_RAW_DATA");
    
    std::string first_encrypted = Php::call("openssl_encrypt", data, method, first_key, openssl_raw_data , iv);  
    std::string second_encrypted = Php::call("hash_hmac", "sha3-512", first_encrypted, second_key, true);

    std::string output = Php::call("base64_encode", iv + second_encrypted + first_encrypted);
    // Php::Value data = Php::call("base64_encode", "some_parameter");
    // Php::Value data = Php::call("openssl_encrypt", "This string was AES-128 / ECB encrypted.","AES-128-ECB","some password");
    Php::out << output << std::endl;
}

void decryption_function(Php::Parameters &params)
{
    std::string firstkey = "Lk5Uz3slx3BrAghS1aaW5AYgWZRV0tIX5eI0yPchFz4=";
    std::string secondkey = "EZ44mFi3TlAey1b2w4Y7lVDuqO+SRxGXsa7nctnr/JmMrA2vN6EJhrvdVZbxaQs5jpSe34X3ejFK/o9+Y5c83w==";
    
    std::string first_key = Php::call("base64_decode", firstkey);
    std::string second_key = Php::call("base64_decode", secondkey);

    std::string mix =  Php::call("base64_decode", params[0]);
    std::string method = "aes-256-cbc";   
    int iv_length = Php::call("openssl_cipher_iv_length", method);
    std::string iv = Php::call("substr", mix, 0, iv_length);

    
    std::string second_encrypted = Php::call("substr", mix, iv_length, 64);
    std::string first_encrypted = Php::call("substr", mix, iv_length+64);

    
    Php::Value openssl_raw_data = Php::constant("OPENSSL_RAW_DATA");
    
    std::string data = Php::call("openssl_decrypt", first_encrypted, method, first_key, openssl_raw_data, iv);  

    std::string second_encrypted_new = Php::call("hash_hmac", "sha3-512", first_encrypted, second_key, true);

    if(Php::call("hash_equals", second_encrypted, second_encrypted_new))
    {
        Php::out << data << std::endl;
    } else {
        Php::out << false << std::endl;
    }

}

extern "C" {
    
    /**
     *  Function that is called by PHP right after the PHP process
     *  has started, and that returns an address of an internal PHP
     *  strucure with all the details and features of your extension
     *
     *  @return void*   a pointer to an address that is understood by PHP
     */
    PHPCPP_EXPORT void *get_module() 
    {
        // static(!) Php::Extension object that should stay in memory
        // for the entire duration of the process (that's why it's static)
        static Php::Extension extension("phpcrypton", "1.0");
        
        // Static Class
        Php::Class<Cryptix> myCrypt("PHPCrypton");
        myCrypt.method<&Cryptix::decrypt>("decode");
        myCrypt.method<&Cryptix::encrypt>("encode");
        myCrypt.method<&Cryptix::encrypt_file>("encodeFile");
        myCrypt.method<&Cryptix::decrypt_file>("decodeFile");
        // myCrypt.method<&Cryptix::aes_dec>("dec");
        extension.add(std::move(myCrypt));

        // extension.add<myFunction>("myFunction");
        // extension.add<sum_everything>("sum_everything");
        // extension.add<out_everything>("out_everything");
        // extension.add<my_function_void>("my_function_void");
        // extension.add<s_function>("s_function");
        // extension.add<try_function>("try_function");
        // extension.add<caesar>("caesar");
        // extension.add<caesard>("caesard");
        extension.add<encryption_function>("encryption_function");
        extension.add<decryption_function>("decryption_function");
        // return the extension
        return extension;
    }
}
