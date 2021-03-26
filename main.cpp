#include <iostream>
#include <phpcpp.h>
#include <string.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <iostream>
#include <ctime>
#include <unistd.h>

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
    static void obfuscation(Php::Parameters &params)
    {
        std::string type = params[0];
        std::string file = params[1];

        Php::Value variable_names_before;
        Php::Value variable_names_after;
        Php::Value function_names_before;
        Php::Value function_names_after;
        Php::Value forbidden_variables;
        forbidden_variables[0] = '$_SERVER';
        forbidden_variables[1] = '$_GET';
        forbidden_variables[2] = '$_POST';
        forbidden_variables[3] = '$_FILES';
        forbidden_variables[4] = '$_COOKIE';
        forbidden_variables[5] = '$_SESSION';
        forbidden_variables[6] = '$_REQUEST';
        forbidden_variables[7] = '$_ENV';

        Php::Value forbidden_functions;
        forbidden_functions[0] = 'unlink';

        // read file
        Php::Value data = Php::call("file_get_contents", file, true);
        bool lock = false;

        Php::Value lock_quote = "";
        for (int i = 0; i< strlen(data); i++)
        {
            // check if there are quotation marks
            if((data[i] == "'" || data[i] == '"'))
            {
                // if first quote
                if(lock_quote == "")
                {
                    // remember quotation mark
                    lock_quote = data[i];
                    lock = true;
                } 
                else if (data[i] == lock_quote)
                {
                    lock_quote = "";
                    lock = false;
                }
            }

            // detect variables
            if(!lock && data[i] == '$')
            {
                int start = i;
                // detect variable variable names
                if(data[i+1] == '$')
                {
                    start++;
                    // increment $i to avoid second detection of variable variable as "normal variable"
                    i++;
                }

                int end = 1;
                // find end of variable name
                while (isalpha(data[start+end]) || isdigit(data[start+end]))
                {
                    end++;
                }

                // extract variable name
                Php::Value variable_name;
                variable_name = Php::call("substr", data, start, end);
                if(variable_name == '$')
                {
                    continue;
                }
                // check if variable name is allowed
                if(Php::call("in_array", variable_name, forbidden_variables))
                {
                    printf("There is forbbiden variables");
                }
                else
                {
                    if(!Php::call("in_array", variable_name, variable_names_before))
                    {
                        variable_names_before = variable_name;
                        // generate random name for variable
                        Php::Value new_variable_name = "";
                        do
                        {
                            new_variable_name = gen_random(8);

                        }
                        while (Php::call("in_array", new_variable_name, variable_names_after));
                        variable_names_after = new_variable_name;
                    }
                }

            }

            // detect function-definitions
            // the third condition checks if the symbol before 'function' is neither a character nor a number
            

        }

    }

    static string gen_random(const int len) {
    
    string tmp_s;
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    
    srand( (unsigned) time(NULL) * getpid());

    tmp_s.reserve(len);

    for (int i = 0; i < len; ++i) 
        tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];
    
    
    return tmp_s;
    
    }


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

    }

    static std::string GenerateRandomString() {
    const int SIZE_OF_STRING_TO_GENERATE = 8;
    int randNum = 0;
    string stringToReturn = "";
    
    vector<char> CharArray {
        'A','B','C','D','E','F',
        'G','H','I','J','K', 'L','M','N',
        'O','P', 'Q','R','S','T','U', 'V',
        'W','X','Y','Z', 'a','b','c','d',
        'e','f', 'g','h','i','j','k', 'l',
        'm','n','o','p', 'q','r','s','t',
        'u', 'v','w','x','y','z'
    };
    
    //Loop SIZE_OF_STRING_TO_GENERATE times
    for(int i = 0; i < SIZE_OF_STRING_TO_GENERATE; i++) {
        //Generate random number
        randNum = rand() % CharArray.size();
        
        //Add to return string
        stringToReturn += CharArray.at(randNum);
    }
    
    //Return random string
    return stringToReturn;
    }

};


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

        // return the extension
        return extension;
    }
}
