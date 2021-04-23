#include <iostream>
#include <phpcpp.h>
#include <algorithm>
#include <stdlib.h>
#include <string>
#include <glob.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <unistd.h>

/**
 *  tell the compiler that the get_module is a pure C function
 */

using namespace std;
string variable_name;
int counter = 0;

void ReplaceStringInPlace(std::string &subject, const std::string &search,
                          const std::string &replace)
{
    size_t pos = 0;
    while ((pos = subject.find(search, pos)) != std::string::npos)
    {
        subject.replace(pos, search.length(), replace);
        pos += replace.length();
    }
}

string random_string(const int len)
{

    string tmp_s;
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    srand((unsigned)time(NULL) * getpid());

    tmp_s.reserve(len);

    for (int i = 0; i < len; ++i)
        tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];

    return tmp_s;
}

bool in_array(const string &needle, const vector<string> &haystack)
{
    int max = haystack.size();

    if (max == 0)
        return false;

    for (int i = 0; i < max; i++)
        if (haystack[i] == needle)
            return true;
    return false;
}

size_t strpos(const string &haystack, const string &needle)
{
    int sleng = haystack.length();
    int nleng = needle.length();

    if (sleng == 0 || nleng == 0)
        return string::npos;

    for (int i = 0, j = 0; i < sleng; j = 0, i++)
    {
        while (i + j < sleng && j < nleng && haystack[i + j] == needle[j])
            j++;
        if (j == nleng)
            return i;
    }
    return string::npos;
}

std::string &rtrim(std::string &str, const std::string &chars = "\0\x0B\t\n\v\f\r ")
{
    str.erase(str.find_last_not_of(chars) + 1);
    return str;
}

std::vector<std::string> glob(const std::string &pattern)
{
    glob_t glob_result = {0}; // zero initialize

    // do the glob operation
    int return_value = ::glob(pattern.c_str(), GLOB_TILDE, NULL, &glob_result);

    if (return_value != 0)
        throw std::runtime_error(std::strerror(errno));

    // collect all the filenames into a std::vector<std::string>
    // using the vector constructor that takes two iterators
    std::vector<std::string> filenames(
        glob_result.gl_pathv, glob_result.gl_pathv + glob_result.gl_pathc);

    // cleanup
    globfree(&glob_result);

    // done
    return filenames;
}

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

    //obfuscation
    static string obfuskasi(string codeAwal)
    {
        vector<string> variable_names_before;
        vector<string> variable_names_after;
        vector<string> function_names_before;
        vector<string> function_names_after;
        vector<string> forbidden_variables =
            {"$GLOBALS", "$_SERVER", "$_GET", "$_POST", "$_FILES",
             "$_COOKIE", "$_SESSION", "$_REQUEST", "$_ENV"

            };

        vector<string> forbidden_functions = {"unlink"};

        string file_contents = codeAwal;
        bool lock = false;
        string lock_quote = "";
        string dblquote = "";
        for (int i = 0; (size_t)i < file_contents.size(); i++)
        {
            // check if there are quotation marks
            string comparestring(1, file_contents.at(i));
            if ((comparestring.compare("'") || file_contents.at(i) == '\"'))
            {
                // if first quote
                if (lock_quote == "")
                {
                    // remember quotation mark
                    lock_quote = file_contents.at(i);
                    lock = true;
                }
                else if (comparestring.compare(lock_quote))
                {
                    lock_quote = "";
                    lock = false;
                }
            }

            // detect variables
            if (!lock && file_contents.at(i) == '$')
            {
                int start = i;
                // detect variable variable names

                if (file_contents.at(i + 1) == '$')
                {
                    start++;
                    i++;
                }

                int end = 1;
                // find end of variable name
                while (isalpha(file_contents.at(start + end)) || isdigit(file_contents.at(start + end)) || file_contents.at(start + end) == '_')
                {
                    end++;
                }
                // extract variable name
                variable_name = file_contents.substr(start, end);

                if (variable_name == "$")
                {
                    continue;
                }

                // check if variable name is allowed
                if (in_array(variable_name, forbidden_variables))
                {
                    cout << "Found forbidden variables" << endl;
                }
                else
                {

                    // check if variable name already has been detected
                    if (!in_array(variable_name, variable_names_before))
                    {
                        variable_names_before.push_back(variable_name);

                        string new_variable_name = "";
                        do
                        {
                            int panjang = Php::call("rand", 5, 20);
                            new_variable_name = random_string(panjang);
                        } while (in_array(new_variable_name, variable_names_after));
                        variable_names_after.push_back(new_variable_name);
                    }
                }
            }
            // detect function-definitions
            // the third condition checks if the symbol before 'function' is neither a character nor a number
            if (!lock && file_contents.substr(i, 8) == "function" && (!isalpha(file_contents[i - 1]) && !isdigit(file_contents[i - 1])))
            {
                // find end of function name
                int end = file_contents.find('(', i);
                // extract function name and remove possible spaces on the right side
                string function_name_helper = file_contents.substr((i + 9), (end - i - 9));
                string function_name = rtrim(function_name_helper);

                // check if function name is allowed
                if (in_array(function_name, forbidden_functions))
                {
                    cout << "found forbidden function" << endl;
                }
                else
                {
                    if (!in_array(function_name, function_names_before))
                    {
                        function_names_before.push_back(function_name);

                        // generate random name for variable
                        string new_function_name = "";
                        do
                        {
                            int panjang = Php::call("rand", 5, 20);
                            new_function_name = random_string(panjang);

                        } while (in_array(new_function_name, function_names_after));
                        function_names_after.push_back(new_function_name);
                    }
                }
            }
        }

        // this array contains prefixes and suffixes for string literals which
        // may contain variable names.
        // if string literals as a return of functions should not be changed
        // remove the last two inner arrays of $possible_pre_suffixes
        // this will enable correct handling of situations like
        // - $func = 'getNewName'; echo $func();
        // but it will break variable variable names like
        // - ${getNewName()}

        // Two-dimensional key
        map<int, map<string, string>> possible_pre_suffixes;
        possible_pre_suffixes[0] = {{"prefix", "= '"}, {"suffix", "'"}};
        possible_pre_suffixes[1] = {{"prefix", "=\""}, {"suffix", "\""}};
        possible_pre_suffixes[2] = {{"prefix", "='"}, {"suffix", "'"}};
        possible_pre_suffixes[3] = {{"prefix", "=\""}, {"suffix", "\""}};
        possible_pre_suffixes[4] = {{"prefix", "rn \""}, {"suffix", "\""}};
        possible_pre_suffixes[5] = {{"prefix", "rn '"}, {"suffix", "'"}};

        // replace variable name

        for (int i = 0; (size_t)i < variable_names_before.size(); i++)
        {
            string dolar = "$";
            string helper = dolar.append(variable_names_after[i]);
            ReplaceStringInPlace(file_contents, variable_names_before[i], helper);

            string name = variable_names_before[i].substr(1);

            for (int j = 0; (size_t)j < possible_pre_suffixes.size(); j++)
            {
                string helpera = possible_pre_suffixes[j]["prefix"].append(name).append(possible_pre_suffixes[j]["suffix"]);
                string helperb = possible_pre_suffixes[j]["prefix"].append(variable_names_after[i]).append(possible_pre_suffixes[j]["suffix"]);
                ReplaceStringInPlace(file_contents, helpera, helperb);
            }
        }

        // replace funciton names
        for (int i = 0; (size_t)i < function_names_before.size(); i++)
        {
            ReplaceStringInPlace(file_contents, function_names_before[i], function_names_after[i]);
        }
        return file_contents;
    }

    static void obfuscation(Php::Parameters &params)
    {
        std::string type = params[0];
        std::string file = params[1];

        string codeAwal = Php::call("file_get_contents", file, true);

        string hasil = obfuskasi(codeAwal);
        std::string enc_code = "<?php PHPCrypton::decode('" + type + "', '" + openssl_enc(type, hasil) + "'); ?>";
        Php::out << Php::call("file_put_contents", file + ".original", codeAwal) << std::endl;
        Php::out << Php::call("file_put_contents", file, enc_code) << std::endl;
        Php::out << Php::call("file_put_contents", file + ".obfuskasi", hasil) << std::endl;
    }

    static void dirobfuscation(Php::Parameters &params)
    {
        std::string type = params[0];
        std::string path = params[1];

        vector<string> forbidden_functions = {"unlink"};
        // std::string path = "/home/ubuntu/PHPCrypton/examples/coba";

        std::vector<std::string> res = glob(path + "/*.php"); // files with an "a" in the filename
        string input;
        string namafile;
        for(string data: res) 
        {
            string namafile = Php::call("basename", data);
            string hasil = Php::call("file_get_contents", data);
            input = hasil + "\n\n";
            string coba = obfuskasi(input);
            Php::out << Php::call("file_put_contents", data + ".obfuskasi", coba) << std::endl;
            std::string enc_code = "<?php PHPCrypton::decode('" + type + "', '" + openssl_enc(type, hasil) + "'); ?>";
            Php::out << Php::call("file_put_contents", data + ".original", hasil) << std::endl;
            Php::out << Php::call("file_put_contents", data, enc_code) << std::endl;
        }
            
    }

    static void obfus(Php::Parameters &params)
    {
        std::string type = params[0];
        std::string path = params[1];

        // std::string path = "/home/ubuntu/PHPCrypton/examples/coba";

        std::vector<std::string> res = glob(path + "/*.php"); // files with an "a" in the filename
        string input, coba;
        string name[res.size()];
        int cnt =0;
        for(string data: res) 
        {
            string nama = Php::call("basename", data);
            name[cnt] = nama;
            string hasil = Php::call("file_get_contents", data);
            cnt++;
            if(cnt<res.size()){
                input += hasil+ "\n" + "end" + "\n";
            }else if(cnt == res.size()){
                input += hasil;
            }
            coba = obfuskasi(input);
        }

        cnt =0;
        int counter =0;
         for(int i= 0; i < res.size(); i++)
        {
            std::size_t pos = coba.find("end");      // position of "end" in coba
            std::string str3 = coba.substr (counter, pos);  
            Php::out << Php::call("file_put_contents", path + "/" + name[cnt] + ".obfuskasi", str3) << std::endl;
            string hasil = Php::call("file_get_contents", path + "/" + name[cnt]);
            Php::out << Php::call("file_put_contents", path +"/" + name[cnt]+ ".original", hasil) << std::endl;
            std::string enc_code = "<?php PHPCrypton::decode('" + type + "', '" + openssl_enc(type, str3) + "'); ?>";
            Php::out << Php::call("file_put_contents", path +"/" + name[cnt], enc_code) << std::endl;
            counter = pos+3;
            cnt++;
        }
       
    }

    static void decrypt(Php::Parameters &params)
    {
        // @todo add implementation
        std::string type = params[0];
        std::string msg = params[1];

        // :TODO kondisi jika tidak ada close tag
        std::string plain_code = openssl_dec(type, msg);
        std::string clean_code = Php::call("rtrim", plain_code);

        // get close tag
        std::string end_code = Php::call("substr", clean_code, -2);
        std::string sanitize_code = Php::call("substr", clean_code, 0, -2);

        // standard code is omitting close php tag
        std::string standard_code;
        if (end_code == "?>")
        {
            // remove closing tag
            standard_code = sanitize_code;
        }
        else
        {
            standard_code = clean_code;
        }

        std::string code = " ?>" + standard_code;
        Php::out << Php::eval(code) << std::endl;
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

    static std::string openssl_enc(std::string method, std::string data)
    {

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

        std::string first_encrypted = Php::call("openssl_encrypt", data, method, first_key, openssl_raw_data, iv);
        std::string second_encrypted = Php::call("hash_hmac", "sha3-512", first_encrypted, second_key, true);

        std::string output = Php::call("base64_encode", iv + second_encrypted + first_encrypted);
        return output;
        // Php::out << output << std::endl;
    }

    static std::string openssl_dec(std::string method, std::string cipher)
    {
        // static void aes_dec(Php::Parameters &params){

        std::string firstkey = "Lk5Uz3slx3BrAghS1aaW5AYgWZRV0tIX5eI0yPchFz4=";
        std::string secondkey = "EZ44mFi3TlAey1b2w4Y7lVDuqO+SRxGXsa7nctnr/JmMrA2vN6EJhrvdVZbxaQs5jpSe34X3ejFK/o9+Y5c83w==";

        std::string first_key = Php::call("base64_decode", firstkey);
        std::string second_key = Php::call("base64_decode", secondkey);

        std::string mix = Php::call("base64_decode", cipher);
        // std::string method = "aes-256-cbc";
        int iv_length = Php::call("openssl_cipher_iv_length", method);
        std::string iv = Php::call("substr", mix, 0, iv_length);

        std::string second_encrypted = Php::call("substr", mix, iv_length, 64);
        std::string first_encrypted = Php::call("substr", mix, iv_length + 64);

        Php::Value openssl_raw_data = Php::constant("OPENSSL_RAW_DATA");

        std::string data = Php::call("openssl_decrypt", first_encrypted, method, first_key, openssl_raw_data, iv);

        std::string second_encrypted_new = Php::call("hash_hmac", "sha3-512", first_encrypted, second_key, true);

        if (Php::call("hash_equals", second_encrypted, second_encrypted_new))
        {
            return data;
        }
        else
        {
            return "0";
        }
    }
};

extern "C"
{

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
        myCrypt.method<&Cryptix::obfuscation>("obfuscation");
        myCrypt.method<&Cryptix::dirobfuscation>("dirobfuscation");
        myCrypt.method<&Cryptix::obfus>("obfus");
        extension.add(std::move(myCrypt));

        //extension.add<random_str>("random_str");
        //extension.add<>("obfuscation");
        // return the extension
        return extension;
    }
}