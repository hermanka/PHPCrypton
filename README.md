# PHPCrypton

## How to Compile

### Requirement before compile : Install PHP-CPP

        sudo apt-get install git gcc make re2c php7.0 php7.0-json php7.0-dev libpcre3-dev 
        git clone https://github.com/CopernicaMarketingSoftware/PHP-CPP.git
        cd PHP-CPP/
        make
        sudo make install

### Compile the source

        make
        sudo make install

## How to Recompile

        make clean
        make
        sudo make install

## Important!

Don't forget to change firstkey and secondkey in main.cpp file.
Change INI_DIR in Makefile according to your machine
make sure you have enable php mod using
        
        phpenmod phpcrypton


