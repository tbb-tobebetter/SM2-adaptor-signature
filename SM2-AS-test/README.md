## Project

This project implements signature schemes based on elliptic-curve hardness assumptions. 

## Specifications

- OS: Linux x64, MAC OS x64

- Language: C++

- Requires: OpenSSL

- The default elliptic curve is "NID_X9_62_prime256v1"

## Install Dependent OpenSSL

The current implementation is based on OpenSSL library. See the installment instructions of OpenSSL as below:  

1. Download [openssl-master.zip](https://github.com/openssl/openssl.git)

2. make a directory "openssl" to save the source codes of MIRACL

```
    mkdir openssl
    mv openssl-master.zip /openssl
```

3. unzip it

4. install openssl on your machine

```
    ./config --prefix=/usr/local/ssl shared
    make 
    sudo make install
```

## How to Use

1. git clone 

2. mkdir build && cd build

3. cmake ..

4. make 

5. run the resulting "test_SM2_AS" in /build