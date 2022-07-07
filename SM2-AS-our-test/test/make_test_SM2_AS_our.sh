#!/bin/bash
dir="~/Documents/Project/openssl-master"

g++ -std=c++11 -pthread -O3 test_SM2_AS_our.cpp -L ${dir} -l ssl -l crypto -o test_SM2_AS_offline -I ${dir}