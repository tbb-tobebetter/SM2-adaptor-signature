# Specify the minimum version for CMake
cmake_minimum_required(VERSION 3.2)

# Project's name 
project(ECDSA_AS_signature)

# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pthread -O3")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -O3")

find_package(OPENSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})
  
add_executable(test_ECDSA_AS ./test/test_ECDSA_AS.cpp)

target_link_libraries(test_ECDSA_AS ${OPENSSL_LIBRARIES})