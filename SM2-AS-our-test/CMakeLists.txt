# Specify the minimum version for CMake
cmake_minimum_required(VERSION 3.2)

# Project's name 
project(SM2_AS_our_signature)

# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pthread -O3")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -O3")

find_package(OPENSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})
  
add_executable(test_SM2_AS_our ./test/test_SM2_AS_our.cpp)

target_link_libraries(test_SM2_AS_our ${OPENSSL_LIBRARIES})