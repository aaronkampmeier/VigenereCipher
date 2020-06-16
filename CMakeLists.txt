cmake_minimum_required(VERSION 3.16)
project(Cipher)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -Wall")

add_executable(Cipher Cipher.cpp)