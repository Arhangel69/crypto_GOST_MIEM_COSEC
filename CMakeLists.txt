cmake_minimum_required(VERSION 3.13)
project(imitovstavka)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)

add_executable(imitovstavka
        ghost2814789.cpp
        ghost2814789.h
        main.cpp)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address,leak,undefined")

add_executable(tests
        ghost2814789.cpp
        ghostopen.h
        tests.cpp)
