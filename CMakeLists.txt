cmake_minimum_required(VERSION 3.16)

set(NAMESPACE imitovstavka)
project(${NAMESPACE}
        VERSION 0.0.0
        LANGUAGES CXX
)


set(CMAKE_CXX_STANDARD 20)

#target_link_libraries(${PROJECT_NAME} PRIVATE
#    mtosdadp::utils
#    benchmark::benchmark_main
#)

#ntc_target(${PROJECT_NAME})

include_directories(.)

add_executable(imitovstavka
        ghost2814789.cpp
        ghost2814789.h
        main.cpp)

add_executable(imitovstavka_simd
        ghost2814789_simd.cpp
        ghost2814789_simd.hpp
        main_simd.cpp)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address,leak,undefined")

add_executable(tests_simd
        test_ghost_simd.hpp
        test_ghost_simd.cpp
        ghost2814789_simd.hpp
        ghost2814789_simd.cpp
        tests_simd.cpp)

add_executable(tests
        ghost2814789.cpp
        ghostopen.h
        tests.cpp)
set(CMAKE_CXX_COMPILE_FEATURES "-DUSE_AVX_INSTRUCTIONS=ON")
