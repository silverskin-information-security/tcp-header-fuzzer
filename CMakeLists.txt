cmake_minimum_required(VERSION 3.5)
project(tcp-header-fuzzer LANGUAGES C VERSION 0.5)

add_executable(tcp-header-fuzzer
    packet.c
    fuzzer.c
)

target_compile_options(tcp-header-fuzzer PRIVATE
    -Wall -Wextra -Wpedantic -O2 
)

set_target_properties(tcp-header-fuzzer PROPERTIES OUTPUT_NAME tcp-header-fuzzer)

