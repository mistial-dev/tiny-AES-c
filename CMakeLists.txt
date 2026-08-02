cmake_minimum_required(VERSION 3.12)

project(tiny-aes C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(TINY_AES_BUILD_TESTS "Build unit tests" ON)

function(add_tiny_aes_library target key_definition)
    add_library(${target} STATIC aes.c)
    target_include_directories(${target} PUBLIC ${CMAKE_CURRENT_LIST_DIR})
    target_compile_definitions(${target} PUBLIC ${key_definition})
endfunction()

add_tiny_aes_library(tiny-aes AES128=1)

if(TINY_AES_BUILD_TESTS)
    enable_testing()

    foreach(variant IN ITEMS 128 192 256)
        if(variant STREQUAL "128")
            set(key_definition AES128=1)
        else()
            set(key_definition AES${variant}=1)
        endif()

        add_tiny_aes_library(tiny-aes-${variant} ${key_definition})
        add_executable(test_aes_${variant} test.c munit.c)
        target_link_libraries(test_aes_${variant} PRIVATE tiny-aes-${variant})
        add_test(NAME test_aes_${variant} COMMAND test_aes_${variant})
    endforeach()
endif()
