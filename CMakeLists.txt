cmake_minimum_required(VERSION 3.12)

project(tiny-aes C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(TINY_AES_BUILD_TESTS "Build unit tests" ON)
option(TINY_AES_ENABLE_CBC "Enable CBC mode in the main library" ON)
option(TINY_AES_ENABLE_ECB "Enable ECB mode in the main library" ON)
option(TINY_AES_ENABLE_CTR "Enable CTR mode in the main library" ON)
option(TINY_AES_WIDE_OPS "Enable portable native-width block helpers" OFF)
set(TINY_AES_SBOX_MODE "secure" CACHE STRING "S-box mode: secure, runtime, or fast")
set_property(CACHE TINY_AES_SBOX_MODE PROPERTY STRINGS secure runtime fast)

if(TINY_AES_SBOX_MODE STREQUAL "secure")
    set(TINY_AES_SBOX_DEFINITION AES_SBOX_MODE=1)
elseif(TINY_AES_SBOX_MODE STREQUAL "runtime")
    set(TINY_AES_SBOX_DEFINITION AES_SBOX_MODE=2)
elseif(TINY_AES_SBOX_MODE STREQUAL "fast")
    set(TINY_AES_SBOX_DEFINITION AES_SBOX_MODE=3)
else()
    message(FATAL_ERROR "TINY_AES_SBOX_MODE must be secure, runtime, or fast")
endif()

if(TINY_AES_WIDE_OPS)
    set(TINY_AES_WIDE_DEFINITION AES_WIDE_OPS=1)
else()
    set(TINY_AES_WIDE_DEFINITION AES_WIDE_OPS=0)
endif()

function(tiny_aes_mode_definitions output cbc ecb ctr)
    set(${output}
        CBC=${cbc}
        ECB=${ecb}
        CTR=${ctr}
        ${TINY_AES_SBOX_DEFINITION}
        ${TINY_AES_WIDE_DEFINITION}
        PARENT_SCOPE
    )
endfunction()

if(TINY_AES_ENABLE_CBC)
    set(TINY_AES_CBC 1)
else()
    set(TINY_AES_CBC 0)
endif()
if(TINY_AES_ENABLE_ECB)
    set(TINY_AES_ECB 1)
else()
    set(TINY_AES_ECB 0)
endif()
if(TINY_AES_ENABLE_CTR)
    set(TINY_AES_CTR 1)
else()
    set(TINY_AES_CTR 0)
endif()

tiny_aes_mode_definitions(tiny_aes_library_definitions
    ${TINY_AES_CBC} ${TINY_AES_ECB} ${TINY_AES_CTR})

add_library(tiny-aes STATIC aes.c)
target_include_directories(tiny-aes PUBLIC ${CMAKE_CURRENT_LIST_DIR})
target_compile_definitions(tiny-aes PUBLIC ${tiny_aes_library_definitions})

if(TINY_AES_BUILD_TESTS)
    enable_testing()

    add_library(tiny-aes-munit OBJECT munit.c)

    function(add_tiny_aes_test key mode sbox_mode wide)
        if(mode STREQUAL "ecb")
            set(cbc 0)
            set(ecb 1)
            set(ctr 0)
        elseif(mode STREQUAL "cbc")
            set(cbc 1)
            set(ecb 0)
            set(ctr 0)
        elseif(mode STREQUAL "ctr")
            set(cbc 0)
            set(ecb 0)
            set(ctr 1)
        elseif(mode STREQUAL "ecb-cbc")
            set(cbc 1)
            set(ecb 1)
            set(ctr 0)
        elseif(mode STREQUAL "ecb-ctr")
            set(cbc 0)
            set(ecb 1)
            set(ctr 1)
        elseif(mode STREQUAL "cbc-ctr")
            set(cbc 1)
            set(ecb 0)
            set(ctr 1)
        elseif(mode STREQUAL "all")
            set(cbc 1)
            set(ecb 1)
            set(ctr 1)
        else()
            message(FATAL_ERROR "Unknown AES test mode: ${mode}")
        endif()

        if(key STREQUAL "128")
            set(key_definition AES128=1)
        else()
            set(key_definition AES${key}=1)
        endif()

        if(sbox_mode STREQUAL "secure")
            set(sbox_definition AES_SBOX_MODE=1)
        elseif(sbox_mode STREQUAL "runtime")
            set(sbox_definition AES_SBOX_MODE=2)
        else()
            set(sbox_definition AES_SBOX_MODE=3)
        endif()

        set(test_name "${key}-${mode}-${sbox_mode}-wide${wide}")
        add_library(test_core_${test_name} OBJECT aes.c test.c)
        target_include_directories(test_core_${test_name} PRIVATE ${CMAKE_CURRENT_LIST_DIR})
        target_compile_definitions(test_core_${test_name} PRIVATE
            CBC=${cbc} ECB=${ecb} CTR=${ctr}
            ${key_definition} ${sbox_definition} AES_WIDE_OPS=${wide}
        )

        add_executable(test_aes_${test_name}
            $<TARGET_OBJECTS:test_core_${test_name}>
            $<TARGET_OBJECTS:tiny-aes-munit>
        )
        add_test(NAME test_aes_${test_name} COMMAND test_aes_${test_name})
    endfunction()

    set(aes_test_modes ecb cbc ctr ecb-cbc ecb-ctr cbc-ctr all)
    set(aes_test_sbox_modes secure runtime fast)
    foreach(key IN ITEMS 128 192 256)
        foreach(mode IN LISTS aes_test_modes)
            foreach(sbox_mode IN LISTS aes_test_sbox_modes)
                add_tiny_aes_test(${key} ${mode} ${sbox_mode} 0)
                add_tiny_aes_test(${key} ${mode} ${sbox_mode} 1)
            endforeach()
        endforeach()
    endforeach()
endif()
