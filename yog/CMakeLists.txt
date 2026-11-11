cmake_minimum_required(VERSION 3.16)
project(yog C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# NFR-2: warnings are errors.  Add -DYOG_SANITIZE=ON to run with ASan + UBSan
# (NFR-3).  Sanitizers are GCC/Clang only; MSVC gets /W4 /WX instead.
option(YOG_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)

if(MSVC)
  add_compile_options(/W4 /WX)
else()
  add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror)
endif()

# MSVC's CRT marks fopen/tmpfile as deprecated; the portable ISO C functions
# are exactly what we want to use on every platform.
if(WIN32)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
endif()

if(YOG_SANITIZE)
  if(MSVC)
    message(WARNING "YOG_SANITIZE is ignored for MSVC; use GCC or Clang")
  else()
    add_compile_options(-g -fsanitize=address,undefined -fno-sanitize-recover=all)
    add_link_options(-fsanitize=address,undefined)
  endif()
endif()

# Every module is included as  #include "lexer/lexer.h"  (relative to src/).
# The public API lives in include/api/yog.h.
set(YOG_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(YOG_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

# ---- libraries, one per compiler stage (single responsibility per target) ----
add_library(yog_lexer STATIC src/lexer/lexer.c)
target_include_directories(yog_lexer PUBLIC ${YOG_SRC_DIR})

add_library(yog_parser STATIC src/parser/ast.c src/parser/parser.c)
target_link_libraries(yog_parser PUBLIC yog_lexer)

add_library(yog_sema STATIC src/sema/symbol_table.c src/sema/sema.c)
target_link_libraries(yog_sema PUBLIC yog_parser)

add_library(yog_ir STATIC src/ir/ir_build.c src/ir/ir_dump.c)
target_link_libraries(yog_ir PUBLIC yog_sema)

add_library(yog_vm STATIC src/vm/unify.c src/vm/engine.c)
target_link_libraries(yog_vm PUBLIC yog_ir)

add_library(yog_api STATIC src/api/yog.c)
target_include_directories(yog_api PUBLIC ${YOG_INCLUDE_DIR} ${YOG_SRC_DIR})
target_link_libraries(yog_api PUBLIC yog_vm)

# ---- tests ----
enable_testing()

function(yog_test name source library)
  add_executable(${name} ${source})
  target_link_libraries(${name} PRIVATE ${library})
  add_test(NAME ${name} COMMAND ${name})
endfunction()

yog_test(test_lexer  tests/lexer/test_lexer.c   yog_lexer)
yog_test(test_parser tests/parser/test_parser.c yog_parser)
yog_test(test_sema   tests/sema/test_sema.c     yog_sema)
yog_test(test_ir     tests/ir/test_ir.c         yog_ir)
yog_test(test_vm     tests/vm/test_vm.c         yog_api)
yog_test(test_api    tests/api/test_api.c       yog_api)

# ---- tools ----
add_executable(lexdump tools/lexdump.c)
target_link_libraries(lexdump PRIVATE yog_lexer)

add_executable(yogc tools/yogc.c)
target_link_libraries(yogc PRIVATE yog_api)
