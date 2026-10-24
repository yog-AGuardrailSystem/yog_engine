cmake_minimum_required(VERSION 3.16)
project(yog C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# NFR-2: warnings are errors.  Add -DYOG_SANITIZE=ON to run with ASan + UBSan (NFR-3).
option(YOG_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)

add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Werror)
if(YOG_SANITIZE)
  add_compile_options(-g -fsanitize=address,undefined -fno-sanitize-recover=all)
  add_link_options(-fsanitize=address,undefined)
endif()

# Every module is included as  #include "lexer/lexer.h"  (relative to src/).
set(YOG_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

# ---- lexer library (the parser will link against this) ----
add_library(yog_lexer STATIC src/lexer/lexer.c)
target_include_directories(yog_lexer PUBLIC ${YOG_SRC_DIR})

# ---- tests ----
enable_testing()
add_executable(test_lexer tests/lexer/test_lexer.c)
target_link_libraries(test_lexer PRIVATE yog_lexer)
add_test(NAME lexer COMMAND test_lexer)

# ---- debugging tool: ./lexdump file.yog ----
add_executable(lexdump tools/lexdump.c)
target_link_libraries(lexdump PRIVATE yog_lexer)
