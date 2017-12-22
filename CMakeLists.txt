cmake_minimum_required(VERSION 3.6)

add_executable(dumplog dumplog.cpp)

set(BINARY_NAME "dumplog-${CMAKE_SYSTEM_PROCESSOR}")
string(TOLOWER ${BINARY_NAME} BINARY_NAME)

target_compile_definitions(dumplog PRIVATE -DARGS_NOEXCEPT)
target_compile_options(dumplog PRIVATE
  -Wall -Wextra -pedantic -Wshadow -Wunused-parameter
  -Wno-zero-length-array)

set_target_properties(dumplog PROPERTIES OUTPUT_NAME "${BINARY_NAME}")

set_target_properties(dumplog PROPERTIES CXX_STANDARD              17)
set_target_properties(dumplog PROPERTIES CXX_STANDARD_REQUIRED     ON)
set_target_properties(dumplog PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_link_libraries(dumplog -static-libstdc++)


if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_SOURCE_DIR} CACHE PATH "Install path prefix prepended on to install directories." FORCE)
endif()


if (NOT CMAKE_BUILD_TYPE MATCHES Debug)
  add_custom_command(
    TARGET dumplog
    POST_BUILD
    COMMAND ${CMAKE_COMMAND}
      -DTARGET_FILE=$<TARGET_FILE:dumplog>
      -DCMAKE_STRIP="${CMAKE_STRIP}"
      -P ${CMAKE_CURRENT_SOURCE_DIR}/post-build.cmake
  )
endif()

install(TARGETS dumplog
  RUNTIME
  DESTINATION "${CMAKE_INSTALL_PREFIX}/bin")

find_program(ADB_PATH NAMES "adb")
if (ADB_PATH)
  add_custom_target("install-device" ALL
    COMMAND ${ADB_PATH} push ${CMAKE_CURRENT_BINARY_DIR}/${BINARY_NAME} /data/local/tmp/dumplog
    DEPENDS dumplog)
endif()
