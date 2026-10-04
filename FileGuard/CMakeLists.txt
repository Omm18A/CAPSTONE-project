cmake_minimum_required(VERSION 3.16)
project(FileGuard VERSION 1.0.0 LANGUAGES C CXX)

# Application = CMake.  Kernel module = Kbuild (see driver/Makefile).  Do not mix them.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)   # Debug | Release
endif()

option(FILEGUARD_BUILD_GUI   "Build the Qt6 GUI (skipped automatically if Qt6 is missing)" ON)
option(FILEGUARD_BUILD_TESTS "Build the test suite" ON)

find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

# Embed database/schema.sql so the SQL file is the single source of truth.
file(READ "${CMAKE_SOURCE_DIR}/database/schema.sql" FILEGUARD_SCHEMA_SQL)
configure_file("${CMAKE_SOURCE_DIR}/src/database/SchemaSql.h.in"
               "${CMAKE_BINARY_DIR}/generated/SchemaSql.h" @ONLY)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/database/schema.sql")

set(FG_WARNINGS -Wall -Wextra -Wpedantic)

add_library(fileguard_core STATIC
  src/core/Common.cpp
  src/core/HashManager.cpp
  src/core/EncryptionManager.cpp
  src/core/ConfigurationManager.cpp
  src/core/LinuxSystemManager.cpp
  src/core/DriverManager.cpp
  src/core/AuditLogger.cpp
  src/core/SecurityManager.cpp
  src/core/UserManager.cpp
  src/core/AuthenticationManager.cpp
  src/core/PermissionManager.cpp
  src/core/FilePackage.cpp
  src/core/FileManager.cpp
  src/database/DatabaseManager.cpp)
target_include_directories(fileguard_core PUBLIC
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/driver"            # fileguard_ioctl.h shared with the kernel module
  "${CMAKE_BINARY_DIR}/generated")
target_link_libraries(fileguard_core PUBLIC OpenSSL::Crypto SQLite::SQLite3)
target_compile_options(fileguard_core PRIVATE ${FG_WARNINGS})

add_executable(fileguard src/cli/cli_main.cpp)
target_link_libraries(fileguard PRIVATE fileguard_core)
target_compile_options(fileguard PRIVATE ${FG_WARNINGS})

if(FILEGUARD_BUILD_GUI)
  find_package(Qt6 COMPONENTS Widgets QUIET)
  if(Qt6_FOUND)
    set(CMAKE_AUTOMOC ON)
    add_executable(fileguard-gui
      src/main.cpp
      src/ui/LoginWindow.cpp src/ui/DashboardWindow.cpp src/ui/FileWindow.cpp
      src/ui/ShareWindow.cpp src/ui/LogsWindow.cpp src/ui/UserWindow.cpp)
    target_link_libraries(fileguard-gui PRIVATE fileguard_core Qt6::Widgets)
    target_compile_options(fileguard-gui PRIVATE ${FG_WARNINGS})
    install(TARGETS fileguard-gui RUNTIME DESTINATION bin)
  else()
    message(WARNING "Qt6 Widgets not found - building CLI only. Install: sudo apt install qt6-base-dev")
  endif()
endif()

if(FILEGUARD_BUILD_TESTS)
  enable_testing()
  foreach(t hash encryption authentication permissions database security endtoend driver)
    add_executable(test_${t} tests/test_${t}.cpp)
    target_link_libraries(test_${t} PRIVATE fileguard_core)
    target_include_directories(test_${t} PRIVATE "${CMAKE_SOURCE_DIR}/tests")
    target_compile_options(test_${t} PRIVATE ${FG_WARNINGS})
    add_test(NAME ${t} COMMAND test_${t})
  endforeach()
  # test_driver exits 77 (= SKIPPED) when /dev/fileguard is not present
  set_tests_properties(driver PROPERTIES SKIP_RETURN_CODE 77)
endif()

install(TARGETS fileguard RUNTIME DESTINATION bin)
