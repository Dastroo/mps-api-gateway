cmake_minimum_required(VERSION 3.16)
project(mps-api-gateway)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -Wall -Wno-unknown-pragmas")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pthread")

enable_testing()
add_subdirectory(unit_tests)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

file(GLOB INCLUDE CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/include/*.h)
file(GLOB SRC CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/src/*.cpp)

add_executable(${PROJECT_NAME}
        ${INCLUDE}
        ${SRC})

find_package(nlohmann_json 3.2.0 REQUIRED)
find_package(rpclib REQUIRED)

target_link_libraries(${PROJECT_NAME}
        ${RPCLIB_LIBS}
        mps_utils my_utils
        nlohmann_json::nlohmann_json
        log_helper
        cryptopp crypto
        ssl) # TODO: add libraries here

if (CMAKE_BUILD_TYPE MATCHES "Debug")
    add_definitions(-DBUILD_DEBUG)
endif ()

if (UNIX AND NOT APPLE)
    include(GNUInstallDirs)
    install(TARGETS ${PROJECT_NAME}
            DESTINATION ${CMAKE_INSTALL_BINDIR})

    # make uninstall
    add_custom_target("uninstall" COMMENT "Uninstall installed files")
    add_custom_command(
            TARGET "uninstall"
            POST_BUILD
            COMMENT "Uninstall files with install_manifest.txt"
            COMMAND xargs rm -vf < install_manifest.txt || echo Nothing in install_manifest.txt to be uninstalled!)
endif ()

if (EXISTS /etc/redhat-release)
    add_definitions(-DREDHAT)
elseif (EXISTS /etc/debian_version)
    add_definitions(-DDEBIAN)
endif ()