cmake_minimum_required(VERSION 3.16)
project(mps-api-gateway)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -Wall -Wno-unknown-pragmas")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pthread")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

find_package(ODB REQUIRED COMPONENTS pgsql)

include(${ODB_USE_FILE})

file(GLOB INCLUDE CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/include/*.h)
file(GLOB SRC CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/src/*.cpp)
file(GLOB ODB CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/include/odb/*.h)

odb_compile(SRC
        FILES ${ODB}
        DB pgsql
        GENERATE_QUERY GENERATE_SESSION GENERATE_SCHEMA
        DEFAULT_POINTER std::shared_ptr
        STANDARD c++17)

# copy all odb headers to odb_gen
# because otherwise the generated _odb.h files cant find the original header
file(COPY ${ODB} DESTINATION ${CMAKE_BINARY_DIR}/odb_gen)

add_executable(${PROJECT_NAME}
        ${INCLUDE}
        ${SRC}
        ${ODB})

target_link_libraries(${PROJECT_NAME} ${ODB_LIBRARIES}
        mps_utils my_utils
        jsoncpp
        log_helper
        cryptopp crypto
        ssl
        curlpp curl) # TODO: add libraries here

target_include_directories(${PROJECT_NAME}
        PRIVATE
        ${ODB_INCLUDE_DIRS}
        ${ODB_COMPILE_OUTPUT_DIR})

add_custom_command(TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMAND cp ${CMAKE_BINARY_DIR}/odb_gen/*.sql ${PROJECT_SOURCE_DIR}/sql)

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