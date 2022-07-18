cmake_minimum_required(VERSION 3.22)
set(TEST_NAME UnitTests)

file(GLOB TESTS CONFIGURE_DEPENDS
        ${PROJECT_SOURCE_DIR}/unit_tests/*.h
        ${PROJECT_SOURCE_DIR}/unit_tests/*.cpp)
#file(GLOB INCLUDE CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/include/*.h)
#file(GLOB SRC CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/src/*.cpp)
#file(GLOB ODB CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/include/odb/*.h)

# EXCLUDE PROJECTS main.cpp file because unit ping has its own
#list(FILTER SRC EXCLUDE REGEX ".*main\\.cpp$")

add_executable(${TEST_NAME}
        ${TESTS}
#        ${INCLUDE}
#        ${SRC}
#        ${ODB}
        ../include/WalletMgrAPI.h
        ../src/WalletMgrAPI.cpp
        )

include_directories(${RPCLIB_INCLUDE_DIR})
find_package(rpclib REQUIRED)

target_link_libraries(${TEST_NAME} ${ODB_LIBRARIES}
        mps_utils
        #        nlohmann_json::nlohmann_json
        ${RPCLIB_LIBS}
        log_helper) # TODO: add libraries here

if (CMAKE_BUILD_TYPE MATCHES "Debug")
    add_definitions(-DBUILD_DEBUG)
endif ()