cmake_minimum_required(VERSION 3.16)
project(mps-api-gateway)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -Wall")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pthread")

add_executable(${PROJECT_NAME} main.cpp
        src/APIGateway.cpp include/APIGateway.h
        src/Accounts.cpp include/Accounts.h
        include/Account.h include/ResponseError.h)

target_link_libraries(${PROJECT_NAME}
        log_helper
        db_helper SQLiteCpp sqlite3
        jsoncpp
        cryptopp crypto ssl
        my_utils
        mps_utils curlpp curl)

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