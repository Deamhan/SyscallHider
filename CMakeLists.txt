cmake_minimum_required(VERSION 3.15)

project(IPC)
set(CMAKE_CXX_STANDARD 17)

include_directories(${PROJECT_SOURCE_DIR}/include)

add_executable(simple-message-client ${IPC_COMMON_SOURCES}
                                     source/main.cpp)

                        