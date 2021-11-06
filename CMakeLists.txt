cmake_minimum_required(VERSION 3.15)

project(IPC)
set(CMAKE_CXX_STANDARD 17)

include_directories(${PROJECT_SOURCE_DIR}/include)

set(NTDLL64LL ${PROJECT_SOURCE_DIR}/lib/ntdll64ll.obj)

add_executable(poc ${IPC_COMMON_SOURCES}
                   source/main.cpp)
                                     
if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_definitions(-D_X64_=1)
else()
    target_link_libraries(poc ${NTDLL64LL})
endif()
                        