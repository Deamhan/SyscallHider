cmake_minimum_required(VERSION 3.15)

project(SyscallHider)
set(CMAKE_CXX_STANDARD 17)

include_directories(${PROJECT_SOURCE_DIR}/include)

set(NTDLL64LL ${PROJECT_SOURCE_DIR}/lib/ntdll64ll.obj)

set(HIDER_COMMON source/parser.cpp)

add_executable(injector ${HIDER_COMMON}
                        source/inject.cpp
                        source/util.cpp)

add_executable(test ${HIDER_COMMON}
                    source/test.cpp
                    source/util.cpp)
                                     
if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_definitions(-D_X64_=1)
else()
    target_link_libraries(injector ${NTDLL64LL})
    target_link_libraries(test ${NTDLL64LL})
endif()
                        