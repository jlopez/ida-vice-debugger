cmake_minimum_required(VERSION 3.22)
project(vice)

set(CMAKE_CXX_STANDARD 14)

set(IDA_PRO /Applications/ida-pro-7.0/idabin)
set(IDA_SDK ${IDA_PRO}/idasdk70)
include_directories(SYSTEM ${IDA_SDK}/include)
link_directories(${IDA_SDK}/lib/x64_mac_gcc_64)
link_libraries(ida64)
add_compile_definitions(
        __PLUGIN__
        __IDP__
        __MAC__
        __EA64__
        __X64__
        DEBUG=1
        _DEBUG
        DEBUG_NETWORK
)

add_library(vice SHARED
        mac_rstub.cpp
        rpc_debmod.cpp
        rpc_hlp.cpp
        tcpip.cpp
        rpc_client.cpp
        rpc_engine.cpp
        debmod.cpp
        util.cpp
)

set_target_properties(vice PROPERTIES
        PREFIX ""
        SUFFIX "64.dylib"
)

add_custom_command(TARGET vice POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:vice> ${IDA_PRO}/plugins)