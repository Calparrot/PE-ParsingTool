cmake_minimum_required(VERSION 3.15)
project("PE_ParsingTool" VERSION 0.0.0 LANGUAGES CXX)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 设置默认构建类型
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
endif()

# 定义源文件目录
set(CORE_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/core/core_include)
set(CORE_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/core/core_src)
set(GUI_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/gui/gui_include)
set(GUI_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/gui/gui_src)

# 定义源文件列表
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/core/core_src/api.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/core/core_src/database.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/core/core_src/diagnostic_helpers.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/core/core_src/peanalyzer.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/gui/gui_src/translator.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/gui/gui_src/utils.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/gui/gui_src/winmain.cpp
)

set(RESOURCES "PE_ParsingTool.rc")

# 创建可执行文件
add_executable(${PROJECT_NAME} WIN32 ${SOURCES} ${RESOURCES})

if(WIN32)
    set_target_properties(${PROJECT_NAME} PROPERTIES
        LINK_FLAGS "/SUBSYSTEM:WINDOWS"
    )
endif()

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CORE_INCLUDE_DIR}
    ${CORE_SRC_DIR}
    ${GUI_INCLUDE_DIR}
    ${GUI_SRC_DIR}
)

#set_target_properties(${PROJECT_NAME} PROPERTIES
#  RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_SOURCE_DIR}/out/build/x64-Debug"
#  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}/out/build/x64-Release"
#)

# 打印配置信息
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
if(MSVC)
    message(STATUS "MSVC version: ${MSVC_VERSION}")
endif()