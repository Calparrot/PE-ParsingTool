cmake_minimum_required(VERSION 3.15)
project("PE_ParsingTool" VERSION 1.0.0 LANGUAGES CXX)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 设置默认构建类型
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
endif()

# 设置Windows子系统（GUI应用）
if(WIN32)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SUBSYSTEM:WINDOWS")
    set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} /ENTRY:wWinMainCRTStartup")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /ENTRY:wWinMainCRTStartup")
endif()

# 定义源文件目录
set(CORE_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/core/core_include)
set(CORE_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/core/core_src)
set(GUI_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/gui/gui_include)
set(GUI_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/gui/gui_src)

# 包含头文件目录
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CORE_INCLUDE_DIR}
    ${CORE_SRC_DIR}
    ${GUI_INCLUDE_DIR}
    ${GUI_SRC_DIR}
)

# 定义源文件列表
set(SOURCES
    ${CORE_SRC_DIR}/api.cpp
    ${CORE_SRC_DIR}/database.cpp
    ${CORE_SRC_DIR}/diagnostic_helpers.cpp
    ${CORE_SRC_DIR}/peanalyzer.cpp
    ${GUI_SRC_DIR}/translator.cpp
    ${GUI_SRC_DIR}/utils.cpp
    ${GUI_SRC_DIR}/winmain.cpp
)

# 定义头文件列表（用于IDE显示）
set(HEADERS
    ${CORE_INCLUDE_DIR}/api.h
    ${CORE_INCLUDE_DIR}/database.h
    ${CORE_INCLUDE_DIR}/diagnostic_codes.h
    ${CORE_INCLUDE_DIR}/peanalyzer.h
    ${GUI_INCLUDE_DIR}/custom_message.h
    ${GUI_INCLUDE_DIR}/translator.h
    ${GUI_INCLUDE_DIR}/utils.h
    ${CMAKE_CURRENT_SOURCE_DIR}/resource.h
)

# 资源文件
set(RESOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/PE ParsingTool.rc"
)

# 图标和图片文件（用于资源）
set(ICON_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/icons/myicon.ico
    ${CMAKE_CURRENT_SOURCE_DIR}/images/cxyxsl.png
)

# 其他文件
set(OTHER_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/README.md
    ${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt
)

# 创建可执行文件
add_executable(${PROJECT_NAME} WIN32 ${SOURCES} ${HEADERS} ${RESOURCES} ${ICON_FILES} ${OTHER_FILES})

set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_SOURCE_DIR}/out/build/x64-Debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}/out/build/x64-Release"
)

# 针对MSVC的特定设置
if(MSVC)
    # 设置警告级别为Level3
    target_compile_options(${PROJECT_NAME} PRIVATE /W3)
    
    # 启用SDLCheck
    target_compile_options(${PROJECT_NAME} PRIVATE /sdl)
    
    # 启用符合性模式
    target_compile_options(${PROJECT_NAME} PRIVATE /permissive-)
    
    # 预处理器定义
    target_compile_definitions(${PROJECT_NAME} PRIVATE _UNICODE)
    target_compile_definitions(${PROJECT_NAME} PRIVATE UNICODE)
    
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        target_compile_definitions(${PROJECT_NAME} PRIVATE _DEBUG)
        target_compile_options(${PROJECT_NAME} PRIVATE /MTd)
    else()
        target_compile_definitions(${PROJECT_NAME} PRIVATE NDEBUG)
        target_compile_options(${PROJECT_NAME} PRIVATE /MT)
        # 全程序优化
        target_compile_options(${PROJECT_NAME} PRIVATE /GL)
        target_link_options(${PROJECT_NAME} PRIVATE /LTCG)
    endif()
    
    # 禁用控制台窗口（使用Windows子系统）
    set_target_properties(${PROJECT_NAME} PROPERTIES
        LINK_FLAGS "/SUBSYSTEM:WINDOWS"
    )
endif()

# 打印配置信息
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
if(MSVC)
    message(STATUS "MSVC version: ${MSVC_VERSION}")
endif()