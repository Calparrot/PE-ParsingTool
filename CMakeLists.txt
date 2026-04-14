cmake_minimum_required(VERSION 3.20)
project(PE_ParsingTool VERSION 1.0.0 LANGUAGES CXX RC)

# ============================================
# 全局设置
# ============================================
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ============================================
# 选项
# ============================================
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(ENABLE_SDL_CHECKS "Enable SDL checks" ON)

# ============================================
# 源文件
# ============================================
set(SOURCES
    core/core_src/api.cpp
    core/core_src/database.cpp
    core/core_src/diagnostic_helpers.cpp
    core/core_src/peanalyzer.cpp
    core/core_src/shellextension.cpp
    core/core_src/siganalyzer.cpp
    gui/gui_src/translator.cpp
    gui/gui_src/winmain.cpp
)

set(HEADERS
    core/core_include/api.h
    core/core_include/database.h
    core/core_include/diagnostic_codes.h
    core/core_include/peanalyzer.h
    core/core_include/shellextension.h
    gui/gui_include/custom_message.h
    gui/gui_include/resource.h
    gui/gui_include/translator.h
)

set(RESOURCES resource.rc)
set(ICONS icons/myicon.ico)

# ============================================
# 可执行文件
# ============================================
add_executable(${PROJECT_NAME} WIN32 ${SOURCES} ${HEADERS} ${RESOURCES} ${ICONS})

# ============================================
# 包含目录
# ============================================
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/core/core_include
    ${CMAKE_CURRENT_SOURCE_DIR}/core/core_src
    ${CMAKE_CURRENT_SOURCE_DIR}/gui/gui_include
    ${CMAKE_CURRENT_SOURCE_DIR}/gui/gui_src
)

# ============================================
# 预处理器定义
# ============================================
target_compile_definitions(${PROJECT_NAME} PRIVATE
    _CRT_SECURE_NO_WARNINGS
    _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS
    $<$<CONFIG:DEBUG>:_DEBUG>
    $<$<CONFIG:RELEASE>:NDEBUG>
    $<$<PLATFORM_ID:Win32>:WIN32>
    $<$<PLATFORM_ID:x64>:_WIN64>
    _CONSOLE
    UNICODE
    _UNICODE
)

# ============================================
# 编译选项
# ============================================
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE
        /W3
        /permissive-
        $<$<BOOL:${ENABLE_SDL_CHECKS}>:/SDL>
        $<$<CONFIG:RELEASE>:/Gy>
        $<$<CONFIG:RELEASE>:/Oi>
        $<$<CONFIG:RELEASE>:/GL>
        $<$<CONFIG:RELEASE>:/O2>
        $<$<CONFIG:DEBUG>:/RTC1>
        $<$<CONFIG:DEBUG>:/Zi>
        $<$<CONFIG:DEBUG>:/Od>
    )
    
    # 多处理器编译
    target_compile_options(${PROJECT_NAME} PRIVATE /MP)
endif()

# ============================================
# 链接选项
# ============================================
if(MSVC)
    target_link_options(${PROJECT_NAME} PRIVATE
        /SUBSYSTEM:WINDOWS
        /ENTRY:wWinMainCRTStartup
        $<$<CONFIG:DEBUG>:/DEBUG>
        $<$<CONFIG:RELEASE>:/LTCG>  # 链接时代码生成
    )
endif()

# ============================================
# 链接库
# ============================================
target_link_libraries(${PROJECT_NAME} PRIVATE
    # Windows 核心库
    user32
    gdi32
    shell32
    comctl32
    comdlg32
    advapi32
    ole32
    oleaut32
)

# ============================================
# 资源编译设置
# ============================================
if(MSVC)
    # 为资源编译器设置包含路径
    set_source_files_properties(${RESOURCES} PROPERTIES
        COMPILE_FLAGS "/I \"${CMAKE_CURRENT_SOURCE_DIR}/gui/gui_include\""
    )
endif()

# ============================================
# 附加文件（用于 IDE 显示）
# ============================================
# 添加 README
configure_file(README.md ${CMAKE_BINARY_DIR}/README.md COPYONLY)

# 添加 CMakeLists.txt 到项目（用于 IDE）
set(CMAKE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt)
source_group("CMake" FILES ${CMAKE_FILES})

# ============================================
# 配置总结
# ============================================
message(STATUS "")
message(STATUS "========================================")
message(STATUS "  ${PROJECT_NAME} Configuration")
message(STATUS "========================================")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Sources: ${SOURCES}")
message(STATUS "  SDL Checks: ${ENABLE_SDL_CHECKS}")
message(STATUS "========================================")
message(STATUS "")