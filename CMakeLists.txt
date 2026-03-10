cmake_minimum_required(VERSION 3.10)
project(PE_Cartographer
    VERSION 1.0.0 
    DESCRIPTION "专注于PE字段扫描的安全诊断辅助工具" 
    LANGUAGES CXX  
)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 设置输出路径
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# 如果是Windows平台，启用UNICODE
if(WIN32)
    add_definitions(-DUNICODE -D_UNICODE)
    set(CMAKE_MSVC_RUNTIME_LIBRARY 
    "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# 核心库的头文件目录
include_directories(core/include)

# 创建核心静态库
file(GLOB CORE_SOURCES
    "core/src/*.cpp"
)

# 排除可能不需要的文件（根据实际情况调整）
list(REMOVE_ITEM CORE_SOURCES 
    "${CMAKE_CURRENT_SOURCE_DIR}/core/src/api.cpp"  # 如果api.cpp是导出的实现，可能需要保留
)

add_library(core STATIC ${CORE_SOURCES})

# 设置核心库的编译选项
target_compile_definitions(core PRIVATE CORE_LIBRARY)

# 如果是Windows，可能需要链接一些系统库
if(WIN32)
    target_link_libraries(core PRIVATE 
        ws2_32      # Windows Socket
        dbghelp     # 调试帮助库，可能用于diagnostic_helpers.cpp
    )
endif()

# 创建GUI可执行文件
file(GLOB GUI_SOURCES
    "gui/src/*.cpp"
)

# 添加资源文件（如果是Windows）
if(WIN32 AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/Resource.rc")
    set(GUI_SOURCES ${GUI_SOURCES} ${CMAKE_CURRENT_SOURCE_DIR}/Resource.rc)
endif()

add_executable(${PROJECT_NAME} WIN32 ${GUI_SOURCES})

# 链接核心库和必要的系统库
target_link_libraries(${PROJECT_NAME} PRIVATE 
    core
)

# 如果是Windows，链接必要的GUI库
if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE 
        comctl32     # 通用控件库
        uxtheme      # 主题支持
        dwmapi       # DWM支持
        shell32      # Shell扩展支持
        gdi32        # GDI绘图
        user32       # 用户界面
    )
endif()

# 设置安装规则
install(TARGETS ${PROJECT_NAME} core
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

# 安装头文件
install(DIRECTORY core/include/ 
    DESTINATION include
    FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp"
)

# 复制README.md到安装目录
install(FILES README.md DESTINATION .)

# 可选：启用编译器警告
if(MSVC)
    # MSVC编译器警告
    target_compile_options(core PRIVATE /W4 /WX)
    target_compile_options(${PROJECT_NAME} PRIVATE /W4 /WX)
else()
    # GCC/Clang编译器警告
    target_compile_options(core PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()