cmake_minimum_required(VERSION 3.10)
project(PE_Cartographer
    VERSION 1.0.0 
    DESCRIPTION "专注于PE字段扫描的安全诊断辅助工具" 
    LANGUAGES CXX  
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(WIN32)
    add_definitions(-DUNICODE -D_UNICODE)
    set(CMAKE_MSVC_RUNTIME_LIBRARY 
    "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# 设置输出目录（可选）
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# ============ 核心控制台程序 ============
add_executable(pe_core
    # 核心分析文件
    main.cpp
    database.cpp
    functool.cpp
    peanalyzer.cpp
    shellextension.cpp
    signal analyzer.cpp
)

# 设置控制台程序属性
set_target_properties(pe_core PROPERTIES
    OUTPUT_NAME "pe_analysis_core"  # 输出文件名
    WIN32_EXECUTABLE FALSE          # 这是控制台程序
)

# ============ GUI窗口程序 ============
add_executable(pe_gui
    # GUI界面文件
    guimain.cpp
    window.cpp
    wrapper.cpp
)

# 设置GUI程序属性
set_target_properties(pe_gui PROPERTIES
    OUTPUT_NAME "pe_analysis_gui"   # 输出文件名
    WIN32_EXECUTABLE TRUE           # 这是窗口程序（无控制台）
)

# Windows特定设置
if(WIN32)
    # GUI程序需要链接Windows库
    target_link_libraries(pe_gui
        user32      # 用户界面服务
        gdi32       # 图形设备接口
        shell32     # Shell API
    )
    
    # 可以设置窗口程序入口（可选）
    # set_target_properties(pe_gui PROPERTIES LINK_FLAGS "/ENTRY:mainCRTStartup")
endif()

# ============ 可选：设置编译选项 ============
if(MSVC)  # Visual Studio编译器
    # 禁用某些警告
    target_compile_options(pe_core PRIVATE /W3)
    target_compile_options(pe_gui PRIVATE /W3)
    
    # 调试信息
    target_compile_options(pe_core PRIVATE /Zi)
    target_compile_options(pe_gui PRIVATE /Zi)
    
    # 优化（Release配置）
    set(CMAKE_CXX_FLAGS_RELEASE "/O2 /MT")
endif()