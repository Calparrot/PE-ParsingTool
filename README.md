# PE ParsingTool

![Windows](https://img.shields.io/badge/Platform-Windows-blue)
![C++](https://img.shields.io/badge/Language-C++17-blue)
![开发中](https://img.shields.io/badge/Status-Development-yellow)

一个用 C++ 编写的 PE 文件分析工具，专注于安全分析、结构验证与查看。
特色：具体到字段的结构输出报告，轻量级文件分析，平均扫描耗时 < 2ms/文件，GUI版本最高运行内存小于15MB，CLI版本实测最高运行内存小于2MB（批量扫描），核心组件无第三方依赖、可跨平台。

 **⚠️ 开发状态**：这是个人在学习过程中独立开发的小项目，正在积极推进中，已完成核心解析框架，但总体功能不完整。

 ## 📸 程序预览

![GUI版本程序运行示例](images/guiout.png)

## ✨ 功能特性

### ✅ 已实现的功能
- **文件头部基础数据分析**：提取 IMAGE_DOS_HEADER 至 IMAGE_SECTION_HEADER 信息并进行关键字段验证
- **支持导出文件**：支持解析报告、十六进制源文件数据的 TXT 文件导出
- **界面设计**：开发图形用户界面，提升用户体验

### 🔄 正在开发的功能
- **导入表解析**：提取并显示导入的 DLL 和函数
- **命令行版本**：支持批量文件扫描处理
- **日常维护**：持续补充扫描规则集、界面美化和内容补充等

### 🚧 计划中的功能
- **导出表解析**：提取并显示导出的函数列表
- **AI辅助扩展**：支持解析报告的 JSON 文件导出，辅助 AI 解析

## 🚀 快速开始

### 环境要求
- Windows 10/11 操作系统
- 支持 C++17 的编译器（Visual Studio 2022 / MinGW / Clang）
- CMake 3.15 或更高版本

### 编译运行

#### 使用命令行（推荐）
# 克隆项目
```bash
git clone https://github.com/Calparrot/PE-ParsingTool.git
cd PE-ParsingTool
```
# 配置并编译
```bash
cmake -B build
cmake --build build
```

# 运行程序
```bash
./build/PE_ParsingTool.exe
```

## 📁 项目结构
```text
PE-ParsingTool/
├── CMakeLists.txt # CMake 构建配置
├── CMakeSettings.json # Visual Studio CMake 配置
├── README.md # 项目说明
├── LICENSE.txt # 许可证文件
│
├── core/ # 核心解析模块（跨平台）
│   ├── core_include/ # 头文件
│   │   ├── api.h # 对外接口
│   │   ├── database.h # 数据结构定义
│   │   ├── diagnostic_codes.h # 诊断错误码
│   │   ├── peanalyzer.h # PE解析器核心类
│   │   ├── recheck.h # 复核规则定义
│   │   └── recheck_data.h # 复核规则数据定义
│   └── core_src/ # 源文件
│       ├── api.cpp
│       ├── database.cpp
│       ├── diagnostic_helpers.cpp
│       ├── peanalyzer.cpp
│       ├── recheck.cpp
│       └── recheck_data.cpp
│
├── gui/ # GUI 模块（Windows 专用）
│   ├── gui_include/ # 头文件
│   │   ├── custom_message.h # 自定义消息定义
│   │   ├── translator.h # 翻译器类定义
│   │   └── utils.h # 工具函数定义
│   └── gui_src/ # 源文件
│       ├── translator.cpp
│       ├── utils.cpp
│       └── winmain.cpp # 程序入口
│
├── cli/ # 命令行模块（跨平台）
│   ├── cli_include/ # 头文件
│   │   └── functions.h # 命令行功能定义
│   └── cli_src/ # 源文件
│       ├── functions.cpp
│       └── main_cli.cpp # 命令行程序入口
│
├── icons/ # 图标资源
│   └── myicon.ico
├── images/ # 示例图片
│   └── guiout.png
├── PE_ParsingTool.rc # 资源文件
└── resource.h # 资源定义
```

## ⚠️ 已知问题与限制

### 界面版本使用说明
1. 点击菜单栏 → 文件 → 打开
2. 选择文件后，单击左侧导航栏项目以显示详细信息
3. 需要导出时，点击菜单栏 → 文件 → 导出，选择需要的格式

### 已知问题

**文件格式限制**
- 暂不支持 ROM 格式
- 不支持大端序
- 未做文件格式验证，传入其他格式会按照PE格式扫描原始二进制数据

**解析限制**
- 不支持调试伪节区扫描
- 节区名白名单不全，容易误报合法节区名
- 文件格式特异性解析不强，主要以`.exe`格式为准，PE文件下不同格式（如`.dll`、`.sys`等）的部分差异会导致误报

**显示与性能**
- 十六进制显示不全，不支持浏览器模式，有需要可选择导出后查看
- 桌面版本和导出报告的显示中略有不同
- 命令行版本目前仅支持批量扫描结果统计，不支持单文件结果查看
- 如在 Linux 平台使用，暂不支持传入中文路径（utf-8编码路径）

**其他**
- 命令行版本仍在开发中，当前 CMakeLists.txt 文件没有为命令行版本写配置，如有需要，可自行包含 cli 和 core 文件夹下的文件进行配置
- 项目在开发阶段，API不稳定
- core 文件夹下的 database 名相关文件和数据库没关系，只因为是管数据的所以叫这个名字
- 测试样本较少，各项指标准确率低
- 不支持其他未知问题 (ˉ▽ˉ ;)