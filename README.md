[中文](README.md) | [English](README.en.md)

# PE ParsingTool

![Windows](https://img.shields.io/badge/Platform-Windows-blue)
![C++](https://img.shields.io/badge/Language-C++17-blue)
![开发中](https://img.shields.io/badge/Status-Development-yellow)

一个用 C++ 编写的 PE 文件分析工具，专注于安全分析、结构验证与查看。

特色：具体到字段的结构输出报告，轻量级文件分析，
平均扫描耗时 < 2ms/文件，GUI版本最高运行内存小于15MB，CLI版本最高运行内存小于2MB（批量扫描），核心组件无第三方依赖、可跨 Windows、Linux 平台。

 **⚠️ 开发状态**：这是个人在学习过程中独立开发的小项目，正在积极推进中，已完成核心解析框架，总体功能仍不完整。

## 📸 程序预览

![GUI版本程序运行示例](images/guiout.png)

## ✨ 功能特性

### ✅ 已实现的功能
- **文件头部基础数据分析**：提取 IMAGE_DOS_HEADER 至 IMAGE_SECTION_HEADER 信息并进行关键字段验证
- **支持导出文件**：支持解析报告、十六进制源文件数据的 TXT 文件导出
- **界面设计**：开发图形用户界面，提升用户体验

### 🔄 正在开发的功能
- **导入表解析**：提取导入的 DLL 和函数
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

### 编译运行（推荐使用命令行）

#### 克隆项目
```bash
git clone https://github.com/Calparrot/PE-ParsingTool.git
cd PE-ParsingTool
```
#### 配置并编译
```bash
cmake -B build
cmake --build build
```
#### 运行程序
```bash
./build/PE_ParsingTool.exe
```

## 📁 项目结构
```text
PE-ParsingTool/
├── CMakeLists.txt # CMake 构建配置
├── CMakeSettings.json # Visual Studio CMake 配置
├── README.md # 项目说明中文版（默认）
├── README.en.md # 项目说明英文版
├── LICENSE.txt # 许可证文件
│
├── core/ # 核心解析模块（跨平台）
│   ├── core_include/ # 头文件
│   │   ├── api.h # 对外接口
│   │   ├── database.h # 核心结果存储定义
│   │   ├── diagnostic_codes.h # 诊断错误码
│   │   ├── peanalyzer.h # PE解析器核心类
│   │   ├── recheck.h # PE解析器细扫规则定义
│   │   └── recheck_data.h # 细扫结果存储定义
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
│   │   ├── translator.h # 格式转换类定义
│   │   └── utils.h # 工具函数定义
│   └── gui_src/ # 源文件
│       ├── translator.cpp
│       ├── utils.cpp
│       └── winmain.cpp # 程序入口
│
├── cli/ # 命令行模块（跨平台）
│   ├── cli_include/ # 头文件
│   │   └── functions.h # 工具函数定义
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

### 命令行版本使用说明
1. 使用 <工具名> -h 或 <工具名> --help 查看使用说明

### 已知问题

**文件格式和平台限制**
- 暂不支持解析 PE 文件规范中的 ROM 镜像
- 不支持大端序平台上运行
- 未做文件格式验证，传入其他格式会按照PE格式扫描原始二进制数据格式解析

**解析限制**
- 部分调试信息块在二进制层面与节区头结构相似，当前版本可能将其错误识别为有效节区头信息。这可能导致解析报告中出现实际不存在的节区。
- 当前节区名白名单主要覆盖标准节区，容易误报特定编译器或者调试环境下的合法节区名（如`.debug$T`、`.fptable`等）
- 文件格式特异性解析不强，主要以`.exe`格式为准，PE文件下不同格式（如`.dll`、`.sys`等）的部分差异会导致误报

**显示与性能**
- GUI版本的十六进制查看功能不全，有需要可以在GUI版本下选择导出“十六进制视图”查看
- GUI版本的扫描结果（界面左下）和导出报告的扫描结果显示可能略有不同
- CLI版本暂时仅支持单文件扫描并查看结果、批量扫描并查看统计信息，暂不支持导出功能
- CLI版本暂不支持传入中文路径（utf-8编码路径）

**其他**
- 项目处于开发阶段，API不稳定，因此暂未给出使用说明
- core 文件夹下的叫 database 的两个文件和数据库没有关系，叫这个名字是因为它们定义了核心结果存储的结构和相关操作
- 用于测试本项目的 PE 文件样本较为有限，各项测试结果可能存在偏差
- 不支持其他未知问题 :(