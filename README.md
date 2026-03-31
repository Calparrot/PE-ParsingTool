# PE ParsingTool

![Windows](https://img.shields.io/badge/Platform-Windows-blue)
![C++](https://img.shields.io/badge/Language-C++17-blue)

一个用 C++ 编写的 PE 文件分析工具，专注于安全分析、格式验证与查看。
特色：具体到字段的输出报告，轻量级单文件分析，核心组件无第三方依赖、可跨平台。

 ⚠️ **开发状态**：这是一个个人在学习PE格式和逆向工程时写的小项目，正在积极开发中，功能不完整。

## ✨ 功能特性

### ✅ 已实现的功能
- **DOS头基础解析**：提取DOS头信息并进行关键字段验证
- **DOS存根数据提取**：提取DOS存根数据
- **文件头基础解析**：提取DOS头信息并进行关键字段验证
- **可选头基础解析**：支持32位和64位PE文件的可选头关键字段验证

### 🔄 正在开发的功能
- **节区头基础解析**：提取可能的节区头并进行关键字段验证
- **界面设计**：开发图形用户界面，提升用户体验

### 🚧 计划中的功能
- **完善反推检验**：增强各头部字段的反推检验功能
- **导入表解析**：提取并显示导入的DLL和函数
- **导出表解析**：提取并显示导出的函数列表
- **支持导出文件**：支持JSON文件导出
- **查壳扩展**：集成解析常见PE壳的检测与分析功能

## 🚀 快速开始

### 环境要求
- Windows 10/11 操作系统
- Visual Studio 2022 或更新版本
- C++ 17 支持

### 编译运行
1. 克隆项目：
   ```bash
   git clone https://github.com/Calparrot/PE-ParsingTool.git
   cd PE-ParsingTool
2. 使用 Visual Studio 打开解决方案文件 `PE-ParsingTool.sln`。
3. 编译项目并运行。

## 📁 项目结构
PE-ParsingTool/
├── core/ # 核心解析模块（跨平台）
│ ├── include/ # 头文件
│ │ ├── api.h # 对外接口
│ │ ├── database.h # 数据结构定义
│ │ ├── diagnostic_codes.h # 诊断错误码
│ │ ├── peanalyer.h # PE解析器核心类
│ │ ├── resource.h # 资源定义
│ │ ├── shellextension.h # 壳扩展（暂留）
│ │ └── signalayer.h # 数据层接口
│ └── src/ # 源文件
│ ├── api.cpp # API 实现
│ ├── database.cpp # 数据结构实现
│ ├── diagnostic_helpers.cpp # 诊断辅助函数
│ ├── functool.cpp # 工具函数（暂留）
│ ├── peanalyer.cpp # PE解析器实现
│ ├── shellextension.cpp # 壳扩展实现（暂留）
│ └── signalayer.cpp # 数据层实现
│
├── gui/ # GUI 模块（Windows 专用）
│ ├── include/
│ │ ├── custom_message.h # 自定义消息定义
│ │ └── translator.h # 界面翻译/转换
│ └── src/
│ ├── translator.cpp # 转换逻辑
│ ├── window.cpp # 窗口实现（暂留）
│ └── winmain.cpp # 程序入口
│
├── CMakeLists.txt # CMake 构建配置
├── myicon.ico # 程序图标
├── resource.rc # Windows 资源文件
└── README.md # 项目说明