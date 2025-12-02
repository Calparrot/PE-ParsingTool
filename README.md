# PE ParsingTool

一个轻量级的Windows PE（可执行文件）解析工具，用于查看和分析PE文件结构。

## ✨ 功能特性

- ✅ **PE文件解析**：完整解析DOS头、NT头、文件头、可选头
- ✅ **节区查看**：显示所有节区名称、大小、虚拟地址等
- 🔄 **导入表解析**：查看DLL导入函数（开发中）
- 🔄 **导出表解析**：查看导出函数信息（开发中）
- 📊 **信息展示**：清晰直观的文本/界面显示

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