[中文](README.md) | [English](README.en.md)

# PE ParsingTool

![Windows](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue)
![C++](https://img.shields.io/badge/Language-C++17-blue)
![Status](https://img.shields.io/badge/Status-Development-yellow)

A lightweight PE file analysis tool written in C++, designed for security analysis, structure validation, and inspection.

**Key features**:
- Field-level structured output reports
- Lightweight file analysis
- Average scan time < 2ms per file
- Max memory usage: < 15MB (GUI), < 2MB (CLI batch scanning)
- Core module has **zero third-party dependencies**
- Cross-platform: Windows & Linux

> ⚠️ **Development Status**: This project is under active development with limited functionality. The API is in early iteration and not yet stable.

## 📸 Preview

![GUI version screenshot](images/guiout.png)

## ✨ Features

### ✅ Implemented
- **Basic file header analysis**: Extract and validate fields from `IMAGE_DOS_HEADER` through `IMAGE_SECTION_HEADER`
- **Export support**: Export analysis reports and hexadecimal source data as TXT files
- **Graphical interface**: User-friendly GUI for enhanced UX

### 🔄 In Development
- **Import table parsing**: Extract imported DLLs and functions
- **CLI version**: Support batch file scanning
- **Ongoing maintenance**: Scanning rule updates, UI polish, and content enhancements

### 🚧 Planned
- **Export table parsing**: Extract and display exported functions
- **AI integration**: JSON export support for AI-assisted analysis

## 🚀 Quick Start

### Requirements
- Windows 10/11
- C++17 compiler (Visual Studio 2022 / MinGW / Clang)
- CMake 3.15 or higher

### Build from Source (Command Line)

```bash
git clone https://github.com/Calparrot/PE-ParsingTool.git
cd PE-ParsingTool
cmake -B build
cmake --build build
```

### Run the Tool

```bash
./build/PE_ParsingTool.exe    # GUI version (Windows only)
# or
./build/cli/PE_ParsingTool_cli --help    # CLI version (cross-platform)
```

## 📖 Programming Interface (API)

Core interface is defined in [`core/core_include/api.h`](core/core_include/api.h).

### Quick Example

```cpp
#include "api.h"
#include <iostream>

int main() {
    FundamentalAnalysis object;                          // Create analyzer instance
    FundamentalAnalysis::error_code result = 
        object.analysis_file("C:/test.exe");             // Analyze PE file
    
    if (result == 0) {                                   // 0 = success
        object.data_manager.scan_report_export("C:/output.txt");  // Export report
        std::cout << "Analysis complete. Report exported." << std::endl;
    }
    return 0;
}
```

### Core Types

| Type | Description |
|------|-------------|
| `FundamentalAnalysis` | Main analyzer class, provides file analysis and result management |
| `FundamentalAnalysis::error_code` | Error code type. `0` = success, non-zero = failure |
| `data_manager` | Public member of `FundamentalAnalysis`, handles report export and data management |

> ⚠️ All methods except `analysis_file` must be called after `analysis_file` returns `0` (success).

### Main Methods

| Method | Return Value | Description |
|--------|--------------|-------------|
| `analysis_file(const std::string& path)` | `error_code` | Analyze PE file at specified path |
| `summary_file()` | Report data struct | Get analysis summary (**does not print**) |
| `data_manager.scan_report_export(const std::string& path)` | `bool` | Export full report to file |
| `data_manager.hexadecimal_document_export(const std::string& path)` | `bool` | Export hexadecimal view to file |
| `data_manager.print_report()` | `void` | Print report to console |

## 📁 Project Structure

```text
PE-ParsingTool/
├── CMakeLists.txt          # CMake build configuration
├── CMakeSettings.json      # Visual Studio CMake settings
├── README.md               # Chinese README (default)
├── README.en.md            # English README
├── LICENSE.txt             # License file
│
├── core/                   # Core parsing module (cross-platform)
│   ├── core_include/       # Headers
│   └── core_src/           # Sources
│
├── gui/                    # GUI module (Windows only)
│   ├── gui_include/        # Headers
│   └── gui_src/            # Sources
│
├── cli/                    # CLI module (cross-platform)
│   ├── cli_include/        # Headers
│   └── cli_src/            # Sources
│
├── icons/                  # Icon resources
├── images/                 # Screenshots
├── PE_ParsingTool.rc       # Resource file
└── resource.h              # Resource definitions
```

## ⚠️ Known Limitations

### UI Usage Notes
1. Menu → File → Open to select a file
2. Click items in the left sidebar to view details
3. Menu → File → Export to save reports

### CLI Usage Notes
- Run `<tool> -h` or `<tool> --help` for command reference

### Known Issues
- No strict PE format validation — non-PE files will be parsed as raw binary (results may be meaningless)
- CLI version on Windows does not fully support UTF-8 Chinese paths