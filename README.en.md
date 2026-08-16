[中文](README.md) | [English](README.en.md)

# PE Parsing Tool

![Windows](https://img.shields.io/badge/Platform-Windows-blue)
![C++](https://img.shields.io/badge/Language-C++17-blue)
![Status](https://img.shields.io/badge/Status-Development-yellow)

A PE file analysis tool written in C++, focused on security analysis, structure validation, and inspection.

**Features**: Field-level structured output reports, lightweight file analysis, average scan time < 2ms per file, GUI version peak memory < 15MB, CLI version peak memory < 2MB (batch scanning), core components with no third-party dependencies, cross-platform support for Windows and Linux.

 **⚠️ Development Status**: Under active development with limited functionality. The API is still evolving and not yet stable.

## 📸 Preview

![GUI version preview](docs/images/screenshot_gui.png)
![TXT report preview (viewed in Notepad)](docs/images/screenshot_report.png)

## ✨ Features

### ✅ Implemented
- **Basic file header analysis**: Extracts information from IMAGE_DOS_HEADER through IMAGE_SECTION_HEADER with key field validation
- **Export support**: Supports exporting analysis reports and hexadecimal source data as TXT files
- **GUI design**: Graphical user interface for improved user experience

### 🔄 In Development
- **Import table parsing**: Extract imported DLLs and functions
- **Command-line version**: Support batch file scanning
- **Ongoing maintenance**: Continuously expanding scan rule sets, UI polish, and content enhancements

### 🚧 Planned
- **Export table parsing**: Extract and display exported function lists
- **AI-assisted expansion**: Support JSON export of analysis reports for AI parsing

## 🚀 Quick Start

### Requirements
- Windows 10/11 operating system
- C++17-compatible compiler (Visual Studio 2022 / MinGW / Clang)
- CMake 3.15 or higher

### Build and Run

#### Windows

1. Clone the project and open the CMake project:
   ```bash
   git clone https://github.com/Calparrot/PE-ParsingTool.git
   cd PE-ParsingTool
   ```

2. Open the project root directory with Visual Studio (**File → Open → CMake**), and select `CMakeLists.txt`.
   > VS will automatically recognize the CMake project without manually generating a `.sln` file.

3. Select the build configuration (**Debug / Release**) in the Visual Studio toolbar, then:
   - Right-click `CMakeLists.txt` → **Build**
   - Or press `Ctrl + Shift + B` to compile directly

4. After compilation, executables are generated at:
   ```bash
   out/build/x64-Debug/PE_ParsingTool.exe      # GUI version
   out/build/x64-Debug/PE_ParsingTool_cli.exe  # CLI version
   ```

> 💡 **If using command line + CMake** (without Visual Studio UI):
> ```bash
> cmake -B build
> cmake --build build --config Release
> ```
> Generated in the `build/Release/` directory.

#### Linux (CLI only)

```bash
git clone https://github.com/Calparrot/PE-ParsingTool.git
cd PE-ParsingTool
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

Run the CLI version:
```bash
./build/PE_ParsingTool_cli
```

#### GUI Usage
1. Click Menu Bar → File → Open
2. After selecting a file, click items in the left navigation panel to view details
3. To export, click Menu Bar → File → Export and select the desired format

#### CLI Usage
1. Use `<tool_name> -h` or `<tool_name> --help` to view usage instructions

## 📖 Programming Interface (API)

Core interfaces are defined in [`core/core_include/api.h`](core/core_include/api.h)

### Quick Example

```cpp
#include "api.h"
#include <iostream>

int main() {
    // Create analysis object and invoke analysis function with file path
    FundamentalAnalysis object;
    FundamentalAnalysis::error_code result = object.analysis_file("C:/test.exe");
    
    // Export analysis report
    if (result == FundamentalAnalysis::error_code::SUCCESS) {          
        object.do_scan_txt_export("C:/output.txt");
        std::cout << "Analysis complete. Report exported." << std::endl;
    }
    return 0;
}
```

### Core Types

| Type | Description |
|------|-------------|
| `FundamentalAnalysis` | Core analysis class, provides file analysis and result management interfaces |
| `FundamentalAnalysis::error_code` | Error code type indicating analysis result status |
| `data_manager` | Public member of `FundamentalAnalysis`, responsible for report export and data management |

### Main Methods

| Method | Return Type | Description |
|--------|--------------|-------------|
| `analysis_file(const std::string& path)` | `error_code` | Analyzes the PE file at the given path, returns error code indicating success/failure |
| `summary_file()` | `ScanResultsDistribution` | Summarizes single analysis result, returns report data (does not print) |
| `do_scan_txt_export(const std::string& path)` | `bool` | Exports analysis report to the specified path |
| `do_hexadecimal_export(const std::string& path)` | `bool` | Exports hexadecimal view data to the specified path |
| `data_manager.print_report()` | `void` | Prints single analysis report to the console |

> Note: Except for `analysis_file`, all other methods must be called after `analysis_file` succeeds (returns `0`).

## 📁 Project Structure

```text
PE-ParsingTool/
├── CMakeLists.txt          # CMake build configuration
├── CMakeSettings.json      # Visual Studio CMake settings
├── core/ # Core parsing module (cross-platform)
│   ├── core_include/       # Headers
│   └── core_src/           # Source files
├── gui/ # GUI module (Windows-only)
│   ├── gui_include/        # Headers
│   └── gui_src/            # Source files
├── cli/ # CLI module (cross-platform)
│   ├── cli_include/        # Headers
│   └── cli_src/            # Source files
├── resources/ # Resource folder
│   ├── icons/              # Icon resources
│   ├── PE_ParsingTool.exe.manifest  # Manifest file
│   ├── PE_ParsingTool.rc   # Resource script
│   └── resource.h          # Resource definitions
├── docs/ # Documentation
│   ├── images/             # Example images
│   └── ARCHITECTURE.md     # Architecture design document
├── tests/ # Tests
│   └── samples/            # Test samples
├── README.md               # Project description (Chinese, default)
├── README.en.md            # Project description (English)
└── LICENSE.txt             # License file
```

## ⚠️ Known Issues and Limitations

**File format and platform limitations**
- ROM image support as specified in the PE specification is not yet implemented
- Big-endian platforms are not supported
- No file format validation is performed; non-PE files will be parsed as raw binary data following PE format conventions

**Parsing limitations**
- Some debug information blocks are structurally similar to section headers at the binary level, and may be incorrectly identified as valid section headers in the current version, potentially resulting in non-existent sections in the analysis report
- The section name whitelist primarily covers standard sections, which may cause false positives for legitimate section names used by specific compilers or debug environments (e.g., `.debug$T`, `.fptable`)
- Format-specific parsing is not highly specialized, with `.exe` as the primary reference; differences among various PE formats (e.g., `.dll`, `.sys`) may cause false positives

**Display and performance**
- The hexadecimal view feature in the GUI version is incomplete; use the "Export Hexadecimal View" option in the GUI as an alternative
- The CLI version does not fully support Chinese paths (UTF-8 encoded paths)
- GBK encoding display issues may occur on Linux platforms

**Other**
- The project is in development, API is unstable, so usage documentation is not yet provided
- The files named `database` under the `core` folder are unrelated to databases; they define the core result storage structure and related operations
- The PE file test samples used are limited, so test results may have some bias
- Other unknown issues are not supported :(
