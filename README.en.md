[中文](README.md) | [English](README.en.md)

# PE ParsingTool

![Windows](https://img.shields.io/badge/Platform-Windows-blue)
![C++](https://img.shields.io/badge/Language-C++17-blue)
![开发中](https://img.shields.io/badge/Status-Development-yellow)

A PE file analysis tool written in C++, focusing on security analysis, structure validation, and inspection.

Features: field-by-field structured output reports, lightweight file analysis,
average scan time < 2ms per file, GUI version peak memory < 15MB, CLI version peak memory < 2MB (batch scan), core components have no third-party dependencies and are cross-platform for Windows and Linux.

 **⚠️ Development Status:** This is a small personal project I'm working on while learning. It's moving along nicely. The core parsing framework is done, but overall functionality is still incomplete.

 ## 📸 Preview

![GUI version demo](images/guiout.png)

## ✨ Features

### ✅ Implemented
- **Basic header analysis**: Extracts info from IMAGE_DOS_HEADER to IMAGE_SECTION_HEADER and validates key fields
- **File export**: Can export parsing reports and hex raw data as TXT files
- **GUI**: A graphical user interface for better user experience

### 🔄 In Progress
- **Import table parsing**: Extract imported DLLs and functions
- **CLI version**: Batch file scanning support
- **Ongoing maintenance**: Continuously adding scanning rules, improving UI, and other updates

### 🚧 Planned
- **Export table parsing**: Extract and display exported functions
- **AI-assisted extension**: JSON export for parsing reports to help with AI analysis

## 🚀 Quick Start

### Requirements
- Windows 10/11
- C++17 compiler (Visual Studio 2022 / MinGW / Clang)
- CMake 3.15 or higher

### Build & Run (command line recommended)

#### Clone the repo
```bash
git clone https://github.com/Calparrot/PE-ParsingTool.git
cd PE-ParsingTool
```
#### Configure and build
```bash
cmake -B build
cmake --build build
```
#### Run the program
```bash
./build/PE_ParsingTool.exe
```

## 📁 Project Structure
```text
PE-ParsingTool/
├── CMakeLists.txt # CMake build config
├── CMakeSettings.json # Visual Studio CMake config
├── README.md # Chinese README (default)
├── README.en.md # English README
├── LICENSE.txt # License file
│
├── core/ # Core parsing module (cross-platform)
│   ├── core_include/ # Headers
│   │   ├── api.h # Public interface
│   │   ├── database.h # Core result storage definitions
│   │   ├── diagnostic_codes.h # Diagnostic error codes
│   │   ├── peanalyzer.h # Main PE parser class
│   │   ├── recheck.h # Fine-grained scan rule definitions
│   │   └── recheck_data.h # Fine-grained scan result storage
│   └── core_src/ # Source files
│       ├── api.cpp
│       ├── database.cpp
│       ├── diagnostic_helpers.cpp
│       ├── peanalyzer.cpp
│       ├── recheck.cpp
│       └── recheck_data.cpp
│
├── gui/ # GUI module (Windows only)
│   ├── gui_include/ # Headers
│   │   ├── custom_message.h # Custom message definitions
│   │   ├── translator.h # Format conversion class
│   │   └── utils.h # Utility functions
│   └── gui_src/ # Source files
│       ├── translator.cpp
│       ├── utils.cpp
│       └── winmain.cpp # Program entry
│
├── cli/ # CLI module (cross-platform)
│   ├── cli_include/ # Headers
│   │   └── functions.h # Utility functions
│   └── cli_src/ # Source files
│       ├── functions.cpp
│       └── main_cli.cpp # CLI program entry
│
├── icons/ # Icon resources
│   └── myicon.ico
├── images/ # Sample images
│   └── guiout.png
├── PE_ParsingTool.rc # Resource file
└── resource.h # Resource definitions
```

## ⚠️ Known Issues & Limitations

### GUI Version Usage
1. Click Menu → File → Open
2. After selecting a file, click items in the left navigation bar to view details
3. To export, click Menu → File → Export and choose the format you want

### CLI Version Usage
1. Use `<toolname> -h` or `<toolname> --help` to see usage info

### Known Issues

**File format and platform limitations**
- ROM images (as defined in the PE spec) are not supported yet
- Doesn't work on big-endian platforms
- No file format validation — if you feed it a non-PE file, it'll still try to parse it as raw binary PE data

**Parsing limitations**
- Some debug info blocks look a lot like section headers at the binary level. The current version might mistake them for real section headers, which can result in reports showing sections that don't actually exist.
- The section name whitelist mainly covers standard sections, so legit section names from specific compilers or debug environments (like .debug$T, .fptable, etc.) might get flagged as suspicious.
- The parser is mainly tuned for .exe files. Other PE formats like .dll and .sys have some differences that can cause false positives.

**Display and performance**
- The hex view in the GUI is not complete. If you need to see the full hex data, use the "Export Hex View" option.
- Scan results shown in the GUI (bottom-left corner) might differ slightly from what's in the exported report.
- The CLI version doesn't support Chinese paths (UTF-8 encoded paths) for now.

**Miscellaneous**
- The project is still in development and the API isn't stable yet, so no API docs for now.
- The two files named "database" under the core folder have nothing to do with actual databases. They're named that because they define the core result storage structures and related operations.
- The set of PE samples used for testing is pretty limited, so test results might have some bias.
- Other unknown issues :(