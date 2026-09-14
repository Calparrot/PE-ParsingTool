# PE Parsing Tool 架构文档 (ARCHITECTURE.md)

## 一、设计思路

### 1.1 项目定位

PE Parsing Tool 是一个核心跨平台的 PE（Portable Executable）文件格式分析工具，提供 GUI（Windows 原生 Win32）和 CLI（命令行）两种用户界面，支持对 Windows 可执行文件/动态链接库的头部结构进行解析、诊断和导出。

### 1.2 核心设计原则

**分层解耦**
项目严格划分为三个层次：
- **表现层**（`gui/` 和 `cli/`）：负责用户交互，不包含任何 PE 解析逻辑。
- **核心层**（`core/`）：零第三方依赖，纯 C++17 标准库实现，包含所有 PE 解析、诊断和报告生成逻辑。核心层无平台差异，可在 Windows/Linux 下编译运行。
- **公共 API 层**（`core/core_include/api.h`）：上层模块仅通过 `FundamentalAnalysis` 和 `Translator` 两个类访问核心功能。

**两遍扫描策略**
在核心层中，分信息获取与关键字段扫描阶段（主要）和可配置与细致扫描阶段（次要），每个层次各含一个扫描执行类和数据容器类。所有阶段的数据来源依赖于主要阶段的数据类。

**渐进式分析流水线**
在核心层中，信息获取与关键字段扫描阶段的分析流程采用顺序管道模式：`DOS Header → DOS Stub → File Header → Optional Header → Section Headers → Import Descriptor`。
每一步依赖前一步的结果（主要涉及地址计算），任一步失败则停止后续分析，但保留已生成的部分结果。

**诊断驱动**
不使用简单的"有效/无效"二元判断，而是通过 `Core::Diagnostic` 结构体记录丰富的上下文信息（对象类型、严重级别、分类、期望值、实际值、偏移地址等），由工厂函数统一构造，保证诊断信息的一致性和可扩展性。

**跨平台抽象**
文件 I/O 通过 `utf8_filesystem.h` 封装平台差异（Windows 上用 `MultiByteToWideChar` 转换 UTF-8 路径，Linux 上直接透传）。构建系统通过 CMake 条件编译分离 GUI（`WIN32` 子系统）和 CLI（控制台）目标。

### 1.3 关键数据结构设计

| 数据结构 | 用途 |
|---|---|
| `Structuresults` | 核心数据容器，持有所有解析得到的二进制结构体副本、每项分析的诊断结果、节区间映射表 |
| `SharedStructure` | 跨分析步骤共享的关键字段提取（e_lfanew、magic、FileAlignment、SectionAlignment 等），避免重复读数 |
| `Diaresults` | 单个被扫描结构组件的结果容器（如 IMAGE_DOS_HEADER 的诊断集合） |
| `SecondaryRecord` | 深度扫描（重检）的增强结果，包含 INT 表和导入模块名解析 |
| `Core::Diagnostic` | 单条诊断信息的最小单元，包含对象类型、严重级别、分类等元数据 |
| `SectionImformation` | 节权限标志位的解码结果，支持已知节名（.text/.rdata 等 15 种）的权限匹配检查 |
| `RangeItem<T>` / `cluster_int_pad<T>()` | 地址聚类模板，将分散的 RVA 按邻近度分组后再批量读取文件，减少 I/O 次数 |

### 1.4 诊断类型体系

诊断信息按两个维度分类：

**严重级别**（`Severity`）：`INFO_LOW` → `SUSPICIOUS` → `WARNING_MED` → `ERROR_HIGH`

**诊断分类**（`DiagCategory`）：值不匹配、无效值、偏移异常、地址越界、长度异常、结构缺失、详细信息、常规问题、索引问题、关系问题、附加信息。

工厂函数（如 `value_mismatch()`、`address_out_of_range()`）保证 `Object` 和 `DiagCategory` 的正确配对，消除人为误配错误。

---

## 二、模块依赖关系

### 2.1 目录结构

```
PE-ParsingTool/
├── CMakeLists.txt               # 构建系统（两个目标：GUI + CLI）
├── core/                        # 核心解析模块（跨平台，零第三方依赖）
│   ├── core_include/
│   │   ├── api.h                # 公共 API（FundamentalAnalysis + Translator）
│   │   ├── database.h           # PE 二进制结构体 + Structuresults 数据容器
│   │   ├── diagnostic_codes.h   # 诊断类型系统（Diagnostic 结构体 + 枚举）
│   │   ├── peanalyzer.h         # 主解析器（PEanalyzer + SharedStructure）
│   │   ├── recheck.h            # 深度重检器（ReInspector）
│   │   ├── recheck_data.h       # 重检数据结构（SecondaryRecord + 聚类模板）
│   │   └── utf8_filesystem.h    # 跨平台文件 I/O 抽象
│   └── core_src/
│       ├── api.cpp
│       ├── database.cpp
│       ├── diagnostic_helpers.cpp
│       ├── peanalyzer.cpp
│       ├── recheck.cpp
│       └── recheck_data.cpp
├── gui/                         # GUI 模块（Windows-only，Win32 API）
│   ├── gui_include/
│   │   ├── custom_message.h     # 自定义 Windows 消息定义
│   │   ├── custom_window.h      # 自定义控件（EDIT + 数据绑定）
│   │   ├── translator.h         # GUI 专用的 wstring 翻译器声明
│   │   └── utils.h              # GUI 工具函数声明
│   └── gui_src/
│       ├── translator.cpp       # 诊断信息 → UI 文本转换
│       ├── utils.cpp            # 工具函数实现
│       └── winmain.cpp          # Win32 入口 + 窗口过程
├── cli/                         # CLI 模块（跨平台）
│   ├── cli_include/
│   │   └── functions.h          # CLI 辅助函数声明
│   └── cli_src/
│       ├── functions.cpp        # 批量统计输出、帮助/版本信息
│       └── main_cli.cpp         # CLI 入口 + 参数解析
├── resource.h                   # Windows 资源 ID 定义
├── PE_ParsingTool.rc            # Windows 资源脚本（图标、菜单）
└── tests/samples/               # 测试用 PE 样本文件
```

### 2.2 模块依赖图

```
                        ┌──────────────────────────────┐
                        │      cli/main_cli.cpp        │
                        │      cli/functions.cpp       │
                        │                              │
                        │  依赖: api.h                 │
                        └──────────────┬───────────────┘
                                       │
                                       ▼
┌──────────────────────────┐    ┌──────────────────────────────────────┐
│   gui/winmain.cpp        │    │        core/api.h (API)              │
│   gui/translator.cpp     │    │    ┌───────────────────────┐         │
│   gui/utils.cpp          │    │    │ FundamentalAnalysis   │         │
│                          │    │    │ Translator            │         │
│  依赖: api.h             │───▶│    │ ScanResultsDistribution│         │
│        translator.h      │    │    └───────────┬───────────┘         │
│        resource.h        │    └────────────────┼─────────────────────┘
│        Windows.h         │                     │
└──────────────────────────┘                     ▼
                         ┌──────────────────────────────────────────────┐
                         │           core/ (CORE LAYER)                 │
                         │                                              │
                         │  ┌─────────────────┐  ┌──────────────────┐  │
                         │  │   PEanalyzer    │  │   ReInspector    │  │
                         │  │ (peanalyzer.h)  │  │  (recheck.h)     │  │
                         │  │  SharedStructure│  │  SecondaryRecord  │  │
                         │  └────────┬────────┘  └────────┬─────────┘  │
                         │           │                    │            │
                         │           ▼                    ▼            │
                         │  ┌──────────────────────────────────────┐   │
                         │  │         database.h                  │   │
                         │  │  DOSHeader, FileHeader, etc.       │   │
                         │  │  Structuresults, Diaresults         │   │
                         │  │  SectionImformation                 │   │
                         │  └──────────────────────────────────────┘   │
                         │                     │                        │
                         │                     ▼                        │
                         │  ┌──────────────────────────────────────┐   │
                         │  │      diagnostic_codes.h              │   │
                         │  │  Core::Diagnostic, Severity, Object   │   │
                         │  │  DiagCategory, 工厂函数              │   │
                         │  └──────────────────────────────────────┘   │
                         └──────────────────────────────────────────────┘
                         ┌──────────────────────────────────────────────┐
                         │           UTILITIES                         │
                         │  ┌──────────────────┐ ┌──────────────────┐  │
                         │  │ utf8_filesystem.h│ │ recheck_data.h   │  │
                         │  │ (平台 I/O 抽象)   │ │ (聚类/区间模板)  │  │
                         │  └──────────────────┘ └──────────────────┘  │
                         └──────────────────────────────────────────────┘
```

### 2.3 编译目标

| 目标 | 条件 | 子系统 | 源文件 | 平台 |
|---|---|---|---|---|
| `PE_ParsingTool` | `WIN32` | `/SUBSYSTEM:WINDOWS` | 全部 core + 全部 gui + .rc | Windows |
| `PE_ParsingTool_cli` | 无条件 | Console | 全部 core + 全部 cli | Windows/Linux |

两个目标**共享所有 core 源文件**，各自静态编译一份副本。

---

## 三、核心类关系

### 3.1 类协作全景

```
用户代码 / GUI / CLI
      │
      ▼
┌─────────────────────────────────────────────────────┐
│  FundamentalAnalysis  (公共 API 入口)                │
│  ────────────────────                                │
│  - myfile: std::ifstream&                           │
│  - file_size: size_t                                │
│  - data_manager: Translator  ◄── 拥有并向外暴露      │
│  - config: Config                                   │
│                                                      │
│  + analysis_file(path) → error_code   ← 主入口       │
│  + recheck_file()                      ← 深度重检    │
│  + summary_file() → ScanResultsDistribution          │
│  + check_settings() → vector<bool>                  │
└──────┬───────────────┬──────────────────────┘
       │ 创建并使用     │ 拥有
       ▼               ▼
┌──────────────┐  ┌──────────────────────────────────┐
│  PEanalyzer  │  │  Translator                      │
│  ─────────── │  │  ────────────────────────         │
│  - file&     │  │  - data_container:                │
│  - mulbuffer │  │      Structuresults&              │
│  - shared    │  │  - recheck_container:             │
│    _struct   │  │      SecondaryRecord&             │
│              │  │                                    │
│  + dosheader │  │  + print_report()                  │
│    _analysis │  │  + hex_document_export()           │
│  + dosstub   │  │  + scan_report_export()            │
│    _analysis │  │  + basic_file_info_translator()    │
│  + file      │  │  + detailed_file_info_translator() │
│    _header   │  │  + single_item_translator()        │
│    _analysis │  │  + ...                             │
│  + optional  │  └──────────┬───────────────────────┘
│    _header   │             │ 持有引用
│    _analysis │             ▼
│  + section   │  ┌──────────────────────────────────┐
│    _headers  │  │  Structuresults  (数据容器)       │
│    _analysis │  │  ──────────────────────            │
│  + import    │  │  - diarelist: vector<Diaresults>   │
│    _descrip  │  │  - sectionheaders: vector<...>     │
│    _seeker   │  │  - dosheader/fileheader/...        │
└──────┬───────┘  │  - section_attributes              │
       │          │  - interval_table (内存/文件)       │
       │ 引用     │  - source_file_data                │
       ▼          │  - crashreport                     │
┌──────────────┐  └──────────────────────────────────┘
│  ReInspector │
│  ─────────── │  ┌──────────────────────────────────┐
│  - file&     │  │  SecondaryRecord  (深度重检数据)   │
│              │  │  ──────────────────────            │
│  + INT       │  │  - rec_diaresults_                │
│    _extract  │  │  - in_module_info32_              │
│  + module    │  │  - in_module_info64_              │
│    _name_    │  │  - 各 header_recheck 结果          │
│    extract   │  └──────────────────────────────────┘
│  + *_recheck │
└──────────────┘
```

### 3.2 类职责说明

**`FundamentalAnalysis`** — 公共 API 入口类
- 封装文件打开、字节序检测、分析流程编排
- 拥有 `Translator` 实例（`data_manager`），供 GUI/CLI 直接调用来生成报告
- 提供三个公开方法：`analysis_file()`（主分析）、`recheck_file()`（深度重检）、`summary_file()`（统计摘要）

**`PEanalyzer`** — 主解析器
- 接收 `std::ifstream&` 引用，不持有文件所有权
- 使用 `mulbuffer[5600]` 临时缓冲区分段读取大文件，使用 `SharedStructure` 跨步传递关键字段
- 每个分析方法接收 `Structuresults&` 引用，将解析结果和诊断信息写入其中
- 包含静态节名匹配表 `SECTION_TABLE[15]` 和区间关系判断算法

**`ReInspector`** — 深度重检器
- 同样接收 `std::ifstream&` 引用
- 实现 INT 表和模块名的 RVA→RAW 转换和批量读取（通过 `cluster_int_pad()` 聚类地址）
- 通过 `file_offset_calculate()` 利用缓存的节索引实现高性能的 RVA 转换
- 各 header 重检方法当前为存根（返回 `true`），预留扩展点

**`Translator`**（core 版本）— 文本报告生成器
- 持有 `Structuresults&` 和 `SecondaryRecord&` 的引用
- 将结构化诊断数据渲染为 UTF-8 中文文本报告
- 提供多种输出策略：控制台打印、TXT 文件导出、十六进制视图导出

**`Translator`**（gui 版本，`gui/gui_include/translator.h`）— GUI 文本生成器
- 功能上与 core 版平行，但输出为 `std::wstring`（Windows 原生宽字符）
- 直接读取 `FundamentalAnalysis::data_manager` 中的数据容器
- 提供结构组件详情渲染（`structure_display()`）、节表摘要、扫描摘要等 UI 专用视图

**`Structuresults`** — 中央数据容器
- 持有所有 PE 二进制结构体的解析副本、诊断结果列表、节属性/区间信息
- 包含 `CrashReport` 用于记录解析过程中的致命错误
- 通过 `out_range_[20]` 追踪各分析块的扫描完成状态

**`SecondaryRecord`** — 重检数据容器
- 持有各结构组件的重检诊断结果
- 保存按模块分组的 `ImportModuleInfo32/64`（包含 IMAGE_THUNK_DATA 和 DLL 名称）

### 3.3 分析数据流

```
analysis_file("path/to/file.exe")
│
├─1. readfile() → 打开文件流, 读取前 2048 字节到 source_file_data
│
├─2. PEanalyzer 构造 (接收文件流引用)
│
├─3. dosheader_analysis(data_container)
│   └─► 读取 0-63 字节, 验证 MZ 签名
│   └─► 提取 e_lfanew → SharedStructure
│   └─► 生成 Diagnostics → data_container.diarelist[0]
│
├─4. dosstub_analysis(data_container)
│   └─► 读取 64 ~ e_lfanew
│   └─► 检测存根长度异常
│   └─► 生成 Diagnostics → data_container.diarelist[1]
│
├─5. file_header_analysis(data_container)
│   └─► 读取 NT Header 处, 验证 PE\0\0 签名
│   └─► 验证 Machine, NumberOfSections, SizeOfOptionalHeader
│   └─► 生成 Diagnostics → data_container.diarelist[2]
│
├─6. optional_header_analysis(data_container)
│   └─► 通过 magic 判断 32/64/ROM
│   └─► 验证 ImageBase, 对齐值, EntryPoint, 数据目录
│   └─► 生成 Diagnostics → data_container.diarelist[3]
│
├─7. section_headers_analysis(data_container)
│   │  ┌─ 第一遍: 探测有效节数量 (is_this_section_valid)
│   │  ├─ 矛盾解决: NumberOfSections vs 探测数 vs 理论最大值
│   │  └─ 第二遍: 每个节的详细校验
│   │     └─► 权限检查, 节名匹配, 区间重叠/排序
│   └─► 生成 Diagnostics → data_container.diarelist[4]
│
├─8. import_descriptor_seeker(data_container)
│   └─► RVA 定位 → 读取导入描述符
│   └─► 验证描述符字段有效性
│   └─► 生成 Diagnostics → data_container.diarelist[5]
│
└─► 返回 SUCCESS / 错误码

recheck_file()  [可选]
│
├─9. ReInspector 构造 (同一文件流)
├─10. INT_extract(recheck_container, ...)
│    └─► 收集 OriginalFirstThunk RVA
│    └─► RVA→RAW 转换 (file_offset_calculate)
│    └─► 聚类→批量读取→解析 IMAGE_THUNK_DATA 数组
│    └─► 结果→recheck_container.in_module_info32/64_
│
├─11. module_name_extract(recheck_container, ...)
│    └─► 收集 Name RVA → RVA→RAW → 聚类→读取→提取 DLL 名
│    └─► 结果→recheck_container
│
└─12. *_recheck() (存根, 预留扩展)

报告生成
│
├─ data_manager.print_report()
│  └─► basic_file_info_translator()    → 文件类型/架构/大小
│  └─► aggregate_info_translator()    → 节地址表/导入描述符表
│  └─► detailed_file_info_translator() → 逐条诊断渲染
│
└─ data_manager.hexadecimal_document_export()
   └─► 源文件十六进制视图
```

### 3.4 GUI 消息流转

```
MainWindowProc (主框架)
│
├─ WM_CREATE → 创建 3 个子窗口 (T 形布局)
│   ├─ NavigationWindowProc (左侧导航栏)
│   ├─ MessageWindowProc   (左下方消息面板)
│   └─ DisplayWindowProc   (右侧数据面板，含 EDIT 控件)
│
├─ WM_COMMAND (菜单)
│   ├─ ID_40001 (打开文件)
│   │   └─► OnFileOpen() → analysis_file()
│   │   └─► WM_DATA_INTERFACE_REFRESH → 更新数据面板
│   │   └─► WM_MSG_INTERFACE_REFRESH   → 更新消息面板
│   ├─ ID_40005 (导出 Hex 视图)
│   ├─ ID_40006 (导出扫描报告)
│   └─ ID_40007 (导出 JSON, 开发中)
│
└─ WM_DESTROY → PostQuitMessage

导航栏点击流程:
  NavigationWindowProc (STN_CLICKED)
    └─► 发送 WM_DATA_INTERFACE_REFRESH
          └─► DisplayWindowProc 收到消息
                └─► structure_display(idx) → 渲染对应结构详情
                └─► SetWindowText(hedit_data, result)
```