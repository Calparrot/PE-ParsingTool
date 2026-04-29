#ifndef UNICODE
#define UNICODE
#endif 

#include <windows.h>
#include <commdlg.h>
#include <iostream>
#include <codecvt>
#include <string>

#include "resource.h"
#include "api.h"
#include "translator.h"
#include "custom_message.h"
#include "utils.h"

/* 全局变量 */
RECT main_client_rect;                    // 客户区主窗口大小
static HWND g_navigation_window = NULL;   // 导航窗口句柄
static HWND g_message_window = NULL;      // 信息窗口句柄
static HWND hedit_message = NULL;         // 信息窗口显示文本控件句柄
static HWND g_data_window = NULL;         // 数据窗口句柄
static HWND hedit_data = NULL;            // 数据窗口显示文本控件句柄

FundamentalAnalysis g_analysis_object;    // 全局分析对象
bool file_loaded = false;                 // 文件是否已加载
wchar_t szFile[MAX_PATH] = { 0 };         // 接收文件路径的缓冲区

struct WindowData {
    std::wstring display_text;
    int total_height;  // 文本总高度
    int scroll_pos;    // 当前滚动位置
    int client_height; // 客户区高度
    int client_width;  // 客户区宽度

    WindowData() : total_height(0), scroll_pos(0), client_height(0), client_width(0) {}
};

/* 字体设置 */
HFONT consolas = CreateFont(
    16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
    CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
    FIXED_PITCH | FF_MODERN, L"Consolas"
);

/* 回调函数 */
LRESULT CALLBACK MainWindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK NavigationWindowProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp);
LRESULT CALLBACK MessageWindowProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp);
LRESULT CALLBACK DisplayWindowProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp);

/* 工具函数 */
void OnFileOpen(HWND hWnd);                         // 处理文件打开
BOOL RegisterAllWindowClasses(HINSTANCE hInstance); // 注册窗口类

/* 入口 */
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow){
    RegisterAllWindowClasses(hInstance);

    HWND main_window = CreateWindowEx(
        0, L"MainClass", L"PE ParsingTool", 
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT,  CW_USEDEFAULT, 1024, 640,
        NULL, NULL, hInstance, NULL
    );

    if (main_window == NULL){
        return 0;
    }

    ShowWindow(main_window, nCmdShow);

    MSG msg = { };
    while (GetMessage(&msg, NULL, 0, 0) > 0){
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}

/* 回调函数实现 */
LRESULT CALLBACK MainWindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam){
    GetClientRect(hWnd, &main_client_rect);

	int client_width = main_client_rect.right - main_client_rect.left;  // 客户区域总宽度
    int client_height = main_client_rect.bottom - main_client_rect.top; // 客户区域总高度
	int x_position = 0;   // 初始x坐标
	int y_position = 0;   // 初始y坐标
	int child_width = 0;  // 子窗口宽度
    int child_height = 0; // 子窗口高度

    int wmId = LOWORD(wParam);

    switch (uMsg) {
    case WM_CREATE: {
        x_position = 8;
        y_position = 8;
        child_width = (client_width - 16) / 4;
        child_height = (client_height - 16) * 4 / 7;
        g_navigation_window = CreateWindowEx(
            0, L"NavigationBar", NULL,
            WS_CHILD | WS_BORDER | WS_VISIBLE,
            x_position, y_position, child_width, child_height,
            hWnd, NULL, GetModuleHandle(NULL), NULL
        );

        x_position = 8;
        y_position = child_height + 12;
        child_width = (client_width - 16) / 4;
        child_height = client_height - child_height - 20;
        g_message_window = CreateWindowEx(
            0, L"InformationBar", NULL,
            WS_CHILD | WS_BORDER | WS_VISIBLE,
            x_position, y_position, child_width, child_height,
            hWnd, NULL, GetModuleHandle(NULL), NULL
        );

        x_position = child_width + 12;
        y_position = 8;
        child_width = client_width - child_width - 20;
        child_height = client_height - 16;
        g_data_window = CreateWindowEx(
            0, L"DisplayBox", NULL,
            WS_CHILD | WS_VISIBLE,
            x_position, y_position, child_width, child_height,
            hWnd, NULL, GetModuleHandle(NULL), NULL
        );

        break;
    }  
    case WM_COMMAND: {
        FundamentalAnalysis object;

        switch (wmId) {
        case ID_40001: { // 菜单栏：文件 -> 打开
            OnFileOpen(hWnd);
            if (szFile[0] != L'\0') {
                std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
                std::string file_path = converter.to_bytes(szFile);

                if (object.analysis_file(file_path) == FundamentalAnalysis::error_code::SUCCESS) {
                    file_loaded = true;
                    g_analysis_object = object;
                    std::wstring* p_data_a = new std::wstring(generate_file_display(object.data_manager.data_container));
                    std::wstring* p_data_b = new std::wstring(scan_summary(object.data_manager.data_container));
                    SendMessage(g_data_window, WM_DATA_INTERFACE_REFRESH, 1, (LPARAM)p_data_a);
                    SendMessage(g_message_window, WM_MSG_INTERFACE_REFRESH, 0, (LPARAM)p_data_b);
                }
                else {
                    MessageBox(hWnd, L"文件打开失败。", L"提示", MB_OK);
                }
            }
            break;
        }
        case ID_40003: { // 菜单栏：文件 -> 关闭
            DestroyWindow(hWnd);
            break;
        }
        case ID_40004: { // 菜单栏：帮助 -> 关于
            MessageBox(hWnd, L"      PE  ParsingTool                \n\n      版本：v0.0.0\n      作者：CalParrot", L"关于", MB_OK);
            break;
        }
		case ID_40005: { // 菜单栏：文件导出 -> 导出十六进制文本
            std::wstring full_path(szFile); 
            int counter = 1;

            size_t last_slash = full_path.find_last_of(L"\\/");
            std::wstring full_filename = (last_slash == std::wstring::npos) ?
                full_path :
                full_path.substr(last_slash + 1);

            size_t last_dot = full_filename.find_last_of(L'.');
            std::wstring basename = (last_dot == std::wstring::npos) ?
                full_filename :
                full_filename.substr(0, last_dot);

            std::wstring output_filename = basename + L"_hex.txt";
            std::wstring output_filepath = get_exe_directory() + L"\\" + output_filename;

            std::wstring final_filepath = output_filepath;
            while (GetFileAttributes(final_filepath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                std::wstring new_filename = basename + L"_hex(" + std::to_wstring(counter) + L").txt";
                final_filepath = get_exe_directory() + L"\\" + new_filename;
                counter++;
            }

            if (file_loaded) {
                if (g_analysis_object.data_manager.hexadecimal_document_export(final_filepath)) {
                    MessageBox(hWnd, (L"文件已导出至" + final_filepath).c_str(), L"导出", MB_OK);
                }
                else {
                    MessageBox(hWnd, L"文件导出失败。", L"导出", MB_OK);
                }
            }
            else {
                MessageBox(hWnd, L"还没有打开需要分析的文件，请打开文件后重试。", L"导出", MB_OK);
            }
            break;
        }
		case ID_40006: { // 菜单栏：文件导出 -> 导出结构化文本
            std::wstring full_path(szFile);
            int counter = 1;

            size_t last_slash = full_path.find_last_of(L"\\/");
            std::wstring full_filename = (last_slash == std::wstring::npos) ?
                full_path :
                full_path.substr(last_slash + 1);

            size_t last_dot = full_filename.find_last_of(L'.');
            std::wstring basename = (last_dot == std::wstring::npos) ?
                full_filename :
                full_filename.substr(0, last_dot);

            std::wstring output_filename = basename + L"_report.txt";
            std::wstring output_filepath = get_exe_directory() + L"\\" + output_filename;

            std::wstring final_filepath = output_filepath;
            while (GetFileAttributes(final_filepath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                std::wstring new_filename = basename + L"_reprot(" + std::to_wstring(counter) + L").txt";
                final_filepath = get_exe_directory() + L"\\" + new_filename;
                counter++;
            }

            if (file_loaded) {
                if (g_analysis_object.data_manager.scan_report_export(final_filepath)) {
                    MessageBox(hWnd, (L"文件已导出至" + final_filepath).c_str(), L"导出", MB_OK);
                }
                else {
                    MessageBox(hWnd, L"文件导出失败。", L"导出", MB_OK);
                }
            }
            else {
                MessageBox(hWnd, L"还没有打开需要分析的文件，请打开文件后重试。", L"导出", MB_OK);
            }
            break;
        }
		case ID_40007: { // 菜单栏：文件导出 -> 导出结构化JSON
            MessageBox(hWnd, L"还在开发中(。_。)", L"导出", MB_OK);
            break;
        }
        }
        break;
    }
    case WM_CLOSE: {
        DestroyWindow(hWnd);
        return 0;
    }
    case WM_DESTROY: {
        PostQuitMessage(0);
        return 0;
    }
    }

    return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK NavigationWindowProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp) {
    HWND hText_a = NULL; // "Source File Information"，ID-1001
    HWND hText_b = NULL; // "IMAGE_DOS_HEADER"，ID-1002
    HWND hText_c = NULL; // "DOS Stub Program"，ID-1003
    HWND hText_d = NULL; // "IMAGE_FILE_HEADER"，ID-1004
    HWND hText_e = NULL; // "IMAGE_OPTIONAL_HEADER"，ID-1005
	HWND hText_f = NULL; // "IMAGE_SECTION_HEADERS"，ID-1006
    HWND hText_g = NULL; // "IMAGE_IMPORT_DESCRIPTOR"，ID-1007

    switch (msg) {
    case WM_CREATE: {
        hText_a = CreateWindowEx(
            WS_EX_TOPMOST, L"STATIC", L" Source File Information",
            WS_CHILD | WS_VISIBLE | SS_NOTIFY | SS_CENTERIMAGE,
            0, 0, (main_client_rect.right - 16) / 4, 25,
            hWnd, (HMENU)1001, NULL, NULL
        );
        SendMessage(hText_a, WM_SETFONT, (WPARAM)consolas, TRUE);

        hText_b = CreateWindowEx(
            WS_EX_TOPMOST, L"STATIC", L" IMAGE_DOS_HEADER",
            WS_CHILD | WS_VISIBLE | SS_NOTIFY | SS_CENTERIMAGE,
            0, 30, (main_client_rect.right - 16) / 4, 25,
            hWnd, (HMENU)1002, NULL, NULL
        );
        SendMessage(hText_b, WM_SETFONT, (WPARAM)consolas, TRUE);

        hText_c = CreateWindowEx(
            WS_EX_TOPMOST, L"STATIC", L" DOS Stub Program",
            WS_CHILD | WS_VISIBLE | SS_NOTIFY | SS_CENTERIMAGE,
            0, 55, (main_client_rect.right - 16) / 4, 25,
            hWnd, (HMENU)1003, NULL, NULL
        );
        SendMessage(hText_c, WM_SETFONT, (WPARAM)consolas, TRUE);

        hText_d = CreateWindowEx(
            WS_EX_TOPMOST, L"STATIC", L" IMAGE_FILE_HEADER",
            WS_CHILD | WS_VISIBLE | SS_NOTIFY | SS_CENTERIMAGE,
            0, 80, (main_client_rect.right - 16) / 4, 25,
            hWnd, (HMENU)1004, NULL, NULL
        );
        SendMessage(hText_d, WM_SETFONT, (WPARAM)consolas, TRUE);

        hText_e = CreateWindowEx(
            WS_EX_TOPMOST, L"STATIC", L" IMAGE_OPTIONAL_HEADER",
            WS_CHILD | WS_VISIBLE | SS_NOTIFY | SS_CENTERIMAGE,
            0, 105, (main_client_rect.right - 16) / 4, 25,
            hWnd, (HMENU)1005, NULL, NULL
        );
        SendMessage(hText_e, WM_SETFONT, (WPARAM)consolas, TRUE);

        hText_f = CreateWindowEx(
            WS_EX_TOPMOST, L"STATIC", L" IMAGE_SECTION_HEADERS",
            WS_CHILD | WS_VISIBLE | SS_NOTIFY | SS_CENTERIMAGE,
            0, 130, (main_client_rect.right - 16) / 4, 25,
            hWnd, (HMENU)1006, NULL, NULL
        );
        SendMessage(hText_f, WM_SETFONT, (WPARAM)consolas, TRUE);

        hText_g = CreateWindowEx(
            WS_EX_TOPMOST, L"STATIC", L" IIMAGE_IMPORT_DESCRIPTOR",
            WS_CHILD | WS_VISIBLE | SS_NOTIFY | SS_CENTERIMAGE,
            0, 155, (main_client_rect.right - 16) / 4, 25,
            hWnd, (HMENU)1007, NULL, NULL
        );
        SendMessage(hText_g, WM_SETFONT, (WPARAM)consolas, TRUE);

        break;
    }
    case WM_LBUTTONDBLCLK: {
        SendMessage(GetParent(hWnd), WM_COMMAND,
            MAKEWPARAM(1001, STN_DBLCLK),
            (LPARAM)hWnd);
        return 0;
    }
    case WM_COMMAND: {
        WORD wID = LOWORD(wp);

        if (HIWORD(wp) == STN_CLICKED && file_loaded) {
            std::wstring* p_data;
            switch (wID) {
            case 1001:  // 右侧窗口刷新，显示源文件信息
				p_data = new std::wstring(generate_file_display(g_analysis_object.data_manager.data_container));
                SendMessage(g_data_window, WM_DATA_INTERFACE_REFRESH, 1, (LPARAM)p_data);
                break;
            case 1002:  // 右侧窗口刷新，显示DOS Header扫描信息
                p_data = new std::wstring(structure_display(g_analysis_object.data_manager.data_container, 1));
                SendMessage(g_data_window, WM_DATA_INTERFACE_REFRESH, 2, (LPARAM)p_data);
                break;
            case 1003: // 右侧窗口刷新，显示DOS Stub扫描信息
                p_data = new std::wstring(L"还在开发中:(");
                SendMessage(g_data_window, WM_DATA_INTERFACE_REFRESH, 3, (LPARAM)p_data);
                break;
            case 1004: // 右侧窗口刷新，显示File Header扫描信息
                p_data = new std::wstring(structure_display(g_analysis_object.data_manager.data_container, 3));
                SendMessage(g_data_window, WM_DATA_INTERFACE_REFRESH, 4, (LPARAM)p_data);
                break;
            case 1005: // 右侧窗口刷新，显示Optional Header扫描信息
                p_data = new std::wstring(structure_display(g_analysis_object.data_manager.data_container, 4));
                SendMessage(g_data_window, WM_DATA_INTERFACE_REFRESH, 5, (LPARAM)p_data);
                break;
			case 1006: // 右侧窗口刷新，显示Section Headers扫描信息
                p_data = new std::wstring(sctheader_summary(g_analysis_object.data_manager.data_container));
                SendMessage(g_data_window, WM_DATA_INTERFACE_REFRESH, 6, (LPARAM)p_data);
				break;
            case 1007:
                p_data = new std::wstring(structure_display(g_analysis_object.data_manager.data_container, 5));
                SendMessage(g_data_window, WM_DATA_INTERFACE_REFRESH, 6, (LPARAM)p_data);
                break;
            }
        }
    }
    }

	return DefWindowProc(hWnd, msg, wp, lp);
}

LRESULT CALLBACK MessageWindowProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_NCCREATE: {
        WindowData* nit_data = new WindowData();
        nit_data->display_text = L"选择文件后显示数据。";
        SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)nit_data);
        return DefWindowProc(hWnd, msg, wp, lp);
    }
    case WM_CREATE: {
        WindowData* p_data = (WindowData*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
        if (p_data) {
            HDC hdc = GetDC(hWnd);
            HFONT h_old_font = (HFONT)SelectObject(hdc, consolas);

            RECT rect;
            GetClientRect(hWnd, &rect);

            RECT text_rect = { 10, 10, rect.right - rect.left - 10, 0 };
            p_data->client_height = rect.bottom - rect.top;
            DrawText(hdc, p_data->display_text.c_str(), -1, &text_rect,
                DT_LEFT | DT_WORDBREAK | DT_CALCRECT);
            p_data->total_height = text_rect.bottom - text_rect.top + 20;

            SelectObject(hdc, h_old_font);
            ReleaseDC(hWnd, hdc);

            SCROLLINFO si = { 0 };
            si.cbSize = sizeof(SCROLLINFO);
            si.fMask = SIF_RANGE | SIF_PAGE;
            si.nMin = 0;
            si.nMax = p_data->total_height;
            si.nPage = p_data->client_height;
            SetScrollInfo(hWnd, SB_VERT, &si, TRUE);
        }
        return 0;
    }
    case WM_MSG_INTERFACE_REFRESH: {
        WindowData* p_data = (WindowData*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
        std::wstring* p_input = (std::wstring*)lp;

        if (p_data && p_input) {
            p_data -> display_text = p_input->empty() ? L"没有数据可显示。" : *p_input;
            p_data->scroll_pos = 0;

            HDC hdc = GetDC(hWnd);
            HFONT hOldFont = (HFONT)SelectObject(hdc, consolas);

            RECT rect;
            GetClientRect(hWnd, &rect);
            int clientHeight = rect.bottom - rect.top;
            rect.left = 10;
            rect.top = 10;
            rect.right -= 20;
            p_data->client_height = clientHeight;

            RECT calcRect = rect;
            DrawText(hdc, p_data->display_text.c_str(), -1, &calcRect,
                DT_LEFT | DT_WORDBREAK | DT_CALCRECT);
            p_data->total_height = calcRect.bottom - calcRect.top + 20;

            SelectObject(hdc, hOldFont);
            ReleaseDC(hWnd, hdc);

            p_data->client_height = rect.bottom - rect.top;
            SCROLLINFO si = { 0 };
            si.cbSize = sizeof(SCROLLINFO);
            si.fMask = SIF_RANGE | SIF_PAGE;
            si.nMin = 0;
            si.nMax = p_data->total_height;
            si.nPage = p_data->client_height;
            SetScrollInfo(hWnd, SB_VERT, &si, TRUE);

            int maxscroll_pos = p_data->total_height - p_data->client_height;
            if (maxscroll_pos < 0) {
                maxscroll_pos = 0;
            }
            if (p_data->scroll_pos > maxscroll_pos) {
                p_data->scroll_pos = maxscroll_pos;
                si.fMask = SIF_POS;
                si.nPos = p_data->scroll_pos;
                SetScrollInfo(hWnd, SB_VERT, &si, TRUE);
            }
        }

        InvalidateRect(hWnd, NULL, TRUE);
        if (p_input) {
            delete p_input;
        }

        return 0;
    }
    case WM_VSCROLL: {
        WindowData* p_data = (WindowData*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
        if (!p_data) break;

        SCROLLINFO si = { 0 };
        si.cbSize = sizeof(SCROLLINFO);
        si.fMask = SIF_TRACKPOS | SIF_POS | SIF_RANGE | SIF_PAGE;
        GetScrollInfo(hWnd, SB_VERT, &si);

        int newPos = p_data->scroll_pos;

        switch (LOWORD(wp)) {
        case SB_LINEUP:      // 向上滚动一行（20像素）
            newPos -= 20;
            break;

        case SB_LINEDOWN:    // 向下滚动一行（20像素）
            newPos += 20;
            break;

        case SB_PAGEUP:      // 向上滚动一页
            newPos -= si.nPage;
            break;

        case SB_PAGEDOWN:    // 向下滚动一页
            newPos += si.nPage;
            break;

        case SB_THUMBTRACK:  // 拖动滚动条
            newPos = si.nTrackPos;
            break;

        case SB_TOP:         // 滚动到顶部
            newPos = si.nMin;
            break;

        case SB_BOTTOM:      // 滚动到底部
            newPos = si.nMax - si.nPage;
            break;

        default:
            break;
        }

        // 限制滚动范围
        int maxPos = p_data->total_height - p_data->client_height;
        if (maxPos < 0) maxPos = 0;
        newPos = max(si.nMin, min(newPos, maxPos));

        // 如果位置改变，更新滚动条并重绘
        if (newPos != p_data->scroll_pos) {
            int delta = p_data->scroll_pos - newPos;
            p_data->scroll_pos = newPos;

            // 更新滚动条位置
            si.fMask = SIF_POS;
            si.nPos = p_data->scroll_pos;
            SetScrollInfo(hWnd, SB_VERT, &si, TRUE);

            // 滚动窗口内容（优化性能）
            ScrollWindow(hWnd, 0, delta, NULL, NULL);
            // 或者简单重绘：InvalidateRect(hWnd, NULL, TRUE);
        }

        return 0;
    }
    case WM_MOUSEWHEEL: {
        WindowData* p_data = (WindowData*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
        if (!p_data) break;

        int delta = GET_WHEEL_DELTA_WPARAM(wp);
        int scrollAmount = (delta / WHEEL_DELTA) * 30;  // 每次滚动30像素

        SCROLLINFO si = { 0 };
        si.cbSize = sizeof(SCROLLINFO);
        si.fMask = SIF_POS | SIF_RANGE | SIF_PAGE;
        GetScrollInfo(hWnd, SB_VERT, &si);

        int newPos = p_data->scroll_pos - scrollAmount;
        int maxPos = p_data->total_height - p_data->client_height;
        if (maxPos < 0) maxPos = 0;
        newPos = max(si.nMin, min(newPos, maxPos));

        if (newPos != p_data->scroll_pos) {
            int deltaScroll = p_data->scroll_pos - newPos;
            p_data->scroll_pos = newPos;

            si.fMask = SIF_POS;
            si.nPos = p_data->scroll_pos;
            SetScrollInfo(hWnd, SB_VERT, &si, TRUE);

            ScrollWindow(hWnd, 0, deltaScroll, NULL, NULL);
        }

        return 0;
    }
    case WM_PAINT: {
        WindowData* p_data = (WindowData*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
        if (!p_data) break;

        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);

        // 设置字体和颜色
        HFONT hOldFont = (HFONT)SelectObject(hdc, consolas);
        SetTextColor(hdc, RGB(0, 0, 0));
        SetBkMode(hdc, TRANSPARENT);

        // 获取客户区矩形
        RECT clientRect;
        GetClientRect(hWnd, &clientRect);

        // 创建文本绘制矩形（考虑滚动偏移）
        RECT textRect;
        textRect.left = 10;
        textRect.top = 10 - p_data->scroll_pos;  // 应用滚动偏移
        textRect.right = clientRect.right - 10;
        textRect.bottom = textRect.top + p_data->total_height;

        // 设置剪裁区域，只绘制可见部分
        HRGN clipRegion = CreateRectRgn(clientRect.left, clientRect.top,
            clientRect.right, clientRect.bottom);
        SelectClipRgn(hdc, clipRegion);
        
        // 绘制文本
        DrawText(hdc, p_data->display_text.c_str(), -1, &textRect,
            DT_LEFT | DT_WORDBREAK);

        // 恢复剪裁区域
        SelectClipRgn(hdc, NULL);
        DeleteObject(clipRegion);
        

        SelectObject(hdc, hOldFont);
        EndPaint(hWnd, &ps);

        break;
    }
    case WM_DESTROY: {
        WindowData* p_data = (WindowData*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
        if (p_data) {
            delete p_data;
            SetWindowLongPtr(hWnd, GWLP_USERDATA, 0);
        }
        return 0;
    }
    }

    return DefWindowProc(hWnd, msg, wp, lp);
}

LRESULT CALLBACK DisplayWindowProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        RECT rc;
        GetClientRect(hWnd, &rc);
        hedit_data = CreateWindowEx(
            0, L"EDIT",
            L" 点击菜单栏 -> 文件 -> 打开，"
            L"\r\n 选择文件后单击左侧导航栏项目以显示详细信息。"
            L"\r\n 有需要也可在打开文件后点击菜单栏 -> 文件 -> 导出选择需要导出的文件\r\n"
            L"\r\n【已知问题告知】"
            L"\r\n 工具现在还没有做文件验证，请不要拿除exe、dll格式以外的文件尝试，会导致扫描结果很奇怪"
            L"\r\n 不支持ROM格式"
            L"\r\n 不支持大端序"
            L"\r\n 不支持调试伪节区扫描"
            L"\r\n 节区名白名单不全，容易误报合法节区名"
            L"\r\n 十六进制显示不全，不支持浏览器模式，有需要可选择导出后查看"
            L"\r\n 可能不支持大文件，目前缺少大文件测试"
            L"\r\n 不支持其他未知问题 (ˉ▽ˉ ;)",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY,
            0, 0, rc.right, rc.bottom,
            hWnd, NULL, GetModuleHandle(NULL), NULL
        );
        SendMessage(hedit_data, WM_SETFONT, (WPARAM)consolas, TRUE);
        break;
    }
    case WM_CTLCOLORSTATIC: {
        HWND hwndCtrl = (HWND)lp;

        if (hwndCtrl == hedit_data) {
            HDC hdcEdit = (HDC)wp;

            SetBkMode(hdcEdit, OPAQUE);
            SetBkColor(hdcEdit, RGB(255, 255, 255));
            SetTextColor(hdcEdit, RGB(0, 0, 0));

            static HBRUSH hBrushWhite = CreateSolidBrush(RGB(255, 255, 255));
            return (LRESULT)hBrushWhite;
        }
        break;
    }
    case WM_DATA_INTERFACE_REFRESH: {
        std::wstring* p_input = (std::wstring*)lp;

        if (p_input && hedit_data) {
            SetWindowText(hedit_data, p_input->c_str());
            delete p_input;
        }

        return 0;
    }
    case WM_DESTROY:{
        WindowData* p_data = (WindowData*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
        if (p_data) {
            delete p_data;
            SetWindowLongPtr(hWnd, GWLP_USERDATA, 0);
        }
        return 0;
    }
    }

    return DefWindowProc(hWnd, msg, wp, lp);
}

/* 工具函数实现 */
void OnFileOpen(HWND hWnd){
    OPENFILENAME ofn = { 0 };
    ofn.lStructSize = sizeof(OPENFILENAME);
    ofn.hwndOwner = hWnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.nFilterIndex = 1;
    ofn.lpstrFilter = L"可执行文件\0*.exe;*.dll\0" 
                      L"所有文件\0*.*\0";
    ofn.lpstrTitle = L"选择一个文件";
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;

    if (GetOpenFileName(&ofn)){
        SetWindowText(hWnd, szFile);
    }
    else {
        MessageBox(hWnd, L"文件打开失败", L"提示", MB_OK);
    }
}

BOOL RegisterAllWindowClasses(HINSTANCE hInstance) {
    // 主窗口类
    WNDCLASS wc_main = { };
    wc_main.style = CS_HREDRAW | CS_VREDRAW;
    wc_main.lpfnWndProc = MainWindowProc;
    wc_main.cbClsExtra = 0;
    wc_main.cbWndExtra = 0;
    wc_main.hInstance = hInstance;
    wc_main.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1));
    wc_main.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc_main.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc_main.lpszMenuName = MAKEINTRESOURCE(IDR_MENU1);
    wc_main.lpszClassName = L"MainClass";

    if (!RegisterClass(&wc_main)) {
        MessageBox(NULL, L"主窗口注册失败。", L"错误", MB_ICONERROR);
        return FALSE;
    }

    // 导航栏窗口类（左上）
    WNDCLASS wc_navigation = { };
    wc_navigation.style = CS_DBLCLKS;
    wc_navigation.lpfnWndProc = NavigationWindowProc;
    wc_navigation.cbClsExtra = 0;
    wc_navigation.cbWndExtra = sizeof(std::wstring*);
    wc_navigation.hInstance = hInstance;
    wc_navigation.hIcon = NULL;
    wc_navigation.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc_navigation.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc_navigation.lpszMenuName = NULL;
    wc_navigation.lpszClassName = L"NavigationBar";

    if (!RegisterClass(&wc_navigation)) {
        MessageBox(NULL, L"导航栏窗口注册失败。", L"错误", MB_ICONERROR);
        return FALSE;
    }

    // 信息提示窗口类（左下）
    WNDCLASS wc_message = { };
    wc_message.style = 0;
    wc_message.lpfnWndProc = MessageWindowProc;
    wc_message.cbClsExtra = 0;
    wc_message.cbWndExtra = sizeof(WindowData*);
    wc_message.hInstance = hInstance;
    wc_message.hIcon = NULL;
    wc_message.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc_message.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc_message.lpszMenuName = NULL;
    wc_message.lpszClassName = L"InformationBar";

    if (!RegisterClass(&wc_message)) {
        MessageBox(NULL, L"信息提示窗口注册失败。", L"错误", MB_ICONERROR);
        return FALSE;
    }

    // 显示框窗口类（右）
    WNDCLASS wc_display_box = { };
    wc_display_box.style = 0;
    wc_display_box.lpfnWndProc = DisplayWindowProc;
    wc_display_box.cbClsExtra = 0;
    wc_display_box.cbWndExtra = sizeof(WindowData*);
    wc_display_box.hInstance = hInstance;
    wc_display_box.hIcon = NULL;
    wc_display_box.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc_display_box.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc_display_box.lpszMenuName = NULL;
    wc_display_box.lpszClassName = L"DisplayBox";

    if (!RegisterClass(&wc_display_box)) {
        MessageBox(NULL, L"显示框窗口注册失败。", L"错误", MB_ICONERROR);
        return FALSE;
    }

    return TRUE;
}