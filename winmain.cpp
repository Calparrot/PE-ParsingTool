#ifndef UNICODE
#define UNICODE
#endif 

#include <windows.h>
#include <commdlg.h>
#include <iostream>
#include <locale>
#include <codecvt>
#include <string>

#include "resource.h"
#include "api.h"
#include "translator.h"
#include "custom_message.h"

/* 全局变量 */
RECT client_rect;                       // 客户区窗口大小
wchar_t szFile[MAX_PATH] = { 0 };       // 接收文件路径的缓冲区
static HWND g_navigation_window = NULL; // 导航窗口句柄
static HWND g_message_window = NULL;    // 信息窗口句柄
static HWND g_data_window = NULL;       // 数据窗口句柄

bool file_loaded = false;               // 文件是否已加载
FundamentalAnalysis object;             // 分析对象
std::wstring source_file_data;          // 源文件数据

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
        0, L"MainClass", L"PE_Cartographer", 
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
// 主窗口
LRESULT CALLBACK MainWindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam){
    GetClientRect(hWnd, &client_rect);

	int client_width = client_rect.right;   // 客户区域总宽度
    int client_height = client_rect.bottom; // 客户区域总高度
	int x_position = 0;                     // 初始x坐标
	int y_position = 0;                     // 初始y坐标
	int child_width = 0;                    // 子窗口宽度
    int child_height = 0;                   // 子窗口高度

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
            WS_CHILD | WS_BORDER | WS_VISIBLE | WS_VSCROLL,
            x_position, y_position, child_width, child_height,
            hWnd, NULL, GetModuleHandle(NULL), NULL
        );

        x_position = child_width + 12;
        y_position = 8;
        child_width = client_width - child_width - 20;
        child_height = client_height - 16;
        g_data_window = CreateWindowEx(
            0, L"DisplayBox", NULL,
            WS_CHILD | WS_BORDER | WS_VISIBLE | WS_VSCROLL,
            x_position, y_position, child_width, child_height,
            hWnd, NULL, GetModuleHandle(NULL), NULL
        );

        break;
    }  
    case WM_COMMAND:{
        switch (wmId) {
        case ID_40001:{ // 菜单栏：文件 -> 打开
            OnFileOpen(hWnd);
            if (szFile[0] != L'\0') {
                std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
                std::string file_path = converter.to_bytes(szFile);

                if (object.analysis_file(file_path) == FundamentalAnalysis::error_code::SUCCESS) {
                    file_loaded = true;
                    std::wstring* p_data_a = new std::wstring(generate_file_display(object.data_container));
                    std::wstring* p_data_b = new std::wstring(scan_summary(object.data_container));
                    SendMessage(g_data_window, WM_DATA_INTERFACE_REFRESH, 1, (LPARAM)p_data_a);
					SendMessage(g_message_window, WM_MSG_INTERFACE_REFRESH, 0, (LPARAM)p_data_b);
                }
                else {
                    MessageBox(hWnd, L"文件打开失败。", L"提示", MB_OK);
                }
            }
            break;
        }
        case ID_40002:{ // 菜单栏：文件 -> 关闭
            DestroyWindow(hWnd);
            break;
        }
        case ID_40003:{ // 菜单栏：帮助 -> 关于
            MessageBox(hWnd, L"还没开始写这个功能。", L"关于", MB_OK);
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

// 左上
LRESULT CALLBACK NavigationWindowProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp) {
    HWND hText_a = NULL; // "Source File Information"，ID-1001
    HWND hText_b = NULL; // "IMAGE_DOS_HEADER"，ID-1002
    HWND hText_c = NULL; // "DOS Stub Program"，ID-1003
    HWND hText_d = NULL; // "IMAGE_FILE_HEADER"，ID-1004
    HWND hText_e = NULL; // "IMAGE_OPTIONAL_HEADER"，ID-1005

    switch (msg) {
    case WM_CREATE: {
        hText_a = CreateWindowEx(
            WS_EX_TOPMOST, L"STATIC", L" Source File Information",
            WS_CHILD | WS_VISIBLE | SS_NOTIFY | SS_CENTERIMAGE,
            0, 0, (client_rect.right - 16) / 4, 25,
            hWnd, (HMENU)1001, NULL, NULL
        );
        SendMessage(hText_a, WM_SETFONT, (WPARAM)consolas, TRUE);

        hText_b = CreateWindowEx(
            WS_EX_TOPMOST, L"STATIC", L" IMAGE_DOS_HEADER",
            WS_CHILD | WS_VISIBLE | SS_NOTIFY | SS_CENTERIMAGE,
            0, 30, (client_rect.right - 16) / 4, 25,
            hWnd, (HMENU)1002, NULL, NULL
        );
        SendMessage(hText_b, WM_SETFONT, (WPARAM)consolas, TRUE);

        hText_c = CreateWindowEx(
            WS_EX_TOPMOST, L"STATIC", L" DOS Stub Program",
            WS_CHILD | WS_VISIBLE | SS_NOTIFY | SS_CENTERIMAGE,
            0, 55, (client_rect.right - 16) / 4, 25,
            hWnd, (HMENU)1003, NULL, NULL
        );
        SendMessage(hText_c, WM_SETFONT, (WPARAM)consolas, TRUE);

        hText_d = CreateWindowEx(
            WS_EX_TOPMOST, L"STATIC", L" IMAGE_FILE_HEADER",
            WS_CHILD | WS_VISIBLE | SS_NOTIFY | SS_CENTERIMAGE,
            0, 80, (client_rect.right - 16) / 4, 25,
            hWnd, (HMENU)1004, NULL, NULL
        );
        SendMessage(hText_d, WM_SETFONT, (WPARAM)consolas, TRUE);

        hText_e = CreateWindowEx(
            WS_EX_TOPMOST, L"STATIC", L" IMAGE_OPTIONAL_HEADER",
            WS_CHILD | WS_VISIBLE | SS_NOTIFY | SS_CENTERIMAGE,
            0, 105, (client_rect.right - 16) / 4, 25,
            hWnd, (HMENU)1005, NULL, NULL
        );
        SendMessage(hText_e, WM_SETFONT, (WPARAM)consolas, TRUE);

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

        if (HIWORD(wp) == STN_DBLCLK && file_loaded) {
            std::wstring* p_data;
            switch (wID) {
            case 1001:  // 右侧窗口刷新，显示源文件信息
                p_data = new std::wstring(generate_file_display(object.data_container));
                SendMessage(g_data_window, WM_DATA_INTERFACE_REFRESH, 1, (LPARAM)p_data);
                
                break;
            case 1002:  // 右侧窗口刷新，显示DOS Header扫描信息
                p_data = new std::wstring(L"还在开发中。");
                SendMessage(g_data_window, WM_DATA_INTERFACE_REFRESH, 2, (LPARAM)p_data);

                break;
            case 1003: // 右侧窗口刷新，显示DOS Stub扫描信息
                p_data = new std::wstring(L"Still under development.");
                SendMessage(g_data_window, WM_DATA_INTERFACE_REFRESH, 3, (LPARAM)p_data);

                break;
            case 1004: // 右侧窗口刷新，显示File Header扫描信息
                p_data = new std::wstring(L"Todavía en desarrollo.");
                SendMessage(g_data_window, WM_DATA_INTERFACE_REFRESH, 4, (LPARAM)p_data);

                break;
            case 1005: // 右侧窗口刷新，显示Optional Header扫描信息
                p_data = new std::wstring(L"還在開發中。");
                SendMessage(g_data_window, WM_DATA_INTERFACE_REFRESH, 5, (LPARAM)p_data);

                break;
            }
        }
    }      
    }

	return DefWindowProc(hWnd, msg, wp, lp);
}

// 左下
LRESULT CALLBACK MessageWindowProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp) {

    return DefWindowProc(hWnd, msg, wp, lp);
}

// 右
LRESULT CALLBACK DisplayWindowProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_NCCREATE: {
        std::wstring* display_text = new std::wstring(
            L"点击菜单栏 -> 文件 -> 打开，\n选择文件后双击左侧导航栏项目以显示详细信息。\n\n注意：目前仅支持小端序架构");
        SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)display_text);
        return DefWindowProc(hWnd, msg, wp, lp);
    }
    case WM_PAINT: {
        std::wstring* display_text = (std::wstring*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
        if (!display_text) {
            break;
        }

        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);

        SetTextColor(hdc, RGB(0, 0, 255));
        SetBkMode(hdc, TRANSPARENT);

        HFONT hOldFont = (HFONT)SelectObject(hdc, consolas);
        SetTextColor(hdc, RGB(0, 0, 0));
        SetBkMode(hdc, TRANSPARENT);

        RECT rect;
        GetClientRect(hWnd, &rect);
        rect.left = 10;
        rect.top = 10;

        DrawText(hdc, display_text->c_str(), -1, &rect, DT_LEFT | DT_WORDBREAK);

        EndPaint(hWnd, &ps);
        break;
    }
    case WM_DATA_INTERFACE_REFRESH: {
        std::wstring* display_text = (std::wstring*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
        std::wstring* p_data = (std::wstring*)lp;
        if (display_text && p_data) {
            *display_text = p_data->empty() ? L"没有数据可显示。" : *p_data;
        }
        InvalidateRect(hWnd, NULL, TRUE);
        if (p_data) {
            delete p_data;
        }

        return 0;
    }
    case WM_DESTROY:{
        std::wstring* display_text = (std::wstring*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
        delete display_text;
        SetWindowLongPtr(hWnd, GWLP_USERDATA, 0);
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
    wc_message.cbWndExtra = sizeof(std::wstring*);
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
    wc_display_box.cbWndExtra = sizeof(std::wstring*);
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