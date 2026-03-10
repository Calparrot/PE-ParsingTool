#ifndef UNICODE
#define UNICODE
#endif 

#include <windows.h>

#include "resource.h"

BOOL RegisterAllWindowClasses(HINSTANCE hInstance);
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow){
    RegisterAllWindowClasses(hInstance);

    HWND main_window = CreateWindowEx(
        0,
        L"MainClass",
        L"PE_Cartographer", 
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, 
        CW_USEDEFAULT, 
        768,
        512,
        NULL,  
        NULL,
        hInstance,
        NULL
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

BOOL RegisterAllWindowClasses(HINSTANCE hInstance) {
	// 主窗口类
    WNDCLASS wc_main = { };
    wc_main.lpszClassName = L"MainClass";
    wc_main.lpfnWndProc = WindowProc;
    wc_main.hInstance = hInstance;
    wc_main.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;
    wc_main.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON2));
    wc_main.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc_main.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc_main.lpszMenuName = MAKEINTRESOURCE(IDR_MENU1);
    wc_main.cbClsExtra = 0;
    wc_main.cbWndExtra = 0;

    if(!RegisterClass(&wc_main)){
        MessageBox(NULL, L"Failed to register main window class!", L"Error", MB_ICONERROR);
        return FALSE;
	}

	// 导航栏窗口类（左上）
    WNDCLASS wc_navigation = { };
    wc_navigation.lpszClassName = L"Navigation";
	wc_navigation.lpfnWndProc = WindowProc;

    // 信息窗口类（左下）

	// 数据窗口类（右）

	return TRUE;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam){
    /*switch (uMsg) {
    case WM_CREATE:
        HWND structure_table = CreateWindowEx(
        
        );

		break;
    }*/
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}