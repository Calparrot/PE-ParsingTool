#pragma once
#include <Windows.h>
#include <string>

// 为EDIT控件附加自定义数据
struct EditCustomData {
    int editId;
    std::wstring customData;
    void (*onTextChanged)(HWND, const std::wstring&);
};

// 创建EDIT并附加数据
HWND CreateEditWithData(HWND parent, int id, int x, int y, int w, int h) {
    HWND hEdit = CreateWindow(L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER,
        x, y, w, h, parent, (HMENU)id,
        GetModuleHandle(NULL), NULL);

    // 创建并存储数据
    EditCustomData* pData = new EditCustomData;
    pData->editId = id;
    pData->onTextChanged = nullptr;

    // 存储到窗口属性（推荐，因为不会干扰窗口过程）
    SetProp(hEdit, L"CustomData", (HANDLE)pData);

    // 子类化以处理消息
    SetWindowSubclass(hEdit, EditWithDataProc, 0, 0);

    return hEdit;
}

LRESULT CALLBACK EditWithDataProc(HWND hWnd, UINT msg, WPARAM wParam,
    LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
    EditCustomData* pData = (EditCustomData*)GetProp(hWnd, L"CustomData");

    switch (msg) {
    case WM_COMMAND:
        if (HIWORD(wParam) == EN_CHANGE && pData && pData->onTextChanged) {
            wchar_t text[256];
            GetWindowText(hWnd, text, 256);
            pData->onTextChanged(hWnd, text);
        }
        break;

    case WM_DESTROY:
        if (pData) {
            RemoveProp(hWnd, L"CustomData");
            delete pData;
        }
        RemoveWindowSubclass(hWnd, EditWithDataProc, uIdSubclass);
        break;
    }

    return DefSubclassProc(hWnd, msg, wParam, lParam);
}