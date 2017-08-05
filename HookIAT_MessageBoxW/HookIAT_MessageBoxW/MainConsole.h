#pragma once
#include <windows.h>
#include <tchar.h>


int HookIAT_MessageBoxW(char* strDllName, char* strFunNameOrOdinal, _Out_ DWORD& dwOldFunAddr, DWORD& dwNewFunAddr);

int WINAPI MyMessageBoxW(HWND hWnd, LPCWSTR wcsText, LPCWSTR wcsCaption, UINT uType);