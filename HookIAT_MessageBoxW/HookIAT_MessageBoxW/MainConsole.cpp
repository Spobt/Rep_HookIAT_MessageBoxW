#include <stdio.h>
#include "MainConsole.h"
#include "PEData.h"


int g_iIndexOfMessageBoxWInIAT = -1;
DWORD g_dwOldFunAddr{};

void main()
{
	MessageBoxW(0, L"", L"", 0);

	DWORD dw1 = (DWORD)MyMessageBoxW;
	int iRes = HookIAT_MessageBoxW("USER32.dll", "MessageBoxW", g_dwOldFunAddr, dw1);
	if (iRes) 
	{
		char strErrorText[MAX_PATH] = "HookIAT_MessageBoxW!";
		sprintf_s(strErrorText, MAX_PATH, "%s  %s%x", strErrorText, "ErrorCode:", iRes);
		MessageBoxA(GetConsoleWindow(), strErrorText, "Error:", MB_ICONERROR);
	}

	MessageBoxW(0, L"", L"", 0);

	return;
}


//****************************************************
// Name: HookIAT_MessageBoxW
// Func: hook指定函数(修改IAT中的地址)
// Args: char * strDllName				DLL名
// Args: char * strFunNameOrOdinal		函数名
// Args: _Out_ DWORD & dwOldFunAddr		被HOOK的函数地址,调用函数后返回	
// Args: DWORD & dwNewFunAddr			HOOK后的地址
// RetV: int  
// return 0; 成功
// return 1; 没有找到同名DLL
// return 2; 找到的(IAT & INT)RVA无效
// return 3; VirtualProtect faild
//****************************************************
int HookIAT_MessageBoxW(char * strDllName, char * strFunNameOrOdinal, _Out_ DWORD & dwOldFunAddr, DWORD & dwNewFunAddr)
{
	// 1.填充PE ************************************************************
	DWORD dwMod = (DWORD)GetModuleHandle(NULL);
	CPEData o((IMAGE_DOS_HEADER*)dwMod);

	// 2.IAT INT ************************************************************
	IMAGE_IMPORT_DESCRIPTOR* pID = (IMAGE_IMPORT_DESCRIPTOR*)(o.m_pDDT[1].VirtualAddress + dwMod);
	//如果是找到相同dll
	BOOL bDllFound{};
	while (pID->Name)
	{
		char* strName = (char*)(pID->Name + dwMod);
		if (0 == strcmp(strDllName, strName))
		{
			bDllFound = TRUE;
			break;
		}

		pID++;
	}

	// return 1; 没有找到同名DLL
	if (!bDllFound) { return 1; }

	// return 2; 找到的(IAT & INT)RVA无效
	if (!pID->FirstThunk || !pID->OriginalFirstThunk) { return 2; }

	IMAGE_THUNK_DATA* pIAT = (IMAGE_THUNK_DATA*)(pID->FirstThunk + dwMod);
	IMAGE_THUNK_DATA* pINT = (IMAGE_THUNK_DATA*)(pID->OriginalFirstThunk + dwMod);

	// 3.找到函数地址 ************************************************************
	BOOL bIsFunAddrFound{};
	g_iIndexOfMessageBoxWInIAT = 0;
	// 如果为0,循环退出,因为IAT结束了
	while ((pIAT+ g_iIndexOfMessageBoxWInIAT)->u1.Function)	
	{
		// 最高位为0时,以名称导入
		if (0 == ((pIAT + g_iIndexOfMessageBoxWInIAT)->u1.Ordinal >> 0x1f))
		{
			IMAGE_IMPORT_BY_NAME* pIBN = (IMAGE_IMPORT_BY_NAME*)((pINT + g_iIndexOfMessageBoxWInIAT)->u1.AddressOfData + dwMod);
			if (0 == strcmp(strFunNameOrOdinal, pIBN->Name))	// 找到函数名
			{
				bIsFunAddrFound = TRUE;
				break;
			}
		}

		g_iIndexOfMessageBoxWInIAT++;
	}

	// 4.保存要修改的函数地址 ************************************************************
	dwOldFunAddr = (DWORD)(pIAT[g_iIndexOfMessageBoxWInIAT].u1.Function);

	// 4.修改对应函数地址 ************************************************************
	DWORD dwOldProtect{};
	if (!VirtualProtect(&pIAT[g_iIndexOfMessageBoxWInIAT].u1.Function, 4, PAGE_READWRITE, &dwOldProtect)) 
	{ return 3;}	// return 3; VirtualProtect faild
	pIAT[g_iIndexOfMessageBoxWInIAT].u1.Function = dwNewFunAddr;
	if (!VirtualProtect(&pIAT[g_iIndexOfMessageBoxWInIAT].u1.Function, 4, dwOldProtect, &dwOldProtect))
	{ return 3;}	// return 3; VirtualProtect faild
	
	// 收尾 **********************************************************************
	return 0;
}

int WINAPI MyMessageBoxW(HWND hWnd, LPCWSTR wcsText, LPCWSTR wcsCaption, UINT uType)
{
	// ::MessageBoxA(hWnd, "", "", uType);

	_asm
	{
		push eax;

		{
			mov eax, [ebp + 0x14];
			push eax;
			mov eax, [ebp + 0x10];
			push eax;
			mov eax, [ebp + 0x0c];
			push eax;
			mov eax, [ebp + 0x8];
			push eax;
			call g_dwOldFunAddr;		// WINAPI --> __stdcall
			// add esp, 0x10;
		}

		pop eax;
	}

	return 0;
}