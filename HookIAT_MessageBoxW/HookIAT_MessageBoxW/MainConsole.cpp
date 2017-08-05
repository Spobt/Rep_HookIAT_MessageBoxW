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
// Func: hookָ������(�޸�IAT�еĵ�ַ)
// Args: char * strDllName				DLL��
// Args: char * strFunNameOrOdinal		������
// Args: _Out_ DWORD & dwOldFunAddr		��HOOK�ĺ�����ַ,���ú����󷵻�	
// Args: DWORD & dwNewFunAddr			HOOK��ĵ�ַ
// RetV: int  
// return 0; �ɹ�
// return 1; û���ҵ�ͬ��DLL
// return 2; �ҵ���(IAT & INT)RVA��Ч
// return 3; VirtualProtect faild
//****************************************************
int HookIAT_MessageBoxW(char * strDllName, char * strFunNameOrOdinal, _Out_ DWORD & dwOldFunAddr, DWORD & dwNewFunAddr)
{
	// 1.���PE ************************************************************
	DWORD dwMod = (DWORD)GetModuleHandle(NULL);
	CPEData o((IMAGE_DOS_HEADER*)dwMod);

	// 2.IAT INT ************************************************************
	IMAGE_IMPORT_DESCRIPTOR* pID = (IMAGE_IMPORT_DESCRIPTOR*)(o.m_pDDT[1].VirtualAddress + dwMod);
	//������ҵ���ͬdll
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

	// return 1; û���ҵ�ͬ��DLL
	if (!bDllFound) { return 1; }

	// return 2; �ҵ���(IAT & INT)RVA��Ч
	if (!pID->FirstThunk || !pID->OriginalFirstThunk) { return 2; }

	IMAGE_THUNK_DATA* pIAT = (IMAGE_THUNK_DATA*)(pID->FirstThunk + dwMod);
	IMAGE_THUNK_DATA* pINT = (IMAGE_THUNK_DATA*)(pID->OriginalFirstThunk + dwMod);

	// 3.�ҵ�������ַ ************************************************************
	BOOL bIsFunAddrFound{};
	g_iIndexOfMessageBoxWInIAT = 0;
	// ���Ϊ0,ѭ���˳�,��ΪIAT������
	while ((pIAT+ g_iIndexOfMessageBoxWInIAT)->u1.Function)	
	{
		// ���λΪ0ʱ,�����Ƶ���
		if (0 == ((pIAT + g_iIndexOfMessageBoxWInIAT)->u1.Ordinal >> 0x1f))
		{
			IMAGE_IMPORT_BY_NAME* pIBN = (IMAGE_IMPORT_BY_NAME*)((pINT + g_iIndexOfMessageBoxWInIAT)->u1.AddressOfData + dwMod);
			if (0 == strcmp(strFunNameOrOdinal, pIBN->Name))	// �ҵ�������
			{
				bIsFunAddrFound = TRUE;
				break;
			}
		}

		g_iIndexOfMessageBoxWInIAT++;
	}

	// 4.����Ҫ�޸ĵĺ�����ַ ************************************************************
	dwOldFunAddr = (DWORD)(pIAT[g_iIndexOfMessageBoxWInIAT].u1.Function);

	// 4.�޸Ķ�Ӧ������ַ ************************************************************
	DWORD dwOldProtect{};
	if (!VirtualProtect(&pIAT[g_iIndexOfMessageBoxWInIAT].u1.Function, 4, PAGE_READWRITE, &dwOldProtect)) 
	{ return 3;}	// return 3; VirtualProtect faild
	pIAT[g_iIndexOfMessageBoxWInIAT].u1.Function = dwNewFunAddr;
	if (!VirtualProtect(&pIAT[g_iIndexOfMessageBoxWInIAT].u1.Function, 4, dwOldProtect, &dwOldProtect))
	{ return 3;}	// return 3; VirtualProtect faild
	
	// ��β **********************************************************************
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