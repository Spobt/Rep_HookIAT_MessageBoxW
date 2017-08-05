#include <windows.h>
#include "PEData.h"


int CPEData::Init(IMAGE_DOS_HEADER * pDH)
{
	m_pDH = pDH;
	m_pNT = (IMAGE_NT_HEADERS*)((DWORD)m_pDH + m_pDH->e_lfanew);
	m_pFH = &m_pNT->FileHeader;
	m_pOH = &m_pNT->OptionalHeader;
	m_pDDT = m_pOH->DataDirectory;
	m_pSHT = (IMAGE_SECTION_HEADER*)(m_pNT + 1);
	m_dwImageBase = (DWORD)pDH;
	m_dwSectionCount = m_pFH->NumberOfSections;
	m_dwSizeOfHeaders = m_pOH->SizeOfHeaders;

	return 0;
}

CPEData::CPEData(IMAGE_DOS_HEADER* pDH)
{
	Init(pDH);
}


CPEData::~CPEData()
{
}
