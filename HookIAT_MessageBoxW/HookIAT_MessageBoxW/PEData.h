#pragma once
class CPEData
{
	// Attributions ***************************************************************************************
public:
	IMAGE_DOS_HEADER* m_pDH{};
	IMAGE_NT_HEADERS* m_pNT{};
	IMAGE_FILE_HEADER* m_pFH{};
	IMAGE_OPTIONAL_HEADER* m_pOH{};
	IMAGE_DATA_DIRECTORY* m_pDDT{};
	IMAGE_SECTION_HEADER* m_pSHT{};
	DWORD m_dwImageBase{};
	DWORD m_dwSectionCount{};
	DWORD m_dwSizeOfHeaders{};




	// Methods ********************************************************************************************
public:
	int Init(IMAGE_DOS_HEADER* pDH);











public:
	CPEData(IMAGE_DOS_HEADER* pDH);
	~CPEData();
};

