/*
 * relocfix
 * 
 * 4/2/2013 - MIT license
 *
 * Fixes relocation of modules ripped from memory by crippel
 * Can also fix relocations of any ripped module or dumps compiled by a minidump
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <tchar.h>
#include <errno.h>
#include <Windows.h>

#define ARG_FILE		1
#define ARG_ADDR		2

typedef DWORD_PTR COMMON_PTR;
//typedef WORD IMAGE_RELOC_ITEM;
typedef struct {
	unsigned int Offset : 12;
	unsigned int Type : 4;
} IMAGE_RELOC_ITEM;

typedef unsigned int PHX_RET;

#define PHX_SUCCESS			0x00		//
#define PHX_INVALID_PARAM	0x01		// Test for other flags when this is returned
#define PHX_FILE_ACCESS		0x02		// Could not open read access on file
#define PHX_MEM_RD_ACCESS	0x04		// Could not read memory
#define PHX_MEM_WR_ACCESS	0x08		// Could not write memory (should not occur?)
#define PHX_INVALID_PE		0x10		// Invalid value in PE
#define PHX_ALLOCATION		0x20		// Could not allocate at valid address

#define PHX_NO_RELOCS		0x40		// relocfix only

const TCHAR* tzUsage = {
	TEXT("relocfix by [ryx]")
	TEXT("\n\tUsage: relocfix [pe] [baseaddr]")
	TEXT("\n\t\t- x86 pe file")
	TEXT("\n\t\t- Ripped base addr")
};

int _tmain(int argc, TCHAR* argv[]) {
	HANDLE hFile,
			hFileMapping;
	void *pFileBase;
	MEMORY_BASIC_INFORMATION mbiAlloc;
	IMAGE_DOS_HEADER *pIDH;
	IMAGE_NT_HEADERS *pINH;
	IMAGE_BASE_RELOCATION	*pIBRbase, 
							*pIBR;
	IMAGE_SECTION_HEADER	*pISHbase,
							*pISH,
							*pISHloop;
	IMAGE_RELOC_ITEM		*pIRI;
	COMMON_PTR				dwDiff,
							dwAddr;
	unsigned int i;

	if(argc != 3) {
		_tprintf(tzUsage);
		return PHX_INVALID_PARAM;
	}

	hFile = CreateFile(argv[ARG_FILE],
				GENERIC_WRITE | GENERIC_READ,
				FILE_SHARE_READ | FILE_SHARE_WRITE, // | FILE_SHARE_DELETE
				NULL,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL,
				NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return PHX_INVALID_PARAM | PHX_FILE_ACCESS;
	hFileMapping = CreateFileMapping(hFile,
				NULL,
				PAGE_READWRITE,
				0,
				0,
				NULL);
	if (!hFileMapping) {
		CloseHandle(hFile);
		return PHX_FILE_ACCESS;
	}
	pFileBase = MapViewOfFile(hFileMapping,
				FILE_MAP_READ | FILE_MAP_WRITE,
				0,
				0,
				0);
	if (!pFileBase) {
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return PHX_FILE_ACCESS;
	}
	VirtualQuery(pFileBase, &mbiAlloc, sizeof(mbiAlloc));

	pIDH =(IMAGE_DOS_HEADER*)pFileBase;
	if (pIDH->e_magic != IMAGE_DOS_SIGNATURE || !pIDH->e_lfanew) {
		UnmapViewOfFile(pFileBase);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return PHX_INVALID_PE;
	}
		
	pINH = (IMAGE_NT_HEADERS*)(pIDH->e_lfanew + (COMMON_PTR)pFileBase);
	if (pINH->Signature != IMAGE_NT_SIGNATURE ||
		pINH->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC ||
		!pINH->FileHeader.NumberOfSections ||
		pINH->FileHeader.NumberOfSections > 96) {
		UnmapViewOfFile(pFileBase);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return PHX_INVALID_PE | PHX_NO_RELOCS;
	}

	pISHbase = (IMAGE_SECTION_HEADER*)((COMMON_PTR)pFileBase + 
										pIDH->e_lfanew +
										sizeof(IMAGE_NT_HEADERS));

	// assume there's a reloc section (potentially fatal but oh well, the RELOCS_STRIPPED flag should indicate
	for(i = 0, pISH = pISHbase; i < pINH->FileHeader.NumberOfSections && memcmp(pISH->Name, ".reloc", 6); ++i, ++pISH) {}
	if(!(uint32_t)pISH->Name) {
		UnmapViewOfFile(pFileBase);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return PHX_NO_RELOCS;
	}

	if(pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress &&
		pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size &&
		!pINH->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) {
			pIBRbase = (IMAGE_BASE_RELOCATION*)(pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress - pISH->VirtualAddress) + pISH->PointerToRawData;
			pIBR = (IMAGE_BASE_RELOCATION*)(pIBRbase + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size -
										sizeof(IMAGE_BASE_RELOCATION));
			dwDiff = pINH->OptionalHeader.ImageBase - _ttoi(argv[ARG_ADDR]);
			for(; pIBRbase < pIBR; pIBRbase += pIBRbase->SizeOfBlock) {
				pIRI = (IMAGE_RELOC_ITEM*)(pIBR + sizeof(IMAGE_BASE_RELOCATION));
				for(i = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC_ITEM); i; --i, pIRI += sizeof(WORD))  {
					switch(pIRI->Type) {
						case IMAGE_REL_BASED_HIGHLOW:
							for(pISHloop = pISHbase; (pIRI->Offset + pIBR->VirtualAddress) <= pISHloop->VirtualAddress &&
							(pIRI->Offset + pIBR->VirtualAddress) >= (pISHloop->VirtualAddress + pISHloop->Misc.VirtualSize); ++pISHloop) {}
							_tprintf(TEXT("Reloc at %08lx to %08lx"), ((COMMON_PTR)pFileBase + pISH->PointerToRawData + pIRI->Offset),  (COMMON_PTR)(pINH->OptionalHeader.ImageBase + pISH->VirtualAddress + pIRI->Offset));
							__try {
								*(COMMON_PTR*)((COMMON_PTR)pFileBase + pISHloop->PointerToRawData + (pISHloop->VirtualAddress - pIBR->VirtualAddress) + pIRI->Offset) += dwDiff;
							} __except(EXCEPTION_EXECUTE_HANDLER) {
								_tprintf(TEXT("Error writing to %08lx"), ((COMMON_PTR)pFileBase + pISH->PointerToRawData + pIRI->Offset));
							}
							break;
						case IMAGE_REL_BASED_ABSOLUTE:
						default:
							break;
					}
				}
			}
	} else {
		UnmapViewOfFile(pFileBase);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return PHX_NO_RELOCS;
	}

	FlushViewOfFile(pFileBase, mbiAlloc.RegionSize);
	UnmapViewOfFile(pFileBase);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);
	return PHX_SUCCESS;
}