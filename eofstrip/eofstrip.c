#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <string.h>

#include "eofstrip.h"

#ifndef NDEBUG
#define assert_msg(condition, msg) assert(condition)
#else
#define assert_msg(condition, msg)
#endif

int main(int argc, char* argv[]) {

    if (argc < 2) {
        printf("eofstrip by kuupa\n\tUsage: eofstrip [in.exe]\n\tOutput is [in.exe].eof");
        _getch();
        return 1;
    }

    FILE* fIn = fopen(argv[1], "rb");
    assert_msg(fIn, NULL);
//    rewind(fIn);

    // read in PE structs
    dos_hdr* pDosHdr = malloc(sizeof(dos_hdr));
    assert_msg(pDosHdr, NULL);
    fread(pDosHdr, sizeof(dos_hdr), 1, fIn);
    
    fseek(fIn, pDosHdr->e_lfanew, SEEK_SET);

    nt_hdr* pNtHdr = malloc(sizeof(nt_hdr));
    assert_msg(pNtHdr, NULL);
    fread(pNtHdr, sizeof(nt_hdr), 1, fIn);

    fseek(fIn, pDosHdr->e_lfanew + sizeof(file_hdr) + sizeof(uint32_t) + pNtHdr->FileHeader.SizeOfOptionalHeader, SEEK_SET);

    sec_hdr** ppSecHdr = malloc(sizeof(sec_hdr*) * pNtHdr->FileHeader.NumberOfSections);
    assert_msg(ppSecHdr, NULL);

    for (register size_t i = 0; i < pNtHdr->FileHeader.NumberOfSections; ++i) {
        ppSecHdr[i] = malloc(sizeof(sec_hdr));
        fread(ppSecHdr[i], sizeof(sec_hdr), 1, fIn);
        assert_msg(ppSecHdr[i], NULL);
    }

    // calculate max file offset
    //size_t cbMaxOffset = pNtHdr->OptionalHeader.SizeOfHeaders;

    // instead we calculate from info without relying on PE specific headers
    size_t cbMaxOffset = pDosHdr->e_lfanew + sizeof(file_hdr) + sizeof(uint32_t) + pNtHdr->FileHeader.SizeOfOptionalHeader + sizeof(sec_hdr) * pNtHdr->FileHeader.NumberOfSections;
    // align up

    // if sec_offset + sec_size > maxoffset
    //    maxoffset = that
    for (register size_t i = 0; i < pNtHdr->FileHeader.NumberOfSections; ++i) {
        cbMaxOffset = cbMaxOffset > ppSecHdr[i]->PointerToRawData + ppSecHdr[i]->SizeOfRawData ? cbMaxOffset : ppSecHdr[i]->PointerToRawData + ppSecHdr[i]->SizeOfRawData;
    }

    // get file size
    fseek(fIn, 0, SEEK_END);
    size_t cbFileSize = ftell(fIn);

    printf("\nActual file size: %zu\nExpected file size: %zu", cbFileSize, cbMaxOffset);

    if (cbFileSize <= cbMaxOffset) {
        printf("\nNo overlay data was found.");
        return 0; // no eof data
    }

    // allocate and read data beyond typical PE
    size_t cbEof = cbFileSize - cbMaxOffset;
    void* pEof = calloc(1, cbEof);
    assert_msg(pEof, NULL);

    fseek(fIn, cbMaxOffset, SEEK_SET);
    assert_msg(fread(pEof, 1, cbEof, fIn) == cbEof, NULL);

    fclose(fIn);

    // new file is [in.exe].eof
    char* szOutFile = calloc(1, strlen(argv[1]) + 5);
    strcpy(szOutFile, argv[1]);
    strcat(szOutFile, ".eof");

    printf("\n%zu bytes of overlay data detected... dumping to %s", cbEof, szOutFile);

    // and finally we're done
    FILE* fOut = fopen(szOutFile, "wb");
    assert_msg(fOut, NULL);

    fwrite(pEof, cbEof, 1, fOut);
    fclose(fOut);

    return 0;
}
