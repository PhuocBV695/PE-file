#include<stdio.h>
#include<windows.h>
#include<stdlib.h>
#include<stdint.h>
int PE32(char* Buffer, DWORD NT_ADD_HEADER,uint8_t bit) {
    //uint8_t bit = 4;
    printf("\n\n***NT_ADDITIONAL_FIELDS***");
    printf("\nNT_ADDITIONAL_FIELDS_OFFSET: 0x%x", NT_ADD_HEADER);
    DWORD imagebase = *(DWORD*)(Buffer + NT_ADD_HEADER);
    printf("\nIMAGE_BASE: 0x%x", imagebase);
    DWORD sectionalignment = *(DWORD*)(Buffer + NT_ADD_HEADER + bit);
    printf("\nSECTION_ALIGNMENT: 0x%x", sectionalignment);
    DWORD filealignment = *(DWORD*)(Buffer + NT_ADD_HEADER + bit + 4);
    printf("\nFILE_ALIGNMENT: 0x%x", filealignment);
    DWORD sizeofimage = *(DWORD*)(Buffer + NT_ADD_HEADER + bit + 4 + 4 + 2 + 2 + 2 + 2 + 2 + 2 + 4);
    printf("\nSIZE_OF_IMAGE: 0x%x", sizeofimage);
    DWORD sizeofheader = *(DWORD*)(Buffer + NT_ADD_HEADER + bit + 4 + 4 + 2 + 2 + 2 + 2 + 2 + 2 + 4 + 4);
    printf("\nSIZE_OF_HEADER: 0x%x", sizeofheader);
    
    return 0;
}

int PE64(char* Buffer, DWORD NT_ADD_HEADER, uint8_t bit) {
    //uint8_t bit = 4;
    printf("\n\n***NT_ADDITIONAL_FIELDS***");
    printf("\nNT_ADDITIONAL_FIELDS_OFFSET: 0x%x", NT_ADD_HEADER);
    uint64_t imagebase = *(uint64_t*)(Buffer + NT_ADD_HEADER);
    printf("\nIMAGE_BASE: 0x%llx", imagebase);
    DWORD sectionalignment = *(DWORD*)(Buffer + NT_ADD_HEADER + bit);
    printf("\nSECTION_ALIGNMENT: 0x%x", sectionalignment);
    DWORD filealignment = *(DWORD*)(Buffer + NT_ADD_HEADER + bit + 4);
    printf("\nFILE_ALIGNMENT: 0x%x", filealignment);
    DWORD sizeofimage = *(DWORD*)(Buffer + NT_ADD_HEADER + bit + 4 + 4 + 2 + 2 + 2 + 2 + 2 + 2 + 4);
    printf("\nSIZE_OF_IMAGE: 0x%x", sizeofimage);
    DWORD sizeofheader = *(DWORD*)(Buffer + NT_ADD_HEADER + bit + 4 + 4 + 2 + 2 + 2 + 2 + 2 + 2 + 4 + 4);
    printf("\nSIZE_OF_HEADER: 0x%x", sizeofheader);

    return 0;
}


int main(int argc, char* argv[])
{
	HANDLE FileW;
    DWORD bytesread;
    const char* Fname = argv[1];
    
	FileW = CreateFileA(
        Fname,              
        GENERIC_READ,          
        FILE_SHARE_READ,       
        NULL,                  
        OPEN_EXISTING,         
        FILE_ATTRIBUTE_NORMAL, 
        NULL                   
    );
    DWORD  Fsize = GetFileSize(FileW, 0);
    char* Buffer = (char*)malloc(Fsize * sizeof(char));
    ReadFile(FileW, Buffer, Fsize, &bytesread, NULL);
    CloseHandle(FileW);
    printf("%s\n", Fname);
    printf("\n-----DOS_HEADER-----");
    printf("\nMAGIC: ");
    for (int i = 0; i < 2; i++) {
        printf("%c", Buffer[i]);
    }
    
    printf("\n\n-----NT_HEADER-----");
    printf("\nPE_OFFSET: ");
    DWORD pe_offset = *(DWORD*)(Buffer + 0x3c);
    printf("0x%x", pe_offset);
    printf("\nMAGIC: ");
    for (int i = pe_offset; i < pe_offset+4; i++) {
        printf("%c", Buffer[i]);
    }
    printf("\n\n-----FILE_HEADER-----");
    WORD machine = *(WORD*)(Buffer + pe_offset + 4);
    printf("\nFILE_HEADER_OFFSET: 0x%x", machine);
    char machin[8] = { 0 };
    if (machine == 0x014c) {
        strcpy_s(machin, "x86");
    }
    else if (machine == 0x8664) {
        strcpy_s(machin, "x64");
    }
    else {
        strcpy_s(machin, "Unknown");
    }
    printf("\nMACHINE: %s", machin);

    WORD number_of_section = *(WORD*)(Buffer + pe_offset + 4 + 2);
    printf("\nNUMBER_OF_SECTION: %hu", number_of_section);
    DWORD timestamp = *(DWORD*)(Buffer + pe_offset + 4 + 2 + 2);
    printf("\nTIME_STAMP: %lu", timestamp);
    WORD sizeofoptionalheader = *(WORD*)(Buffer + pe_offset + 4 + 2 + 2 + 4+4+4);
    printf("\nSIZE_OF_OPTIONAL_HEADER: 0x%x", sizeofoptionalheader);
    WORD characteristics = *(WORD*)(Buffer + pe_offset + 4 + 2 + 2 + 4 + 4 + 4 + 2);
    printf("\nCHARACTERISTICS: 0x%x\n", characteristics);

    if (characteristics & IMAGE_FILE_RELOCS_STRIPPED)
        printf(" - RELOCS_STRIPPED\n");
    if (characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
        printf(" - EXECUTABLE_IMAGE (.exe or .dll)\n");
    if (characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED)
        printf(" - LINE_NUMS_STRIPPED\n");
    if (characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED)
        printf(" - LOCAL_SYMS_STRIPPED\n");
    if (characteristics & IMAGE_FILE_DLL)
        printf(" - DLL\n");
    if (characteristics & IMAGE_FILE_SYSTEM)
        printf(" - SYSTEM\n");
    if (characteristics & IMAGE_FILE_32BIT_MACHINE)
        printf(" - 32BIT_MACHINE\n");

    DWORD optional = pe_offset + 4 + 2 + 2 + 4 + 4 + 4 + 2 + 2;
    printf("\n-----OPTIONAL_HEADER-----");
    printf("\nOPTIONAL_HEADER_OFFSET: 0x%x", optional);
    printf("\n\n***STANDARD_FIELDS***");
    printf("\nSTANDARD_FIELDS_OFFSET: 0x%x", optional);
    WORD opmagic = *(WORD*)(Buffer + optional);
    if (opmagic == 0x10b) {
        printf("\nMAGIC: PE32");
    }
    else if (opmagic == 0x20b) {
        printf("\nMAGIC: PE64");
    }
    else{
        printf("\nMAGIC: UNKNOWN");
        return 0;
    }
    DWORD sizeofcode = *(DWORD*)(Buffer + optional + 2 + 1 + 1);
    printf("\nSIZE_OF_CODE: 0x%x", sizeofcode);
    DWORD sizeofinitdata= *(DWORD*)(Buffer + optional + 2 + 1 + 1 + 4);
    printf("\nSIZE_OF_INITIALIZE_DATA: 0x%x", sizeofinitdata);
    DWORD addrofentrypoint = *(DWORD*)(Buffer + optional + 2 + 1 + 1 + 4 + 4 + 4);
    printf("\nADDRESS_OF_ENTRYPOINT: 0x%x", addrofentrypoint);
    DWORD baseofcode = *(DWORD*)(Buffer + optional + 2 + 1 + 1 + 4 + 4 + 4 + 4);
    printf("\nBASE_OF_CODE: 0x%x", baseofcode);
    uint8_t bit;
    DWORD NT_ADD_HEADER;
    if (opmagic == 0x10b) {
        NT_ADD_HEADER = optional + 2 + 1 + 1 + 4 + 4 + 4 + 4 + 4 + 4;
        bit = 4;
        PE32(Buffer, NT_ADD_HEADER,bit);
    }
    else if (opmagic == 0x20b) {
        NT_ADD_HEADER = optional + 2 + 1 + 1 + 4 + 4 + 4 + 4 + 4;
        bit = 8;
        PE64(Buffer, NT_ADD_HEADER, bit);
    }
    else {
        return 0;
    }
    printf("\n\n-----IMAGE_DATA_DIRECTORY-----");
    DWORD IMAGE_DATA_DIRECTORY = NT_ADD_HEADER + bit + 4 + 4 + 2 + 2 + 2 + 2 + 2 + 2 + 4 + 4 + 4 + 4 + 2 + 2 + bit + bit + bit + bit + 4 + 4;
    DWORD exportdirectoryRVA = *(DWORD*)(Buffer + IMAGE_DATA_DIRECTORY);
    printf("\nEXPORT_DIRECTORY_RVA: 0x%x", exportdirectoryRVA);
    DWORD exportdirectorysize = *(DWORD*)(Buffer + IMAGE_DATA_DIRECTORY + 4);
    printf("\nEXPORT_DIRECTORY_SIZE: 0x%x", exportdirectorysize);
    DWORD importdirectoryRVA = *(DWORD*)(Buffer + IMAGE_DATA_DIRECTORY + 4 + 4);
    printf("\nIMPORT_DIRECTORY_RVA: 0x%x", importdirectoryRVA);
    DWORD importdirectorysize = *(DWORD*)(Buffer + IMAGE_DATA_DIRECTORY + 4 + 4 + 4);
    printf("\nIMPORT_DIRECTORY_SIZE: 0x%x", importdirectorysize);
    printf("\n\n-----SECTION_HEADER-----");
    DWORD sectionheader = optional + sizeofoptionalheader;
    printf("\nSECTION_HEADER_OFFSET: 0x%x", sectionheader);
    DWORD section;

    DWORD rawoffset;
    DWORD viraddr;
    DWORD importsection;
    for (DWORD count = 0; count < number_of_section; count++) {
        printf("\n\n***SECTION_%u***", count);
        section =  sectionheader+count*40;
        printf("\nOFFSET: 0x%x", section);
        
        printf("\nSECTION_NAME: ");
        for (char i = 0; i < 8; i++) {
            printf("%c", *(char*)(Buffer + section + i));
        }
        DWORD virtualsize = *(DWORD*)(Buffer + section + 8);
        printf("\nVIRTUAL_SIZE: 0x%x", virtualsize);
        DWORD virtualaddr = *(DWORD*)(Buffer + section + 8 + 4);
        printf("\nVIRTUAL_ADDRESS: 0x%x", virtualaddr);
        DWORD sizeofrawdata = *(DWORD*)(Buffer + section + 8 + 4 + 4);
        printf("\nSIZE_OF_RAW_DATA: 0x%x", sizeofrawdata);
        DWORD pointertorawdata = *(DWORD*)(Buffer + section + 8 + 4 + 4 + 4);
        printf("\nPOINTER_TO_RAW_DATA: 0x%x", pointertorawdata);
        DWORD pointertoreloc = *(DWORD*)(Buffer + section + 8 + 4 + 4 + 4 + 4);
        printf("\nPOINTER_TO_RELOCATIONS: 0x%x", pointertoreloc);
        DWORD pointertolinenumbers = *(DWORD*)(Buffer + section + 8 + 4 + 4 + 4 + 4 + 4);
        printf("\nPOINTER_TO_LINE_NUMBERS: 0x%x", pointertolinenumbers);
        WORD numberofreloc = *(WORD*)(Buffer + section + 8 + 4 + 4 + 4 + 4 + 4 + 4);
        printf("\nNUMBER_OF_RELOCATIONS: 0x%x", numberofreloc);
        WORD numberoflinenumbers = *(WORD*)(Buffer + section + 8 + 4 + 4 + 4 + 4 + 4 + 4 + 2);
        printf("\nNUMBER_OF_LINE_NUMBERS: 0x%x", numberoflinenumbers);
        DWORD characteristics = *(DWORD*)(Buffer + section + 8 + 4 + 4 + 4 + 4 + 4 + 4 + 2 + 2);
        printf("\nCHARACTERISTICS: 0x%x\n", characteristics);
        if (importdirectoryRVA >= virtualaddr && importdirectoryRVA < (virtualaddr + virtualsize)) {
            importsection = section;
            rawoffset = pointertorawdata;
            viraddr=virtualaddr;
            
        }
        
    }
    //printf("0x%x", importsection);
    ;
    int index = 0;

    while(1) {
        DWORD importdescriptor = rawoffset - viraddr + importdirectoryRVA;
        DWORD importdescriptor_name = *(DWORD*)(Buffer + importdescriptor + 12 + 20 * index);
        DWORD importdescriptor_firstthunk = *(DWORD*)(Buffer + importdescriptor + 16 + 20 * index);
        if (importdescriptor_name == 0 && importdescriptor_firstthunk == 0) {
            break;
        }
        printf("\nDLL: %s\n    APIs: ",Buffer+ rawoffset + importdescriptor_name - viraddr);
        DWORD thunk;
        if (*(DWORD*)(Buffer + importdescriptor + 20 * index) == 0) {
            thunk = importdescriptor_firstthunk;
        }
        else {
            thunk = *(DWORD*)(Buffer + importdescriptor + 20 * index);
        }
        if (opmagic == 0x10b) { // PE32
            DWORD thunkindex = 0;
            while (1) {
                DWORD thunkdata = *(DWORD*)(Buffer + rawoffset + (thunk - viraddr) + thunkindex * 4);
                if (thunkdata == 0) break;

                if (thunkdata & 0x80000000) {
                    printf("\n\tOrdinal: 0x%x", (WORD)(thunkdata & 0xFFFF));
                }
                else {
                    DWORD name_offset = rawoffset + (thunkdata - viraddr);
                    printf("\n\t%s", Buffer + name_offset + 2);
                }

                thunkindex++;
            }
        }
        else if (opmagic == 0x20b) { // PE64
            DWORD thunkindex = 0;
            while (1) {
                uint64_t thunkdata = *(uint64_t*)(Buffer + rawoffset + (thunk - viraddr) + thunkindex * 8);
                if (thunkdata == 0) break;

                if (thunkdata & 0x8000000000000000) {
                    printf("\n\tOrdinal: 0x%x", (WORD)(thunkdata & 0xFFFF));
                }
                else {
                    DWORD name_offset = rawoffset + (thunkdata - viraddr);
                    printf("\n\t%s", Buffer + name_offset + 2);
                }

                thunkindex++;
            }
        }


        index++;

    }
    free(Buffer);
    printf("\n\n-----END-----");
    return 0;

}
