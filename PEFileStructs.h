/**
	AUTHOR: nishant_pamnani@yahoo.com
**/
#ifndef _PEFILESTRUCTS_H_
#define _PEFILESTRUCTS_H_

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int DWORD;
typedef unsigned int LONG;
typedef unsigned long long ULONGLONG;

typedef struct 
{
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;


enum machine {
  IMAGE_FILE_MACHINE_UNKNOWN = 0,
  IMAGE_FILE_MACHINE_I386 = 0x14c,
  IMAGE_FILE_MACHINE_IA64 = 0x200,
  IMAGE_FILE_MACHINE_AMD64 = 0x8664
};

#define  IMAGE_FILE_EXECUTABLE_IMAGE 0x0002
#define  IMAGE_FILE_DLL  0x2000
#define  FILE_TYPE(X)  (X & (IMAGE_FILE_EXECUTABLE_IMAGE |IMAGE_FILE_DLL ))
#define  IS_DLL  (IMAGE_FILE_EXECUTABLE_IMAGE |IMAGE_FILE_DLL )
#define  IS_EXE  IMAGE_FILE_EXECUTABLE_IMAGE

typedef struct 
{
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct 
{
    WORD Magic;
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    DWORD BaseOfData;
    DWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    DWORD SizeOfStackReserve;
    DWORD SizeOfStackCommit;
    DWORD SizeOfHeapReserve;
    DWORD SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct 
{
    WORD Magic;
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    ULONGLONG ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct 
{
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    union {
      WORD Magic;
      IMAGE_OPTIONAL_HEADER32 OptHdr32;
      IMAGE_OPTIONAL_HEADER64 OptHdr64;
    } u_or;
} IMAGE_PE_COMPOSITE_HEADERS,*PIMAGE_PE_COMPOSITE_HEADERS;

#define PE_SIGNATURE 0x4550

#define PE32 0x10B
#define PE32_PLUS 0x20B


#define IMAGE_DIRECTORY_ENTRY_EXPORT            0
#define IMAGE_DIRECTORY_ENTRY_IMPORT            1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE          2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION         3
#define IMAGE_DIRECTORY_ENTRY_SECURITY          4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC         5
#define IMAGE_DIRECTORY_ENTRY_DEBUG             6
#define IMAGE_DIRECTORY_ENTRY_COPYRIGHT         7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR         8   
#define IMAGE_DIRECTORY_ENTRY_TLS               9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG       10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT      11
#define IMAGE_DIRECTORY_ENTRY_IAT               12 
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT      13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR    14

typedef struct 
{
  DWORD   RVAImportLookupTbl;
  DWORD   TimeDateStamp; 
  DWORD   ForwarderChain;
  DWORD   Name;
  DWORD   RVAImportAddrTbl;
} IMAGE_IMPORT_DESCRIPTOR,*PIMAGE_IMPORT_DESCRIPTOR;

typedef struct 
{
   BYTE  Name[8];
   DWORD VirtualSize;
   DWORD VirtualAddress;
   DWORD SizeOfRawData;
   DWORD PointerToRawData;
   DWORD PointerToRelocations;
   DWORD PointerToLinenumbers;
   WORD  NumberOfRelocations;
   WORD  NumberOfLinenumbers;
   DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct 
{
  WORD Hint;
  BYTE Name[256];
} IMAGE_IMPORT_BY_NAME,*PIMAGE_IMPORT_BY_NAME;

typedef union {
  ULONGLONG Ordinal;
  ULONGLONG AddressOfData;
} IMAGE_THUNK_DATA64,*PIMAGE_THUNK_DATA64;

typedef union {
  DWORD Ordinal;
  DWORD AddressOfData;
} IMAGE_THUNK_DATA32,*PIMAGE_THUNK_DATA32;

typedef struct 
{
         DWORD   ExportFlags;
         DWORD   TimeDateStamp;
         WORD    MajorVersion;
         WORD    MinorVersion;
         DWORD   NameRVA;
         DWORD   OrdinalBase;
         DWORD   NumberOfAddrTblEntries;
         DWORD   NumberOfNameTblEntries;
         DWORD   RVAOfExportAddrTbl;
         DWORD   RVAOfNamesTbl;
         DWORD   RVAOFOrdinalTbl;
 } IMAGE_EXPORT_DIRECTORY,*PIMAGE_EXPORT_DIRECTORY;

#define BIT_MASK32 0x80000000
#define BIT_MASK64 0x8000000000000000ULL

#endif
