
/**
	AUTHOR: nishant_pamnani@yahoo.com
**/
#include "PEFileStructs.h"
#include "PEUtils.h"
#include "PEReader.h"

PEObject&  PEObject::getPEObject(char const * const PEObjectName)
{
  static PEObject peObj(PEObjectName);
  return peObj;
}

PEObject::PEObject(char const * const PEObjectName ): 
                           inFileStream(PEObjectName,std::ios::in|std::ios::binary),
                           is64Bit(false)
{
 
  if (!inFileStream) {
    throw std::runtime_error("Cannot open input file");
  }

  inFileStream >> SetOffset(0x3c) >> offsetPESignature; 

  ReadInitialHeaders();
  GetObjectPEType();
  ReadSectionHeaders();
  ReadImportTable();
  ReadExportTable();
}

void PEObject::ProcessSectionHeader(IMAGE_SECTION_HEADER & she)
{
  
  she.VirtualAddress   = LittleE2NativeBO(she.VirtualAddress);
  she.VirtualSize      = LittleE2NativeBO(she.VirtualSize);
  she.PointerToRawData = LittleE2NativeBO(she.PointerToRawData);
}

void PEObject::ReadSectionHeaders()
{
  DWORD sectionOffSet = LittleE2NativeBO(offsetPESignature)
                         + sizeof(DWORD) 
                           + sizeof(IMAGE_FILE_HEADER) 
                             + LittleE2NativeBO(pCompHeader->FileHeader.SizeOfOptionalHeader);

  mNumberOfSections = LittleE2NativeBO(pCompHeader->FileHeader.NumberOfSections);
  for(WORD ndx = 0; ndx < mNumberOfSections; ndx++)
  {
    IMAGE_SECTION_HEADER iSH;
    inFileStream >> SetOffset(sectionOffSet) >> iSH; 
    ProcessSectionHeader(iSH);
    mSectionHeaders.push_back(iSH);
    sectionOffSet += sizeof(IMAGE_SECTION_HEADER);
  }
	
}

void PEObject::ShowSections()
{
  
  std::cout <<  std::endl;
  std::cout << std::setw(36) << "*******SECTION TABLE*******"<< std::endl; 
  std::cout <<  std::setw(8)  << "Section" 
            <<  std::setw(16) << "RVA" 
            <<  std::setw(16) << "Vsize" 
            <<  std::setw(16) << "Offset" 
            <<  std::endl;
  for (WORD ndx = 0; ndx < mSectionHeaders.size(); ndx++)
  {
    std::stringstream va;
    std::stringstream vs;
    std::stringstream pd;
    va << "0x" << std::hex << mSectionHeaders[ndx].VirtualAddress;
    vs << "0x" << std::hex << mSectionHeaders[ndx].VirtualSize;
    pd << "0x" << std::hex << mSectionHeaders[ndx].PointerToRawData;

    std::cout << std::setw(8)  << mSectionHeaders[ndx].Name 
              << std::setw(16) << va.str()
              << std::setw(16) << vs.str()
              << std::setw(16) << pd.str()
              << std::endl;
  }
}

void PEObject::ShowObjectPEType(bool useNewLine)
{
  WORD optinalHdrMagic = LittleE2NativeBO(pCompHeader->u_or.Magic);

  switch (optinalHdrMagic)
  {
    case PE32:
      std::cout << "PE32 ";
      break;
    case PE32_PLUS:
      std::cout << "PE32+ (64bit) ";
  }

  if(useNewLine) {
    std::cout << std::endl;
  }
}

void PEObject::ShowMachineType(bool useNewLine)
{
  
  WORD machineType = LittleE2NativeBO(pCompHeader->FileHeader.Machine);

  switch (machineType)
  {
    case IMAGE_FILE_MACHINE_I386:
      std::cout << "I386_arch ";
      break;
    case IMAGE_FILE_MACHINE_IA64:
      std::cout << "IA64_arch ";
      break;
    case IMAGE_FILE_MACHINE_AMD64:
      std::cout << "X86_64_arch ";
      break;
    case IMAGE_FILE_MACHINE_UNKNOWN:
    default:
      std::cout << "Unknown_arch ";
  }

  if(useNewLine) {
    std::cout << std::endl;
  }
} 

void PEObject::ShowFileType(bool useNewLine)
{
  WORD fileAttrs = LittleE2NativeBO(pCompHeader->FileHeader.Characteristics);

  switch (FILE_TYPE(fileAttrs))
  {
    case IS_DLL:
      std::cout << "(DLL) ";
      break;
    case IS_EXE:
      std::cout << "(EXE) ";
      break;
    default:
      std::cout << "(Not properly linked file!) ";
  }

  if(useNewLine) {
    std::cout << std::endl;
  }
}

void PEObject::ShowImportSymbols()
{
  std::cout <<  std::endl;
  if ( mImprtTbl.empty() ) {
    std::cout << std::setw(36) << "Import Table not Found!"<< std::endl; 
    return;
  }
  std::cout << std::setw(36) << "*******IMPORT TABLE******* "<< std::endl; 
  IMTable::Iterator iter =  mImprtTbl.begin(); 
  while(iter != mImprtTbl.end())
  {
    iter->ShowImportSymbols();
    ++iter;
  }
}

void PEObject::ShowExportSymbols()
{
  std::cout <<  std::endl;

  if ( mExportTbl.empty() ) {
    std::cout << std::setw(36) << "Export Table not Found!"<< std::endl; 
    return;
  }

  std::cout << std::setw(36) << "*******EXPORT TABLE******* "<< std::endl; 
  EXTable::Iterator iter =  mExportTbl.begin(); 
  while(iter != mExportTbl.end())
  {
    iter->ShowExportSymbols();
    ++iter;
  }
}

void PEObject::ShowImportDLLs()
{
  std::cout <<  std::endl;
  if ( mImprtTbl.empty() ) {
    std::cout << std::setw(36) << "Import Table not Found!"<< std::endl; 
    return; 
  }

  std::cout << std::setw(36) << "*******IMPORT DLLs******* "<< std::endl; 
  IMTable::Iterator iter =  mImprtTbl.begin(); 
  while(iter != mImprtTbl.end())
  {
    std::cout << iter->getImportDLL() << std::endl;
    iter++;
  }
}

void PEObject::ShowSignature()
{
  ShowObjectPEType();
  ShowMachineType();
  ShowFileType(true);
}

void PEObject::ShowAll()
{
  ShowSignature();
  ShowSections();
  ShowImportSymbols();
  ShowExportSymbols();
}

void PEObject::ReadInitialHeaders() 
{
  pCompHeader = Auto_Ptr<IMAGE_PE_COMPOSITE_HEADERS>(new IMAGE_PE_COMPOSITE_HEADERS);
  inFileStream >> SetOffset(LittleE2NativeBO(offsetPESignature)) >> *pCompHeader;
  if ( PE_SIGNATURE != LittleE2NativeBO(pCompHeader->Signature) ) {
    throw std::runtime_error ("PE SIGNATURE NOT FOUND!!!");
  }
}

void PEObject::GetObjectPEType()
{
  WORD optinalHdrMagic = LittleE2NativeBO(pCompHeader->u_or.Magic);
  switch (optinalHdrMagic)
  {
    case PE32:
      break;
    case PE32_PLUS:
      is64Bit = true;
  }
}

DWORD PEObject::Vaddr2Offset(DWORD vaddr)
{
  DWORD StartAddr, EndAddr;
  WORD count;
  for (count=0; count < mNumberOfSections; count++ )
  {
    StartAddr = mSectionHeaders[count].VirtualAddress;
    EndAddr = StartAddr + mSectionHeaders[count].VirtualSize;
    if ( StartAddr <= vaddr && vaddr <= EndAddr )
    {
      break;
    }
  }

  std::stringstream ss;
  if ( count < mNumberOfSections )
    return mSectionHeaders[count].PointerToRawData + (vaddr - StartAddr);
  else
  {
    ss <<  "RVA " << vaddr << " Does not belong to any sections" ;
    throw std::out_of_range(ss.str());
  }

}

const IMAGE_DATA_DIRECTORY & PEObject::getDataDirectoryEntry(WORD ndx)
{
  if (is64Bit)
    return pCompHeader->u_or.OptHdr64.DataDirectory[ndx];
  else
    return pCompHeader->u_or.OptHdr32.DataDirectory[ndx];
}

void PEObject::ReadImportTable()
{
  IMAGE_IMPORT_DESCRIPTOR ID;
  DWORD vaddr = LittleE2NativeBO(getDataDirectoryEntry(IMAGE_DIRECTORY_ENTRY_IMPORT).VirtualAddress);
  DWORD size = getDataDirectoryEntry(IMAGE_DIRECTORY_ENTRY_IMPORT).Size;

  if (0 == size)
    return;

  DWORD importTblOffset = Vaddr2Offset(vaddr);

  while(1)
  {
    inFileStream >> SetOffset(importTblOffset) >> ID; 
    if ( ID.RVAImportLookupTbl == 0 ) {
      break;
    }

    char dllname[MAX_SYM_SIZE];
    IMAGE_IMPORT_DESCRIPTOR l_ID;
    DWORD dllNameOffset     = Vaddr2Offset(LittleE2NativeBO(ID.Name));
    l_ID.RVAImportLookupTbl = Vaddr2Offset(LittleE2NativeBO(ID.RVAImportLookupTbl));
    l_ID.TimeDateStamp      = LittleE2NativeBO(ID.TimeDateStamp);
    l_ID.ForwarderChain     = LittleE2NativeBO(ID.ForwarderChain);
    l_ID.Name               = dllNameOffset;
    l_ID.RVAImportAddrTbl   = Vaddr2Offset(LittleE2NativeBO(ID.RVAImportAddrTbl));
    
     
    inFileStream >> SetOffset(dllNameOffset) >> dllname; 
    dllname[MAX_SYM_SIZE - 1] = 0;

    mImprtTbl.insert(dllname,l_ID);
    importTblOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR);

  }
}

void PEObject::ReadExportTable()
{
  IMAGE_EXPORT_DIRECTORY ED;
  DWORD vaddr = LittleE2NativeBO(getDataDirectoryEntry(IMAGE_DIRECTORY_ENTRY_EXPORT).VirtualAddress);
  DWORD size = getDataDirectoryEntry(IMAGE_DIRECTORY_ENTRY_EXPORT).Size;
  if (0 == size)
    return;

  DWORD exportTblOffset = Vaddr2Offset(vaddr);

  inFileStream >> SetOffset(exportTblOffset) >> ED; 

  char dllname[MAX_SYM_SIZE];
  IMAGE_EXPORT_DIRECTORY l_ED;
  DWORD dllNameOffset         = Vaddr2Offset(LittleE2NativeBO(ED.NameRVA));
  l_ED.ExportFlags            = LittleE2NativeBO(ED.ExportFlags); 
  l_ED.TimeDateStamp          = LittleE2NativeBO(ED.TimeDateStamp); 
  l_ED.MajorVersion           = LittleE2NativeBO(ED.MajorVersion);
  l_ED.MinorVersion           = LittleE2NativeBO(ED.MinorVersion);
  l_ED.NameRVA                = dllNameOffset;
  l_ED.OrdinalBase            = LittleE2NativeBO(ED.OrdinalBase);
  l_ED.NumberOfAddrTblEntries = LittleE2NativeBO(ED.NumberOfAddrTblEntries);
  l_ED.NumberOfNameTblEntries = LittleE2NativeBO(ED.NumberOfNameTblEntries);
  l_ED.RVAOfExportAddrTbl     = Vaddr2Offset(LittleE2NativeBO(ED.RVAOfExportAddrTbl));
  l_ED.RVAOfNamesTbl          = Vaddr2Offset(LittleE2NativeBO(ED.RVAOfNamesTbl));
  l_ED.RVAOFOrdinalTbl        = Vaddr2Offset(LittleE2NativeBO(ED.RVAOFOrdinalTbl)); 
    
  inFileStream >> SetOffset(dllNameOffset) >> dllname; 
  dllname[MAX_SYM_SIZE - 1] = 0;
  mExportTbl.insert(dllname,l_ED);
}

void PEExportDescriptor::ShowExportSymbols() 
{
  DWORD kount;
  DWORD symNameOffset;
  DWORD ordinalOffset = mED.RVAOFOrdinalTbl;
  DWORD offsetOFNamesTbl = mED.RVAOfNamesTbl;
  WORD  ordinal;
  std::cout << "DLL: "<< mExportDLL << std::endl; 
  std::cout << "Ordinal base:" << mED.OrdinalBase << std::endl;
  std::cout << std::setw(12)<< "Ordinal" <<  " Symbol Name" << std::endl;
  for ( kount=0; kount < mED.NumberOfNameTblEntries; kount++ )
  {
    char symName[MAX_SYM_SIZE];
    inFileStream >> SetOffset(offsetOFNamesTbl) >> symNameOffset; 
    symNameOffset = Vaddr2Offset(LittleE2NativeBO(symNameOffset));
    inFileStream >> SetOffset(symNameOffset) >> symName; 
    symName[MAX_SYM_SIZE - 1] = 0;
    inFileStream >> SetOffset(ordinalOffset) >> ordinal;
    ordinal = LittleE2NativeBO(ordinal); 
    std::stringstream ss;
    ss << "[" << std::dec << ordinal << "]";
    std::cout << std::setw(12) << ss.str() << " " << symName << std::endl;
    offsetOFNamesTbl += sizeof(DWORD);
    ordinalOffset += sizeof(WORD);
  }
}

