/**
	AUTHOR: nishant_pamnani@yahoo.com
**/
#ifndef _PEREADER_H_
#define _PEREADER_H_

#define BUFF_SIZE     4096
#define MAX_SYM_SIZE  256


class PEObject;
class PEImportDescriptor; 
class PEExportDescriptor; 

template <typename DESCRIPTOR_INTERP, typename DESCRIPTOR>
class GenPETable
{
  
  public:

    typedef typename std::map<std::string, DESCRIPTOR>::iterator iterator;
    class Iterator 
    {
      public:
        typedef Auto_Ptr<DESCRIPTOR_INTERP> DescInterP;
        Iterator(iterator const & it):miter(it){}

        DescInterP operator->() 
        {
          DescInterP pdesc(new DESCRIPTOR_INTERP(miter->second,miter->first));
          return pdesc;
        }

        DescInterP operator*() 
        {
          DescInterP pdesc(new DESCRIPTOR_INTERP(miter->second,miter->first));
          return pdesc;
        }

        Iterator operator ++()
        {
          ++miter;
          return *this;
        }

        Iterator operator ++(int)
        {
          Iterator tmp = *this;
          ++*this;
          return tmp;
        }

        bool operator != (Iterator const & iter)
        {
          return this->miter != iter.miter;
        }

      private:
        iterator miter;
        
       
    };
    void insert(std::string const & key, DESCRIPTOR & tbldes)
    {
      mTbl[key] = tbldes;
    }

    Iterator begin()
    {
      return Iterator(mTbl.begin());
    }

    Iterator end()
    {
      return Iterator(mTbl.end());
    }

    bool empty() { return mTbl.size() == 0 ; }
  private:
    std::map<std::string,DESCRIPTOR> mTbl;
   
};

class PEObject{

  public:

    static PEObject & getPEObject(char const * const = NULL);

    void ShowObjectPEType(bool useNewLine = false);
    void ShowMachineType(bool useNewLine = false);
    void ShowFileType(bool useNewLine = false);
    void ShowSections();
    void ShowSignature();
    void ShowImportDLLs();
    void ShowImportSymbols();
    void ShowExportSymbols();
    void ShowAll();

    bool Is64Bit() { return is64Bit;}
    DWORD Vaddr2Offset(DWORD);
    std::ifstream & getFileStream()
    {
      return inFileStream;
    }
    const IMAGE_DATA_DIRECTORY & getDataDirectoryEntry(WORD);
  private:
    PEObject(char const * const); 
    PEObject(PEObject const &); 
    void ReadInitialHeaders(); 
    void ReadSectionHeaders();
    void ReadImportTable();
    void ReadExportTable();
    void GetObjectPEType();
    void ProcessSectionHeader(IMAGE_SECTION_HEADER &);

  private:
    std::ifstream inFileStream; 
    Auto_Ptr<IMAGE_PE_COMPOSITE_HEADERS>  pCompHeader;
    std::vector<IMAGE_SECTION_HEADER> mSectionHeaders;
    typedef GenPETable<PEImportDescriptor,IMAGE_IMPORT_DESCRIPTOR> IMTable; 
    IMTable mImprtTbl; 
    typedef GenPETable<PEExportDescriptor,IMAGE_EXPORT_DIRECTORY>  EXTable; 
    EXTable mExportTbl; 
    DWORD offsetPESignature;
    WORD mNumberOfSections;
    bool is64Bit; 
};

class PEImportDescriptor {
  public:
    PEImportDescriptor(IMAGE_IMPORT_DESCRIPTOR const & ID, std::string const & dll): 
                       mID(ID),
                       mImportDLL(dll),
                       peObj(PEObject::getPEObject()),
                       inFileStream(peObj.getFileStream()){}

    void ShowImportSymbols()
    {
      if ( peObj.Is64Bit() )
        ShowDLLSymbols<THUNK_TRAITS64>(); 
      else  
        ShowDLLSymbols<THUNK_TRAITS32>(); 
    }

    std::string const & getImportDLL() { return mImportDLL;}
  private:
    struct THUNK_TRAITS64 {
      typedef IMAGE_THUNK_DATA64 THUNK_TYPE;
      static const ULONGLONG BIT_MASK = BIT_MASK64;
    };

    struct THUNK_TRAITS32 {
      typedef IMAGE_THUNK_DATA32 THUNK_TYPE;
      static const LONG BIT_MASK = BIT_MASK32;
    };

    template <typename TRAITS> 
    void ShowDLLSymbols();

    template <typename TRAITS>
    void GetSymbolName(typename TRAITS::THUNK_TYPE & ITData);

    DWORD Vaddr2Offset(DWORD vaddr)
    {
      return peObj.Vaddr2Offset(vaddr);
    }
  private:  
    IMAGE_IMPORT_DESCRIPTOR mID;
    const std::string mImportDLL;
    PEObject & peObj;
    std::ifstream & inFileStream; 

    
};

template <typename TRAITS> 
void  PEImportDescriptor::ShowDLLSymbols()
{
  DWORD ImpNameTblOffset = mID.RVAImportLookupTbl;
  typedef typename TRAITS::THUNK_TYPE  IMAGE_THUNK_TYPE;
  IMAGE_THUNK_TYPE iTData; 
  
  inFileStream >> SetOffset(ImpNameTblOffset) >> iTData; 
  std::cout << "DLL: "<< mImportDLL << std::endl; 
  std::cout << std::setw(16)  << "RVA" 
            << std::setw(13)  << "Ordinal/Hint" 
            << " Symbol Name" << std::endl;
  while ( iTData.AddressOfData )
  {
    if ( LittleE2NativeBO(iTData.AddressOfData) & TRAITS::BIT_MASK ) { 
      std::cout << std::setw(16) << std::hex << LittleE2NativeBO(iTData.AddressOfData) 
                << std::setw(13) << std::dec << (LittleE2NativeBO(iTData.Ordinal) & ~TRAITS::BIT_MASK)
                << " <none>" 
                << std::endl;
    } else {
      GetSymbolName<TRAITS>(iTData);
    }
    ImpNameTblOffset += sizeof(IMAGE_THUNK_TYPE);
    inFileStream >> SetOffset(ImpNameTblOffset) >> iTData; 
  }
}

template <typename TRAITS>
void PEImportDescriptor::GetSymbolName(typename TRAITS::THUNK_TYPE & ITData)
{
  IMAGE_IMPORT_BY_NAME iName;
  DWORD symNameOffset = Vaddr2Offset(LittleE2NativeBO(ITData.AddressOfData));
  inFileStream >> SetOffset(symNameOffset) >> iName; 
  std::cout << std::setw(16) << std::hex << LittleE2NativeBO(ITData.AddressOfData) 
            << std::setw(13)  << std::dec << LittleE2NativeBO(iName.Hint) 
            << " " << iName.Name 
            << std::endl;

}

class PEExportDescriptor {

  public:
    PEExportDescriptor(IMAGE_EXPORT_DIRECTORY const & ED, std::string const & dll): 
                       mED(ED),
                       mExportDLL(dll),
                       peObj(PEObject::getPEObject()),
                       inFileStream(peObj.getFileStream())
    {
      mEDDEntry =  peObj.getDataDirectoryEntry(IMAGE_DIRECTORY_ENTRY_EXPORT);
      mEDDEntry.VirtualAddress = LittleE2NativeBO(mEDDEntry.VirtualAddress);
      mEDDEntry.Size =  LittleE2NativeBO(mEDDEntry.Size);
    }

    void ShowExportSymbols();
    std::string const & getExportDLL() { return mExportDLL;}

  private:
    DWORD Vaddr2Offset(DWORD vaddr)
    {
      return peObj.Vaddr2Offset(vaddr);
    }
  private:  
    IMAGE_EXPORT_DIRECTORY mED;
    const std::string mExportDLL;
    PEObject & peObj;
    std::ifstream & inFileStream; 
    IMAGE_DATA_DIRECTORY mEDDEntry;
};

#endif
