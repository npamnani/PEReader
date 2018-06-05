#include "PEFileStructs.h"
#include "PEUtils.h"
#include "PEReader.h"

ArgInterp::ArgInterp(int argc, char **argv)
{
  progname = argv[0];
  for(WORD ndx = 1;argv[ndx];ndx++)
  {
    if (!std::string("-i").compare(argv[ndx]))
      funcList["3.Import Table"] = &PEObject::ShowImportSymbols;
    else if (!std::string("-e").compare(argv[ndx]))
      funcList["4.Export Table"] = &PEObject::ShowExportSymbols;
    else if (!std::string("-a").compare(argv[ndx]))
      funcList["1.Signature"] = &PEObject::ShowSignature;
    else if (!std::string("-s").compare(argv[ndx]))
      funcList["2.Sections"] = &PEObject::ShowSections;
    else if (!std::string("-I").compare(argv[ndx]))
      funcList["5.Imported DLLs"] = &PEObject::ShowImportDLLs;
    else if (!std::string("-h").compare(argv[ndx]))
      throw std::invalid_argument ("");
    else if (!std::string(argv[ndx]).substr(0,1).compare("-"))
      throw std::invalid_argument(std::string("Invalid option ") + argv[ndx]);
    else if (filename.size()) 
      throw std::invalid_argument(std::string("Extraneous Argument ") + argv[ndx]);
    else
      filename= argv[ndx];
  }
  if (!filename.size())
    throw std::invalid_argument ("Argument Missing, provide (EXE/DLL)");
  if (!funcList.size())
    funcList["All"] = &PEObject::ShowAll;
}

ArgInterp::Iterator ArgInterp::Iterator::operator ++()
{
     ++map_iter;
     return *this;
}
ArgInterp::Iterator ArgInterp::Iterator::operator ++(int)
{
   Iterator tmp = *this;
   ++*this;
   return tmp;
}
void ArgInterp::Iterator::operator ()()
{
  PEObject & peobj = PEObject::getPEObject(pArg->fileName().c_str());
  (peobj.*map_iter->second)();
}
bool ArgInterp::Iterator::operator !=(Iterator const & iter)
{
    return this->map_iter != iter.map_iter;
}
   
ArgInterp::Iterator ArgInterp::begin()
{
   map_iterator iter= funcList.begin();
   return Iterator(iter,this);
}

ArgInterp::Iterator ArgInterp::end()
{
  map_iterator iter= funcList.end();
  return Iterator(iter,this);
}

void Usage(char **argv)
{
  std::cerr << "Usage: " << argv[0] << " <options> "  << "EXE/DLL" << std::endl
            << "options:" << std::endl
            << " -a Signature of EXE/DLL" << std::endl
            << " -s List Sections" << std::endl
            << " -i Show Import Table" << std::endl
            << " -e Show Export Table" << std::endl
            << " -I Show Imported DLLs name" << std::endl
            << "Show all if no option is specified." << std::endl;
}

int main(int argc, char **argv)
{

  std::string prog;
  std::string exe_or_dll;
  try 
  {
    ArgInterp argp(argc,argv);
    prog = argp.progName();
    exe_or_dll = argp.fileName();
    ArgInterp::Iterator iter = argp.begin();
    while(iter != argp.end())
    {
      iter();
      ++iter;
    }
  }
  catch (std::runtime_error &eObj)
  {
    std::cerr << eObj.what() << std::endl;
  }
  catch (std::invalid_argument &eObj)
  {
    std::cerr << eObj.what() << std::endl;
    Usage(argv);
  }
  catch (std::out_of_range &eObj)
  {
    std::cerr << eObj.what() << std::endl;
    std::cerr << "Try: " << prog << " " << "-s " << exe_or_dll << std::endl
              << " to list the various section ranges" << std::endl;
  }
  return 0;
}

