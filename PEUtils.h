/**
	AUTHOR: nishant_pamnani@yahoo.com
**/
#ifndef _PEUTILS_H_
#define _PEUTILS_H_

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <stdexcept>
#include <string>
#include <map>

class PEObject;
struct __setOffset {
    __setOffset(DWORD offset, char const *file,unsigned line):
               _offset(offset),
                filename(file),
                lineno(line){}
    operator DWORD() const { return _offset; }
    std::string getErrLocation () const
    {
      std::stringstream ss;
      ss << filename << ":" << lineno;
      return ss.str();
    }
  private:
    const DWORD _offset;
    char const *filename;
    const unsigned lineno;
     
};

inline 
__setOffset SetOffset(DWORD offset, char const *file, unsigned line)
{
  return __setOffset(offset,file,line); 
} 

#define SetOffset(x) SetOffset(x,__FILE__,__LINE__)

inline 
void checkStatus(std::ifstream & in, __setOffset const & offset)
{
  if(in.rdstate()) 
  {
    std::string err = std::string("I/O error at ") + offset.getErrLocation();
    throw std::runtime_error(err);
  }
}

template <typename T>
inline
std::ifstream & operator >> (std::ifstream & in, T & Obj)
{
  in.read(reinterpret_cast<char*>(&Obj), sizeof(T)); 
  return in;
}

inline
std::ifstream & operator >> (std::ifstream & in, __setOffset const & offset)
{
  in.seekg(offset, std::ios::beg);
  checkStatus(in, offset);
  return in;
}


enum Endianness {LittleEndian = 0, BigEndian = 1};
template<Endianness BO, typename T>
inline T Convert2NativeBO(T Obj)
{

  BYTE arr[16] = {0};
  *reinterpret_cast<T*>(&arr[8]) = Obj;

  return (T(arr[8 + sizeof(T) - 1 ]) << ( ((sizeof(T) - 1) ^ ( (sizeof(T) -1) * BO )) * 8)
         |T(arr[8 + sizeof(T) - 2 ]) << ((((sizeof(T) - 2) & (sizeof(T)-1))^((sizeof(T) -1) * BO )) * 8)
         |T(arr[8 + sizeof(T) - 3 ]) << ((((sizeof(T) - 3) & (sizeof(T)-1))^((sizeof(T) -1) * BO )) * 8) 
         |T(arr[8 + sizeof(T) - 4 ]) << ((((sizeof(T) - 4) & (sizeof(T)-1))^((sizeof(T) -1) * BO )) * 8) 
         |T(arr[8 + sizeof(T) - 5 ]) << ((((sizeof(T) - 5) & (sizeof(T)-1))^((sizeof(T) -1) * BO )) * 8) 
         |T(arr[8 + sizeof(T) - 6 ]) << ((((sizeof(T) - 6) & (sizeof(T)-1))^((sizeof(T) -1) * BO )) * 8) 
         |T(arr[8 + sizeof(T) - 7 ]) << ((((sizeof(T) - 7) & (sizeof(T)-1))^((sizeof(T) -1) * BO )) * 8) 
         |T(arr[8 + sizeof(T) - 8 ]) << ((((sizeof(T) - 8) & (sizeof(T)-1))^((sizeof(T) -1) * BO )) * 8));
}

template <typename T>
inline T LittleE2NativeBO(T Obj)
{
  return Convert2NativeBO<LittleEndian>(Obj);
}

template <typename T>
inline T BigE2NativeBO(T Obj)
{
  return Convert2NativeBO<BigEndian>(Obj);
}

class ArgInterp {
  public:

    typedef void (PEObject::*ShowFunc_t)();
    typedef std::map<std::string, ShowFunc_t>::iterator map_iterator;
    ArgInterp(int argc, char **argv);

    class Iterator {
      public:
        Iterator(map_iterator & iter,ArgInterp *aIP):map_iter(iter),pArg(aIP){}
        Iterator operator ++();
        Iterator operator ++(int);
        void operator ()();
        bool operator !=(Iterator const & iter);
      private:
        map_iterator map_iter;
        ArgInterp * pArg;
    };

    Iterator begin();
    Iterator end();
    std::string const & fileName() const  { return filename;}
    std::string const & progName() const { return progname;}
  private:
    std::map<std::string,ShowFunc_t> funcList;
    std::string filename;
    std::string progname;
};

template <typename T>
class Auto_Ptr
{
  public:
    explicit Auto_Ptr(T * ptr = 0):_ptr(ptr){}

    ~Auto_Ptr() { delete _ptr; };

    Auto_Ptr(Auto_Ptr const & cap)
    {
      Auto_Ptr & ap = const_cast<Auto_Ptr&>(cap);
      _ptr = ap._ptr;
      ap._ptr = 0;
    }

    Auto_Ptr & operator=(Auto_Ptr const & cap)
    {
      Auto_Ptr & ap = const_cast<Auto_Ptr&>(cap);
      if ( this == &ap )
        return *this;
      if (_ptr)
        delete _ptr;
      _ptr = ap._ptr;
      ap._ptr = 0;
      return *this;
    }
    
    T* operator->()
    {
      return _ptr;
    }

    T& operator*()
    {
      return *_ptr;
    }

    operator bool()
    {
      return _ptr != 0;
    }

  private:
    T *_ptr;
};

#endif
