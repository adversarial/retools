/*
    RgnScanner.hpp
        by adversarial

    Released under MIT license.
*/

#include <string>
#include <vector>
#include <exception>

#ifdef _WIN32
#include <Windows.h>
#else
#error "No support for non-Windows OSs!"
#endif

class RgnScanner {
/*
    RgnScanner
        by adversarial

    A small library to aid in patching. UnsafeScan can be used to search
    an entire process' address space. Uses IDA style sigs

        "1Fx02?2."

    Supported wildcards:
*/  
    // Internal wildcard list
    const std::string WildCards = "?x.*";
/*
    
    This list can be changed by creating a child class that overrides either
    InternalScan, InternalCmp, or InternalIsWildCard, which are respectively
    lower level. 

    Safe Scan:
        Will only return pages that already have read attribute

    Unsafe Scan:
        Scans can potentially return non-accessible memory pages
        (VirtualProtect/ReadProcessMemory or another equivalent
        function must be used to get read access to the pages).

    Internal Scan:
        Is called by SafeScan & UnsafeScan, contains scanning logic.
        It is allowed to be overridden by child classes to enable users
        to include their own scanning logic to support different masks.
*/
private:
    // Points to the scanning region
    const void* RgnBase;
    // Size in bytes of the region
    std::ptrdiff_t RgnLen;

protected:
    // Returns if c should be accepted as a substitute for any hex character
    virtual bool InternalIsWildCard(const char c);
    // Returns if the MaskedByte of 2 chars in hi-lo form HL (e.g. "10") is equivalent to the target (e.g. 0x10)
    virtual bool InternalCmp(const std::string& MaskedByte, const void* TargetByte);
    // Can return false to stop scanning of memory (on error?)
    virtual bool InternalScan(const void* Base, std::ptrdiff_t Len, const std::string& Mask, std::vector<const void*>& Matches);

public:
    // Internal region size is Base - End
    RgnScanner(const void* Base, const void* End);
    RgnScanner(const void* Base, std::ptrdiff_t Len);

    bool SafeScan(const std::string& Mask, std::vector<const void*>& Matches);
    bool UnsafeScan(const std::string& Mask, std::vector<const void*>& Matches);
    bool Scan(const std::string& Mask, std::vector<const void*>& Matches, bool SafeMode = true);

    class RgnBoundsException : public std::exception {

        virtual const char* what() const throw() {
            return "Region length must be a positive value";
        }

    } RgnOutOfBoundsException; // those java name styles
};

int main() {

    RgnScanner Mem(NULL, 0xffffff);
    std::vector<const void*> Matches;

    return (int)Mem.SafeScan("lol", Matches);
}