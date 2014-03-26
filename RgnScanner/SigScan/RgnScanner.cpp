#include "RgnScanner.hpp"

#include <climits>
#include <cstdlib>
#include <cstdint>

RgnScanner::RgnScanner(const void* Base, const void* End) 
{
    RgnScanner(Base, (std::ptrdiff_t)End - (std::ptrdiff_t)Base);
}

RgnScanner::RgnScanner(const void* Base, std::ptrdiff_t Len) 
 : RgnBase(Base),
   RgnLen(Len)
{
    if (Len <= 0)
        throw RgnOutOfBoundsException;
}

#pragma region InternalXxx (Overrideable functions)
bool RgnScanner::InternalIsWildCard(const char c) {

    return WildCards.find(c) != std::string::npos ? true : false;
}

bool RgnScanner::InternalCmp(const std::string& MaskedByte, const void* TargetByte) {

    const unsigned char* Target = (const unsigned char*)TargetByte;

    return ((InternalIsWildCard(MaskedByte[0])  // Hi nibble
     || strtol(MaskedByte.substr(0, 1).c_str(), NULL, 16) == *Target & 0xf0)
    && (InternalIsWildCard(MaskedByte[1])       // Lo nibble
     || strtol(MaskedByte.substr(1, 2).c_str(), NULL, 16) == *Target & 0x0f));
}

bool RgnScanner::InternalScan(const void* Base, std::ptrdiff_t Len, const std::string& Mask, std::vector<const void*>& Matches) {
    
    const char* TargetByte = static_cast<const char*>(Base);

    for (auto i = Len; i; ++i, ++TargetByte) {
        std::size_t CurMaskIndex = 0;
        while (InternalCmp(Mask.substr(CurMaskIndex, CurMaskIndex + 2), TargetByte)) {
            if (CurMaskIndex >= Mask.length()) {
                Matches.push_back(static_cast<const void*>((static_cast<const char*>(Base) + i)));
                goto NextByte;
            }
            ++TargetByte;
            CurMaskIndex += 2;
        }
    // Label here instead of break statement in while loop to avoid confusion
    NextByte:
    }

    return true;
}
#pragma endregion

bool RgnScanner::SafeScan(const std::string& Mask, std::vector<const void*>& Matches) {

    return Scan(Mask, Matches, true);
}

bool RgnScanner::UnsafeScan(const std::string& Mask, std::vector<const void*>& Matches) {
    
    return Scan(Mask, Matches, false);
}

bool RgnScanner::Scan(const std::string& Mask, std::vector<const void*>& Matches, bool SafeMode /* = true*/) {

    SYSTEM_INFO SysInfo = { 0 };
    GetSystemInfo(&SysInfo);

    for (const unsigned char* p = static_cast<const unsigned char*>(RgnBase); p < (const unsigned char*)RgnBase + RgnLen;) {
        MEMORY_BASIC_INFORMATION PageInfo;
        VirtualQuery(p, &PageInfo, sizeof(PageInfo));

        // Second bit of each nibble is R attribute
        if (PageInfo.Protect & 0x22
          || !SafeMode) {

            // Check number of bytes left 
            // (RgnEnd - p) > 0 ? continue : exit
            const std::ptrdiff_t CurScanLeft = (const unsigned char*)RgnBase + RgnLen - p;
            if (CurScanLeft <= 0)
                break;

            // Scan only current page
            std::ptrdiff_t CurRgnSize = CurScanLeft > PageInfo.RegionSize ? PageInfo.RegionSize : CurScanLeft;

            // Implementation defined InternalScan may return false to quit scan
            if (!InternalScan(p, CurRgnSize, Mask, Matches))
                return false;
        }

        // Advance to next page
        p = (const unsigned char*)((char*)PageInfo.BaseAddress + PageInfo.RegionSize);
    }
    return true;
}