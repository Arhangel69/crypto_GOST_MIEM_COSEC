#include <iostream>
#include <string>
#include <cstdint>
#include "ghost2814789.h"

#define bn 1275196581750192750921735621973691275023521570275607261251

int main()
{
    //std::string msg = "0123456789ABCCEF";
    std::string msg = "53C. BaseSensor1"; // 3752305998
    std::cout << "Your message: " << msg << std::endl;
    std::cout << "Your message len: " << msg.length() << std::endl;
    crypto::ghost2814789 imit;
    // Run1 115852435
    // Run2 115563667
    uint64_t result = imit.imitovstavka(msg);
    std::cout << "Imitovstavka: " << result << std::endl;
}
