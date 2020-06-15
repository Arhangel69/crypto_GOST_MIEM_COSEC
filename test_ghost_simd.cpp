#include "test_ghost_simd.hpp"

namespace crypto
{

/*test_ghost_simd::test_ghost_simd(){}

/// test get_key(const uint8_t current_round)
bool test_ghost_simd::test_get_key()
{
    bool badResult = false;
    std::cout << "\nStarting test get_key...\n";
    crypto::ghost2814789_simd imit;
    const uint32_t KEYS_[8] = {0xF772316B, 0x225C45A1, 0x2CB5B620, 0x7A042DCA, 0xAD2A633E, 0x2619D373, 0x4957B027,
                               0x19F96B97};
    for (std::size_t i = 0; i < 8; i++)
    {
        if (imit.get_key(i) != KEYS_[i])
        {
            badResult = true;
            break;
        }
    }

    if (badResult)
    {
        std::cout << "get_key Error\n";
        return 1;
    } else
        std::cout << "Done!\n\n";
}

/// test splitBlocks(const uint32_t block, uint8_t splitMassive[4])
bool test_ghost_simd::test_splitBlocks()
{
    bool badResult = false;
    std::cout << "Starting test splitBlocks...\n";
    const uint32_t block = 0x12344321;
    const uint8_t EsplitMassive[4] = {0x12, 0x34, 0x43, 0x21};
    uint8_t splitMassive[4] = {0};
    crypto::splitBlocks(block, splitMassive);
    for (size_t i = 0; i < 4; i++)
    {
        if (EsplitMassive[i] != splitMassive[i])
        {
            badResult = true;
        }
    }
    if (badResult)
    {
        for (size_t i = 0; i < 4; i++)
        {
            std::cout << "splitBlocks Error\n";
            std::cout << std::hex << "Etalon" << i << ": " << EsplitMassive[i] << std::endl;
            std::cout << std::hex << "Curent" << i << ": " << splitMassive[i] << std::endl;
        }
        return 1;
    } else
        std::cout << "Done!\n\n";
}

/// test unsplitBlocks(const uint8_t splitMassive[4])
bool test_ghost_simd::test_unsplitBlocks()
{
    std::cout << "Starting test unsplitBlocks...\n";
    const uint32_t Eblock = 0x12344321;
    const uint8_t splitMassive[4] = {0x12, 0x34, 0x43, 0x21};
    uint32_t block = 0;
    block = crypto::unsplitBlocks(splitMassive);
    if (Eblock != block)
    {
        std::cout << "unsplitBlocks Error\n";
        std::cout << std::hex << "Etalon:  " << Eblock << std::endl;
        std::cout << std::hex << "Current: " << block << std::endl;
    } else
        std::cout << "Done!\n\n";
}

/// test stringToInt(const std::string &text)
bool test_ghost_simd::test_stringToInt()
{
    std::cout << "Starting test stringToInt...\n";
    std::string text = "01"; //0011 0000 0011 0001
    uint64_t result = crypto::stringToInt(text);
    uint64_t E_result = 12337;
    if (E_result == result)
    {
        std::cout << "Done!\n\n";
    } else
    {
        std::cout << "stringToInt Error\n";
        std::cout << "Etalon: " << E_result;
        std::cout << "\nCurrent: " << result << '\n';
        return 1;
    }
}

/// test setAiBi(const std::string &blockText)
bool test_ghost_simd::test_setAiBi_txt()
{
    std::cout << "Starting test setAiBi_text...\n";
    crypto::ghost2814789_simd imit;
    std::string blockText = "01233210";
    imit.setAiBi(blockText);
    uint32_t EAi = 0x30313233;
    uint32_t EBi = 0x33323130;
    if ((EAi == imit.Ai_) && (EBi == imit.Bi_))
    {
        std::cout << "Done!\n\n";
    } else
    {
        std::cout << "setAiBi_text Error\n";
        std::cout << std::hex << "Ai current: " << imit.Ai_;
        std::cout << std::hex << "\nAi etalon: " << EAi;
        std::cout << std::hex << "\nBi current: " << imit.Bi_;
        std::cout << std::hex << "\nBi etalon: " << EBi << '\n';
        return 1;
    }
}

/// test setAiBi(const uint64_t num)
bool test_ghost_simd::test_setAiBi()
{
    std::cout << "Starting test setAiBi_num...\n";
    ghost2814789_simd imit;
    imit.setAiBi(0x12344321ABCDDCBA);
    uint32_t EAi = 0x12344321;
    uint32_t EBi = 0xABCDDCBA;
    if ((EAi == imit.Ai_) && (EBi == imit.Bi_))
    {
        std::cout << "Done!\n\n";
    } else
    {
        std::cout << "setAiBi_num Error\n";
        std::cout << std::hex << "Ai current: " << imit.Ai_;
        std::cout << std::hex << "\nAi etalon: " << EAi;
        std::cout << std::hex << "\nBi current: " << imit.Bi_;
        std::cout << std::hex << "\nBi etalon: " << EBi << '\n';
        return 1;
    }
}

/// test cyclicShift(const uint32_t sBlock, const uint8_t numShift)
bool test_ghost_simd::test_cyclicShift()
{
    std::cout << "Starting test cyclicShift...\n";
    crypto::ghost2814789_simd imit;
    const uint32_t E_result = 0xFF88F1C; // 0000 1111 1111 1000 1000 1‬111 0001 1100
    const uint32_t sBlock = 0xE381FF11;  // 1110 0011 1000 0001 1111 1111 0001 0001‬
    uint32_t result = imit.cyclicShift(sBlock, CYCLIC_PITCH);
    if (E_result != result)
    {
        std::cout << "cyclicShift Error\n";
        std::cout << std::hex << "Started: " << sBlock;
        std::cout << std::hex << "\nEtalon:  " << E_result;
        std::cout << std::hex << "\nCurrent: " << result << '\n';
        return 1;
    } else
        std::cout << "Done!\n\n";
}

/// test replaceS_block(const uint32_t result)
bool test_ghost_simd::test_replaceS_block()
{
    std::cout << "Starting test replaceS_block...\n";
    crypto::ghost2814789_simd imit;
    const uint32_t num = 0xFFFFFFFF;
    const uint32_t E_result = 0x39B32ECC;
    uint32_t result = imit.replaceS_block(num);
    if (E_result != result)
    {
        std::cout << "replaceS_block Error\n";
        std::cout << std::hex << "Started: " << num;
        std::cout << std::hex << "\nEtalon:  " << E_result;
        std::cout << std::hex << "\nCurrent: " << result << '\n';
        return 1;
    } else
        std::cout << "Done!\n\n";
}

/// test func_f(const uint32_t A_cur, const uint32_t X_key)
bool test_ghost_simd::test_func_f()
{
    std::cout << "Starting test func_f...\n";
    crypto::ghost2814789_simd imit;
    const uint32_t A_cur = 0x12345678; // 305 419 896
    const uint32_t X_key = imit.get_key(0); //4 151 456 107‬
    // clear result 4 456 876 003‬ mod 2^32 = 161 908 707
    // after replaceS_block 0x4a69021e == 1 137 265 952
    // after cyclicShift 0x4a69021e == 1 248 395 806
    const uint32_t Eresult = 0x4a69021e;
    uint32_t result = imit.func_f(A_cur, X_key);
    if (Eresult != result)
    {
        std::cout << "func_f Error\n";
        std::cout << std::hex << "Etalon:  " << Eresult << std::endl;
        std::cout << std::hex << "Current: " << result << std::endl;
        return 1;
    } else
        std::cout << "Done!\n\n";
}

/// test simple_replacement(const uint8_t num_of_rounds)
bool test_ghost_simd::test_simple_replacement()
{
    std::cout << "Starting test simple_replacement...\n";
    crypto::ghost2814789_simd imit;
    const uint8_t num_of_rounds = 16;
    const uint64_t Eresult = 0x3f36103aabcddcba;
    imit.setAiBi(0x12344321ABCDDCBA);
    uint64_t result = imit.simple_replacement(num_of_rounds);
    if (Eresult != result)
    {
        std::cout << "func_f Error\n";
        std::cout << std::hex << "Etalon:  " << Eresult << std::endl;
        std::cout << std::hex << "Current: " << result << std::endl;
        return 1;
    } else
        std::cout << "Done!\n\n";
}

/// test choosingImitationInsert(const uint64_t evaluationResult, const uint8_t L)
bool test_choosingImitationInsert()
{
    std::cout << "Starting test choosingImitationInsert...\n";
    crypto::ghost2814789_simd imit;
    const uint64_t evaluationResult = 0x12344321ABCDDCBA;
    const uint8_t L = 32;
    const uint32_t E_result = 0x12344321;
    uint32_t result = imit.choosingImitationInsert(evaluationResult, L);
    if (E_result != result)
    {
        std::cout << "choosingImitationInsert Error\n";
        std::cout << std::hex << "\nEtalon:  " << E_result;
        std::cout << std::hex << "\nCurrent: " << result << '\n';
        return 1;
    } else
        std::cout << "Done!\n\n";
}

/// test imitovstavka(const std::string &openText)
bool test_ghost_simd::test_imitovstavka()
{
    std::cout << "Starting test imitovstavka...\n";
    const std::string msg = "24C. BaseSensor1";
    crypto::ghost2814789_simd imit;
    const uint32_t E_result = 0xdfa5b9ce;
    uint32_t result = imit.imitovstavka(msg);
    std::cout << "Test result: " << result << '\n';
    if (E_result != result)
    {
        std::cout << "imitovstavka Error\n";
        std::cout << "\nEtalon:  " << E_result;
        std::cout << "\nCurrent: " << result << '\n';
        return 1;
    } else
        std::cout << "Done!\n\n";
}

/// test get_imit_from_text(const std::string &openText)
bool test_ghost_simd::test_get_imit_from_text()
{
    std::cout << "Starting test get_imit_from_text...\n";
    const std::string msg = "24C. BaseSensor1<<**3752180174**>>";
    crypto::ghost2814789_simd imit;
    const uint32_t E_result = 0xdfa5b9ce;
    uint32_t result = imit.get_imit_from_text(msg);
    if (E_result != result)
    {
        std::cout << "get_imit_from_text Error\n";
        std::cout << std::hex << "\nEtalon:  " << E_result;
        std::cout << std::hex << "\nCurrent: " << result << '\n';
        return 1;
    } else
        std::cout << "Done!\n\n";
}

/// test get_open_text_from_text_with_imit(const std::string& textWithImit)
bool test_ghost_simd::test_get_open_text_from_text_with_imit()
{
    std::cout << "Starting test get_open_text_from_text_with_imit...\n";
    const std::string msg = "24C. BaseSensor1<<**3752180174**>>";
    crypto::ghost2814789_simd imit;
    const std::string E_result = "24C. BaseSensor1";
    std::string result = imit.get_open_text_from_text_with_imit(msg);
    if (E_result != result)
    {
        std::cout << "get_imit_from_text Error\n";
        std::cout << "\nEtalon:  " << E_result;
        std::cout << "\nCurrent: " << result << '\n';
        return 1;
    } else
        std::cout << "Done!\n\n";
}

/// test check_imitovstavka(const std::string &openText)
bool test_ghost_simd::test_check_imitovstavka()
{
    std::cout << "Starting test check_imitovstavka...\n";
    const std::string msg = "24C. BaseSensor1<<**3752180174**>>";
    crypto::ghost2814789_simd imit;
    bool checked_result;
    bool E_checked_result = true;
    checked_result = imit.check_imitovstavka(msg);
    if (E_checked_result != checked_result)
    {
        std::cout << "check_imitovstavka Error\n";
        return 1;
    } else
        std::cout << "Done!\n\n";
}*/
}
