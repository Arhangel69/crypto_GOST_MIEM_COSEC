#include "ghost2814789_simd.hpp"

// TODO
uint64_t crypto::ghost2814789_simd::simple_replacement(const uint8_t num_of_rounds)
{
    for (uint8_t i = 1; i < num_of_rounds; i++)
    {
        __m256i Xi = _mm256_set1_epi16(get_key(i));
        Ai1_ = _mm256_xor_epi32(Ai_, Xi);
        //Ai1_ = Bi_ ^ func_f(Ai_, Xi);
        Bi1_ = Ai_;
    }

    __m256i result_1 = {0};
    __m256i result_2 = {0};
    result_1 |= ((result_1 | Ai1_) << 32);
    result_2 |= Bi_;
    //result |= ((result | Ai1_) << 32);
    //result |= Bi_;
    //__m512i result = {result_1, result_2};
    uint64_t result = (_mm256_cvtsi256_si32(result_1));
    result = (result<<32) + _mm256_cvtsi256_si32(result_2);
    return result;
}

// TODO
uint32_t crypto::ghost2814789_simd::replaceS_block(const uint32_t result)
{
    uint8_t sBlocks[4] = {0};
    uint32_t sBlock = 0;
    uint32_t result_ = result;
    splitBlocks(result_, sBlocks);
    uint8_t sBlocksNew[4] = {0};
    for (uint8_t i = 0; i < 4; i++)
    {
        sBlocksNew[i] |= sBlock_[i * 2][sBlocks[i] >> 4] << 4;
        sBlocksNew[i] |= sBlock_[i * 2 + 1][sBlocks[i] & 0x0F];
    }
    sBlock = unsplitBlocks(sBlocksNew);
    return sBlock;
}

// TODO
uint32_t crypto::ghost2814789_simd::cyclicShift(const uint32_t sBlock, const uint8_t numShift)
{
    uint32_t sBlockNew = sBlock;
    uint8_t numShift_ = numShift % static_cast<uint8_t>(32);
    uint32_t partCycle = sBlockNew >> (32 - numShift_);
    sBlockNew = (sBlockNew << numShift_) | partCycle;
    return sBlockNew;
}

// TODO
uint32_t crypto::ghost2814789_simd::func_f(const uint32_t A_cur, const uint32_t X_key)
{
    uint64_t twoIn32 = 4294967296;
    uint32_t result = static_cast<uint32_t >((A_cur + X_key) % twoIn32);
    result = replaceS_block(result);
    result = cyclicShift(result, CYCLIC_PITCH);
    return result;
}

// TODO
uint32_t crypto::ghost2814789_simd::get_key(const uint8_t current_round)
{
    return KEYS_[current_round % 8];
}

// TODO
void crypto::splitBlocks(const uint32_t block, uint8_t splitMassive[4])
{
    uint32_t block_ = block;
    for (uint8_t i = 0; i < 4; i++)
    {
        splitMassive[3 - i] |= (block_ & 0x000000FF);
        block_ >>= 8;
    }
}

// TODO
uint32_t crypto::unsplitBlocks(const uint8_t splitMassive[4])
{
    uint32_t sBlock = 0;
    for (uint8_t i = 0; i < 4; i++)
    {
        sBlock |= splitMassive[i];
        if (i != 3)
            sBlock <<= 8;
    }
    return sBlock;
}

// DONE
crypto::ghost2814789_simd::ghost2814789_simd()
{
    Ai_ = {0};
    Ai1_ = {0};
    Bi_ = {0};
    Bi1_ = {0};
}

// DONE
void crypto::ghost2814789_simd::setAiBi(const std::string &blockText)
{
    uint32_t Ai_h = 0;
    uint32_t Bi_h = 0;
    for (uint16_t i = 0; i < 4; i++)
    {
        Ai_h |= blockText[i];
        Bi_h |= blockText[i + 4];
        if (i < 3)
        {
            Ai_h <<= 8;
            Bi_h <<= 8;
        }
    }
    Ai_ = _mm256_set1_epi16(Ai_h);
    Bi_ = _mm256_set1_epi16(Bi_h);
}

// DONE
void crypto::ghost2814789_simd::setAiBi(const uint64_t num)
{
    Ai_ = _mm256_set1_epi16(static_cast<uint32_t >(num >> 32));
    Bi_ = _mm256_set1_epi16(static_cast<uint32_t >(num));
}

// TODO
uint32_t crypto::ghost2814789_simd::choosingImitationInsert(const uint64_t evaluationResult, const uint8_t L)
{
    uint32_t result = 0;
    result |= (evaluationResult >> 32);
    result <<= (32 - L);
    result >>= (32 - L);
    return result;
}

// TODO
__m512i crypto::stringToInt(const std::string &text)
{
    uint64_t result = 0;
    uint8_t size = static_cast<uint8_t >(text.length());
    for (uint8_t i = 0; i < size; i++)
    {
        result |= (text[i]);
        if (i < size - 1)
            result <<= 8;
    }
    return _mm512_set1_epi64(result);
}

// TODO
uint32_t crypto::ghost2814789_simd::imitovstavka(const std::string &openText)
{
    uint64_t result = 0;
    uint8_t num_of_rouds = 0;
    size_t lenRaw = openText.length();
    size_t lenInsuf = openText.length() % 8;
    size_t lenNew = lenRaw;
    if (lenInsuf > 0)
    {
        lenNew += 8 - lenInsuf;
    }
    std::string workText = openText;
    if (lenInsuf > 0)
    {
        for (size_t i = lenRaw; i < lenNew; i++)
        {
            workText += '\0';
        }
    }
    num_of_rouds = static_cast<uint8_t >(lenNew / 8 - 1);
    std::string workPart = workText.substr(0, 8);
    workText = workText.substr(8, workText.length());
    setAiBi(workPart);
    result = simple_replacement(16);
    for (std::uint8_t i = 0; i < num_of_rouds; i++)
    {
        workPart = workText.substr(0, 8);
        workText = workText.substr(8, workText.length());
        result = _mm512_cvtsi512_si32(_mm512_xor_epi64(_mm512_set1_epi64(result), stringToInt(workPart)));
        //result ^= stringToInt(workPart);
        setAiBi(result);
        result = simple_replacement(16);
    }
    uint32_t imitovstavka = choosingImitationInsert(result, L_);
    reset();
    return imitovstavka;
}

// TODO
uint32_t crypto::ghost2814789_simd::get_imit_from_text(const std::string &textWithImit)
{
    std::string imitovstavka;
    std::size_t startPos = textWithImit.find("<<**");
    if (startPos == -1)
    {
        return 0;
    }
    startPos += 4;
    imitovstavka = textWithImit.substr(startPos, textWithImit.length());
    std::size_t endPos = imitovstavka.find("**>>");
    //std::size_t endPos = textWithImit.find("**>>");
    if (endPos == -1)
    {
        return 0;
    }
    // imitovstavka = textWithImit.substr(startPos, endPos); // don't work!!!
    // but imitovstavka = textWithImit.substr(startPos, endPos-20); work
    imitovstavka = imitovstavka.substr(0, endPos);
    return static_cast<uint32_t >(atoi(imitovstavka.c_str()));
}

// TODO
std::string crypto::ghost2814789_simd::get_open_text_from_text_with_imit(const std::string& textWithImit)
{
    std::string openText;
    std::size_t endPos = textWithImit.find("<<**");
    if (endPos == -1)
    {
        openText = textWithImit;
    }
    openText = textWithImit.substr(0, endPos);
    return openText;
}

// TODO
bool crypto::ghost2814789_simd::check_imitovstavka(const std::string &textWithImit)
{
    uint32_t imit_to_check = get_imit_from_text(textWithImit);
    uint32_t calculated_imit = imitovstavka(get_open_text_from_text_with_imit(textWithImit));
    reset();
    return (imit_to_check==calculated_imit);
}

// DONE
void crypto::ghost2814789_simd::reset()
{
    Ai_ = {0};
    Ai1_ = {0};
    Bi_ = {0};
    Bi1_ = {0};
}
