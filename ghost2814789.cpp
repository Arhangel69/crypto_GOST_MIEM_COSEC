#ifndef TESTS

#include "ghost2814789.h"

#else
#include "ghostopen.h"
#endif

uint64_t crypto::ghost2814789::simple_replacement(const uint8_t num_of_rounds) //done
{
    for (uint8_t i = 1; i < num_of_rounds; i++)
    {
        uint32_t Xi = get_key(i);
        Ai1_ = Bi_ ^ func_f(Ai_, Xi);
        Bi1_ = Ai_;
    }

    uint64_t result = 0;
    result |= ((result | Ai1_) << 32);
    result |= Bi_;
    return result;
}

uint32_t crypto::ghost2814789::func_f(const uint32_t A_cur, const uint32_t X_key) //done
{
    uint64_t twoIn32 = 4294967296;
    uint32_t result = static_cast<uint32_t >((A_cur + X_key) % twoIn32);
    result = replaceS_block(result);
    result = cyclicShift(result, CYCLIC_PITCH);
    return result;
}

uint32_t crypto::ghost2814789::get_key(const uint8_t current_round) //done
{
    return KEYS_[current_round % 8];
}

void crypto::splitBlocks(const uint32_t block, uint8_t splitMassive[4]) //done
{
    uint32_t block_ = block;
    for (uint8_t i = 0; i < 4; i++)
    {
        splitMassive[3 - i] |= (block_ & 0x000000FF);
        block_ >>= 8;
    }
}

uint32_t crypto::unsplitBlocks(const uint8_t splitMassive[4]) //done
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

uint32_t crypto::ghost2814789::replaceS_block(const uint32_t result) //done
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

uint32_t crypto::ghost2814789::cyclicShift(const uint32_t sBlock, const uint8_t numShift) //done
{
    uint32_t sBlockNew = sBlock;
    uint8_t numShift_ = numShift % static_cast<uint8_t>(32);
    uint32_t partCycle = sBlockNew >> (32 - numShift_);
    sBlockNew = (sBlockNew << numShift_) | partCycle;
    return sBlockNew;
}

crypto::ghost2814789::ghost2814789()
{
    Ai_ = 0;
    Ai1_ = 0;
    Bi_ = 0;
    Bi1_ = 0;
}

crypto::ghost2814789::~ghost2814789()
{

}

void crypto::ghost2814789::setAiBi(const std::string &blockText) //done
{
    for (uint16_t i = 0; i < 4; i++)
    {
        Ai_ |= blockText[i];
        Bi_ |= blockText[i + 4];
        if (i < 3)
        {
            Ai_ <<= 8;
            Bi_ <<= 8;
        }
    }
}

void crypto::ghost2814789::setAiBi(const uint64_t num) //done
{
    Ai_ = static_cast<uint32_t >(num >> 32);
    Bi_ = static_cast<uint32_t >(num);
}

uint32_t crypto::ghost2814789::choosingImitationInsert(const uint64_t evaluationResult, const uint8_t L) //done
{
    uint32_t result = 0;
    result |= (evaluationResult >> 32);
    result <<= (32 - L);
    result >>= (32 - L);
    return result;
}

uint64_t crypto::stringToInt(const std::string &text) //done
{
    uint64_t result = 0;
    uint8_t size = static_cast<uint8_t >(text.length());
    for (uint8_t i = 0; i < size; i++)
    {
        result |= (text[i]);
        if (i < size - 1)
            result <<= 8;
    }
    return result;
}

uint32_t crypto::ghost2814789::imitovstavka(const std::string &openText) //done
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
        result ^= stringToInt(workPart);
        setAiBi(result);
        result = simple_replacement(16);
    }
    uint32_t imitovstavka = choosingImitationInsert(result, L_);
    reset();
    return imitovstavka;
}

uint32_t crypto::ghost2814789::get_imit_from_text(const std::string &textWithImit) //done
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

std::string crypto::ghost2814789::get_open_text_from_text_with_imit(const std::string& textWithImit) //done
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

bool crypto::ghost2814789::check_imitovstavka(const std::string &textWithImit) //done
{
    uint32_t imit_to_check = get_imit_from_text(textWithImit);
    uint32_t calculated_imit = imitovstavka(get_open_text_from_text_with_imit(textWithImit));
    reset();
    return (imit_to_check==calculated_imit);
}

void crypto::ghost2814789::reset()
{
    Ai_ = 0;
    Ai1_ = 0;
    Bi_ = 0;
    Bi1_ = 0;
}
