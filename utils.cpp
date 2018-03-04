//
//  utils.cpp
//  crypto_challange_1
//
//  Created by Solomon Corîiu on 21/03/2018.
//  Copyright © 2018 Solomon Corîiu. All rights reserved.
//

#include "utils.hpp"
#include <assert.h>

#include <random>
#include <climits>
#include <algorithm>
#include <functional>

std::string str2hex(const std::string &str) {
    static const char lookUpTable[] = "0123456789ABCDEF";

    std::string output;
    output.reserve(str.length() * 2);
    for (int i = 0; i < str.length(); i++) {
        const uint8_t c = str[i];
        output.push_back(lookUpTable[c >> 4]);
        output.push_back(lookUpTable[c & 0x0f]);
    }
    return output;
}

std::string hex2str(const std::string &input) {
    static const std::string lookUpTable = "0123456789ABCDEF";

    std::string hex = input;
    std::transform(hex.begin(), hex.end(), hex.begin(), ::toupper);
    std::string output;
    output.reserve(hex.length() / 2);
    for (int i = 0; i < hex.length(); i+=2) {
        output.push_back((lookUpTable.find(hex[i]) << 4) | lookUpTable.find(hex[i+1]));
    }
    return output;
}

std::string str2base64(const std::string &str) {
    static const char lookUpTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    uint8_t bytesThree[3] = { 0x00 };
    uint8_t bytesFour[4] = { 0x00 };
    auto inputLength = str.length();

    std::string output;
    output.reserve((inputLength/3)*4 + (inputLength%3) ? 4 : 0);
    int j = 0;
    for (auto i = 0; i < inputLength; i++) {
        bytesThree[j++] = str[i];
        if (j == 3) {
            bytesFour[0] = (bytesThree[0] & 0xFC) >> 2;
            bytesFour[1] = ((bytesThree[0] & 0x03) << 4) | ((bytesThree[1] & 0xF0) >> 4);
            bytesFour[2] = ((bytesThree[1] & 0x0F) << 2) | ((bytesThree[2] & 0xC0) >> 6);
            bytesFour[3] = bytesThree[2] & 0x3f;

            int b = 0;
            while(b < 4) {
                output.push_back(lookUpTable[bytesFour[b++]]);
            }

            memset(&bytesThree, 0x00, sizeof(bytesThree));
            memset(&bytesFour, 0x00, sizeof(bytesFour));

            j = 0;
        }
    }

    if (j) {
        while (j < 3) {
            bytesThree[j++] = '\0';
        }

        bytesFour[0] = (bytesThree[0] & 0xFC) >> 2;
        bytesFour[1] = ((bytesThree[0] & 0x03) << 4) | ((bytesThree[1] & 0xF0) >> 4);
        bytesFour[2] = ((bytesThree[1] & 0x0F) << 2) | ((bytesThree[2] & 0xC0) >> 6);
        bytesFour[3] = bytesThree[2] & 0x3f;

        int b = 0;
        while (b < 4) {
            output.push_back((bytesFour[b] != '\0') ? (lookUpTable[bytesFour[b]]) : '=');
            b++;
        }
    }
    return output;
}

std::string base642str(const std::string &base64) {
    const std::string lut = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    uint8_t bytesThree[3] = { 0x00 };
    uint8_t bytesFour[4] = { 0x00 };
    auto inputLength = base64.length();

    std::string output;
    output.reserve((inputLength/4)*3);
    int j = 0;
    int i = 0;
    for (i = 0; i < inputLength; i++) {
        if (base64[i] == '=') {
            continue;
        }

        bytesFour[j++] = lut.find(base64[i]);
        if (j == 4) {
            bytesThree[0] = (bytesFour[0] << 2) | (bytesFour[1] >> 4);
            bytesThree[1] = ((bytesFour[1] & 0x0F) << 4) | (bytesFour[2] >> 2);
            bytesThree[2] = ((bytesFour[2] & 0x03) << 6) | bytesFour[3];

            int b = 0;
            while(b < 3) {
                output.push_back(bytesThree[b++]);
            }

            memset(&bytesThree, 0x00, sizeof(bytesThree));
            memset(&bytesFour, 0x00, sizeof(bytesFour));

            j = 0;
        }
    }

    if (i) {
        for(j = i; j < 4; j++) {
            bytesThree[j] = 0;
        }

        bytesThree[0] = (bytesFour[0] << 2) | (bytesFour[1] >> 4);
        bytesThree[1] = ((bytesFour[1] & 0x0F) << 4) | (bytesFour[2] >> 2);
        bytesThree[2] = ((bytesFour[2] & 0x03) << 6) | bytesFour[3];

        int b = 0;
        while (b < 3) {
            if (bytesThree[b] == 0) {
                b++;
                continue;
            }
            output.push_back(bytesThree[b++]);
        }
    }
    return output;
}

std::string hex2base64(const std::string &hex) {
    static const char lookUpTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    uint8_t bytesThree[3] = { 0x00 };
    uint8_t bytesFour[4] = { 0x00 };
    auto inputLength = hex.length();

    auto decodeHex = [](uint8_t m, uint8_t l) -> uint8_t {
        static const std::string hexLut = "0123456789ABCDEF";
        return hexLut.find(toupper(m)) << 4 | hexLut.find(toupper(l));
    };

    std::string output;
    output.reserve((inputLength/3)*4 + (inputLength%3) ? 4 : 0);
    int j = 0;
    for (auto i = 0; i < inputLength; i+=2) {
        bytesThree[j++] = decodeHex(hex[i], hex[i+1]);
        if (j == 3) {
            bytesFour[0] = (bytesThree[0] & 0xFC) >> 2;
            bytesFour[1] = ((bytesThree[0] & 0x03) << 4) | ((bytesThree[1] & 0xF0) >> 4);
            bytesFour[2] = ((bytesThree[1] & 0x0F) << 2) | ((bytesThree[2] & 0xC0) >> 6);
            bytesFour[3] = bytesThree[2] & 0x3f;

            int b = 0;
            while(b < 4) {
                output.push_back(lookUpTable[bytesFour[b++]]);
            }

            memset(&bytesThree, 0x00, sizeof(bytesThree));
            memset(&bytesFour, 0x00, sizeof(bytesFour));

            j = 0;
        }
    }

    if (j) {
        while (j < 3) {
            bytesThree[j++] = '\0';
        }

        bytesFour[0] = (bytesThree[0] & 0xFC) >> 2;
        bytesFour[1] = ((bytesThree[0] & 0x03) << 4) | ((bytesThree[1] & 0xF0) >> 4);
        bytesFour[2] = ((bytesThree[1] & 0x0F) << 2) | ((bytesThree[2] & 0xC0) >> 6);
        bytesFour[3] = bytesThree[2] & 0x3f;

        int b = 0;
        while (b < 4) {
            output.push_back((bytesFour[b] != '\0') ? (lookUpTable[bytesFour[b]]) : '=');
            b++;
        }
    }
    return output;
}

std::string xorStr(const std::string &s1, const std::string &s2) {
    if (s1.length() != s2.length()) throw;
    std::string output;
    output.reserve(s1.length() + 1);
    for (int i = 0; i < s1.length(); i++) {
        output.push_back(s1[i] ^ s2[i]);
    }

    return output;
}

std::string xorBySingleByte(const std::string &str, uint8_t c) {
    std::string output;
    output.reserve(str.length());
    for (int i = 0; i < str.length(); i++) {
        output.push_back(str[i] ^ c);
    }
    return output;
}

int scoreEnglishFreq(const std::string &str) {
    int score = 0;
    for (int i = 0; i < 255; i++) {
        for (int j = 0; j < str.length(); j++) {
            score += englishFreq[str[j]];
        }
    }
    return score;
}

uint8_t mostFrequentByte(const std::string &str) {
    std::map<char, int> reps;
    int maxRepByte = 0;
    uint8_t result = 0;
    for (int i = 0; i < str.length(); i++) {
        reps[str[i]]++;
        if (reps[str[i]] > maxRepByte) {
            maxRepByte = reps[str[i]];
            result = str[i];
        }
    }
    return result;
}

std::string encryptXor(const std::string &str, const std::string &key) {
    std::string output;
    output.reserve(str.length());
    for (int i = 0; i < str.length(); i++) {
        output.push_back(str[i] ^ key[i % key.length()]);
    }
    return output;
}

uint32_t hammingDistance(const std::string &str1, const std::string &str2) {
    uint32_t distance = 0;
    assert(str1.length() == str2.length());
    for (int i = 0; i < str1.length(); i++) {
        uint8_t diff = str1[i] ^ str2[i];
        while (diff) {
            distance++;
            diff &= diff - 1;
        }
    }
    return distance;
}

uint32_t findKeySize(const std::string &str, uint32_t min, uint32_t max) {
    uint32_t minNormDist = INT_MAX;
    uint32_t keySize = 0;
    for (int i = min; i < max; i++) {
        uint32_t dist = 0;
        std::vector<std::string> chunks;

        const uint8_t nbOfSamples = 5;
        for (int j = 0; j < str.length(); j += i) {
            chunks.push_back(str.substr(j, i));
            if (chunks.size() > nbOfSamples) {
                break;
            }
        }

        for (int j = 0; j < chunks.size(); j++) {
            for (int k = j+1; k < chunks.size(); k++) {
                dist += hammingDistance(chunks[j], chunks[k]);
            }
        }

        dist /= i;

        if (dist < minNormDist) {
            minNormDist = dist;
            keySize = i;
        }
    }
    return keySize;
}

std::string PKCS7(const std::string &input, uint8_t k) {
    std::string output = input;

    if (k < 2 || k > 255) {
        throw("invalid value for 'k'");
    }

    uint8_t n = k - (input.length() % k);
    for (int i = 0; i < n; i ++) {
        output.push_back(n);
    }

    return output;
}

std::string randBytes(size_t size)
{
    std::string output;
    output.reserve(size);

    for (uint8_t i = 0; i < size; i++) {
        output.push_back(rand() % 256);
    }

    return output;
}
