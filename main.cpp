#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <assert.h>

#define ENABLE_CHALLANGE 6

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

    uint8_t bytes_three[3] = { 0x00 };
    uint8_t bytes_four[4] = { 0x00 };
    auto inputLength = str.length();

    std::string output;
    output.reserve((inputLength/3)*4 + (inputLength%3) ? 4 : 0);
    int j = 0;
    for (auto i = 0; i < inputLength; i++) {
        bytes_three[j++] = str[i];
        if (j == 3) {
            bytes_four[0] = (bytes_three[0] & 0xFC) >> 2;
            bytes_four[1] = ((bytes_three[0] & 0x03) << 4) | ((bytes_three[1] & 0xF0) >> 4);
            bytes_four[2] = ((bytes_three[1] & 0x0F) << 2) | ((bytes_three[2] & 0xC0) >> 6);
            bytes_four[3] = bytes_three[2] & 0x3f;

            int b = 0;
            while(b < 4) {
                output.push_back(lookUpTable[bytes_four[b++]]);
            }

            memset(&bytes_three, 0x00, sizeof(bytes_three));
            memset(&bytes_four, 0x00, sizeof(bytes_four));

            j = 0;
        }
    }

    if (j) {
        while (j < 3) {
            bytes_three[j++] = '\0';
        }

        bytes_four[0] = (bytes_three[0] & 0xFC) >> 2;
        bytes_four[1] = ((bytes_three[0] & 0x03) << 4) | ((bytes_three[1] & 0xF0) >> 4);
        bytes_four[2] = ((bytes_three[1] & 0x0F) << 2) | ((bytes_three[2] & 0xC0) >> 6);
        bytes_four[3] = bytes_three[2] & 0x3f;

        int b = 0;
        while (b < 4) {
            output.push_back((bytes_four[b] != '\0') ? (lookUpTable[bytes_four[b]]) : '=');
            b++;
        }
    }
    return output;
}

std::string base642str(const std::string &base64) {
    const std::string lut = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    uint8_t bytes_three[3] = { 0x00 };
    uint8_t bytes_four[4] = { 0x00 };
    auto inputLength = base64.length();

    std::string output;
    output.reserve((inputLength/4)*3);
    int j = 0;
    int i = 0;
    for (i = 0; i < inputLength; i++) {
        if (base64[i] == '=') {
            continue;
        }

        bytes_four[j++] = lut.find(base64[i]);
        if (j == 4) {
            bytes_three[0] = (bytes_four[0] << 2) | (bytes_four[1] >> 4);
            bytes_three[1] = ((bytes_four[1] & 0x0F) << 4) | (bytes_four[2] >> 2);
            bytes_three[2] = ((bytes_four[2] & 0x03) << 6) | bytes_four[3];

            int b = 0;
            while(b < 3) {
                output.push_back(bytes_three[b++]);
            }

            memset(&bytes_three, 0x00, sizeof(bytes_three));
            memset(&bytes_four, 0x00, sizeof(bytes_four));

            j = 0;
        }
    }

    if (i) {
        for(j = i; j < 4; j++) {
            bytes_three[j] = 0;
        }

        bytes_three[0] = (bytes_four[0] << 2) | (bytes_four[1] >> 4);
        bytes_three[1] = ((bytes_four[1] & 0x0F) << 4) | (bytes_four[2] >> 2);
        bytes_three[2] = ((bytes_four[2] & 0x03) << 6) | bytes_four[3];

        int b = 0;
        while (b < 3) {
            if (bytes_three[b] == 0) {
                b++;
                continue;
            }
            output.push_back(bytes_three[b++]);
        }
    }
    return output;
}

std::string hex2base64(const std::string &hex) {
    static const char lookUpTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    uint8_t bytes_three[3] = { 0x00 };
    uint8_t bytes_four[4] = { 0x00 };
    auto inputLength = hex.length();

    auto decodeHex = [](uint8_t m, uint8_t l) -> uint8_t {
        static const std::string hexLut = "0123456789ABCDEF";
        return hexLut.find(toupper(m)) << 4 | hexLut.find(toupper(l));
    };

    std::string output;
    output.reserve((inputLength/3)*4 + (inputLength%3) ? 4 : 0);
    int j = 0;
    for (auto i = 0; i < inputLength; i+=2) {
        bytes_three[j++] = decodeHex(hex[i], hex[i+1]);
        if (j == 3) {
            bytes_four[0] = (bytes_three[0] & 0xFC) >> 2;
            bytes_four[1] = ((bytes_three[0] & 0x03) << 4) | ((bytes_three[1] & 0xF0) >> 4);
            bytes_four[2] = ((bytes_three[1] & 0x0F) << 2) | ((bytes_three[2] & 0xC0) >> 6);
            bytes_four[3] = bytes_three[2] & 0x3f;

            int b = 0;
            while(b < 4) {
                output.push_back(lookUpTable[bytes_four[b++]]);
            }

            memset(&bytes_three, 0x00, sizeof(bytes_three));
            memset(&bytes_four, 0x00, sizeof(bytes_four));

            j = 0;
        }
    }

    if (j) {
        while (j < 3) {
            bytes_three[j++] = '\0';
        }

        bytes_four[0] = (bytes_three[0] & 0xFC) >> 2;
        bytes_four[1] = ((bytes_three[0] & 0x03) << 4) | ((bytes_three[1] & 0xF0) >> 4);
        bytes_four[2] = ((bytes_three[1] & 0x0F) << 2) | ((bytes_three[2] & 0xC0) >> 6);
        bytes_four[3] = bytes_three[2] & 0x3f;

        int b = 0;
        while (b < 4) {
            output.push_back((bytes_four[b] != '\0') ? (lookUpTable[bytes_four[b]]) : '=');
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

std::map<char, double> englishFreq = {
    {'a', 8.167}, {'b', 1.492}, {'c', 2.782}, {'d', 4.253}, {'e', 12.702}, {'f', 2.228}, {'g', 2.015},
    {'h', 6.094}, {'i', 6.966}, {'j', 0.153}, {'k', 0.772}, {'l', 4.025}, {'m', 2.406}, {'n', 6.749},
    {'o', 7.507}, {'p', 1.929}, {'q', 0.095}, {'r', 5.987}, {'s', 6.327}, {'t', 9.056}, {'u', 2.758},
    {'v', 0.978}, {'w', 2.360}, {'x', 0.150}, {'y', 1.974}, {'z', 0.074}, {' ', 23}
};

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
    uint32_t min_norm_dist = INT_MAX;
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

        if (dist < min_norm_dist) {
            min_norm_dist = dist;
            keySize = i;
        }
    }
    return keySize;
}

int main() {
#if ENABLE_CHALLANGE == 1
    
    // phase 1
    printf("Phase 1");
    const std::string test1 = "\n I'm killing your brain like a poisonous mushroom";
    fprintf(stdout, "\n to hex: %s", str2hex(test1).c_str());
    fprintf(stdout, "\n back to str str: \"%s\"", hex2str(str2hex(test1)).c_str());
    fprintf(stdout, "\n to base64: %s", str2base64(test1).c_str());
    fprintf(stdout, "\n to base64: %s", hex2base64(str2hex(test1)).c_str());
#elif ENABLE_CHALLANGE == 2

    // phase 2
    printf("\n\n Phase 2");
    const std::string test2 = "1c0111001f010100061a024b53535009181c";
    const std::string xorResult = xorStr(hex2str(test2), hex2str("686974207468652062756c6c277320657965"));
    fprintf(stdout, "\n XOR to hex: %s / %s", str2hex(xorResult).c_str(), xorResult.c_str());
#elif ENABLE_CHALLANGE == 3

    // phase 3
    printf("\n\n Phase 3");
    const std::string test3 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    const std::string decoded3 = hex2str(test3);
    fprintf(stdout, "\n to str: %s decoded %s", test3.c_str(), decoded3.c_str());
    int max_score = -1;
    int winner = 0;
    for (int i = 0; i < 255; i++) {
        std::string xored = xorBySingleByte(decoded3, i);
        int score = 0;
        for (int j = 0; j < xored.length(); j++) {
            score += englishFreq[xored[j]];
            if (score > max_score) {
                max_score = score;
                winner = i;
            }
        }
    }
    fprintf(stdout, "\n The cypher is '%c' with a score of %d. And result: %s ",
                        winner, max_score, xorBySingleByte(decoded3, winner).c_str());
#elif ENABLE_CHALLANGE == 4

    // phase 4
    printf("\n\n Phase 4");
    std::ifstream in("data/input4.txt");
    std::string line;
    std:: string winner4;
    int max_score4 = 0;
    while (std::getline(in, line)) {
        std::string decoded4 = hex2str(line);

        int max_score_bytes = 0;
        int score_bytes = 0;
        std::string winner_bytes_forced;
        for (int i = 0; i < 255; i++) {
            std::string xored = xorBySingleByte(decoded4, i);
            score_bytes = scoreEnglishFreq(xored);

            if (score_bytes > max_score_bytes) {
                max_score_bytes = score_bytes;
                winner_bytes_forced = xored;
            }
        }

        if (max_score_bytes > max_score4) {
            max_score4 = max_score_bytes;
            winner4 = winner_bytes_forced;
        }
        static int ln = 0;
        fprintf(stdout, "%d ", ln++);
    }
    in.close();
    fprintf(stdout, "\n Winner4 %s ", winner4.c_str());
#elif ENABLE_CHALLANGE == 5

    // phase 5
    printf("\n\n Phase 5");
    const std::string test5 = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    const std::string key5 = "ICE";
    fprintf(stdout, "\n Winner5 %s ", str2hex(encryptXor(test5, key5)).c_str());
#elif ENABLE_CHALLANGE == 6

    // phase 6
    printf("\n\n Phase 6");
    std::ifstream in6("data/input6.txt");
    std::string line6;
    std::string decoded6;
    while (std::getline(in6, line6)) {
        decoded6.append(base642str(line6));
    }
    in6.close();

    fprintf(stdout, "\n Hamming distance %u ", hammingDistance("this is a test", "wokka wokka!!!"));
    uint32_t keySize = findKeySize(decoded6, 2, 40);
    fprintf(stdout, "\n KeySize %u ", keySize);

    std::vector<std::string> transcoded_blocks;
    for (size_t i = 0; i < keySize; i++) { transcoded_blocks.push_back(""); }
    for (int i = 0; i < decoded6.length(); i++) {
        transcoded_blocks[i % keySize].push_back(decoded6[i]);
    }

    std::string key6;
    for (auto block : transcoded_blocks) {
        int max_score_bytes = 0;
        int score_bytes = 0;

        uint8_t block_ctypher_candidate = 0;
        for (uint8_t i = 0; i < 255; i++) {
            std::string xored = xorBySingleByte(block, i);
            score_bytes = scoreEnglishFreq(xored);

            if (score_bytes > max_score_bytes) {
                max_score_bytes = score_bytes;
                block_ctypher_candidate = i;
            }
        }

        key6.push_back(block_ctypher_candidate);
    }

    fprintf(stdout, "\n Winner6 %s ", key6.c_str());
    fprintf(stdout, "\n Decoded text %s ", encryptXor(decoded6, key6).c_str());
#endif

    printf("\n\n");
    return (0);
}

