#include <string>
#include <fstream>
#include <vector>
#include <map>
#include <assert.h>

#include "utils.hpp"
#include "aes.hpp"

#define ACTIVE_CHALLANGE ALL
#define CHALLANGE_ENABLED(x) (ACTIVE_CHALLANGE == x || ACTIVE_CHALLANGE == ALL)

void challange_1()
{
    // Challange 1
    fprintf(stdout, "\n\n \e[1;7m%s \e[0m", "Challange 1");
    const std::string data = "\n I'm killing your brain like a poisonous mushroom";
    fprintf(stdout, "\n to hex: %s", str2hex(data).c_str());
    fprintf(stdout, "\n back to str str: \"%s\"", hex2str(str2hex(data)).c_str());
    fprintf(stdout, "\n to base64: %s", str2base64(data).c_str());
    fprintf(stdout, "\n to base64: %s", hex2base64(str2hex(data)).c_str());
}


void challange_2()
{
    // Challange 2
    fprintf(stdout, "\n\n \e[1;7m%s \e[0m", "Challange 2");
    const std::string data = "1c0111001f010100061a024b53535009181c";
    const std::string xorResult = xorStr(hex2str(data), hex2str("686974207468652062756c6c277320657965"));
    fprintf(stdout, "\n XOR to hex: %s / %s", str2hex(xorResult).c_str(), xorResult.c_str());
}

void challange_3()
{
    // Challange 3
    fprintf(stdout, "\n\n \e[1;7m%s \e[0m", "Challange 3");
    const std::string data = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    const std::string decoded = hex2str(data);
    fprintf(stdout, "\n to str: %s decoded %s", data.c_str(), decoded.c_str());
    int maxScore = -1;
    int winner = 0;
    for (int i = 0; i < 255; i++) {
        std::string xored = xorBySingleByte(decoded, i);
        int score = 0;
        for (int j = 0; j < xored.length(); j++) {
            score += englishFreq[xored[j]];
            if (score > maxScore) {
                maxScore = score;
                winner = i;
            }
        }
    }
    fprintf(stdout, "\n The cyphertext is '%c' with a score of %d. And result: %s ",
            winner, maxScore, xorBySingleByte(decoded, winner).c_str());
}

void challange_4()
{
    // Challange 4
    fprintf(stdout, "\n\n \e[1;7m%s \e[0m", "Challange 4");
    std::ifstream in("data/input4.txt");
    std::string line;
    std:: string winner;
    int maxScore = 0;
    while (std::getline(in, line)) {
        std::string decoded = hex2str(line);

        int maxScoreBytes = 0;
        int scoreBytes = 0;
        std::string winneAtBytesForced;
        for (int i = 0; i < 255; i++) {
            std::string xored = xorBySingleByte(decoded, i);
            scoreBytes = scoreEnglishFreq(xored);

            if (scoreBytes > maxScoreBytes) {
                maxScoreBytes = scoreBytes;
                winneAtBytesForced = xored;
            }
        }

        if (maxScoreBytes > maxScore) {
            maxScore = maxScoreBytes;
            winner = winneAtBytesForced;
        }

        static int ln = 0;
        fprintf(stdout, " %d", ln++);
    }
    in.close();
    fprintf(stdout, "\n Winner4 %s ", winner.c_str());
}

void challange_5()
{
    // Challange 5
    fprintf(stdout, "\n\n \e[1;7m%s \e[0m", "Challange 5");
    const std::string data = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    const std::string key5 = "ICE";
    fprintf(stdout, "\n Winner5 %s ", str2hex(encryptXor(data, key5)).c_str());
}

void challange_6()
{
    // Challange 6
    fprintf(stdout, "\n\n \e[1;7m%s \e[0m", "Challange 6");
    std::ifstream in("data/input6.txt");
    std::string line;
    std::string decoded;
    while (std::getline(in, line)) {
        decoded.append(base642str(line));
    }
    in.close();

    fprintf(stdout, "\n Hamming distance %u ", hammingDistance("this is a test", "wokka wokka!!!"));
    uint32_t keySize = findKeySize(decoded, 2, 40);
    fprintf(stdout, "\n KeySize %u ", keySize);

    std::vector<std::string> transcoded_blocks;
    for (size_t i = 0; i < keySize; i++) { transcoded_blocks.push_back(""); }
    for (int i = 0; i < decoded.length(); i++) {
        transcoded_blocks[i % keySize].push_back(decoded[i]);
    }

    std::string key6;
    for (auto block : transcoded_blocks) {
        int maxScoreBytes = 0;
        int scoreBytes = 0;

        uint8_t block_ctypher_candidate = 0;
        for (uint8_t i = 0; i < 255; i++) {
            std::string xored = xorBySingleByte(block, i);
            scoreBytes = scoreEnglishFreq(xored);

            if (scoreBytes > maxScoreBytes) {
                maxScoreBytes = scoreBytes;
                block_ctypher_candidate = i;
            }
        }

        key6.push_back(block_ctypher_candidate);
    }

    fprintf(stdout, "\n Winner6 %s ", key6.c_str());
    fprintf(stdout, "\n Decoded text %s ", encryptXor(decoded, key6).c_str());
}

void challange_7()
{
    // Challange 7
    fprintf(stdout, "\n\n \e[1;7m%s \e[0m", "Challange 7");
    const std::string key = "YELLOW SUBMARINE";

    std::ifstream in("data/input7.txt");
    std::string line;
    std::string cyphertext;
    while (std::getline(in, line)) {
        cyphertext.append(base642str(line));
    }
    in.close();

    AES aes(OpMode::ECB, key);
    std::string plaintext = aes.decrypt(cyphertext);
    fprintf (stdout, "\n decrypted %s ", plaintext.c_str());
}

void challange_8()
{
    // Challange 8
    fprintf(stdout, "\n\n \e[1;7m%s \e[0m", "Challange 8");

    std::ifstream in("data/input8.txt");
    std::string line;
    std::vector<std::string> candidates;
    while (std::getline(in, line)) {
        candidates.push_back(hex2str(line));
    }
    in.close();

    int maxScore = INT_MIN;
    int winner = 0;
    for (int i = 0; i < candidates.size(); i++) {
        std::map<std::string, int> scoreBlock;
        int maxBlockScore = INT_MIN;
        for (int j = 0; j < candidates[i].length(); j+= 16) {
            std::string block = candidates[i].substr(j, 16);
            scoreBlock[block]++;
            if ((scoreBlock[block]) > maxBlockScore) {
                maxBlockScore = scoreBlock[block];
            }
        }

        if (maxBlockScore > maxScore) {
            maxScore = maxBlockScore;
            winner = i;
        }
    }

    fprintf(stdout, "\n Winner8 %s score %d line %d ", str2hex(candidates[winner]).c_str(), maxScore, winner+1);
}

void challange_9()
{
    // Challange 9
    fprintf(stdout, "\n\n \e[1;7m%s \e[0m", "Challange 9");
    const std::string data = "YELLOW SUBMARINE";
    std::string padded = PKCS7(data, 20);
    fprintf (stdout, "\n padded: ");
    for (size_t i = 0; i < padded.length(); i++) {
        fprintf (stdout, "%c ", padded[i]);
    }
}

void challange_10()
{
    // Challange 10
    fprintf(stdout, "\n\n \e[1;7m%s \e[0m", "Challange 10");

    std::ifstream in("data/input10.txt");
    std::string line;
    std::string cyphertext;
    while (std::getline(in, line)) {
        cyphertext.append(base642str(line));
    }
    in.close();

    std::string key = "YELLOW SUBMARINE";
    std::string iv("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);
    AES aes(OpMode::CBC, key, iv);
    std::string plaintext = aes.decrypt(cyphertext);
    fprintf (stdout, "\n decrypted: \n %s ", plaintext.c_str());
}

void challange_11()
{
    // Challange 11
    fprintf(stdout, "\n\n \e[1;7m%s \e[0m", "Challange 11");

    const std::string key = randBytes(16);
    const std::string iv = randBytes(16);

    char input_bytes[16 * 3] = { 'a' };
    std::string plaintext(input_bytes, sizeof(input_bytes));
    plaintext = randBytes(5 + (rand() % 5)) + plaintext;
    plaintext = plaintext + randBytes(5 + (rand() % 5));

    for (int j = 0; j < 100; j++) {
        OpMode actualMode = rand() % 2 ? OpMode::ECB : OpMode::CBC;
        AES aes(actualMode, key, iv);
        std::string cyphertext = aes.encrypt(plaintext);

        OpMode detectedMode = memcmp(&cyphertext[16], &cyphertext[32], 16) == 0 ? OpMode::ECB : OpMode::CBC;

        assert(actualMode == detectedMode);
        fprintf (stdout, "\n mode %d detected %d ", actualMode, detectedMode);
    }
}

int main() {

#if CHALLANGE_ENABLED(1)
    challange_1();
#endif

#if CHALLANGE_ENABLED(2)
    challange_2();
#endif

#if CHALLANGE_ENABLED(3)
    challange_3();
#endif

#if CHALLANGE_ENABLED(4)
    challange_4();
#endif

#if CHALLANGE_ENABLED(5)
    challange_5();
#endif

#if CHALLANGE_ENABLED(6)
    challange_6();
#endif

#if CHALLANGE_ENABLED(7)
    challange_7();
#endif

#if CHALLANGE_ENABLED(8)
    challange_8();
#endif

#if CHALLANGE_ENABLED(9)
    challange_9();
#endif

#if CHALLANGE_ENABLED(10)
    challange_10();
#endif

#if CHALLANGE_ENABLED(11)
    challange_11();
#endif

    printf("\n\n");
    return (0);
}

