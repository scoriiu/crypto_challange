//
//  aes.cpp
//  crypto_challange_1
//
//  Created by Solomon Corîiu on 11/03/2018.
//  Copyright © 2018 Solomon Corîiu. All rights reserved.
//
// AES ECB encryption
// key wihitening (add sub key at start and end)
// Key scheduling, 4 phases: (10/12/14 rounds), where each round:
// 1) Bytes substitution
// 2) Shifting Rows
// 3) Mixed columns
// 4) Expanded key addition
// Note: The last round doesn't contain 'Mixed columns'


#include "aes.hpp"

#include "utils.hpp"


/* Multiply two numbers in the GF(2^8) finite field defined
 * by the polynomial x^8 + x^4 + x^3 + x + 1 = 0
 * using the Russian Peasant Multiplication algorithm
 * (the other way being to do carry-less multiplication followed by a modular reduction)
 */
uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0; /* the product of the multiplication */
    while (a && b) {
        if (b & 1) /* if b is odd, then add the corresponding a to p (final product = sum of all a's corresponding to odd b's) */
            p ^= a; /* since we're in GF(2^m), addition is an XOR */

        if (a & 0x80) /* GF modulo: if a >= 128, then it will overflow when shifted left, so reduce */
            a = (a << 1) ^ 0x11b; /* XOR with the primitive polynomial x^8 + x^4 + x^3 + x + 1 (0b1_0001_1011) – you can change it but it must be irreducible */
        else
            a <<= 1; /* equivalent to a*2 */
        b >>= 1; /* equivalent to b // 2 */
    }
    return p;
}

AES::AES(OpMode mode, const std::string &key, const std::string iv) :
    m_mode(mode)
{
    if (!iv.empty() && iv.length() != 16) {
        throw std::runtime_error("Iv must be 128 bits long.");
    }

    for (size_t i = 0; i < iv.length(); i+=4) {
        uint32_t group = 0;
        for (auto const &c : iv.substr(i, 4)) {
            group = (group << 8) + static_cast<uint8_t>(c);
        }
        m_iv.push_back(group);
    }

    generateSubKeys(key);
}

void AES::generateSubKeys(const std::string &key)
{
    if (key.length() != 16) {
        throw std::runtime_error("Key must be 128 bits long.");
    }

    std::vector <uint32_t> keys;
    m_rounds = key.length() / 4 + 6;
    uint8_t n = key.length() / 4;

    for (uint8_t i = 0; i < n; i++) {
        uint32_t group = 0;
        for (auto const &c : key.substr(i << 2, 4)) {
            group = (group << 8) + static_cast<uint8_t>(c);
        }
        keys.push_back(group);
    }

    for (uint8_t round = 1; round <= m_rounds; round++) {
        uint32_t o = 0;
        keyScheduleCore(round, keys.back(), o);
        uint32_t t = keys[keys.size() - n] ^ o;
        keys.push_back(t);

        for(uint8_t j = 0; j < 3; j++){
            keys.push_back(keys.back() ^ keys[keys.size() - n]);
        }
    }

    m_keys.resize(11);
    for (int i = 0; i < keys.size(); i++) {
        m_keys[i / 4].push_back(keys[i]);
    }
}

void AES::keyScheduleCore(uint8_t round, const uint32_t keyIn, uint32_t &keyOut)
{
    keyOut = (keyIn << 8) | (keyIn >> 24);

    uint32_t s = 0;
    for (uint8_t i = 0; i < 4; i++) {
        s ^= sBox[static_cast<uint8_t>((keyOut >> (i * 8)) & 0xFF)] << (i * 8);
    }

    keyOut = s ^ (rcon[round] << 24);
}

std::vector<uint32_t> AES::encryptBlock(std::vector<uint32_t> plaintext)
{
    std::vector<uint32_t> cyphertext = plaintext;

    addRoundKey(0, cyphertext);
    for (int r = 1; r <= m_rounds; r++) {
        subBytes(cyphertext);
        shiftRow(cyphertext);

        if (r != m_rounds) {
            mixColumns(cyphertext);
        }

        addRoundKey(r, cyphertext);
    }

    return cyphertext;
}

std::vector<uint32_t> AES::decryptBlock(std::vector<uint32_t> cyphertext)
{
    std::vector<uint32_t> plaintext = cyphertext;

    addRoundKey(m_rounds, plaintext);
    for (int r = m_rounds - 1; r >= 0; r--) {
        invShiftRow(plaintext);
        invSubBytes(plaintext);
        addRoundKey(r, plaintext);

        if (r != 0) {
            invMixColumns(plaintext);
        }
    }

    return plaintext;
}

std::string AES::encrypt(const std::string &data)
{
    if (data.size() < 16){
        return data;
    }

    std::vector<std::vector<uint32_t>> states;
    for (int i = 16; i < data.length() + 1; i+=16) {
        std::vector<uint32_t> state;
        for (int j = i - 16; j < i; j+=4) {
            uint32_t group = 0;
            for (auto const &c : data.substr(j, 4)) {
                group = (group << 8) + static_cast<uint8_t>(c);
            }
            state.push_back(group);
        }

        states.push_back(state);
    }

    // leftovers
    /*
     if (data.size() % 16) {
        uint8_t pad_unit = 16 - (data.size() % 16);
        std::string padding;
        for (size_t i = (data.length() / 16) * 16; i < (data.length() + 16); i++) {
            padding.push_back(i < data.length() ? data[i] : pad_unit);
        }

        std::vector<uint32_t> state;
        for (size_t i = 0; i < padding.length(); i+=4) {
            uint32_t group = 0;
            for (auto const &c : padding.substr(i, 4)) {
                group = (group << 8) + static_cast<uint8_t>(c);
            }
            state.push_back(group);
        }

        states.push_back(state);
    }
     */

    std::string encrypted;
    std::vector<uint32_t> diffblock = m_iv;
    for (auto &state : states) {
        std::vector<uint32_t> cyphertext;
        if (m_mode == OpMode::ECB) {
            cyphertext = encryptBlock(state);
        } else if (m_mode == OpMode::CBC) {
            for (int i = 0; i < state.size(); i++) {
                state[i] ^= diffblock[i];
            }
            cyphertext = encryptBlock(state);
            diffblock = cyphertext;
        }

        for (int i = 0; i < cyphertext.size(); i++) {
            for (int j = sizeof(uint32_t); j > 0; j--) {
                encrypted.push_back(static_cast<uint8_t>((cyphertext[i] >> (j-1) * 8) & 0xFF));
            }
        }
    }

    return encrypted;
}

std::string AES::decrypt(const std::string &data)
{
    if (data.size() < 16){
        return data;
    }

    std::vector<std::vector<uint32_t>> states;
    for (int i = 16; i < data.length() + 1; i+=16) {
        std::vector<uint32_t> state;
        for (int j = i - 16; j < i; j+=4) {
            uint32_t group = 0;
            for (auto const &c : data.substr(j, 4)) {
                group = (group << 8) + static_cast<uint8_t>(c);
            }
            state.push_back(group);
        }

        states.push_back(state);
    }

    std::string decrypted;
    std::vector<uint32_t> diffblock = m_iv;
    for (auto &state : states) {
        std::vector<uint32_t> plaintext;
        if (m_mode == OpMode::ECB) {
            plaintext = decryptBlock(state);
        } else if (m_mode == OpMode::CBC) {
            plaintext = decryptBlock(state);
            for (int i = 0; i < plaintext.size(); i++) {
                plaintext[i] ^= diffblock[i];
            }
            diffblock = state;
        }

        for (int i = 0; i < plaintext.size(); i++) {
            for (int j = sizeof(uint32_t); j > 0; j--) {
                decrypted.push_back(static_cast<uint8_t>((plaintext[i] >> (j-1) * 8) & 0xFF));
            }
        }
    }

    return decrypted;
}

void AES::subBytes(std::vector<uint32_t> &state)
{
    for (int i = 0; i < 4; i++) {
        state[i] = (sBox[(state[i] >> 24) & 0xFF] << 24) ^ (sBox[(state[i] >> 16) & 0xFF] << 16) ^
                  (sBox[(state[i] >> 8) & 0xFF] << 8) ^ (sBox[state[i] & 0xFF]);
    }
}

void AES::shiftRow(std::vector<uint32_t> &state)
{
    std::vector<uint32_t> shifted = { 0x00, 0x00, 0x00, 0x00 };
    for (uint8_t i = 0; i < 4; i++) {
        for (uint8_t j = 0; j < 4; j++) {
            uint8_t futurePos = shiftRowMap[j][i];
            uint8_t byteNb = futurePos / 4;
            uint8_t posInByte = futurePos % 4;

            uint8_t c = ((state[byteNb] >> (8 * (3 - posInByte))) & 0xFF);
            shifted[i] ^= (c << (3-j) * 8);
        }
    }

    state.assign(shifted.begin(), shifted.end());
}

void AES::mixColumns(std::vector<uint32_t> &state)
{
    std::vector <uint32_t> mixed;
    for(uint8_t i = 0; i < 4; i++){
        mixed.push_back(((gmul(2, (state[i] >> 24) & 0xFF) ^ gmul(3, (state[i] >> 16) & 0xFF) ^ ((state[i] >> 8) & 0xFF) ^ (state[i] & 0xFF)) << 24) +
                        ((gmul(2, (state[i] >> 16) & 0xFF) ^ gmul(3, (state[i] >> 8) & 0xFF) ^ (state[i] & 0xFF) ^ ((state[i] >> 24) & 0xFF)) << 16) +
                        ((gmul(2, (state[i] >> 8) & 0xFF) ^ gmul(3, state[i] & 0xFF) ^ ((state[i] >> 24) & 0xFF) ^ ((state[i] >> 16) & 0xFF)) << 8 ) +
                        ((gmul(2, state[i] & 0xFF) ^ gmul(3, (state[i] >> 24) & 0xFF) ^ ((state[i] >> 16) & 0xFF) ^ ((state[i] >> 8) & 0xFF))));
    }
    state.assign(mixed.begin(), mixed.end());
}

void AES::addRoundKey(uint8_t round, std::vector<uint32_t> &state)
{
    for (int i = 0; i < 4; i++) {
        state[i] ^= m_keys[round][i];
    }
}


void AES::invSubBytes(std::vector<uint32_t> &state)
{
    for (int i = 0; i < 4; i++) {
        state[i] = (sBoxInv[(state[i] >> 24) & 0xFF] << 24) ^ (sBoxInv[(state[i] >> 16) & 0xFF] << 16) ^
                    (sBoxInv[(state[i] >> 8) & 0xFF] << 8) ^ (sBoxInv[state[i] & 0xFF]);
    }
}

void AES::invShiftRow(std::vector<uint32_t> &state)
{
    std::vector<uint32_t> shifted = { 0x00, 0x00, 0x00, 0x00 };
    for (uint8_t i = 0; i < 4; i++) {
        for (uint8_t j = 0; j < 4; j++) {
            uint8_t futurePos = shiftRowMapInv[j][i];
            uint8_t byteNb = futurePos / 4;
            uint8_t posInByte = futurePos % 4;

            uint8_t c = ((state[byteNb] >> (8 * (3 - posInByte))) & 0xFF);
            shifted[i] ^= (c << (3-j) * 8);
        }
    }

    state.assign(shifted.begin(), shifted.end());
}

void AES::invMixColumns(std::vector<uint32_t> &state)
{
    std::vector <uint32_t> mixed;
    for(uint8_t i = 0; i < 4; i++){
        mixed.push_back( ((gmul(14, (state[i] >> 24) & 0xFF) ^ gmul(9, (state[i] & 0xFF)) ^ gmul(13, (state[i] >> 8) & 0xFF) ^ gmul(11, (state[i] >> 16) & 0xFF)) << 24) +
                        ((gmul(14, (state[i] >> 16) & 0xFF) ^ gmul(9, (state[i] >> 24) & 0xFF) ^ gmul(13, (state[i] & 0xFF)) ^ gmul(11, (state[i] >> 8) & 0xFF)) << 16) +
                        ((gmul(14, (state[i] >> 8) & 0xFF) ^ gmul(9, (state[i] >> 16) & 0xFF) ^ gmul(13, (state[i] >> 24) & 0xFF) ^ gmul(11, (state[i] & 0xFF))) << 8 ) +
                        ((gmul(14, (state[i] & 0xFF)) ^ gmul(9, (state[i] >> 8) & 0xFF) ^ gmul(13, (state[i] >> 16) & 0xFF) ^ gmul(11, (state[i] >> 24) & 0xFF))));
    }

    state.assign(mixed.begin(), mixed.end());
}
