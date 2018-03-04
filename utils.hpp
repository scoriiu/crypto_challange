//
//  utils.hpp
//  crypto_challange_1
//
//  Created by Solomon Corîiu on 21/03/2018.
//  Copyright © 2018 Solomon Corîiu. All rights reserved.
//

#pragma once

#include <stdio.h>
#include <string>
#include <vector>
#include <map>

static std::map<char, double> englishFreq = {
    {'a', 8.167}, {'b', 1.492}, {'c', 2.782}, {'d', 4.253}, {'e', 12.702}, {'f', 2.228}, {'g', 2.015},
    {'h', 6.094}, {'i', 6.966}, {'j', 0.153}, {'k', 0.772}, {'l', 4.025}, {'m', 2.406}, {'n', 6.749},
    {'o', 7.507}, {'p', 1.929}, {'q', 0.095}, {'r', 5.987}, {'s', 6.327}, {'t', 9.056}, {'u', 2.758},
    {'v', 0.978}, {'w', 2.360}, {'x', 0.150}, {'y', 1.974}, {'z', 0.074}, {' ', 23}
};

std::string str2hex(const std::string &str);

std::string hex2str(const std::string &input);

std::string str2base64(const std::string &str);

std::string base642str(const std::string &base64);

std::string hex2base64(const std::string &hex);

std::string xorStr(const std::string &s1, const std::string &s2);

std::string xorBySingleByte(const std::string &str, uint8_t c);

int scoreEnglishFreq(const std::string &str);

uint8_t mostFrequentByte(const std::string &str);

std::string encryptXor(const std::string &str, const std::string &key);

uint32_t hammingDistance(const std::string &str1, const std::string &str2);

uint32_t findKeySize(const std::string &str, uint32_t min, uint32_t max);

std::string PKCS7(const std::string &input, uint8_t k);

std::string randBytes(size_t size);
