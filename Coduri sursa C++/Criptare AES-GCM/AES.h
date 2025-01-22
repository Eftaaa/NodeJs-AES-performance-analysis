#include <math.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <random>
#include <chrono>
#ifndef AES_H
#define AES_H



     

    uint8_t SBox(uint8_t a);
    uint32_t SubWord(uint32_t w);
    uint32_t RotWord(uint32_t w);
    uint32_t* KeyExpansion(const uint8_t* key);
    void SubBytes(uint8_t** s);
    void ShiftRows(uint8_t** s);
    uint8_t Multiply(uint8_t a, uint8_t b);
    void MixColumns(uint8_t** s);
    void AddRoundKey(uint8_t** state, const uint32_t* w);

  
    uint8_t* Cipher(uint8_t* in, uint8_t size, const uint8_t* key);



 
 







#endif