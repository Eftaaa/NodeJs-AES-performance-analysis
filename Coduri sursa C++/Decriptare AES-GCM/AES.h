#include <math.h>
#include <iostream>
#include <fstream>
#include <math.h>
#include <string>
#include <vector>
#include <random>
#ifndef AESINV_H
#define AESINV_H





extern int roundkey;
extern int Nk;
extern int Nr;


    uint8_t InvSBox(uint8_t a);
    uint32_t InvSubWord(uint32_t w);
    uint32_t InvRotWord(uint32_t w);
    uint32_t* KeyExpansion(const uint8_t* key);
    void InvSubBytes(uint8_t** s);
    void InvShiftRows(uint8_t** s);
    uint8_t Multiply(uint8_t a, uint8_t b);
    void InvMixColumns(uint8_t** s);
    void AddRoundKey(uint8_t** state, const uint32_t* w);


    uint8_t* InvCipher(uint8_t* in, uint8_t size, const uint8_t* key);



    uint8_t SBox(uint8_t a);
    uint32_t SubWord(uint32_t w);
    uint32_t RotWord(uint32_t w);
  
    void SubBytes(uint8_t** s);
    void ShiftRows(uint8_t** s);
   
    void MixColumns(uint8_t** s);
    


    uint8_t* Cipher(uint8_t* in, uint8_t size, const uint8_t* key);












#endif