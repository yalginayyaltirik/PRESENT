#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#define NUMBER_OF_ROUND 32
#define PERMUTATION_SIZE 64

// Define the 4-bit S-box
const uint8_t sBox[16] = {
    0xC, 0x5, 0x6, 0xB,
    0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8,
    0x4, 0x7, 0x1, 0x2
};

// Define the 64-bit Permutation Order
const uint64_t permutationOrder[PERMUTATION_SIZE] = {0, 16, 32, 48, 1, 17, 33, 49,
                                                    2, 18, 34, 50, 3, 19, 35, 51,
                                                    4, 20, 36, 52, 5, 21, 37, 53,
                                                    6, 22, 38, 54, 7, 23, 39, 55,
                                                    8, 24, 40, 56, 9, 25, 41, 57,
                                                    10, 26, 42, 58, 11, 27, 43, 59,
                                                    12, 28, 44, 60, 13, 29, 45, 61,
                                                    14, 30, 46, 62, 15, 31, 47, 63
};

//Generates 32-round keys for each round
uint64_t generateRoundKey(uint64_t userKey[], uint32_t roundCounter){
    uint64_t beShifted0to19Bit;
    uint64_t beShifted20to39Bit;
    uint64_t beShifted40to80Bit;
    uint64_t s4Out;
    uint64_t s4In;
    uint64_t xor5In;

    // Round key is the left-most 64bits of the user-key
    uint64_t roundKey = userKey[0];

    // Update the user-key
    // Extract bits 19, 20 and 41 sized chunks to manipulate
    beShifted0to19Bit = ((userKey[0] & 0x7) << 16) | userKey[1];  // rightmost 19bit.
    beShifted20to39Bit = (userKey[0] >> 3) & 0xFFFFF; // rightmost 19 to 39 bit
    beShifted40to80Bit = (userKey[0] >> 23) & 0x1FFFFFFFFFF; // rightmost 40 to 80 bit

    // Perform S-box operation to the left-most 4bits, then update the bit chunk
    s4In = (beShifted0to19Bit >> 15) & 0xF;
    s4Out = sBox[s4In];
    beShifted0to19Bit = (s4Out << 15) | (beShifted0to19Bit & 0x7FFF);

    // XOR the left-most 5 bits of bit chunk,  then update the bit chunk
    xor5In = (beShifted20to39Bit >> 15) & 0x1F;
    xor5In ^= roundCounter;
    beShifted20to39Bit = (beShifted20to39Bit & 0x07FFF) | (xor5In << 15); 

    // Clear user-key, then update the user-key with the manipulated bit chunks
    userKey[0] = 0;
    userKey[1] = 0;
    userKey[0] = ((beShifted0to19Bit << 45) & 0xFFFFE00000000000) | ((beShifted40to80Bit << 4) & 0x00001FFFFFFFFFF0) | ((beShifted20to39Bit >> 16) & 0xF) ;
    userKey[1] = beShifted20to39Bit & 0xFFFF; 

    return roundKey;

}

//xor the state with the round key
void addRoundKey(uint64_t* state, uint64_t roundKey){
    *state ^= roundKey;
}

//4-bit to 4-bit s-box operation
void sBoxLayer(uint64_t* state){

    uint8_t s4In;
    uint8_t s4Out;
    // Extract 4-bit value, perform s-box operation, clear the correct position, write the S-box output to correct place
    for(uint32_t i = 0; i<16; i++){
        s4In = (*state >> 4 * i) & 0xF;
        s4Out = sBox[s4In];
        *state &=  ~(0xFULL << (4 * i));
        *state |= (int64_t)s4Out << (4 * i);
    }
}

// Perform permutation on s-box output.
void pLayer(uint64_t* state){

    uint64_t permutation = 0;
    // permute 64bit
    for (uint8_t i=0; i<64; i++){
        int distance = 63 - i;
        permutation |= ((*state >> distance & 0x1) << 63 - permutationOrder[i]);
    }
    *state = permutation;
    return;
}

// present-cipher-encryption algorithm
uint64_t presentCipher(uint64_t state, uint64_t userKey[]){

    uint64_t ciphertext = 0x0;
    uint64_t roundKey[NUMBER_OF_ROUND];

    // Perform add round key, s-box operation and permutation accordingly
    for(uint32_t i=0; i< NUMBER_OF_ROUND - 1; i++){
        roundKey[i] = generateRoundKey(userKey, i+1);
        addRoundKey(&state, roundKey[i]);
        sBoxLayer(&state);
        pLayer(&state);
        //printf("Round Key %d is %016llx\n",i+1, roundKey[i]);
        // printf("Round Output: %d: %016llx\n", i+1, state);
    }
    roundKey[31] = generateRoundKey(userKey, 32);
    // printf("Round Key 32 is %016llx\n", roundKey[31]);
    addRoundKey(&state, roundKey[31]);
    ciphertext = state;
    // printf("Ciphertext: %016llx\n", state);

    return ciphertext;
}

// present-cipher-encryption algorithm
uint64_t CBCModePresent(uint64_t plaintext, uint64_t userKey[], uint64_t numberOfBlock){

    static uint64_t ciphertext[2] = {0, 0};
    
    if(numberOfBlock > 1){
        plaintext ^= ciphertext[0];    
        ciphertext[1]= presentCipher(plaintext, userKey); 
        // printf("ciphertext[1] is %016llx\n", ciphertext[1]);
        ciphertext[0] = ciphertext[1]; // To use further blocks reputetive
        return ciphertext[1];
    }
    else{
        uint64_t IV = rand();
        plaintext ^= IV;  
        ciphertext[0]= presentCipher(plaintext, userKey); 
        // printf("ciphertext[0] is %016llx\n", 0, ciphertext[0]);
        return ciphertext[0];
    }
    
}
