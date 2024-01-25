#include <math.h>
#include <stdio.h>
#include <time.h>
#include"present.h"


int main(){

    // 80-bit user-key is parsed as userKey[0] (64-bit), userKey[1] (16-bit)
    uint64_t userKey[2] = {0x0000000000000000, 0x0000};
    uint64_t state = 0x0;
    uint64_t ciphertext = 0x0;
    
    // Question-1: Implement PRESENT algorithm
    ciphertext = presentCipher(state, userKey);
 
    // Question-2: Encrypting my fullname by PRESENT cipher with CBC mode
    // Yalginay Yaltirik ASCI: 59616C67696E61792059616C746972696B
    // Yalginay Yaltirik ASCI with padding (10*)
    uint64_t fullname[3] = {0x59616C67696E6179, 0x2059616C74697269, 0x6B80000000000000};
    uint64_t keyForName[2] = {0x59616C67696E6179, 0x2059};
    uint64_t nameCiphertext[3] = {0x0, 0x0, 0x0};
    uint64_t numberOfBlock = 3;
 
    // CBC-Mode PRESENT
    for(uint8_t i=0; i < numberOfBlock; i++){
        nameCiphertext[i] =  CBCModePresent(fullname[i], keyForName, numberOfBlock);
        printf("CBC Mode -> CipherText[%d] : %016llx\n", i, nameCiphertext[i]);
    }

    //  Question-3: Take the encryption time of 64MB * 64bit plaintext with CBC mode
    uint64_t testPlaintext = {0x2059616C74697269};
    uint64_t testKey[2] = {0x2059616C74697269, 0x2059};
    uint64_t testCiphertext = {0x0};

    clock_t startTime;
    clock_t endTime;
    
    startTime = clock();
    for(uint64_t i = 1; i <= pow(2, 23); i++){
        testCiphertext = presentCipher(testPlaintext, testKey);
    }
    endTime = clock();
    double cpuUsedTime = (double)((endTime - startTime) / CLOCKS_PER_SEC);
    printf("PRESENT cipher encryption takes: %lf seconds on a single core of Intel(R) Core(TM) i7-10700F CPU @ 2.90GHz\n ", cpuUsedTime);
 
    return 0;
}
