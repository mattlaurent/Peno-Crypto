#include <stdio.h>
#include <stdlib.h>
#include <ccm.h>
#include "aes.h"

# define GETU32(pt) (((uint32_t)(pt)[0] << 24) ^ ((uint32_t)(pt)[1] << 16) ^ ((uint32_t)(pt)[2] <<  8) ^ ((uint32_t)(pt)[3]))
# define PUTU32(ct, st) { (ct)[0] = (uint8_t)((st) >> 24); (ct)[1] = (uint8_t)((st) >> 16); (ct)[2] = (uint8_t)((st) >>  8); (ct)[3] = (uint8_t)(st); }

//Function declaration
void aes(uint32_t cbcMac[]);
void ctrStart(unsigned char *out, uint32_t so[]);
void ctrUpdate(const aes_key * key, uint32_t ctr[], uint32_t block[], uint32_t output[]);
void printArray(unsigned char arr[]);
void printArray4(uint32_t arr[]);
void encryptXor(const aes_key * key, unsigned char output[], uint32_t block[], unsigned char *out);

void selectMSB(unsigned char *in, uint32_t *out);


//Variable declaration 
uint32_t ctr0[4]= {0x01000000,  0x03020100, 0xA0A1A2A3, 0xA4A50001};
uint32_t b1[4] = {0x00080001, 0x02030405, 0x06070000,  0x00000000};
uint32_t b2[4] = {0x08090a0b, 0x0c0d0e0f, 0x10111213,  0x14151617};
uint32_t b3[4] = {0x18191a1b, 0x1c1d1e00, 0x00000000,  0x00000000};


void ccm(void) {
	//Declaring variabels
	aes_key key;	
	unsigned char output[16];
	uint32_t cbcMac[2], s0[2], mac[2];
	uint32_t ciphertext[4];
	
	aes_set_encrypt_key(&key, "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf", 128);

  	printf("ccm started!\n");
  	
	ctrStart(output, s0);
	
  	
  	ctrUpdate(&key, ctr0, b2, ciphertext); //werkt
  	
  	printArray4(ciphertext);
  	printf("\n");
  	
  	ctrUpdate(&key, ctr0, b3, ciphertext); //werkt
  	
  	printArray4(ciphertext);
  	printf("\n");
  	
  	//printArray(output);
    
    aes(cbcMac);
    
    mac[0] = cbcMac[0] ^ s0[0];
    mac[1] = cbcMac[1] ^ s0[1];
    printf("de mac moet zijn %0x \n", s0[0]);
    printf("de mac moet zijn %0x \n", cbcMac[0]);
    printf("de mac moet zijn %0x \n", mac[0]);

  return;
}

void selectMSB(unsigned char *in, uint32_t *out){
  out[0] = (in[0] << 24) + (in[1] << 16) + (in[2] << 8) + in[3];
  out[1] = (in[4] << 24) + (in[5] << 16) + (in[6] << 8) + in[7];
}

void ctrUpdate(const aes_key * key, uint32_t ctr[], uint32_t block[], uint32_t output[]){
	uint16_t counter = ctr[3]+1;
	uint16_t ctrRest = ctr[3]>>16;
	unsigned char in[16];
	unsigned char outEnc[16];
	    
	    //Storing CTR0 in format for AES	
  		PUTU32(in,ctr[0]);
  		PUTU32(in+4,ctr[1]);
  		PUTU32(in+8,ctr[2]);
  		PUTU32(in+12,ctr[3]);
  		
  	aes_encrypt(key, in, outEnc);
  	
  	//printArray(outEnc);
  	
  	uint32_t rk[8];	
	
		//Xoring the block with AES output
		output[0] = GETU32(outEnc) 		^ block[0];
    	output[1] = GETU32(outEnc+4)	^ block[1];
    	output[2] = GETU32(outEnc+8)	^ block[2];
    	output[3] = GETU32(outEnc+12)	^ block[3];
    	
    	
	ctr[3] = (ctrRest << 16) | counter; //Misschien beter als je van ctr 16 bit array maakt moet je niet splitsen
}

void ctrStart(unsigned char *out, uint32_t so[]){
	//Declaring variabels
	uint32_t rk[8];	
	unsigned char in[16];	
	aes_key key;	
	
	aes_set_encrypt_key(&key, "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf", 128);
	
	    //Storing CTR0 in format for AES	
  		PUTU32(in,ctr0[0]);
  		PUTU32(in+4,ctr0[1]);
  		PUTU32(in+8,ctr0[2]);
  		PUTU32(in+12,ctr0[3]);
  		
  	aes_encrypt(&key, in, out);
  	
  	selectMSB(out, so);
}



void aes(uint32_t cbcMac[]) {
aes_key key;
unsigned char output[16];
unsigned char out[16];

  aes_set_encrypt_key(&key, "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf", 128);
  
  
  aes_encrypt(&key, "\x59\x00\x00\x00\x03\x02\x01\x00\xA0\xA1\xA2\xA3\xA4\xA5\x00\x17", output);
  
  /*

  aes_set_decrypt_key(&key, "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c", 128);
  
  aes_decrypt(&key, "\x3a\xd7\x7b\xb4\x0d\x7a\x36\x60\xa8\x9e\xca\xf3\x24\x66\xef\x97", output);

  if (memcmp(output, "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a", 16) != 0) {
    fprintf(stderr, "Decryption failed\n");
    abort();
  }*/
  
  encryptXor(&key, output, b1, output);
  encryptXor(&key, output, b2, output);
  encryptXor(&key, output, b3, output);
  
  selectMSB(output, cbcMac);
  
  printArray(output);
  printf("\n Correct \n");
}




void encryptXor(const aes_key * key, unsigned char outEnc[], uint32_t block[], unsigned char *out){
	//Declaring var
	uint32_t rk[8];	
	unsigned char in[16];	
	
		//Xoring the block with AES output
		rk[0] = GETU32(outEnc) ^ block[0] ;
    	rk[1] = GETU32(outEnc+4) ^ block[1];
    	rk[2] = GETU32(outEnc+8) ^ block[2];
    	rk[3] = GETU32(outEnc+12) ^ block[3];
    	
    	//Storing results in format for AES	
  		PUTU32(in,rk[0]);
  		PUTU32(in+4,rk[1]);
  		PUTU32(in+8,rk[2]);
  		PUTU32(in+12,rk[3]);
  		
  		//Encrypting with AES
  		aes_encrypt(key, in, out);
  		
}





void printArray(unsigned char arr[]){
int i;
	for(i=0;i<16;i++){
		printf("%0x ",arr[i]);
	}
}

void printArray4(uint32_t arr[]){
int i;
	for(i=0;i<4;i++){
		printf("%0x ",arr[i]);
	}
}
