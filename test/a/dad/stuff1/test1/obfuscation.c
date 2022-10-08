//gcc -o obfuscation base64.c obfuscation.c -lssl -lcrypto -lmcrypt -lm -lz

#include <jni.h>

#include<stdio.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <string.h>
#include <mcrypt.h>
#include <math.h>
#include <stdint.h>qwdqwdqwdqwd
#include <inttypes.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <zlib.h>


#define FALSE 0
#define TRUE 1
#define BUFFSIZE 32768

#define Max(a,b) (a>b?a:b)
#define FREE(p) \
do \
{ \
  free(p); \
  p = NULL; \
} \
while(0)


int Base64encode(char *encoded, const char *string, int len);


void hex2binstr(char ciphertext_hash[], char ciphertext_hash_binstr[]){

	int i;
	for(i=0; ciphertext_hash[i]!='\0'; i++)
    {
        switch(ciphertext_hash[i])
        {
            case '0':
                strcat(ciphertext_hash_binstr, "0000");
                break;
            case '1':
                strcat(ciphertext_hash_binstr, "0001");
                break;
            case '2':
                strcat(ciphertext_hash_binstr, "0010");
                break;
            case '3':
                strcat(ciphertext_hash_binstr, "0011");
                break;
            case '4':
                strcat(ciphertext_hash_binstr, "0100");
                break;
            case '5':
                strcat(ciphertext_hash_binstr, "0101");
                break;
            case '6':
                strcat(ciphertext_hash_binstr, "0110");
                break;
            case '7':
                strcat(ciphertext_hash_binstr, "0111");
                break;
            case '8':
                strcat(ciphertext_hash_binstr, "1000");
                break;
            case '9':
                strcat(ciphertext_hash_binstr, "1001");
                break;
            case 'a':
            case 'A':
                strcat(ciphertext_hash_binstr, "1010");
                break;
            case 'b':
            case 'B':
                strcat(ciphertext_hash_binstr, "1011");
                break;
            case 'c':
            case 'C':
                strcat(ciphertext_hash_binstr, "1100");
                break;
            case 'd':
            case 'D':
                strcat(ciphertext_hash_binstr, "1101");
                break;
            case 'e':
            case 'E':
                strcat(ciphertext_hash_binstr, "1110");
                break;
            case 'f':
            case 'F':
                strcat(ciphertext_hash_binstr, "1111");
                break;
            default:
                printf("Invalid hexadecimal input.");
        }
    }

}


//func to chop chars from beginning of string
void chopN(char *str, size_t n)
{
    //assert(n != 0 && str != 0);
	if (n != 0){

		size_t len = strlen(str);
		if (n > len)
		    return;  // Or: n = len;
		memmove(str, str+n, len - n + 1);

	}
}



//func to reverse string - used when converting binstr2hex
char *strrev(char *str)
{
      char *p1, *p2;

      if (! str || ! *str)
            return str;
      for (p1 = str, p2 = str + strlen(str) - 1; p2 > p1; ++p1, --p2)
      {
            *p1 ^= *p2;
            *p2 ^= *p1;
            *p1 ^= *p2;
      }
      return str;
}


/*---------------sha256sum funcs--------------*/

void sha256_hash_string (unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65])
{
    int i = 0;

    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }

    outputBuffer[64] = 0;
}


void sha256_string(char *string, char outputBuffer[65])
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256);
    int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = 0;
}

/*---------------------------------------------*/


//AES encryption with mcrypt
int encrypt(
    void* buffer,
    int buffer_len, /* Because the plaintext could include null bytes*/
    char* IV, 
    char* key,
    int key_len 
){
  MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
  int blocksize = mcrypt_enc_get_block_size(td);
  if( buffer_len % blocksize != 0 ){return 1;}

  mcrypt_generic_init(td, key, key_len, IV);
  mcrypt_generic(td, buffer, buffer_len);
  mcrypt_generic_deinit (td);
  mcrypt_module_close(td);
  
  return 0;
}



int handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    return FALSE;
}


 

void obfuscate(char *indata){

   int ret = 0; 
   int ciphertext_len = 0; 
   unsigned char key[32] = "" ; 
   unsigned char iv[16] = "";
   unsigned char *enc_data = NULL;
   unsigned char *base64encode = NULL; 
   unsigned char *base64decode = NULL; 


    //allocating memories 
     enc_data = (unsigned char *)malloc(1024);
     base64encode = (unsigned char *)malloc(1024);
     base64decode = (unsigned char *)malloc(1024);
     
	
	//generating random 16 bytes for secretkey
    if(!RAND_bytes(key, sizeof key)) {
        /* OpenSSL reports a failure, act accordingly */
        printf("From Obfuscation library \n");
        fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
        FREE(enc_data);
        FREE(base64encode);
        FREE(base64decode);
    }
		

	//converting above 16 bytes to hex
	char secretKey_hex[33];
	secretKey_hex[32] = 0;
	int j;
	for(j = 0; j < 16; j++)
	sprintf(&secretKey_hex[2*j], "%02x", key[j]);

		//taking first 16 chars of above hex to be used as secret key for encryption
		char secretKey_final[16];
   		int position = 1;
		int length = 16;
		int c = 0;	

		while (c < length) {
      		secretKey_final[c] = secretKey_hex[position+c-1];
      		c++;
   		}
   		secretKey_final[c] = '\0';



   	//generating 16 random bytes for IV
    if(!RAND_bytes(iv, sizeof iv)) {
      /* OpenSSL reports a failure, act accordingly */
        printf("From Obfuscation library \n");
        fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
        FREE(enc_data);
        FREE(base64encode);
        FREE(base64decode);
    }

		//converting above 16 bytes to hex
		char iv_hex[33];
		iv_hex[32] = 0;
		for(j = 0; j < 16; j++)
		sprintf(&iv_hex[2*j], "%02x", iv[j]);


		//taking the first 16 chars of above hex to be used as IV for encryption
		char iv_final[16];
   		int position2 = 1;
		int length2 = 16;
		int c2 = 0;	

		while (c2 < length2) {
      		iv_final[c2] = iv_hex[position2+c2-1];
      		c2++;
   		}
   		iv_final[c2] = '\0';


	//padding manually for AES encryption wrt multiple of 16 bytes
	int padding_diff = 16 * ( (strlen(indata)/16) + 1 ) - strlen(indata);

	char indata_final[padding_diff + strlen(indata)];
	strcpy(indata_final, indata);

	for (int  n = 0; n < padding_diff; ++n) {
			strcat(indata_final, "\0");
	}
	

	char ciphertext[padding_diff + strlen(indata)];	
	strncpy(ciphertext, indata_final, padding_diff + strlen(indata));


	//encrypting given data using AES
	encrypt(ciphertext, padding_diff + strlen(indata), iv_final, secretKey_final, 16);

	//encoding ciphertext to base64
	Base64encode(base64encode, ciphertext, padding_diff + strlen(indata));
	unsigned char *ciphertext_base64;
	ciphertext_base64 = base64encode;


	//getting hash of encrypted data in base64
	static unsigned char ciphertext_hash[65];
	sha256_string(ciphertext_base64, ciphertext_hash);

	//converting above hash to binstr for XORing later
	char ciphertext_hash_binstr[256];
	hex2binstr(ciphertext_hash, ciphertext_hash_binstr);




	if (strlen(ciphertext_hash_binstr) > 128){

		chopN(ciphertext_hash_binstr, strlen(ciphertext_hash_binstr)-256);

	}



	//converting the secret key in hex to binstr for XORing later
	char secretKey_binstr[128];
	hex2binstr(secretKey_hex, secretKey_binstr);



	if (strlen(secretKey_binstr) > 128){

		chopN(secretKey_binstr, strlen(secretKey_binstr)-128);

	}


	//padding the 128 bit secretkey with 128 zeroes in front, for XORing later
	char secretKey_binstr_final[256] = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

	strcat(secretKey_binstr_final, secretKey_binstr);


	//XORing the secretkey and hash of encrypted data(in base64)
	char xored_binstr[256];

	int i;
    for (i=0; i<256; i++)
    {

       if (secretKey_binstr_final[i] == ciphertext_hash_binstr[i]){

		    strcat(xored_binstr, "0");

		}else{

		    strcat(xored_binstr, "1");

		}

    }
	

	//converting above XORed string to hex
	int hexConstant[] = {0, 1, 10, 11, 100, 101, 110, 111, 1000, 1001, 1010, 1011, 1100, 1101, 1110, 1111};

	char xored_string_hex[64];
    int index, digit;

	index = 0;
    int len = strlen(xored_binstr) ;
    for(int j =  len-1; j>=0; j-=4) {

         if(j-3>=0) digit = (xored_binstr[j-3]-'0')*1000 + (xored_binstr[j-2]-'0')*100 + (xored_binstr[j-1]-'0') * 10 + (xored_binstr[j]-'0');
         else if(j-3>=0) digit = (xored_binstr[j-2]-'0')*100 + (xored_binstr[j-1]-'0') * 10 + (xored_binstr[j]-'0');
         else if(j-1>=0) digit = (xored_binstr[j-1]-'0') * 10 + (xored_binstr[j]-'0');
         else digit = (xored_binstr[j]-'0');

         for(i=0; i<16; i++)
        {
            if(hexConstant[i] == digit)
            {
                if(i<10)
                {
                    xored_string_hex[index] = (char)(i + 48);
                }
                else
                {
                    xored_string_hex[index] = (char)((i-10) + 65);
                }

                index++;
                break;
            }
        }
    }

    xored_string_hex[index] = '\0';

    strrev(xored_string_hex);



	//concatenating the encrypted data, xored key and ivi
	//preprefinalmsg => ciphertext in base64 + xoredkey in hex + iv_final in hex
	char preprefinalmsg[strlen(ciphertext_base64)+strlen(xored_string_hex)+strlen(iv_final)];
	strcpy(preprefinalmsg, ciphertext_base64);
	strcat(preprefinalmsg, xored_string_hex);
	strcat(preprefinalmsg, iv_final);
	

	//taking crc32 of above, converting to hex and appending it -> first layer
	char prefinalmsg[strlen(preprefinalmsg)+8];
	uLong crc1 = crc32(0L, Z_NULL, 0);
	crc1 = crc32(crc1, preprefinalmsg, strlen(preprefinalmsg));
	char crc1_hex[32];
	sprintf(crc1_hex, "%lx", crc1);
	
	strcpy(prefinalmsg, preprefinalmsg);
	strcat(prefinalmsg, crc1_hex);

	//taking crc32 of above, converting to hex and appending it -> first layer -> second layer
	char finalmsg[strlen(prefinalmsg)+8];
	uLong crc2 = crc32(0L, Z_NULL, 0);
	crc2 = crc32(crc2, prefinalmsg, strlen(prefinalmsg));
	char crc2_hex[32];
	sprintf(crc2_hex, "%lx", crc2);

	strcpy(finalmsg, crc2_hex);
	strcat(finalmsg, prefinalmsg);


	//final msg -> (encrypted_data + xored_key + ivi) + crc32(encrypted_data + xored_key + ivi) + crc32(crc32(encrypted_data + xored_key))

	printf("\nencryptedData-------------->%s\n\n", finalmsg);

}



/*int main(){


char *data = "helloworld";
obfuscate(data);

return 0;

}*/



JNIEXPORT void JNICALL Java_Obfuscation_cjniobfuscation
  (JNIEnv *env, jobject jobj)
{

	obfuscate("hellworld");

}




