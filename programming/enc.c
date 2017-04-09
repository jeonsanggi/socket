#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#define IN_FILE "plain.txt"
#define OUT_FILE "encrypt.bin"

unsigned char * readFile(char * file, int *readLen);
unsigned char * readFileBio(BIO * fileBIO, int *readLen);
unsigned char * addString(unsigned char *destString, int destLen, const unsigned char *addString, int addLen);

int main(){

		unsigned char key[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
		unsigned char iv[] = {1,2,3,4,5,6,7,8};

		BIO *errBIO = NULL;
		BIO *outBIO = NULL;

		ERR_load_crypto_strings();
		
		
		if((errBIO = BIO_new(BIO_s_file()))!= NULL)
			BIO_set_fp(errBIO,stderr,BIO_NOCLOSE|BIO_FP_TEXT);
		outBIO = BIO_new_file(OUT_FILE, "wb");

		if(!outBIO){
			BIO_printf(errBIO, "make error [%s]\n", OUT_FILE);
			ERR_print_errors(errBIO);
			exit(1);
		}

		int len;
		unsigned char * readBuffer = readFile(IN_FILE, &len);

		EVP_CIPHER_CTX ctx;
		EVP_CIPHER_CTX_init(&ctx);

		EVP_Encryptlnit_ex(&ctx, EVP_bf_cbc(), NULL, key, iv);

		unsigned char * outbuf = (unsigned char *)malloc(sizeof(unsigned char)*(len + EVP_CIPHER_CTX_block_size(&ctx)));

		int outlen, tmplen;

		if(!EVP_encryptUpdate(&ctx, outbuf,&outlen, readBuffer, strlen((char *)readBuffer)))
			return 0;
		
		if(!EVP_EncryptFinal_ex(&ctx, outbuf + outlen, &tmplen))
			return 0;

		outlen += tmplen;
		EVP_CIPHER_CTX_cleanup(&ctx);

		BIO_printf(errBIO, "Success make encrypt\n save [%s] file\n", OUT_FILE);

		BIO_write(outBIO, outbuf, outlen);

		BIO_free(outBIO);

		return 0;
}

unsigned char * readFileBio(BIO * fileBIO, int *readLen){

	unsigned char * retBuffer = NULL;
	unsigned char * buffer = (unsigned char *)malloc(1001);
	int length = 0;

	*readLen = 0;

	while(1){
		length = BIO_read(fileBIO, buffer, 1000);
		buffer[length] = 0;
		retBuffer = addString(retBuffer,*readLen, buffer, length);
		*readLen = *readLen + length;

		if(length == 1000)
			BIO_seek(fileBIO, 1000);
		else
			break;
	}
	return retBuffer;
}

unsigned char *addString(unsigned char *destString, int destLen, const unsigned char *addString, int addLen){
	unsigned char * retString;
	int i;

	if((destString == NULL)||(destLen == 0)){
		retString = (unsigned char *)malloc(sizeof(unsigned char)*(addLen+1));

		for(i = 0; i<addLen;i++){
			retString[i] = addString[i];
		}

		retString[i] = NULL;
	}
	else{
		retString = (unsigned char *)malloc(sizeof(unsigned char)*(destLen+addLen+1));

		for(i = 0; i < destLen;i++){
			retString[i] = destString[i];
		}

		for(i = 0; i < addLen;i++){
			retString[i+destLen] = addString[i];
		}

		retString[i+destLen] = NULL;
	}

	free(destString);

	return retString;
	
}


