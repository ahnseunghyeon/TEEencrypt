/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>

#include <TEEencrypt_ta.h>

#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)



struct ta_attrs {
	TEEC_Context ctx;
	TEEC_Session sess;
};

void prepare_ta_session(struct ta_attrs *ta)
{
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t origin;
	TEEC_Result res;

	res = TEEC_InitializeContext(NULL, &ta->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InitializeContext failed with code 0x%x\n", res);

	res = TEEC_OpenSession(&ta->ctx, &ta->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_Opensession failed with code 0x%x origin 0x%x\n", res, origin);
}

void terminate_tee_session(struct ta_attrs *ta)
{
	TEEC_CloseSession(&ta->sess);
	TEEC_FinalizeContext(&ta->ctx);
}


void prepare_RSAop(TEEC_Operation *op, char *in, size_t in_sz, char *out, size_t out_sz) {
	memset(op, 0, sizeof(*op));

	op->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 		TEEC_MEMREF_TEMP_OUTPUT,
					 		TEEC_NONE, TEEC_NONE);
	op->params[0].tmpref.buffer = in;
	op->params[0].tmpref.size = in_sz;
	op->params[1].tmpref.buffer = out;
	op->params[1].tmpref.size = out_sz;
}

void prepare_CEASERop(TEEC_Operation *op, char *plaintext, int len) {
	memset(op, 0, sizeof(*op));

	op->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE);
	
	op->params[0].tmpref.buffer = plaintext;
	op->params[0].tmpref.size = len;
	op->params[1].value.a = 0;
}


void rsa_gen_keys(struct ta_attrs *ta) {
	TEEC_Result res;

	res = TEEC_InvokeCommand(&ta->sess, TA_RSA_CMD_GENKEYS, NULL, NULL);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_GENKEYS) failed %#x\n", res);
	printf("\n=========== Keys already generated. ==========\n");
}

void rsa_encrypt(struct ta_attrs *ta, char *in, size_t in_sz, char *out, size_t out_sz, char *argv)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	FILE *fp;

	printf("========================Encryption========================\n");

	fp = fopen(argv, "r");
	fread(in,1,in_sz,fp);
	fclose(fp);

	printf("\n============ RSA ENCRYPT CA SIDE ============\n");
	prepare_RSAop(&op, in, in_sz, out, out_sz);

	res = TEEC_InvokeCommand(&ta->sess, TA_RSA_CMD_ENCRYPT,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_ENCRYPT) failed 0x%x origin 0x%x\n",
			res, origin);
	printf("\nThe text sent was encrypted: %s\n", out);

	fp = fopen("RSAencrypt.txt", "w");
	fputs(out,fp);
	fclose(fp);
}

void ceaser_encrypt(struct ta_attrs *ta, char *plaintext, int len, char *argv, char *ciphertext)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	FILE *fp;
	char buffer[100] = {0,};

	fp = fopen(argv, "r");
	fread(buffer,1,sizeof(buffer),fp);
	fclose(fp);

	prepare_CEASERop(&op, plaintext, len);
	printf("========================Encryption========================\n");
	memcpy(op.params[0].tmpref.buffer, buffer, len);

	res = TEEC_InvokeCommand(&ta->sess, TA_TEEencrypt_CMD_ENCRYPT, &op,
				 &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, origin);

	memcpy(ciphertext, op.params[0].tmpref.buffer, len);
	
	fp = fopen("ciphertext.txt", "w");
	fputs(ciphertext,fp);
	fclose(fp);
	printf("Ciphertext : %s\n", ciphertext);
		
	fp = fopen("encryptedkey.txt", "w");
	fprintf(fp,"%d\n",op.params[1].value.a);
	fclose(fp);
	printf("Cipherkey : %d\n", op.params[1].value.a);
}

void ceaser_decrypt(struct ta_attrs *ta, char *plaintext, int len, char *argv1, char *argv2, char *ciphertext)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	FILE *fp;
	char buffer[100] = {0,};
	int cipherkey=0;

	fp = fopen(argv1,"r");
	fread(buffer,1,100,fp);
	fclose(fp);
	
	fp = fopen(argv2,"r");
	fscanf(fp,"%d",&cipherkey);
	fclose(fp);

	prepare_CEASERop(&op, plaintext, len);
	printf("========================Decryption========================\n");
	memcpy(op.params[0].tmpref.buffer, buffer, len);

	op.params[1].value.a = cipherkey;

	res = TEEC_InvokeCommand(&ta->sess, TA_TEEencrypt_CMD_DECRYPT, &op,
				 &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, origin);
	memcpy(plaintext, op.params[0].tmpref.buffer, len);
	
	printf("Plaintext : %s\n", plaintext);

	fp = fopen("decryptedtext.txt", "w");
	fputs(plaintext,fp);
	fclose(fp);
}

int main(int argc, char *argv[])
{
	struct ta_attrs ta;
	char clear[RSA_MAX_PLAIN_LEN_1024];
	char ciph[RSA_CIPHER_LEN_1024];
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	int len=64;

	prepare_ta_session(&ta);

	if(strcmp(argv[1], "-e")==0 && strcmp(argv[3], "RSA")==0){

		rsa_gen_keys(&ta);
		rsa_encrypt(&ta, clear, RSA_MAX_PLAIN_LEN_1024, ciph, RSA_CIPHER_LEN_1024, argv[2]);
	}
	else{
		if((strcmp(argv[1], "-e")==0) && (strcmp(argv[3], "Ceaser")==0)){
			ceaser_encrypt(&ta, plaintext, len, argv[2], ciphertext);
		}
		if(strcmp(argv[1], "-d")==0){
			ceaser_decrypt(&ta, plaintext, len, argv[2], argv[3], ciphertext);
	
		}
	}
	terminate_tee_session(&ta);
	return 0;
}
