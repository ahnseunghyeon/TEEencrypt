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
#include <stdio.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <TEEencrypt_ta.h>

#define RSA_KEY_SIZE 1024
#define MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

int random_key;
int root_key=10;
unsigned int rnd;

struct rsa_session {
	TEE_OperationHandle op_handle;	
	TEE_ObjectHandle key_handle; 
};

TEE_Result prepare_rsa_operation(TEE_OperationHandle *handle, uint32_t alg, TEE_OperationMode mode, TEE_ObjectHandle key) {
	TEE_Result ret = TEE_SUCCESS;	
	TEE_ObjectInfo key_info;
	ret = TEE_GetObjectInfo1(key, &key_info);
	if (ret != TEE_SUCCESS) {
		EMSG("\nTEE_GetObjectInfo1: %#\n" PRIx32, ret);
		return ret;
	}

	ret = TEE_AllocateOperation(handle, alg, mode, key_info.keySize);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc operation handle : 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Operation allocated successfully. ==========\n");

	ret = TEE_SetOperationKey(*handle, key);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to set key : 0x%x\n", ret);
		return ret;
	}
    DMSG("\n========== Operation key already set. ==========\n");

	return ret;
}

TEE_Result check_params(uint32_t param_types) {
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	return TEE_SUCCESS;
}

TEE_Result RSA_create_key_pair(void *session) {
	TEE_Result ret;
	size_t key_size = RSA_KEY_SIZE;
	struct rsa_session *sess = (struct rsa_session *)session;
	
	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc transient object handle: 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Transient object allocated. ==========\n");

	ret = TEE_GenerateKey(sess->key_handle, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		EMSG("\nGenerate key failure: 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Keys generated. ==========\n");
	return ret;
}

TEE_Result RSA_encrypt(void *session, uint32_t param_types, TEE_Param params[4]) {
	TEE_Result ret;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	struct rsa_session *sess = (struct rsa_session *)session;

	if (check_params(param_types) != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	void *plain_txt = params[0].memref.buffer;
	size_t plain_len = params[0].memref.size;
	void *cipher = params[1].memref.buffer;
	size_t cipher_len = params[1].memref.size;

	DMSG("\n========== Preparing encryption operation ==========\n");
	ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_ENCRYPT, sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to prepare RSA operation: 0x%x\n", ret);
		goto err;
	}

	DMSG("\nData to encrypt: %s\n", (char *) plain_txt);
	ret = TEE_AsymmetricEncrypt(sess->op_handle, (TEE_Attribute *)NULL, 0,
					plain_txt, plain_len, cipher, &cipher_len);					
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to encrypt the passed buffer: 0x%x\n", ret);
		goto err;
	}
	DMSG("\nEncrypted data: %s\n", (char *) cipher);
	DMSG("\n========== Encryption successfully ==========\n");
	return ret;

err:
	TEE_FreeOperation(sess->op_handle);
	TEE_FreeOperation(sess->key_handle);
	return ret;
}

static TEE_Result encrypt_value(uint32_t param_types,
	TEE_Param params[4])
{
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen(params[0].memref.buffer);
	char encrypted[64]={0,};
	TEE_GenerateRandom(&rnd, sizeof(rnd));
	random_key = rnd%25+1;

	DMSG("========================Encryption========================\n");
	DMSG ("Plaintext :  %s", in);
	memcpy(encrypted, in, in_len);
	for(int i=0; i<in_len;i++){
		if(encrypted[i]>='a' && encrypted[i] <='z'){
			encrypted[i] -= 'a';
			encrypted[i] += random_key;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'a';
		}
		else if (encrypted[i] >= 'A' && encrypted[i] <= 'Z') {
			encrypted[i] -= 'A';
			encrypted[i] += random_key;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'A';
		}
	}
	
	DMSG("Ciphertext :  %s", encrypted);
	memcpy(in, encrypted, in_len);
	params[1].value.a = random_key+root_key;

	return TEE_SUCCESS;
}

static TEE_Result decrypt_value(uint32_t param_types,
	TEE_Param params[4])
{
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen (params[0].memref.buffer);
	char decrypted [64]={0,};

	DMSG("========================Decryption========================\n");
	DMSG ("Ciphertext :  %s", in);
	memcpy(decrypted, in, in_len);
	random_key = params[1].value.a-root_key;
	DMSG ("key :  %d", random_key);
	for(int i=0; i<in_len;i++){
		if(decrypted[i]>='a' && decrypted[i] <='z'){
			decrypted[i] -= 'a';
			decrypted[i] -= random_key;
			decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
			decrypted[i] += 'a';
		}
		else if (decrypted[i] >= 'A' && decrypted[i] <= 'Z') {
			decrypted[i] -= 'A';
			decrypted[i] -= random_key;
			decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
			decrypted[i] += 'A';
		}
	}
	DMSG ("Plaintext :  %s", decrypted);
	memcpy(in, decrypted, in_len);

	return TEE_SUCCESS;
}



TEE_Result TA_CreateEntryPoint(void) {
	/* Nothing to do */
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
	/* Nothing to do */
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
					TEE_Param __unused params[4],
					void __unused **session) {
	struct rsa_session *sess;
	sess = TEE_Malloc(sizeof(*sess), 0);
	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	sess->key_handle = TEE_HANDLE_NULL;
	sess->op_handle = TEE_HANDLE_NULL;

	*session = (void *)sess;
	DMSG("\nSession %p: newly allocated\n", *session);

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
	struct rsa_session *sess;

	DMSG("Session %p: release session", session);
	sess = (struct rsa_session *)session;

	
	if (sess->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->key_handle);
	if (sess->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(sess->op_handle);
	TEE_Free(sess);
}



TEE_Result TA_InvokeCommandEntryPoint(void *session,
					uint32_t cmd,
					uint32_t param_types,
					TEE_Param params[4]) {
	switch (cmd) {
		case TA_RSA_CMD_GENKEYS:
			return RSA_create_key_pair(session);
		case TA_RSA_CMD_ENCRYPT:
			return RSA_encrypt(session, param_types, params);
		case TA_TEEencrypt_CMD_ENCRYPT:
			return encrypt_value(param_types, params);
		case TA_TEEencrypt_CMD_DECRYPT:
			return decrypt_value(param_types, params);
		default:
			EMSG("Command ID 0x%x is not supported", cmd);
			return TEE_ERROR_NOT_SUPPORTED;
	}
}
