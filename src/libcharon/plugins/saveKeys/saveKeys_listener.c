/*
 * Copyright (C) 2016 Codrut Cristian Grosu (codrut.cristian.grosu@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */


#include "saveKeys_listener.h"

#include <stdio.h>
#include <stdlib.h>

typedef struct private_saveKeys_listener_t private_saveKeys_listener_t;

/**
 * Default path for the directory where the decryption tables will be stored.
 */
static char *default_path = "/tmp/";

/**
 * Private data of an saveKeys_listener_t object.
 */
struct private_saveKeys_listener_t {

	/**
	 * Public saveKeys_listener_t interface.
	 */
	saveKeys_listener_t public;

	/**
	 * SPI_i for IKEv2.
	 */
	chunk_t spi_i;

	/**
	 * SPI_r for IKEv2.
	 */
	chunk_t spi_r;

	/**
	 * Path to the directory where the decryption tables will be stored.
	 */
	char *directory_path;
};

/**
 * Expands the name of encryption algorithms for IKE decryption table.
 */
static inline char *expand_enc_name(uint16_t enc_alg, uint16_t size)
{
	char *name;
	switch (enc_alg) {
		case ENCR_3DES:
			name = malloc(strlen("3DES [RFC2451]") + 1);
			strcpy(name, "3DES [RFC2451]");
			break;
		case ENCR_AES_CBC:
			name = malloc(strlen("AES-CBC-128 [RFC3602]") + 1);
			strcpy(name, "AES-CBC-");
			switch (size) {
				case 128:
					strcat(name, "128 [RFC3602]");
					break;
				case 192:
					strcat(name, "192 [RFC3602]");
					break;
				case 256:
					strcat(name, "256 [RFC3602]");
					break;
				default:
					free(name);
					name = NULL;
			}
			break;
		case ENCR_NULL:
			name = malloc(strlen("NULL [RFC2410]") + 1);
			strcpy(name, "NULL [RFC2410]");
			break;
		default:
			name = NULL;
			break;
	}
	return name;
}

/**
 * Expands the name of encryption algorithms for ESP decryption table.
 */
static inline char *esp_expand_enc_name(uint16_t enc_alg, int *ICV_length)
{
	char *name;
	switch (enc_alg) {
		case ENCR_NULL:
			name = malloc(strlen("NULL") + 1);
			strcpy(name, "NULL");
			break;
		case ENCR_3DES:
			name = malloc(strlen("TripleDes-CBC [RFC2451]") + 1);
			strcpy(name, "TripleDes-CBC [RFC2451]");
			break;
		case ENCR_AES_CBC:
			name = malloc(strlen("AES-CBC [RFC3602]") + 1);
			strcpy(name, "AES-CBC [RFC3602]");
			break;
		case ENCR_AES_CTR:
			name = malloc(strlen("AES-CTR [RFC3686]") + 1);
			strcpy(name, "AES-CTR [RFC3686]");
			break; 
		case ENCR_DES:
			name = malloc(strlen("DES-CBC [RFC2405]") + 1);
			strcpy(name, "DES-CBC [RFC2405]");
			break;
		case ENCR_CAST:
			name = malloc(strlen("CAST5-CBC [RFC2144]") + 1);
			strcpy(name, "CAST5-CBC [RFC2144]");
			break;
		case ENCR_BLOWFISH:
			name = malloc(strlen("BLOWFISH-CBC [RFC2451]") + 1);
			strcpy(name, "BLOWFISH-CBC [RFC2451]");
			break;
		case ENCR_TWOFISH_CBC:
			name = malloc(strlen("TWOFISH-CBC") + 1);
			strcpy(name, "TWOFISH-CBC");
			break;
		case ENCR_AES_GCM_ICV8:
			(*ICV_length) = 128;
			name = malloc(strlen("AES-GCM [RFC4106]") + 1);
			strcpy(name, "AES-GCM [RFC4106]");
			break;
		case ENCR_AES_GCM_ICV12:
			(*ICV_length) = 192;
			name = malloc(strlen("AES-GCM [RFC4106]") + 1);
			strcpy(name, "AES-GCM [RFC4106]");
			break;
		case ENCR_AES_GCM_ICV16:
			(*ICV_length) = 256;
			name = malloc(strlen("AES-GCM [RFC4106]") + 1);
			strcpy(name, "AES-GCM [RFC4106]");
			break;
		default:
			name = NULL;
			break;
	}
	return name;
}

/**
 * Reverse SPI ESP
 */
static inline uint32_t byte_reverse_32(uint32_t num) {
    union bytes {
        uint8_t b[4];
        uint32_t n;
    } bytes;
    uint8_t t;

    bytes.n = num;

    t = bytes.b[0]; bytes.b[0] = bytes.b[3]; bytes.b[3] = t;
    t = bytes.b[1]; bytes.b[1] = bytes.b[2]; bytes.b[2] = t;

    return bytes.n;
}

/**
 * Expands the name of integrity algorithms for IKE decryption table.
 */
static inline char *expand_int_name(uint16_t int_alg)
{
	char *name;
	enum_name_t *type2 = transform_get_enum_names(INTEGRITY_ALGORITHM);
	char *short_int_alg = enum_to_name(type2, int_alg);
	int size_short_name = strlen(short_int_alg);
	switch (int_alg)
	{
		case AUTH_HMAC_MD5_96:
			name = malloc(size_short_name + strlen(" [RFC2403]")  + 1);
			strcpy(name, short_int_alg);
			strcat(name, " [RFC2403]");
			break;
		case AUTH_HMAC_SHA1_96:
			name = malloc(size_short_name + strlen(" [RFC2404]") + 1);
			strcpy(name, short_int_alg);
			strcat(name, " [RFC2404]");
			break;
		case AUTH_HMAC_SHA2_256_96:
			name = malloc(size_short_name + strlen(" [draft-ietf-ipsec-ciph-sha-256-00]") + 1);
			strcpy(name, short_int_alg);
			strcat(name, " [draft-ietf-ipsec-ciph-sha-256-00]");
			break;
		case AUTH_HMAC_SHA2_512_256:
			name = malloc(size_short_name + strlen(" [RFC4868]") + 1);
			strcpy(name, short_int_alg);
			strcat(name, " [RFC4868]");
			break;
		case AUTH_HMAC_SHA2_384_192:
			name = malloc(size_short_name + strlen(" [RFC4868]") + 1);
			strcpy(name, short_int_alg);
			strcat(name, " [RFC4868]");
			break;
		case AUTH_HMAC_SHA2_256_128:
			name = malloc(size_short_name + strlen(" [RFC4868]") + 1);
			strcpy(name, short_int_alg);
			strcat(name, " [RFC4868]");
			break;
		default :
			name = NULL;
			break;
	}
	return name;
}

METHOD(listener_t, send_spis, bool,
	private_saveKeys_listener_t *this, chunk_t spi_i, chunk_t spi_r)
{
	this->spi_i = chunk_clone(spi_i);
	this->spi_r = chunk_clone(spi_r);
	return TRUE;
}

METHOD(listener_t, save_child_keys, bool,
	private_saveKeys_listener_t *this, ike_version_t ike_version,
	int protocol, uint16_t enc_alg, uint16_t int_alg, chunk_t init_ip,
	chunk_t resp_ip, uint32_t spi_out, chunk_t encr_key_out,
	chunk_t int_key_out, uint32_t spi_in, chunk_t encr_key_in,
	chunk_t int_key_in)
{
	int icv_length = -1;
	chunk_t chunk_encr_out = chunk_empty, chunk_encr_in = chunk_empty;
	chunk_t chunk_integ_out = chunk_empty, chunk_integ_in = chunk_empty;
	char *buffer_encr_out = NULL, *buffer_encr_in = NULL, *buffer_integ_in = NULL;
	char *buffer_integ_out = NULL;
	FILE *esp_file;
	char *path_esp = malloc (strlen(this->directory_path) + strlen("esp_sa") + 1);
	strcpy(path_esp, this->directory_path);
	strcat(path_esp, "esp_sa");

	esp_file = fopen(path_esp, "a");
	chunk_encr_out = chunk_to_hex(encr_key_out, buffer_encr_out, FALSE);
	chunk_encr_in = chunk_to_hex(encr_key_in, buffer_encr_in, FALSE);
	chunk_integ_in = chunk_to_hex(int_key_in, buffer_integ_in, FALSE);
	chunk_integ_out = chunk_to_hex(int_key_out, buffer_integ_out, FALSE);

	fprintf(esp_file, "chunk_encr_out=%s\n\n", chunk_encr_out.ptr);
	fprintf(esp_file, "chunk_encr_in=%s\n\n", chunk_encr_in.ptr);
	fprintf(esp_file, "chunk_integ_in=%s\n\n", chunk_integ_in.ptr);
	fprintf(esp_file, "chunk_integ_out=%s\n\n", chunk_integ_out.ptr);
	fprintf(esp_file, "init_ip=%d.%d.%d.%d\n\n", init_ip.ptr[0], init_ip.ptr[1],
						init_ip.ptr[2], init_ip.ptr[3]);
	fprintf(esp_file, "resp_ip=%d.%d.%d.%d\n\n", resp_ip.ptr[0], resp_ip.ptr[1],
						resp_ip.ptr[2], resp_ip.ptr[3]);

	fprintf(esp_file, "spi_out=0x%08x\n\n", byte_reverse_32(spi_out));
	fprintf(esp_file, "spi_in=0x%08x\n\n", byte_reverse_32(spi_in));


	fprintf(esp_file, "enc_alg=%s\n\n", esp_expand_enc_name(enc_alg, &icv_length));
	fprintf(esp_file, "icv_length=%d\n\n", icv_length);
	fprintf(esp_file, "integ_alg=%u\n\n", int_alg);
	fprintf(esp_file, "protocol=%d\n\n", protocol);


	chunk_clear(&chunk_encr_in);
	chunk_clear(&chunk_encr_out);
	chunk_clear(&chunk_integ_in);
	chunk_clear(&chunk_integ_out);

	fclose(esp_file);
	free(path_esp);
	free(this->directory_path);
	return TRUE;
}

METHOD(listener_t, save_ike_keys, bool,
        private_saveKeys_listener_t *this, ike_version_t ike_version,
	chunk_t sk_ei, chunk_t sk_er, chunk_t sk_ai, chunk_t sk_ar, uint16_t enc_alg,
	uint16_t key_size, uint16_t int_alg)
{
	char *buffer_sk_ei = NULL, *buffer_sk_er = NULL, *buffer_sk_ai = NULL;
	char *buffer_sk_ar = NULL, *buffer_enc_alg = NULL;
	char *buffer_int_alg = NULL, *buffer_spi_i = NULL, *buffer_spi_r = NULL;
	FILE *ikev2_file, *ikev1_file;
	chunk_t chunk_spi_i = chunk_empty, chunk_spi_r = chunk_empty;
	chunk_t chunk_sk_ei = chunk_empty, chunk_sk_er = chunk_empty;
	chunk_t chunk_sk_ar = chunk_empty, chunk_sk_ai = chunk_empty;

	char *path_ikev2 = malloc (strlen(this->directory_path) + strlen("ikev2_decrytion_table") + 1);
	char *path_ikev1 = malloc (strlen(this->directory_path) + strlen("ikev1_decrytion_table") + 1);
	strcpy(path_ikev2, this->directory_path);
	strcpy(path_ikev1, this->directory_path);
	strcat(path_ikev2, "ikev2_decrytion_table");
	strcat(path_ikev1, "ikev1_decrytion_table");

	if (ike_version == IKEV2)
	{
		buffer_enc_alg = expand_enc_name(enc_alg, key_size);
		buffer_int_alg = expand_int_name(int_alg);
		if (buffer_enc_alg && buffer_enc_alg)
		{
			chunk_spi_i = chunk_to_hex(this->spi_i, buffer_spi_i, TRUE);
			chunk_spi_r = chunk_to_hex(this->spi_r, buffer_spi_r, TRUE);
			chunk_sk_ei = chunk_to_hex(sk_ei, buffer_sk_ei, TRUE);
			chunk_sk_er = chunk_to_hex(sk_er, buffer_sk_er, TRUE);
			chunk_sk_ai = chunk_to_hex(sk_ai, buffer_sk_ai, TRUE);
			chunk_sk_ar = chunk_to_hex(sk_ar, buffer_sk_ar, TRUE);
			ikev2_file = fopen(path_ikev2, "w");
			fprintf(ikev2_file, "# This file is automatically generated, DO NOT MODIFY.\n");
			fprintf(ikev2_file, "%s,%s,%s,%s,\"%s\",%s,%s,\"%s\"\n",
				chunk_spi_i.ptr, chunk_spi_r.ptr,
				chunk_sk_ei.ptr, chunk_sk_er.ptr,
				buffer_enc_alg, chunk_sk_ai.ptr, chunk_sk_ar.ptr,
				buffer_int_alg);
			fclose(ikev2_file);
			chunk_clear(&chunk_spi_i);
			chunk_clear(&chunk_spi_r);
			chunk_clear(&chunk_sk_ei);
			chunk_clear(&chunk_sk_er);
			chunk_clear(&chunk_sk_ai);
			chunk_clear(&chunk_sk_ar);
		}
	}
	else {
		chunk_spi_i = chunk_to_hex(this->spi_i, buffer_spi_i, TRUE);
		chunk_sk_ei = chunk_to_hex(sk_ei, buffer_sk_ei, TRUE);
		ikev1_file = fopen(path_ikev1, "w");
		fprintf(ikev1_file, "# This file is automatically generated, DO NOT MODIFY.\n");
		fprintf(ikev1_file, "%s,%s\n", chunk_spi_i.ptr, chunk_sk_ei.ptr);
		fclose(ikev1_file);
		chunk_clear(&chunk_spi_i);
		chunk_clear(&chunk_sk_ei);
	}

	free(buffer_int_alg);
	free(buffer_enc_alg);
	chunk_clear(&this->spi_i);
	chunk_clear(&this->spi_r);
	free(path_ikev2);
	free(path_ikev1);

        return TRUE;
}


/**
 * See header.
 */
saveKeys_listener_t *saveKeys_listener_create()
{
	private_saveKeys_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
				.save_ike_keys = _save_ike_keys,
				.send_spis = _send_spis,
				.save_child_keys = _save_child_keys,
			},
		}
	);

	this->directory_path = lib->settings->get_str(lib->settings,
							"%s.plugins.saveKeys.directory_path", default_path, lib->ns);
	return &this->public;
}
