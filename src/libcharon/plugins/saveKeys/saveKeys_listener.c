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
};

/**
 * Uppercase hexadecimals are transform into lowercase hexadecimals.
 */
static inline char *hex_tolower(char *str)
{
	int i, size;
	size = strlen(str);
	for (i = 0; i < size; i ++)
	{
		str[i] = tolower(str[i]);
	}
	return str;
}

/**
 * Expands the name of encryption algorithms for wireshark decryption table.
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
 * Expands the name of integrity algorithms for wireshark decryption table.
 */
static inline char *expand_int_name(uint16_t int_alg)
{
	char *name;
	enum_name_t *type2 = transform_get_enum_names(INTEGRITY_ALGORITHM);
	char *short_int_alg = enum_to_name(type2, int_alg);
	int size_short_name = strlen(short_int_alg);
	switch (int_alg) {
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

METHOD(listener_t, save_ike_keys, bool,
        private_saveKeys_listener_t *this, ike_version_t ike_version, bool aead,
	chunk_t sk_ei, chunk_t sk_er, chunk_t sk_ai, chunk_t sk_ar, uint16_t enc_alg,
	uint16_t key_size, uint16_t int_alg)
{
	char *buffer_sk_ei, *buffer_sk_er, *buffer_sk_ai, *buffer_sk_ar, *buffer_enc_alg;
	char *buffer_int_alg, *buffer_spi_i, *buffer_spi_r;
	FILE *wireshark_file;
	char path[] = "/home/ubuntu/Desktop/ikev2_decryption_table";
	chunk_t chunk_spi_i, chunk_spi_r, chunk_sk_ei, chunk_sk_er, chunk_sk_ai;
	chunk_t chunk_sk_ar;

	if (ike_version == IKEV2)
	{
		if (!aead)
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
				wireshark_file = fopen(path, "w");
				fprintf(wireshark_file, "# This file is automatically generated, DO NOT MODIFY.\n");
				fprintf(wireshark_file, "%s,%s,%s,%s,\"%s\",%s,%s,\"%s\"",
					hex_tolower(chunk_spi_i.ptr), hex_tolower(chunk_spi_r.ptr),
					hex_tolower(chunk_sk_ei.ptr), hex_tolower(chunk_sk_er.ptr),
					buffer_enc_alg, hex_tolower(chunk_sk_ai.ptr), hex_tolower(chunk_sk_ar.ptr),
					buffer_int_alg);
				fclose(wireshark_file);
			}
		}
	}

	chunk_clear(&chunk_spi_i);
	chunk_clear(&chunk_spi_r);
	chunk_clear(&chunk_sk_ei);
	chunk_clear(&chunk_sk_er);
	chunk_clear(&chunk_sk_ai);
	chunk_clear(&chunk_sk_ar);
	free(buffer_int_alg);
	free(buffer_enc_alg);
	chunk_clear(&this->spi_i);
	chunk_clear(&this->spi_r);

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
			},
		}
	);

	return &this->public;
}
