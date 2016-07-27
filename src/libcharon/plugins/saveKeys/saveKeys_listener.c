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
        char *buf2 = NULL;
        chunk_write(chunk_to_hex(sk_ei, buf2, TRUE), "/home/ubuntu/Desktop/sk_ei.txt", 0777, FALSE);
        free(buf2);

        chunk_write(chunk_to_hex(sk_er, buf2, TRUE), "/home/ubuntu/Desktop/sk_er.txt", 0777, FALSE);
        free(buf2);

        chunk_write(chunk_to_hex(sk_ai, buf2, TRUE), "/home/ubuntu/Desktop/sk_ai.txt", 0777, FALSE);
        free(buf2);

        chunk_write(chunk_to_hex(sk_ar, buf2, TRUE), "/home/ubuntu/Desktop/sk_ar.txt", 0777, FALSE);
        free(buf2);


	chunk_write(chunk_to_hex(this->spi_i, buf2, TRUE), "/home/ubuntu/Desktop/spi_i.txt", 0777, FALSE);
	free(buf2);

	chunk_write(chunk_to_hex(this->spi_r, buf2, TRUE), "/home/ubuntu/Desktop/spi_r.txt", 0777, FALSE);
	free(buf2);

	chunk_clear(&this->spi_i);
	chunk_clear(&this->spi_r);

	enum_name_t *type1 = transform_get_enum_names(ENCRYPTION_ALGORITHM);
        enum_name_t *type2 = transform_get_enum_names(INTEGRITY_ALGORITHM);
        char *encc = enum_to_name(type1, enc_alg);
        char *intt = enum_to_name(type2, int_alg);
        FILE *pr = fopen ("/home/ubuntu/Desktop/alg_enc.txt", "w");
        fprintf(pr, "%s-%d", encc, key_size);
        fclose(pr);
        FILE *pr1 = fopen ("/home/ubuntu/Desktop/alg_int.txt", "w");
        fprintf(pr1, "%s", intt);
        fclose(pr1);


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
