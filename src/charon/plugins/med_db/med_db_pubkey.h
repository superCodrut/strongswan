/*
 * Copyright (C) 2008 Martin Willi
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * $Id$
 */

/**
 * @defgroup med_db_pubkey med_db_pubkey
 * @{ @ingroup med_db
 */

#ifndef MED_DB_PUBKEY_H_
#define MED_DB_PUBKEY_H_

#include <credentials/keys/public_key.h>
#include <credentials/certificates/certificate.h>

typedef struct med_db_pubkey_t med_db_pubkey_t;

/**
 * A trusted public key wrapped into certificate of type CERT_TRUSTED_PUBKEY.
 */
struct med_db_pubkey_t {

	/**
	 * Implements certificate_t.
	 */
	certificate_t interface;
};

/**
 * Create a wrapped public key instance using a public_key.
 *
 * The certifcate uses the public_key ID as subject.
 *
 * @param key		public key to wrap
 * @return			public key implementing certificate interface
 */
med_db_pubkey_t *med_db_pubkey_create(public_key_t *key);

#endif /* MED_DB_PUBKEY_H_ @}*/
