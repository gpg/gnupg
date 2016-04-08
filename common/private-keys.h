/* private-keys.h - Parser and writer for the extended private key format.
 *	Copyright (C) 2016 g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GNUPG_COMMON_PRIVATE_KEYS_H
#define GNUPG_COMMON_PRIVATE_KEYS_H

struct private_key_container;
typedef struct private_key_container *pkc_t;

struct private_key_entry;
typedef struct private_key_entry *pke_t;



/* Memory management, and dealing with entries.  */

/* Allocate a private key container structure.  */
pkc_t pkc_new (void);

/* Release a private key container structure.  */
void pkc_release (pkc_t pk);

/* Get the name.  */
char *pke_name (pke_t pke);

/* Get the value.  */
char *pke_value (pke_t pke);



/* Lookup and iteration.  */

/* Get the first non-comment entry.  */
pke_t pkc_first (pkc_t pk);

/* Get the first entry with the given name.  */
pke_t pkc_lookup (pkc_t pk, const char *name);

/* Get the next non-comment entry.  */
pke_t pke_next (pke_t entry);

/* Get the next entry with the given name.  */
pke_t pke_next_value (pke_t entry, const char *name);



/* Adding and modifying values.  */

/* Add (NAME, VALUE) to PK.  If an entry with NAME already exists, it
   is not updated but the new entry is appended.  */
gpg_error_t pkc_add (pkc_t pk, const char *name, const char *value);

/* Add (NAME, VALUE) to PK.  If an entry with NAME already exists, it
   is updated with VALUE.  If multiple entries with NAME exist, the
   first entry is updated.  */
gpg_error_t pkc_set (pkc_t pk, const char *name, const char *value);

/* Delete the given entry from PK.  */
void pkc_delete (pkc_t pk, pke_t pke);



/* Private key handling.  */

/* Get the private key.  */
gpg_error_t pkc_get_private_key (pkc_t pk, gcry_sexp_t *retsexp);

/* Set the private key.  */
gpg_error_t pkc_set_private_key (pkc_t pk, gcry_sexp_t sexp);



/* Parsing and serialization.  */

/* Parse STREAM and return a newly allocated private key container
   structure in RESULT.  If ERRLINEP is given, the line number the
   parser was last considering is stored there.  */
gpg_error_t pkc_parse (pkc_t *result, int *errlinep, estream_t stream);

/* Write a representation of PK to STREAM.  */
gpg_error_t pkc_write (pkc_t pk, estream_t stream);

#endif /* GNUPG_COMMON_PRIVATE_KEYS_H */
