/* name-value.h - Parser and writer for a name-value format.
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef GNUPG_COMMON_NAME_VALUE_H
#define GNUPG_COMMON_NAME_VALUE_H

struct name_value_container;
typedef struct name_value_container *nvc_t;

struct name_value_entry;
typedef struct name_value_entry *nve_t;



/* Memory management, and dealing with entries.  */

/* Allocate a name value container structure.  */
nvc_t nvc_new (void);

/* Allocate a name value container structure for use with the extended
 * private key format.  */
nvc_t nvc_new_private_key (void);

/* Release a name value container structure.  */
void nvc_release (nvc_t pk);

/* Get the name.  */
char *nve_name (nve_t pke);

/* Get the value.  */
char *nve_value (nve_t pke);



/* Lookup and iteration.  */

/* Get the first non-comment entry.  */
nve_t nvc_first (nvc_t pk);

/* Get the first entry with the given name.  */
nve_t nvc_lookup (nvc_t pk, const char *name);

/* Get the next non-comment entry.  */
nve_t nve_next (nve_t entry);

/* Get the next entry with the given name.  */
nve_t nve_next_value (nve_t entry, const char *name);



/* Adding and modifying values.  */

/* Add (NAME, VALUE) to PK.  If an entry with NAME already exists, it
   is not updated but the new entry is appended.  */
gpg_error_t nvc_add (nvc_t pk, const char *name, const char *value);

/* Add (NAME, VALUE) to PK.  If an entry with NAME already exists, it
   is updated with VALUE.  If multiple entries with NAME exist, the
   first entry is updated.  */
gpg_error_t nvc_set (nvc_t pk, const char *name, const char *value);

/* Delete the given entry from PK.  */
void nvc_delete (nvc_t pk, nve_t pke);



/* Private key handling.  */

/* Get the private key.  */
gpg_error_t nvc_get_private_key (nvc_t pk, gcry_sexp_t *retsexp);

/* Set the private key.  */
gpg_error_t nvc_set_private_key (nvc_t pk, gcry_sexp_t sexp);



/* Parsing and serialization.  */

/* Parse STREAM and return a newly allocated private key container
   structure in RESULT.  If ERRLINEP is given, the line number the
   parser was last considering is stored there.  */
gpg_error_t nvc_parse (nvc_t *result, int *errlinep, estream_t stream);

/* Parse STREAM and return a newly allocated name value container
   structure in RESULT - assuming the extended private key format.  If
   ERRLINEP is given, the line number the parser was last considering
   is stored there.  */
gpg_error_t nvc_parse_private_key (nvc_t *result, int *errlinep,
                                   estream_t stream);

/* Write a representation of PK to STREAM.  */
gpg_error_t nvc_write (nvc_t pk, estream_t stream);

#endif /* GNUPG_COMMON_NAME_VALUE_H */
