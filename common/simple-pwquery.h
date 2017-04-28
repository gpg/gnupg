/* simple-pwquery.c - A simple password query client for gpg-agent
 *	Copyright (C) 2002 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef SIMPLE_PWQUERY_H
#define SIMPLE_PWQUERY_H

#ifdef SIMPLE_PWQUERY_IMPLEMENTATION /* Begin configuration stuff. */

/* Include whatever files you need.  */
#include <gcrypt.h>
#include "../common/logging.h"

/* Try to write error message using the standard gnupg log mechanism.  */
#define SPWQ_USE_LOGGING  1

/* Memory allocation functions used by the implementation.  Note, that
   the returned value is expected to be freed with
   spwq_secure_free. */
#define spwq_malloc(a)         gcry_malloc (a)
#define spwq_free(a)           gcry_free (a)
#define spwq_secure_malloc(a)  gcry_malloc_secure (a)
#define spwq_secure_free(a)    gcry_free (a)

#endif /*SIMPLE_PWQUERY_IMPLEMENTATION*/ /* End configuration stuff. */


/* Ask the gpg-agent for a passphrase and present the user with a
   DESCRIPTION, a PROMPT and optiaonlly with a TRYAGAIN extra text.
   If a CACHEID is not NULL it is used to locate the passphrase in
   the cache and store it under this ID.  If OPT_CHECK is true
   gpg-agent is asked to apply some checks on the passphrase security.
   If ERRORCODE is not NULL it should point a variable receiving an
   errorcode; this errocode might be 0 if the user canceled the
   operation.  The function returns NULL to indicate an error. */
char *simple_pwquery (const char *cacheid,
                      const char *tryagain,
                      const char *prompt,
                      const char *description,
                      int opt_check,
                      int *errorcode);

/* Ask the gpg-agent to clear the passphrase for the cache ID CACHEID.  */
int simple_pwclear (const char *cacheid);

/* Perform the simple query QUERY (which must be new-line and 0
   terminated) and return the error code.  */
int simple_query (const char *query);

/* Set the name of the standard socket to be used if GPG_AGENT_INFO is
   not defined.  The use of this function is optional but if it needs
   to be called before any other function.  Returns 0 on success.  */
int simple_pw_set_socket (const char *name);

#endif /*SIMPLE_PWQUERY_H*/
