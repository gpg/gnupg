/* simple-pwquery.c - A simple password query cleint for gpg-agent
 *	Copyright (C) 2002 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef SIMPLE_PWQUERY_H
#define SIMPLE_PWQUERY_H

#ifdef SIMPLE_PWQUERY_IMPLEMENTATION /* Begin configuration stuff. */

/* Include whatever files you need.  */
#include <gcrypt.h>
#include "../jnlib/logging.h"

/* Try to write error message using the standard log mechanism.  The
   current implementation requires that the HAVE_JNLIB_LOGGING is also
   defined. */
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
   If a CACHEID is not NULL it is used to locate the passphrase in in
   the cache and store it under this ID.  If ERRORCODE is not NULL it
   should point a variable receiving an errorcode; this errocode might
   be 0 if the user canceled the operation.  The function returns NULL
   to indicate an error. */
char *simple_pwquery (const char *cacheid, 
                      const char *tryagain,
                      const char *prompt,
                      const char *description,
                      int *errorcode);


#define SPWQ_OUT_OF_CORE 1
#define SPWQ_IO_ERROR 2
#define SPWQ_PROTOCOL_ERROR 3 
#define SPWQ_ERR_RESPONSE 4
#define SPWQ_NO_AGENT 5
#define SPWQ_SYS_ERROR 6
#define SPWQ_GENERAL_ERROR 7

#endif /*SIMPLE_PWQUERY_H*/
