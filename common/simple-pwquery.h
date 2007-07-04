/* simple-pwquery.c - A simple password query cleint for gpg-agent
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
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

#define SPWQ_OUT_OF_CORE 1
#define SPWQ_IO_ERROR 2
#define SPWQ_PROTOCOL_ERROR 3 
#define SPWQ_ERR_RESPONSE 4
#define SPWQ_NO_AGENT 5
#define SPWQ_SYS_ERROR 6
#define SPWQ_GENERAL_ERROR 7
#define SPWQ_NO_PIN_ENTRY 8


/* We often need to map error codes to gpg-error style error codes.
   To have a consistent mapping this macro may be used to implemt the
   mapping function.  */
#define MAP_SPWQ_ERROR_IMPL                                 \
       static gpg_error_t                                   \
       map_spwq_error (int err)                             \
       {                                                    \
         switch (err)                                       \
           {                                                \
           case 0:                                          \
             return 0;                                      \
           case SPWQ_OUT_OF_CORE:                           \
             return gpg_error_from_errno (ENOMEM);          \
           case SPWQ_IO_ERROR:                              \
             return gpg_error_from_errno (EIO);             \
           case SPWQ_PROTOCOL_ERROR:                        \
             return gpg_error (GPG_ERR_PROTOCOL_VIOLATION); \
           case SPWQ_ERR_RESPONSE:                          \
             return gpg_error (GPG_ERR_INV_RESPONSE);       \
           case SPWQ_NO_AGENT:                              \
             return gpg_error (GPG_ERR_NO_AGENT);           \
           case SPWQ_SYS_ERROR:                             \
             return gpg_error_from_syserror ();             \
           case SPWQ_NO_PIN_ENTRY:                          \
             return gpg_error (GPG_ERR_NO_PIN_ENTRY);       \
           case SPWQ_GENERAL_ERROR:                         \
           default:                                         \
             return gpg_error (GPG_ERR_GENERAL);            \
           }                                                \
       }                                                      
/* End of MAP_SPWQ_ERROR_IMPL.  */       


#endif /*SIMPLE_PWQUERY_H*/
