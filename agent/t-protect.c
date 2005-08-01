/* t-protect.c - Module tests for protect.c
 * Copyright (C) 2005 Free Software Foundation, Inc.
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

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "agent.h"


#define pass()  do { ; } while(0)
#define fail()  do { fprintf (stderr, "%s:%d: test failed\n",\
                              __FILE__,__LINE__);            \
                     exit (1);                               \
                   } while(0)


static void
test_agent_protect (void)
{
  /* Protect the key encoded in canonical format in PLAINKEY.  We assume
     a valid S-Exp here. */
/*   int  agent_protect (const unsigned char *plainkey, const char *passphrase, */
/*                       unsigned char **result, size_t *resultlen); */
}


static void
test_agent_unprotect (void)
{
  /* Unprotect the key encoded in canonical format.  We assume a valid
     S-Exp here. */
/*   int  */
/*     agent_unprotect (const unsigned char *protectedkey, const char *passphrase, */
/*                      unsigned char **result, size_t *resultlen) */
}


static void
test_agent_private_key_type (void)
{
/* Check the type of the private key, this is one of the constants:
   PRIVATE_KEY_UNKNOWN if we can't figure out the type (this is the
   value 0), PRIVATE_KEY_CLEAR for an unprotected private key.
   PRIVATE_KEY_PROTECTED for an protected private key or
   PRIVATE_KEY_SHADOWED for a sub key where the secret parts are stored
   elsewhere. */
/* int */
/* agent_private_key_type (const unsigned char *privatekey) */
}


static void
test_make_shadow_info (void)
{
#if 0
  static struct 
  {
    const char *snstr; 
    const char *idstr;
    const char *expected;
  } data[] = {
    { "", "", NULL },
    
  };
  int i;
  unsigned char *result;

  for (i=0; i < DIM(data); i++)
    {
      result =  make_shadow_info (data[i].snstr, data[i].idstr);
      if (!result && !data[i].expected)
        pass ();
      else if (!result && data[i].expected)
        fail ();
      else if (!data[i].expected)
        fail ();
      /* fixme: Need to compare the result but also need to check
         proper S-expression syntax. */
    }
#endif
}



static void
test_agent_shadow_key (void)
{
/* Create a shadow key from a public key.  We use the shadow protocol
  "ti-v1" and insert the S-expressionn SHADOW_INFO.  The resulting
  S-expression is returned in an allocated buffer RESULT will point
  to. The input parameters are expected to be valid canonicalized
  S-expressions */
/* int  */
/* agent_shadow_key (const unsigned char *pubkey, */
/*                   const unsigned char *shadow_info, */
/*                   unsigned char **result) */
}


static void
test_agent_get_shadow_info (void)
{
/* Parse a canonical encoded shadowed key and return a pointer to the
   inner list with the shadow_info */
/* int  */
/* agent_get_shadow_info (const unsigned char *shadowkey, */
/*                        unsigned char const **shadow_info) */
}




int
main (int argc, char **argv)
{
  test_agent_protect ();
  test_agent_unprotect ();
  test_agent_private_key_type ();
  test_make_shadow_info ();
  test_agent_shadow_key ();
  test_agent_get_shadow_info ();

  return 0;
}
