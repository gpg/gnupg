/* t-ldap-parse-uri.c - Tests for ldap-parse-uri.c and ldap-misc.c
 * Copyright (C) 2015  g10 Code GmbH
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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <gpg-error.h>

#include "../common/util.h"
#include "t-support.h"
#include "ldap-misc.h"


static void
test_ldap_parse_extfilter (void)
{
  struct {
    const char *string;
    const char *base;
    const char *filter;
    int scope;
    gpg_err_code_t ec;
  } tests[] =
  {
   { "^CN=foo, OU=My Users&(objectClasses=*)",
     "CN=foo, OU=My Users", "(objectClasses=*)",
     -1 },
   { "^CN=foo, OU=My Users&base&(objectClasses=*)",
     "CN=foo, OU=My Users", "(objectClasses=*)",
     LDAP_SCOPE_BASE },
   { "^CN=foo, OU=My Users&one&(objectClasses=*)",
     "CN=foo, OU=My Users", "(objectClasses=*)",
     LDAP_SCOPE_ONELEVEL },
   { "^CN=foo, OU=My Users&sub&(objectClasses=*)",
     "CN=foo, OU=My Users", "(objectClasses=*)",
     LDAP_SCOPE_SUBTREE },
   /* { "^CN=foo, OU=My Users&children&(objectClasses=*)", */
   /*   "CN=foo, OU=My Users", "(objectClasses=*)", */
   /*   LDAP_SCOPE_CHILDREN }, */
   { "^CN=foo, OU=My Users&",
     "CN=foo, OU=My Users", NULL,
     -1 },
   { "^CN=foo, OU=My Users&sub&",
     "CN=foo, OU=My Users", NULL,
     LDAP_SCOPE_SUBTREE },
   /* { "^&children&(objectClasses=*)", */
   /*   "", "(objectClasses=*)", */
   /*   LDAP_SCOPE_CHILDREN }, */
   { "^CN=foo, OU=My &&Users&base&(objectClasses=*)",
     "CN=foo, OU=My &Users", "(objectClasses=*)",
     LDAP_SCOPE_BASE },
   { "^CN=foo, OU=My Users&&&base&(objectClasses=*)",
     "CN=foo, OU=My Users&", "(objectClasses=*)",
     LDAP_SCOPE_BASE },
   { "^CN=foo, OU=My Users",
     NULL, NULL,
     LDAP_SCOPE_BASE, GPG_ERR_SYNTAX },
   { "^CN=foo, OU=My Users&base(objectClasses=*)",
     NULL, NULL,
     LDAP_SCOPE_BASE, GPG_ERR_SYNTAX },
   { "^CN=foo, OU=My Users&base&objectClasses=*)",
     NULL, NULL,
     LDAP_SCOPE_BASE, GPG_ERR_SYNTAX },
   { "^CN=foo, OU=My Users&base&(objectClasses=*",
     NULL, NULL,
     LDAP_SCOPE_BASE, GPG_ERR_SYNTAX }
  };
  int idx;
  gpg_error_t err;
  int errcount = 0;
  char *base, *filter;
  int scope;

  for (idx= 0; idx < DIM (tests); idx++)
    {
      scope = -1;
      err = ldap_parse_extfilter (tests[idx].string, 1, &base, &scope, &filter);
      if (err && tests[idx].ec)
        {
          if (gpg_err_code (err) != tests[idx].ec)
            {
              fprintf (stderr, "%s: test %d failed: wrong error code %d\n",
                       __func__, idx, err);
              errcount++;
            }
          continue;
        }
      if (err)
        {
          fprintf (stderr, "%s: test %d failed: %s\n",
                   __func__, idx, gpg_strerror (err));
          errcount++;
          continue;
        }
      if (tests[idx].ec)
        {
          fprintf (stderr, "%s: test %d failed: error not detected\n",
                   __func__, idx);
          errcount++;
          continue;
        }
      if ((!tests[idx].base ^ !base)
          || (tests[idx].base && strcmp (tests[idx].base, base)))
        {
          fprintf (stderr, "%s: test %d failed: base mismatch ('%s')\n",
                   __func__, idx, base? base : "(null");
          errcount++;
        }
      if ((!tests[idx].filter ^ !filter)
          || (tests[idx].filter && strcmp (tests[idx].filter, filter)))
        {
          fprintf (stderr, "%s: test %d failed: filter mismatch ('%s')\n",
                   __func__, idx, filter? filter : "(null");
          errcount++;
        }
      if (tests[idx].scope != scope)
        {
          fprintf (stderr, "%s: test %d failed: scope mismatch (%d)\n",
                   __func__, idx, scope);
          errcount++;
        }
      xfree (base);
      xfree (filter);
    }
  if (errcount)
    exit (1);
}




int
main (int argc, char **argv)
{
  (void)argc;
  (void)argv;

  test_ldap_parse_extfilter ();

  return 0;
}
