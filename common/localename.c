/* localename.c - Determine the current selected locale.
   Copyright (C) 1995-1999, 2000-2003, 2007, 
                 2008 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation; either version 2.1,
   or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, see <http://www.gnu.org/licenses/>.
*/
/* Written by Ulrich Drepper <drepper@gnu.org>, 1995.  */
/* Win32 code written by Tor Lillqvist <tml@iki.fi>.  */
/* Modified for GpgOL use by Werner Koch <wk@gnupg.org>, 2005.  */ 
/* Modified for GnuPG use by Werner Koch <wk@gnupg.org>, 2007 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#include "../jnlib/w32help.h"

/* XPG3 defines the result of 'setlocale (category, NULL)' as:
   "Directs 'setlocale()' to query 'category' and return the current
    setting of 'local'."
   However it does not specify the exact format.  Neither do SUSV2 and
   ISO C 99.  So we can use this feature only on selected systems (e.g.
   those using GNU C Library).  */
#if defined _LIBC || (defined __GNU_LIBRARY__ && __GNU_LIBRARY__ >= 2)
# define HAVE_LOCALE_NULL
#endif

/* Use a dummy value for LC_MESSAGES in case it is not defined.  This
   works becuase we always test for HAVE_LC_MESSAGES and the core
   fucntion takes the category as a string as well.  */
#ifndef HAVE_LC_MESSAGES
#define LC_MESSAGES 0
#endif


/* Determine the current locale's name, and canonicalize it into XPG syntax
     language[_territory[.codeset]][@modifier]
   The codeset part in the result is not reliable; the locale_charset()
   should be used for codeset information instead.
   The result must not be freed; it is statically allocated.  */

#ifndef HAVE_W32_SYSTEM
static const char *
do_nl_locale_name (int category, const char *categoryname)
{
  const char *retval;

  /* Use the POSIX methods of looking to 'LC_ALL', 'LC_xxx', and 'LANG'.
     On some systems this can be done by the 'setlocale' function itself.  */
# if defined HAVE_SETLOCALE && defined HAVE_LC_MESSAGES && defined HAVE_LOCALE_NULL
  (void)categoryname;
  retval = setlocale (category, NULL);
# else 
  /* Setting of LC_ALL overwrites all other.  */
  retval = getenv ("LC_ALL");
  if (retval == NULL || retval[0] == '\0')
    {
      /* Next comes the name of the desired category.  */
      retval = getenv (categoryname);
      if (retval == NULL || retval[0] == '\0')
	{
	  /* Last possibility is the LANG environment variable.  */
	  retval = getenv ("LANG");
	  if (retval == NULL || retval[0] == '\0')
	    /* We use C as the default domain.  POSIX says this is
	       implementation defined.  */
	    retval = "C";
	}
    }
# endif

  return retval;
}
#endif /* HAVE_W32_SYSTEM */



/* Return the locale used for translatable messages.  The standard C
   and POSIX are locale names are mapped to an empty string.  If a
   locale can't be found an empty string will be returned.  */
const char *
gnupg_messages_locale_name (void)
{
  const char *s;

#ifdef HAVE_W32_SYSTEM
  /* We use the localname function from ../jnlib/w32-gettext.c. */
  s = gettext_localename ();
#else
  s = do_nl_locale_name (LC_MESSAGES, "LC_MESSAGES");
#endif
  if (!s)
    s = "";
  else if (!strcmp (s, "C") || !strcmp (s, "POSIX"))
    s = "";

  return s;
}

