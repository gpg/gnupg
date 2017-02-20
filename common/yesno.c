/* yesno.c - Yes/No questions
 * Copyright (C) 1998, 1999, 2000, 2001, 2003 Free Software Foundation, Inc.
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
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>
#include <errno.h>

#include "i18n.h"
#include "util.h"


/* Check the string S for a YES or NO answer and take care of
   localization.  If no valid string is given the value of DEF_ANSWER
   is returned.  Returns 1 for yes and 0 for no.  */
int
answer_is_yes_no_default (const char *s, int def_answer)
{
  /* TRANSLATORS: See doc/TRANSLATE about this string. */
  const char *long_yes = _("yes");
  const char *short_yes = _("yY");
  /* TRANSLATORS: See doc/TRANSLATE about this string. */
  const char *long_no = _("no");
  const char *short_no = _("nN");

  /* Note: we have to use the local dependent compare here. */
  if ( match_multistr(long_yes,s) )
    return 1;
  if ( *s && strchr( short_yes, *s ) && !s[1] )
    return 1;
  /* Test for "no" strings to catch ambiguities for the next test. */
  if ( match_multistr(long_no,s) )
    return 0;
  if ( *s && strchr( short_no, *s ) && !s[1] )
    return 0;
  /* Test for the english version (for those who are used to type yes). */
  if ( !ascii_strcasecmp(s, "yes" ) )
    return 1;
  if ( *s && strchr( "yY", *s ) && !s[1] )
    return 1;
  return def_answer;
}

int
answer_is_yes ( const char *s )
{
  return answer_is_yes_no_default(s,0);
}

/****************
 * Return 1 for yes, -1 for quit, or 0 for no
 */
int
answer_is_yes_no_quit ( const char *s )
{
  /* TRANSLATORS: See doc/TRANSLATE about this string. */
  const char *long_yes = _("yes");
  /* TRANSLATORS: See doc/TRANSLATE about this string. */
  const char *long_no = _("no");
  /* TRANSLATORS: See doc/TRANSLATE about this string. */
  const char *long_quit = _("quit");
  const char *short_yes = _("yY");
  const char *short_no = _("nN");
  const char *short_quit = _("qQ");

  /* Note: we have to use a local dependent compare here. */
  if ( match_multistr(long_no,s) )
    return 0;
  if ( match_multistr(long_yes,s) )
    return 1;
  if ( match_multistr(long_quit,s) )
    return -1;
  if ( *s && strchr( short_no, *s ) && !s[1] )
    return 0;
  if ( *s && strchr( short_yes, *s ) && !s[1] )
      return 1;
  if ( *s && strchr( short_quit, *s ) && !s[1] )
    return -1;
  /* but not here. */
  if ( !ascii_strcasecmp(s, "yes" ) )
    return 1;
  if ( !ascii_strcasecmp(s, "quit" ) )
      return -1;
  if ( *s && strchr( "yY", *s ) && !s[1] )
    return 1;
  if ( *s && strchr( "qQ", *s ) && !s[1] )
    return -1;
  return 0;
}

/*
   Return 1 for okay, 0 for cancel or DEF_ANSWER for default.
 */
int
answer_is_okay_cancel (const char *s, int def_answer)
{
  /* TRANSLATORS: See doc/TRANSLATE about this string. */
  const char *long_okay = _("okay|okay");
  /* TRANSLATORS: See doc/TRANSLATE about this string. */
  const char *long_cancel = _("cancel|cancel");
  const char *short_okay = _("oO");
  const char *short_cancel = _("cC");

  /* Note: We have to use the locale dependent compare. */
  if ( match_multistr(long_okay,s) )
    return 1;
  if ( match_multistr(long_cancel,s) )
    return 0;
  if ( *s && strchr( short_okay, *s ) && !s[1] )
    return 1;
  if ( *s && strchr( short_cancel, *s ) && !s[1] )
    return 0;
  /* Always test for the English values (not locale here). */
  if ( !ascii_strcasecmp(s, "okay" ) )
    return 1;
  if ( !ascii_strcasecmp(s, "ok" ) )
    return 1;
  if ( !ascii_strcasecmp(s, "cancel" ) )
    return 0;
  if ( *s && strchr( "oO", *s ) && !s[1] )
    return 1;
  if ( *s && strchr( "cC", *s ) && !s[1] )
    return 0;
  return def_answer;
}
