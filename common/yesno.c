/* yesno.c - Yes/No questions
 * Copyright (C) 1998, 1999, 2000, 2001, 2003 Free Software Foundation, Inc.
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
#include <stdlib.h>
#include <errno.h>

#include "i18n.h"
#include "util.h"

int
answer_is_yes_no_default( const char *s, int def_answer )
{
    const char *long_yes = _("yes");
    const char *short_yes = _("yY");
    const char *long_no = _("no");
    const char *short_no = _("nN");

    /* Note: we have to use the local dependent strcasecmp here */
    if( !strcasecmp(s, long_yes ) )
	return 1;
    if( *s && strchr( short_yes, *s ) && !s[1] )
	return 1;
    /* test for no strings to catch ambiguities for the next test */
    if( !strcasecmp(s, long_no ) )
	return 0;
    if( *s && strchr( short_no, *s ) && !s[1] )
	return 0;
    /* test for the english version (for those who are used to type yes) */
    if( !ascii_strcasecmp(s, "yes" ) )
	return 1;
    if( *s && strchr( "yY", *s ) && !s[1] )
	return 1;
    return def_answer;
}

int
answer_is_yes( const char *s )
{
  return answer_is_yes_no_default(s,0);
}

/****************
 * Return 1 for yes, -1 for quit, or 0 for no
 */
int
answer_is_yes_no_quit( const char *s )
{
    const char *long_yes = _("yes");
    const char *long_no = _("no");
    const char *long_quit = _("quit");
    const char *short_yes = _("yY");
    const char *short_no = _("nN");
    const char *short_quit = _("qQ");

    /* Note: We have to use the locale dependent strcasecmp */
    if( !strcasecmp(s, long_no ) )
	return 0;
    if( !strcasecmp(s, long_yes ) )
	return 1;
    if( !strcasecmp(s, long_quit ) )
	return -1;
    if( *s && strchr( short_no, *s ) && !s[1] )
	return 0;
    if( *s && strchr( short_yes, *s ) && !s[1] )
	return 1;
    if( *s && strchr( short_quit, *s ) && !s[1] )
	return -1;
    /* but not here */
    if( !ascii_strcasecmp(s, "yes" ) )
	return 1;
    if( !ascii_strcasecmp(s, "quit" ) )
	return -1;
    if( *s && strchr( "yY", *s ) && !s[1] )
	return 1;
    if( *s && strchr( "qQ", *s ) && !s[1] )
	return -1;
    return 0;
}
