/* gpgconf-list.c - Print list of options.
 *	Copyright (C) 2003 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gpgconf.h"
#include "i18n.h"

/* Format of the colon delimited listing is:

   Area: gpg, gpgsm, gpg-agent, scdaemon, dirmngr, "G" or empty for unspecified.
   Option name: Name of the option
   Expert level: Expertnesslevel of option: 0 - basic
   Immediately Change: "1" is the option is immediatley changeable
                       (e.g. through SIGHUP)
   Option index: Instance number of the option value to build lists. 
   Option value: Current value of the option
   
*/


/* List global options, i.er. those which are commonly required and
   may affect more than one program. */
static void
list_global_options (void)
{


}



void
gpgconf_list_standard_options (void)
{

  list_global_options ();


}
