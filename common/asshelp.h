/* asshelp.h - Helper functions for Assuan
 *	Copyright (C) 2004 Free Software Foundation, Inc.
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

#ifndef GNUPG_COMMON_ASSHELP_H
#define GNUPG_COMMON_ASSHELP_H

#include <assuan.h>
#include <gpg-error.h>

gpg_error_t
send_pinentry_environment (assuan_context_t ctx,
                           const char *opt_display,
                           const char *opt_ttyname,
                           const char *opt_ttytype,
                           const char *opt_lc_ctype,
                           const char *opt_lc_messages);


#endif /*GNUPG_COMMON_ASSHELP_H*/
