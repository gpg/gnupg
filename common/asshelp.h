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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 */

#ifndef GNUPG_COMMON_ASSHELP_H
#define GNUPG_COMMON_ASSHELP_H

#include <assuan.h>
#include <gpg-error.h>

gpg_error_t
send_pinentry_environment (assuan_context_t ctx,
                           gpg_err_source_t errsource,
                           const char *opt_display,
                           const char *opt_ttyname,
                           const char *opt_ttytype,
                           const char *opt_lc_ctype,
                           const char *opt_lc_messages);

/* This fucntion is used by the call-agent.c modules to fire up a new
   agent.  What a parameter list ;-).  */
gpg_error_t
start_new_gpg_agent (assuan_context_t *r_ctx,
                     gpg_err_source_t errsource,
                     const char *homedir,
                     const char *agent_program,
                     const char *opt_display,
                     const char *opt_ttyname,
                     const char *opt_ttytype,
                     const char *opt_lc_ctype,
                     const char *opt_lc_messages,
                     int verbose, int debug,
                     gpg_error_t (*status_cb)(ctrl_t, int, ...),
                     ctrl_t status_cb_arg);


#endif /*GNUPG_COMMON_ASSHELP_H*/
