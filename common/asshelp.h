/* asshelp.h - Helper functions for Assuan
 *	Copyright (C) 2004, 2007 Free Software Foundation, Inc.
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

#ifndef GNUPG_COMMON_ASSHELP_H
#define GNUPG_COMMON_ASSHELP_H

#include <assuan.h>
#include <gpg-error.h>

#include "session-env.h"

gpg_error_t
send_pinentry_environment (assuan_context_t ctx,
                           gpg_err_source_t errsource,
                           const char *opt_lc_ctype,
                           const char *opt_lc_messages,
                           session_env_t session_env);

/* This fucntion is used by the call-agent.c modules to fire up a new
   agent.  */
gpg_error_t
start_new_gpg_agent (assuan_context_t *r_ctx,
                     gpg_err_source_t errsource,
                     const char *homedir,
                     const char *agent_program,
                     const char *opt_lc_ctype,
                     const char *opt_lc_messages,
                     session_env_t session_env,
                     int verbose, int debug,
                     gpg_error_t (*status_cb)(ctrl_t, int, ...),
                     ctrl_t status_cb_arg);


#endif /*GNUPG_COMMON_ASSHELP_H*/
