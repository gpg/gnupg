/* asshelp.h - Helper functions for Assuan
 *	Copyright (C) 2004, 2007 Free Software Foundation, Inc.
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

#ifndef GNUPG_COMMON_ASSHELP_H
#define GNUPG_COMMON_ASSHELP_H

#include <assuan.h>
#include <gpg-error.h>

#include "session-env.h"
#include "util.h"

/*-- asshelp.c --*/

void setup_libassuan_logging (unsigned int *debug_var_address,
                              int (*log_monitor)(assuan_context_t ctx,
                                                 unsigned int cat,
                                                 const char *msg));
void set_libassuan_log_cats (unsigned int newcats);


gpg_error_t
send_pinentry_environment (assuan_context_t ctx,
                           gpg_err_source_t errsource,
                           const char *opt_lc_ctype,
                           const char *opt_lc_messages,
                           session_env_t session_env);

/* This function is used by the call-agent.c modules to fire up a new
   agent.  */
gpg_error_t
start_new_gpg_agent (assuan_context_t *r_ctx,
                     gpg_err_source_t errsource,
                     const char *agent_program,
                     const char *opt_lc_ctype,
                     const char *opt_lc_messages,
                     session_env_t session_env,
                     int autostart, int verbose, int debug,
                     gpg_error_t (*status_cb)(ctrl_t, int, ...),
                     ctrl_t status_cb_arg);

/* This function is used to connect to the keyboxd.  If needed the
 * keyboxd is started.  */
gpg_error_t
start_new_keyboxd (assuan_context_t *r_ctx,
                   gpg_err_source_t errsource,
                   const char *keyboxd_program,
                   int autostart, int verbose, int debug,
                   gpg_error_t (*status_cb)(ctrl_t, int, ...),
                   ctrl_t status_cb_arg);

/* This function is used to connect to the dirmngr.  On some platforms
   the function is able starts a dirmngr process if needed.  */
gpg_error_t
start_new_dirmngr (assuan_context_t *r_ctx,
                   gpg_err_source_t errsource,
                   const char *dirmngr_program,
                   int autostart, int verbose, int debug,
                   gpg_error_t (*status_cb)(ctrl_t, int, ...),
                   ctrl_t status_cb_arg);

/* Return the version of a server using "GETINFO version".  */
gpg_error_t get_assuan_server_version (assuan_context_t ctx,
                                       int mode, char **r_version);

/* Print a server version mismatch warning.  */
gpg_error_t warn_server_version_mismatch (assuan_context_t ctx,
                                          const char *servername, int mode,
                                          gpg_error_t (*status_fnc)
                                                           (ctrl_t ctrl,
                                                            int status_id,
                                                            ...),
                                          void *status_func_ctrl,
                                          int print_hints);


/*-- asshelp2.c --*/

void set_assuan_context_func (assuan_context_t (*func)(ctrl_t ctrl));

/* Helper function to print an assuan status line using a printf
   format string.  */

gpg_error_t status_printf (ctrl_t ctrl, const char *keyword, const char *format,
                           ...) GPGRT_ATTR_PRINTF(3,4);
gpg_error_t status_no_printf (ctrl_t ctrl, int no, const char *format,
                           ...) GPGRT_ATTR_PRINTF(3,4);

gpg_error_t print_assuan_status (assuan_context_t ctx,
                                 const char *keyword,
                                 const char *format,
                                 ...) GPGRT_ATTR_PRINTF(3,4);
gpg_error_t vprint_assuan_status (assuan_context_t ctx,
                                  const char *keyword,
                                  const char *format,
                                  va_list arg_ptr) GPGRT_ATTR_PRINTF(3,0);

gpg_error_t vprint_assuan_status_strings (assuan_context_t ctx,
                                          const char *keyword,
                                          va_list arg_ptr);
gpg_error_t print_assuan_status_strings (assuan_context_t ctx,
                                         const char *keyword,
                                         ...) GPGRT_ATTR_SENTINEL(1);


#endif /*GNUPG_COMMON_ASSHELP_H*/
