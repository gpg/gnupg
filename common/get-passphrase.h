/* get-passphrase.h - Definitions to ask for a passphrase via the agent.
 * Copyright (C) 2009 Free Software Foundation, Inc.
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

#ifndef GNUPG_COMMON_GET_PASSPHRASE_H
#define GNUPG_COMMON_GET_PASSPHRASE_H

#include "session-env.h"

void gnupg_prepare_get_passphrase (gpg_err_source_t errsource,
                                   int verbosity,
                                   const char *homedir,
                                   const char *agent_program,
                                   const char *opt_lc_ctype,
                                   const char *opt_lc_messages,
                                   session_env_t session_env);

gpg_error_t gnupg_get_passphrase (const char *cache_id,
                                  const char *err_msg,
                                  const char *prompt,
                                  const char *desc_msg,
                                  int repeat,
                                  int check_quality,
                                  int use_secmem,
                                  char **r_passphrase);

gpg_error_t gnupg_clear_passphrase (const char *cache_id);


#endif /*GNUPG_COMMON_GET_PASSPHRASE_H*/
