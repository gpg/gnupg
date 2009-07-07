/* session-env.h - Definitions for session environment functions
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

#ifndef GNUPG_COMMON_SESSION_ENV_H
#define GNUPG_COMMON_SESSION_ENV_H

struct session_environment_s;
typedef struct session_environment_s *session_env_t;

const char *session_env_list_stdenvnames (int *iterator, 
                                          const char **r_assname);

session_env_t session_env_new (void);
void session_env_release (session_env_t se);

gpg_error_t session_env_putenv (session_env_t se, const char *string);
gpg_error_t session_env_setenv (session_env_t se, 
                                const char *name, const char *value);

char *session_env_getenv (session_env_t se, const char *name);
char *session_env_getenv_or_default (session_env_t se, const char *name,
                                     int *r_default);
char *session_env_listenv (session_env_t se, int *iterator, 
                           const char **r_value, int *r_default);


#endif /*GNUPG_COMMON_SESSION_ENV_H*/
