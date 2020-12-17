/* keyserver-internal.h - Keyserver internals
 * Copyright (C) 2001, 2002, 2004, 2005, 2006 Free Software Foundation, Inc.
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _KEYSERVER_INTERNAL_H_
#define _KEYSERVER_INTERNAL_H_

#include <time.h>
#include "../common/keyserver.h"
#include "../common/iobuf.h"
#include "../common/types.h"

int parse_keyserver_options(char *options);
void free_keyserver_spec(struct keyserver_spec *keyserver);
struct keyserver_spec *keyserver_match(struct keyserver_spec *spec);
struct keyserver_spec *parse_keyserver_uri (const char *string,
                                            int require_scheme);
struct keyserver_spec *parse_preferred_keyserver(PKT_signature *sig);
int keyserver_any_configured (ctrl_t ctrl);
int keyserver_export (ctrl_t ctrl, strlist_t users);
int keyserver_import (ctrl_t ctrl, strlist_t users);
int keyserver_import_fprint (ctrl_t ctrl, const byte *fprint,size_t fprint_len,
                             struct keyserver_spec *keyserver, int quick);
int keyserver_import_keyid (ctrl_t ctrl, u32 *keyid,
                            struct keyserver_spec *keyserver, int quick);
gpg_error_t keyserver_refresh (ctrl_t ctrl, strlist_t users);
gpg_error_t keyserver_search (ctrl_t ctrl, strlist_t tokens);
int keyserver_fetch (ctrl_t ctrl, strlist_t urilist, int origin);
int keyserver_import_cert (ctrl_t ctrl, const char *name, int dane_mode,
                           unsigned char **fpr,size_t *fpr_len);
gpg_error_t keyserver_import_pka (ctrl_t ctrl, const char *name,
                                  unsigned char **fpr,size_t *fpr_len);
gpg_error_t keyserver_import_wkd (ctrl_t ctrl, const char *name, int quick,
                                  unsigned char **fpr, size_t *fpr_len);
int keyserver_import_ntds (ctrl_t ctrl, const char *name,
                           unsigned char **fpr,size_t *fpr_len);
int keyserver_import_name (ctrl_t ctrl,
                           const char *name,unsigned char **fpr,size_t *fpr_len,
                           struct keyserver_spec *keyserver);
int keyserver_import_ldap (ctrl_t ctrl, const char *name,
                           unsigned char **fpr,size_t *fpr_len);

#endif /* !_KEYSERVER_INTERNAL_H_ */
