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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _KEYSERVER_INTERNAL_H_
#define _KEYSERVER_INTERNAL_H_

#include <time.h>
#include "keyserver.h"
#include "iobuf.h"
#include "types.h"

int parse_keyserver_options(char *options);
void free_keyserver_spec(struct keyserver_spec *keyserver);
struct keyserver_spec *keyserver_match(struct keyserver_spec *spec);
struct keyserver_spec *parse_keyserver_uri(const char *string,
					   int require_scheme,
					   const char *configname,
					   unsigned int configlineno);
struct keyserver_spec *parse_preferred_keyserver(PKT_signature *sig);
int keyserver_export(STRLIST users);
int keyserver_import(STRLIST users);
int keyserver_import_fprint(const byte *fprint,size_t fprint_len,
			    struct keyserver_spec *keyserver);
int keyserver_import_keyid(u32 *keyid,struct keyserver_spec *keyserver);
int keyserver_refresh(STRLIST users);
int keyserver_search(STRLIST tokens);
int keyserver_fetch(STRLIST urilist);
int keyserver_import_cert(const char *name,
			  unsigned char **fpr,size_t *fpr_len);
int keyserver_import_pka(const char *name,unsigned char **fpr,size_t *fpr_len);
int keyserver_import_name(const char *name,unsigned char **fpr,size_t *fpr_len,
			  struct keyserver_spec *keyserver);
int keyserver_import_ldap(const char *name,
			  unsigned char **fpr,size_t *fpr_len);

#endif /* !_KEYSERVER_INTERNAL_H_ */
