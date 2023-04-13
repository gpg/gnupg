/* ks-action.h - OpenPGP keyserver actions definitions
 * Copyright (C) 2011 Free Software Foundation, Inc.
 *               2015 g10 Code GmbH
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

#ifndef DIRMNGR_KS_ACTION_H
#define DIRMNGR_KS_ACTION_H 1

gpg_error_t ks_action_parse_uri (const char *uri, uri_item_t *r_parseduri);
gpg_error_t ks_action_help (ctrl_t ctrl, const char *url);
gpg_error_t ks_action_resolve (ctrl_t ctrl, uri_item_t keyservers);
gpg_error_t ks_action_search (ctrl_t ctrl, uri_item_t keyservers,
			      strlist_t patterns, estream_t outfp);
gpg_error_t ks_action_get (ctrl_t ctrl, uri_item_t keyservers,
			   strlist_t patterns, unsigned int ks_get_flags,
                           gnupg_isotime_t newer, estream_t outfp);
gpg_error_t ks_action_fetch (ctrl_t ctrl, const char *url, estream_t outfp);
gpg_error_t ks_action_put (ctrl_t ctrl, uri_item_t keyservers,
			   void *data, size_t datalen,
			   void *info, size_t infolen);
gpg_error_t ks_action_query (ctrl_t ctrl, const char *ldapserver,
                             unsigned int ks_get_flags,
                             const char *filter, char **attr,
                             gnupg_isotime_t newer, estream_t outfp);


#endif /*DIRMNGR_KS_ACTION_H*/
