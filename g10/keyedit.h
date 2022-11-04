/* keyedit.h - Edit properties of a key
 * Copyright (C) 1998-2010 Free Software Foundation, Inc.
 * Copyright (C) 1998-2017 Werner Koch
 * Copyright (C) 2015-2017 g10 Code GmbH
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

#ifndef GNUPG_G10_KEYEDIT_H
#define GNUPG_G10_KEYEDIT_H

#define NODFLG_BADSIG (1<<0)	/* Bad signature.  */
#define NODFLG_NOKEY  (1<<1)	/* No public key.  */
#define NODFLG_SIGERR (1<<2)	/* Other sig error.  */

#define NODFLG_MARK_A (1<<4)	/* Temporary mark.  */
#define NODFLG_DELSIG (1<<5)	/* To be deleted.  */

#define NODFLG_SELUID (1<<8)	/* Indicate the selected userid. */
#define NODFLG_SELKEY (1<<9)	/* Indicate the selected key.  */
#define NODFLG_SELSIG (1<<10)	/* Indicate a selected signature.  */

#define NODFLG_MARK_B (1<<11)   /* Temporary mark in key listing code.  */

/*-- keyedit.c --*/
void keyedit_menu (ctrl_t ctrl, const char *username, strlist_t locusr,
		   strlist_t commands, int quiet, int seckey_check );
void keyedit_passwd (ctrl_t ctrl, const char *username);
void keyedit_quick_adduid (ctrl_t ctrl, const char *username,
                           const char *newuid);
void keyedit_quick_addkey (ctrl_t ctrl, const char *fpr, const char *algostr,
                           const char *usagestr, const char *expirestr);
void keyedit_quick_revuid (ctrl_t ctrl, const char *username,
                           const char *uidtorev);
void keyedit_quick_sign (ctrl_t ctrl, const char *fpr,
                         strlist_t uids, strlist_t locusr, int local);
void keyedit_quick_revsig (ctrl_t ctrl, const char *username,
                           const char *sigtorev, strlist_t affected_uids);
void keyedit_quick_set_expire (ctrl_t ctrl,
                               const char *fpr, const char *expirestr,
                               char **subkeyfprs);
void keyedit_quick_set_primary (ctrl_t ctrl, const char *username,
                                const char *primaryuid);
void keyedit_quick_update_pref (ctrl_t ctrl, const char *username);
void show_basic_key_info (ctrl_t ctrl, kbnode_t keyblock, int print_sec);
int keyedit_print_one_sig (ctrl_t ctrl, estream_t fp,
                           int rc, kbnode_t keyblock,
			   kbnode_t node, int *inv_sigs, int *no_key,
			   int *oth_err, int is_selfsig,
			   int print_without_key, int extended);

#endif	/* GNUPG_G10_KEYEDIT_H */
