/* g130syshelp.h - Global definitions for G13-SYSHELP.
 * Copyright (C) 2015 Werner Koch
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

#ifndef G13_SYSHELP_H
#define G13_SYSHELP_H

#include "g13-common.h"
#include "g13tuple.h"

struct tab_item_s;
typedef struct tab_item_s *tab_item_t;

struct tab_item_s
{
  tab_item_t next;
  char *label;       /* Optional malloced label for that entry.  */
  char *mountpoint;  /* NULL or a malloced mountpoint.  */
  char blockdev[1];  /* String with the name of the block device.  If
                        it starts with a slash it is a regular device
                        name, otherwise it is a PARTUUID.  */
};



/* Forward declaration for an object defined in g13-sh-cmd.c.  */
struct server_local_s;

/* Session control object.  This object is passed down to most
   functions.  The default values for it are set by
   g13_syshelp_init_default_ctrl(). */
struct server_control_s
{
  int no_server;      /* We are not running under server control */
  int  status_fd;     /* Only for non-server mode */
  struct server_local_s *server_local;

  struct {
    uid_t uid;     /* UID of the client calling use.  */
    char *uname;
    tab_item_t tab;/* Linked list with the g13tab items for this user.  */
  } client;

  /* Flag indicating that we should fail all commands.  */
  int fail_all_cmds;

  /* Type of the current container.  See the CONTTYPE_ constants.  */
  int conttype;

  /* A pointer into client.tab with the selected tab line or NULL. */
  tab_item_t devti;
};


/*-- g13-syshelp.c --*/
void g13_syshelp_init_default_ctrl (struct server_control_s *ctrl);
void g13_syshelp_i_know_what_i_am_doing (void);

/*-- sh-cmd.c --*/
gpg_error_t syshelp_server (ctrl_t ctrl);
gpg_error_t sh_encrypt_keyblob (ctrl_t ctrl,
                                const void *keyblob, size_t keybloblen,
                                char **r_enckeyblob, size_t *r_enckeybloblen);

/*-- sh-blockdev.c --*/
gpg_error_t sh_blockdev_getsz (const char *name, unsigned long long *r_nblocks);
gpg_error_t sh_is_empty_partition (const char *name);

/*-- sh-dmcrypt.c --*/
gpg_error_t sh_dmcrypt_create_container (ctrl_t ctrl, const char *devname,
                                         estream_t devfp);
gpg_error_t sh_dmcrypt_mount_container (ctrl_t ctrl, const char *devname,
                                        tupledesc_t keyblob);
gpg_error_t sh_dmcrypt_umount_container (ctrl_t ctrl, const char *devname);
gpg_error_t sh_dmcrypt_suspend_container (ctrl_t ctrl, const char *devname);
gpg_error_t sh_dmcrypt_resume_container (ctrl_t ctrl, const char *devname,
                                         tupledesc_t keyblob);



#endif /*G13_SYSHELP_H*/
