/* call-agent.h - Divert operations to the agent
 * Copyright (C) 2003 Free Software Foundation, Inc.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */
#ifndef GNUPG_G10_CALL_AGENT_H
#define GNUPG_G10_CALL_AGENT_H 


struct agent_card_info_s {
  int error;         /* private. */
  char *serialno;    /* malloced hex string. */
  char *disp_name;   /* malloced. */
  char *pubkey_url;  /* malloced. */
  char fpr1valid;
  char fpr2valid;
  char fpr3valid;
  char fpr1[20];
  char fpr2[20];
  char fpr3[20];
};

struct agent_card_genkey_s {
  char fprvalid;
  char fpr[20];
  u32  created_at;
  gcry_mpi_t n;
  gcry_mpi_t e;
};

/* Return card info. */
int agent_learn (struct agent_card_info_s *info);

/* Check whether the secret key for the key identified by HEXKEYGRIP
   is available.  Return 0 for yes or an error code. */
int agent_havekey (const char *hexkeygrip);

/* Send a SETATTR command to the SCdaemon. */
int agent_scd_setattr (const char *name,
                       const unsigned char *value, size_t valuelen);

/* Send a GENKEY command to the SCdaemon. */
int agent_scd_genkey (struct agent_card_genkey_s *info, int keyno, int force);

/* Send a PKSIGN command to the SCdaemon. */
int agent_scd_pksign (const char *keyid, int hashalgo,
                      const unsigned char *indata, size_t indatalen,
                      char **r_buf, size_t *r_buflen);

/* Ask the agent to let the user change the passphrase of the secret
   key identified by HEXKEYGRIP. */
int agent_passwd (const char *hexkeygrip);






#endif /*GNUPG_G10_CALL_AGENT_H*/

