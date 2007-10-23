/* status.h
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003,
 *               2004 Free Software Foundation, Inc.
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
#ifndef G10_STATUS_H
#define G10_STATUS_H

#define STATUS_ENTER	 1
#define STATUS_LEAVE	 2
#define STATUS_ABORT	 3

#define STATUS_GOODSIG	 4
#define STATUS_BADSIG	 5
#define STATUS_ERRSIG	 6

#define STATUS_BADARMOR  7

#define STATUS_RSA_OR_IDEA 8
#define STATUS_KEYEXPIRED  9
#define STATUS_KEYREVOKED  10

#define STATUS_TRUST_UNDEFINED 11
#define STATUS_TRUST_NEVER     12
#define STATUS_TRUST_MARGINAL  13
#define STATUS_TRUST_FULLY     14
#define STATUS_TRUST_ULTIMATE  15

#define STATUS_SHM_INFO        16
#define STATUS_SHM_GET	       17
#define STATUS_SHM_GET_BOOL    18
#define STATUS_SHM_GET_HIDDEN  19

#define STATUS_NEED_PASSPHRASE 20
#define STATUS_VALIDSIG        21
#define STATUS_SIG_ID	       22
#define STATUS_ENC_TO	       23
#define STATUS_NODATA	       24
#define STATUS_BAD_PASSPHRASE  25
#define STATUS_NO_PUBKEY       26
#define STATUS_NO_SECKEY       27
#define STATUS_NEED_PASSPHRASE_SYM 28
#define STATUS_DECRYPTION_FAILED 29
#define STATUS_DECRYPTION_OKAY	 30
#define STATUS_MISSING_PASSPHRASE 31
#define STATUS_GOOD_PASSPHRASE	32
#define STATUS_GOODMDC		33
#define STATUS_BADMDC		34
#define STATUS_ERRMDC		35
#define STATUS_IMPORTED 	36
#define STATUS_IMPORT_RES	37
#define STATUS_FILE_START	38
#define STATUS_FILE_DONE	39
#define STATUS_FILE_ERROR	40

#define STATUS_BEGIN_DECRYPTION 41
#define STATUS_END_DECRYPTION	42
#define STATUS_BEGIN_ENCRYPTION 43
#define STATUS_END_ENCRYPTION	44

#define STATUS_DELETE_PROBLEM	45
#define STATUS_GET_BOOL 	46
#define STATUS_GET_LINE 	47
#define STATUS_GET_HIDDEN	48
#define STATUS_GOT_IT		49
#define STATUS_PROGRESS 	50
#define STATUS_SIG_CREATED	51
#define STATUS_SESSION_KEY	52
#define STATUS_NOTATION_NAME    53
#define STATUS_NOTATION_DATA    54
#define STATUS_POLICY_URL       55
#define STATUS_BEGIN_STREAM     56
#define STATUS_END_STREAM       57
#define STATUS_KEY_CREATED      58
#define STATUS_USERID_HINT      59
#define STATUS_UNEXPECTED       60
#define STATUS_INV_RECP         61
#define STATUS_NO_RECP          62
#define STATUS_ALREADY_SIGNED   63
#define STATUS_SIGEXPIRED       64
#define STATUS_EXPSIG           65
#define STATUS_EXPKEYSIG        66
#define STATUS_ATTRIBUTE        67
#define STATUS_IMPORT_OK 	68
#define STATUS_IMPORT_CHECK     69
#define STATUS_REVKEYSIG        70
#define STATUS_CARDCTRL         71
#define STATUS_NEWSIG           72
#define STATUS_PLAINTEXT        73
#define STATUS_PLAINTEXT_LENGTH 74
#define STATUS_KEY_NOT_CREATED  75
#define STATUS_NEED_PASSPHRASE_PIN 76
#define STATUS_SIG_SUBPACKET    77

/* Extra status codes for certain smartcard operations.  Primary
   useful to double check that change PIN worked as expected.  */
#define STATUS_SC_OP_FAILURE    79
#define STATUS_SC_OP_SUCCESS    80

#define STATUS_BACKUP_KEY_CREATED 81

#define STATUS_PKA_TRUST_BAD    82
#define STATUS_PKA_TRUST_GOOD   83

#define STATUS_BEGIN_SIGNING    84

#define STATUS_ERROR  85


/*-- status.c --*/
void set_status_fd ( int fd );
int  is_status_enabled ( void );
void write_status ( int no );
void write_status_text ( int no, const char *text );
void write_status_buffer ( int no,
                           const char *buffer, size_t len, int wrap );
void write_status_text_and_buffer ( int no, const char *text,
                                    const char *buffer, size_t len, int wrap );

#ifdef USE_SHM_COPROCESSING
  void init_shm_coprocessing ( ulong requested_shm_size, int lock_mem );
#endif /*USE_SHM_COPROCESSING*/

int cpr_enabled(void);
char *cpr_get( const char *keyword, const char *prompt );
char *cpr_get_no_help( const char *keyword, const char *prompt );
char *cpr_get_utf8( const char *keyword, const char *prompt );
char *cpr_get_hidden( const char *keyword, const char *prompt );
void cpr_kill_prompt(void);
int  cpr_get_answer_is_yes( const char *keyword, const char *prompt );
int  cpr_get_answer_yes_no_quit( const char *keyword, const char *prompt );
int  cpr_get_answer_okay_cancel (const char *keyword,
                                 const char *prompt,
                                 int def_answer);

#endif /*G10_STATUS_H*/
