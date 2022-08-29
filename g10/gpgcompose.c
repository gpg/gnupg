/* gpgcompose.c - Maintainer tool to create OpenPGP messages by hand.
 * Copyright (C) 2016 g10 Code GmbH
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

#include <config.h>
#include <errno.h>

#define INCLUDED_BY_MAIN_MODULE 1
#include "gpg.h"
#include "packet.h"
#include "keydb.h"
#include "main.h"
#include "options.h"

static int do_debug;
#define debug(fmt, ...) \
  do { if (do_debug) log_debug (fmt, ##__VA_ARGS__); } while (0)

/* --encryption, for instance, adds a filter in front of out.  There
   is an operator (--encryption-pop) to end this.  We use the
   following infrastructure to make it easy to pop the state.  */
struct filter
{
  void *func;
  void *context;
  int pkttype;
  int partial_block_mode;
  struct filter *next;
};


/* Hack to ass CTRL to some functions.  */
static ctrl_t global_ctrl;


static struct filter *filters;

static void
filter_push (iobuf_t out, void *func, void *context,
             int type, int partial_block_mode)
{
  gpg_error_t err;
  struct filter *f = xmalloc_clear (sizeof (*f));
  f->next = filters;
  f->func = func;
  f->context = context;
  f->pkttype = type;
  f->partial_block_mode = partial_block_mode;

  filters = f;

  err = iobuf_push_filter (out, func, context);
  if (err)
    log_fatal ("Adding filter: %s\n", gpg_strerror (err));
}

static void
filter_pop (iobuf_t out, int expected_type)
{
  gpg_error_t err;
  struct filter *f = filters;

  log_assert (f);

  if (f->pkttype != expected_type)
    log_fatal ("Attempted to pop a %s container, "
               "but current container is a %s container.\n",
               pkttype_str (f->pkttype), pkttype_str (expected_type));

  if (f->pkttype == PKT_ENCRYPTED)
    {
      err = iobuf_pop_filter (out, f->func, f->context);
      if (err)
        log_fatal ("Popping encryption filter: %s\n", gpg_strerror (err));
    }
  else
    log_fatal ("FILTERS appears to be corrupted.\n");

  if (f->partial_block_mode)
    iobuf_set_partial_body_length_mode (out, 0);

  filters = f->next;
  xfree (f);
}

/* Return if CIPHER_ID is a valid cipher.  */
static int
valid_cipher (int cipher_id)
{
  return (cipher_id == CIPHER_ALGO_IDEA
          || cipher_id == CIPHER_ALGO_3DES
          || cipher_id == CIPHER_ALGO_CAST5
          || cipher_id == CIPHER_ALGO_BLOWFISH
          || cipher_id == CIPHER_ALGO_AES
          || cipher_id == CIPHER_ALGO_AES192
          || cipher_id == CIPHER_ALGO_AES256
          || cipher_id == CIPHER_ALGO_TWOFISH
          || cipher_id == CIPHER_ALGO_CAMELLIA128
          || cipher_id == CIPHER_ALGO_CAMELLIA192
          || cipher_id == CIPHER_ALGO_CAMELLIA256);
}

/* Parse a session key encoded as a string of the form x:HEXDIGITS
   where x is the algorithm id.  (This is the format emitted by gpg
   --show-session-key.)  */
struct session_key
{
  int algo;
  int keylen;
  char *key;
};

static struct session_key
parse_session_key (const char *option, char *p, int require_algo)
{
  char *tail;
  struct session_key sk;

  memset (&sk, 0, sizeof (sk));

  /* Check for the optional "cipher-id:" at the start of the
     string.  */
  errno = 0;
  sk.algo = strtol (p, &tail, 10);
  if (! errno && tail && *tail == ':')
    {
      if (! valid_cipher (sk.algo))
        log_info ("%s: %d is not a known cipher (but using anyways)\n",
                  option, sk.algo);
      p = tail + 1;
    }
  else if (require_algo)
    log_fatal ("%s: Session key must have the form algo:HEXCHARACTERS.\n",
               option);
  else
    sk.algo = 0;

  /* Ignore a leading 0x.  */
  if (p[0] == '0' && p[1] == 'x')
    p += 2;

  if (strlen (p) % 2 != 0)
    log_fatal ("%s: session key must consist of an even number of hexadecimal characters.\n",
               option);

  sk.keylen = strlen (p) / 2;
  sk.key = xmalloc (sk.keylen);

  if (hex2bin (p, sk.key, sk.keylen) == -1)
    log_fatal ("%s: Session key must only contain hexadecimal characters\n",
               option);

  return sk;
}

/* A callback.

   OPTION_STR is the option that was matched.  ARGC is the number of
   arguments following the option and ARGV are those arguments.
   (Thus, argv[0] is the first string following the option and
   argv[-1] is the option.)

   COOKIE is the opaque value passed to process_options.  */
typedef int (*option_prcessor_t) (const char *option_str,
                                  int argc, char *argv[],
                                  void *cookie);

struct option
{
  /* The option that this matches.  This must start with "--" or be
     the empty string.  The empty string matches bare arguments.  */
  const char *option;
  /* The function to call to process this option.  */
  option_prcessor_t func;
  /* Documentation.  */
  const char *help;
};

/* Merge two lists of options.  Note: this makes a shallow copy!  The
   caller must xfree() the result.  */
static struct option *
merge_options (struct option a[], struct option b[])
{
  int i, j;
  struct option *c;

  for (i = 0; a[i].option; i ++)
    ;
  for (j = 0; b[j].option; j ++)
    ;

  c = xmalloc ((i + j + 1) * sizeof (struct option));
  memcpy (c, a, i * sizeof (struct option));
  memcpy (&c[i], b, j * sizeof (struct option));
  c[i + j].option = NULL;

  if (a[i].help && b[j].help)
    c[i + j].help = xasprintf ("%s\n\n%s", a[i].help, b[j].help);
  else if (a[i].help)
    c[i + j].help = a[i].help;
  else if (b[j].help)
    c[i + j].help = b[j].help;

  return c;
}

/* Returns whether ARG is an option.  All options start with --.  */
static int
is_option (const char *arg)
{
  return arg[0] == '-' && arg[1] == '-';
}

/* OPTIONS is a NULL terminated array of struct option:s.  Finds the
   entry that is the same as ARG.  Returns -1 if no entry is found.
   The empty string option matches bare arguments.  */
static int
match_option (const struct option options[], const char *arg)
{
  int i;
  int bare_arg = ! is_option (arg);

  for (i = 0; options[i].option; i ++)
    if ((! bare_arg && strcmp (options[i].option, arg) == 0)
        /* Non-options match the empty string.  */
        || (bare_arg && options[i].option[0] == '\0'))
      return i;

  return -1;
}

static void
show_help (struct option options[])
{
  int i;
  int max_length = 0;
  int space;

  for (i = 0; options[i].option; i ++)
    {
      const char *option = options[i].option[0] ? options[i].option : "ARG";
      int l = strlen (option);
      if (l > max_length)
        max_length = l;
    }

  space = 72 - (max_length + 2);
  if (space < 40)
    space = 40;

  for (i = 0; ; i ++)
    {
      const char *option = options[i].option;
      const char *help = options[i].help;

      int l;
      int j;
      char *tmp;
      char *formatted;
      char *p;
      char *newline;

      if (! option && ! help)
        break;

      if (option)
        {
          const char *o = option[0] ? option : "ARG";
          l = strlen (o);
          fprintf (stdout, "%s", o);
        }

      if (! help)
        {
          fputc ('\n', stdout);
          continue;
        }

      if (option)
        for (j = l; j < max_length + 2; j ++)
          fputc (' ', stdout);

#define BOLD_START "\033[1m"
#define NORMAL_RESTORE "\033[0m"
#define BOLD(x) BOLD_START x NORMAL_RESTORE

      if (! option || options[i].func)
        tmp = (char *) help;
      else
        tmp = xasprintf ("%s " BOLD("(Unimplemented.)"), help);

      if (! option)
        space = 72;
      formatted = format_text (tmp, space, space + 4);
      if (!formatted)
        abort ();

      if (tmp != help)
        xfree (tmp);

      if (! option)
        {
          printf ("\n%s\n", formatted);
          break;
        }

      for (p = formatted;
           p && *p;
           p = (*newline == '\0') ? newline : newline + 1)
        {
          newline = strchr (p, '\n');
          if (! newline)
            newline = &p[strlen (p)];

          l = (size_t) newline - (size_t) p;

          if (p != formatted)
            for (j = 0; j < max_length + 2; j ++)
              fputc (' ', stdout);

          fwrite (p, l, 1, stdout);
          fputc ('\n', stdout);
        }

      xfree (formatted);
  }
}

/* Return value is number of consumed argv elements.  */
static int
process_options (const char *parent_option,
                 struct option break_options[],
                 struct option local_options[], void *lcookie,
                 struct option global_options[], void *gcookie,
                 int argc, char *argv[])
{
  int i;
  for (i = 0; i < argc; i ++)
    {
      int j;
      struct option *option;
      void *cookie;
      int bare_arg;
      option_prcessor_t func;
      int consumed;

      if (break_options)
        {
          j = match_option (break_options, argv[i]);
          if (j != -1)
            /* Match.  Break out.  */
            return i;
        }

      j = match_option (local_options, argv[i]);
      if (j == -1)
        {
          if (global_options)
            j = match_option (global_options, argv[i]);
          if (j == -1)
            {
              if (strcmp (argv[i], "--help") == 0)
                {
                  if (! global_options)
                    show_help (local_options);
                  else
                    {
                      struct option *combined
                        = merge_options (local_options, global_options);
                      show_help (combined);
                      xfree (combined);
                    }
                  g10_exit (0);
                }

              if (parent_option)
                log_fatal ("%s: Unknown option: %s\n", parent_option, argv[i]);
              else
                log_fatal ("Unknown option: %s\n", argv[i]);
            }

          option = &global_options[j];
          cookie = gcookie;
        }
      else
        {
          option = &local_options[j];
          cookie = lcookie;
        }

      bare_arg = strcmp (option->option, "") == 0;

      func = option->func;
      if (! func)
        {
          if (bare_arg)
            log_fatal ("Bare arguments unimplemented.\n");
          else
            log_fatal ("Unimplemented option: %s\n",
                       option->option);
        }

      consumed = func (bare_arg ? parent_option : argv[i],
                       argc - i - !bare_arg, &argv[i + !bare_arg],
                       cookie);
      i += consumed;
      if (bare_arg)
        i --;
    }

  return i;
}

/* The keys, subkeys, user ids and user attributes in the order that
   they were added.  */
PACKET components[20];
/* The number of components.  */
int ncomponents;

static int
add_component (int pkttype, void *component)
{
  int i = ncomponents ++;

  log_assert (i < sizeof (components) / sizeof (components[0]));
  log_assert (pkttype == PKT_PUBLIC_KEY
              || pkttype == PKT_PUBLIC_SUBKEY
              || pkttype == PKT_SECRET_KEY
              || pkttype == PKT_SECRET_SUBKEY
              || pkttype == PKT_USER_ID
              || pkttype == PKT_ATTRIBUTE);

  components[i].pkttype = pkttype;
  components[i].pkt.generic = component;

  return i;
}

static void
dump_component (PACKET *pkt)
{
  struct kbnode_struct kbnode;

  if (! do_debug)
    return;

  memset (&kbnode, 0, sizeof (kbnode));
  kbnode.pkt = pkt;
  dump_kbnode (&kbnode);
}

/* Returns the first primary key in COMPONENTS or NULL if there is
   none.  */
static PKT_public_key *
primary_key (void)
{
  int i;
  for (i = 0; i < ncomponents; i ++)
    if (components[i].pkttype == PKT_PUBLIC_KEY)
      return components[i].pkt.public_key;
  return NULL;
}

/* The last session key (updated when adding a SK-ESK, PK-ESK or SED
   packet.  */
static DEK session_key;

static int user_id (const char *option, int argc, char *argv[],
                    void *cookie);
static int public_key (const char *option, int argc, char *argv[],
                       void *cookie);
static int sk_esk (const char *option, int argc, char *argv[],
                   void *cookie);
static int pk_esk (const char *option, int argc, char *argv[],
                   void *cookie);
static int encrypted (const char *option, int argc, char *argv[],
                      void *cookie);
static int encrypted_pop (const char *option, int argc, char *argv[],
                          void *cookie);
static int literal (const char *option, int argc, char *argv[],
                    void *cookie);
static int signature (const char *option, int argc, char *argv[],
                      void *cookie);
static int copy (const char *option, int argc, char *argv[],
                 void *cookie);

static struct option major_options[] = {
  { "--user-id", user_id, "Create a user id packet." },
  { "--public-key", public_key, "Create a public key packet." },
  { "--private-key", NULL, "Create a private key packet." },
  { "--public-subkey", public_key, "Create a subkey packet." },
  { "--private-subkey", NULL, "Create a private subkey packet." },
  { "--sk-esk", sk_esk,
    "Create a symmetric-key encrypted session key packet." },
  { "--pk-esk", pk_esk,
    "Create a public-key encrypted session key packet." },
  { "--encrypted", encrypted, "Create a symmetrically encrypted data packet." },
  { "--encrypted-mdc", encrypted,
    "Create a symmetrically encrypted and integrity protected data packet." },
  { "--encrypted-pop", encrypted_pop,
    "Pop the most recent encryption container started by either"
    " --encrypted or --encrypted-mdc." },
  { "--compressed", NULL, "Create a compressed data packet." },
  { "--literal", literal, "Create a literal (plaintext) data packet." },
  { "--signature", signature, "Create a signature packet." },
  { "--onepass-sig", NULL, "Create a one-pass signature packet." },
  { "--copy", copy, "Copy the specified file." },
  { NULL, NULL,
    "To get more information about a given command, use:\n\n"
    "  $ gpgcompose --command --help to list a command's options."},
};

static struct option global_options[] = {
  { NULL, NULL, NULL },
};

/* Make our lives easier and use a static limit for the user name.
   10k is way more than enough anyways... */
const int user_id_max_len = 10 * 1024;

static int
user_id_name (const char *option, int argc, char *argv[], void *cookie)
{
  PKT_user_id *uid = cookie;
  int l;

  if (argc == 0)
    log_fatal ("Usage: %s USER_ID\n", option);

  if (uid->len)
    log_fatal ("Attempt to set user id multiple times.\n");

  l = strlen (argv[0]);
  if (l > user_id_max_len)
    log_fatal ("user id too long (max: %d)\n", user_id_max_len);

  memcpy (uid->name, argv[0], l);
  uid->name[l] = 0;
  uid->len = l;

  return 1;
}

static struct option user_id_options[] = {
  { "", user_id_name,
    "Set the user id.  This is usually in the format "
    "\"Name (comment) <email@example.org>\"" },
  { NULL, NULL,
    "Example:\n\n"
    "  $ gpgcompose --user-id \"USERID\" | " GPG_NAME " --list-packets" }
};

static int
user_id (const char *option, int argc, char *argv[], void *cookie)
{
  iobuf_t out = cookie;
  gpg_error_t err;
  PKT_user_id *uid = xmalloc_clear (sizeof (*uid) + user_id_max_len);
  int c = add_component (PKT_USER_ID, uid);
  int processed;

  processed = process_options (option,
                               major_options,
                               user_id_options, uid,
                               global_options, NULL,
                               argc, argv);

  if (! uid->len)
    log_fatal ("%s: user id not given", option);

  err = build_packet (out, &components[c]);
  if (err)
    log_fatal ("Serializing user id packet: %s\n", gpg_strerror (err));

  debug ("Wrote user id packet:\n");
  dump_component (&components[c]);

  return processed;
}

static int
pk_search_terms (const char *option, int argc, char *argv[], void *cookie)
{
  gpg_error_t err;
  KEYDB_HANDLE hd;
  KEYDB_SEARCH_DESC desc;
  kbnode_t kb;
  PKT_public_key *pk = cookie;
  PKT_public_key *pk_ref;
  int i;

  if (argc == 0)
    log_fatal ("Usage: %s KEYID\n", option);

  if (pk->pubkey_algo)
    log_fatal ("%s: multiple keys provided\n", option);

  err = classify_user_id (argv[0], &desc, 0);
  if (err)
    log_fatal ("search terms '%s': %s\n", argv[0], gpg_strerror (err));

  hd = keydb_new ();

  err = keydb_search (hd, &desc, 1, NULL);
  if (err)
    log_fatal ("looking up '%s': %s\n", argv[0], gpg_strerror (err));

  err = keydb_get_keyblock (hd, &kb);
  if (err)
    log_fatal ("retrieving keyblock for '%s': %s\n",
               argv[0], gpg_strerror (err));

  keydb_release (hd);

  pk_ref = kb->pkt->pkt.public_key;

  /* Copy the timestamp (if not already set), algo and public key
     parameters.  */
  if (! pk->timestamp)
    pk->timestamp = pk_ref->timestamp;
  pk->pubkey_algo = pk_ref->pubkey_algo;
  for (i = 0; i < pubkey_get_npkey (pk->pubkey_algo); i ++)
    pk->pkey[i] = gcry_mpi_copy (pk_ref->pkey[i]);

  release_kbnode (kb);

  return 1;
}

static int
pk_timestamp (const char *option, int argc, char *argv[], void *cookie)
{
  PKT_public_key *pk = cookie;
  char *tail = NULL;

  if (argc == 0)
    log_fatal ("Usage: %s TIMESTAMP\n", option);

  errno = 0;
  pk->timestamp = parse_timestamp (argv[0], &tail);
  if (errno || (tail && *tail))
    log_fatal ("Invalid value passed to %s (%s)\n", option, argv[0]);

  return 1;
}

#define TIMESTAMP_HELP \
  "Either as seconds since the epoch or as an ISO 8601 formatted " \
  "string (yyyymmddThhmmss, where the T is a literal)."

static struct option pk_options[] = {
  { "--timestamp", pk_timestamp,
    "The creation time.  " TIMESTAMP_HELP },
  { "", pk_search_terms,
    "The key to copy the creation time and public key parameters from."  },
  { NULL, NULL,
    "Example:\n\n"
    "  $ gpgcompose --public-key $KEYID --user-id \"USERID\" \\\n"
    "  | " GPG_NAME " --list-packets" }
};

static int
public_key (const char *option, int argc, char *argv[], void *cookie)
{
  gpg_error_t err;
  iobuf_t out = cookie;
  PKT_public_key *pk;
  int c;
  int processed;
  int t = (strcmp (option, "--public-key") == 0
           ? PKT_PUBLIC_KEY : PKT_PUBLIC_SUBKEY);

  (void) option;

  pk = xmalloc_clear (sizeof (*pk));
  pk->version = 4;

  c = add_component (t, pk);

  processed = process_options (option,
                               major_options,
                               pk_options, pk,
                               global_options, NULL,
                               argc, argv);

  if (! pk->pubkey_algo)
    log_fatal ("%s: key to extract public key parameters from not given",
               option);

  /* Clear the keyid in case we updated one of the relevant fields
     after accessing it.  */
  pk->keyid[0] = pk->keyid[1] = 0;

  err = build_packet (out, &components[c]);
  if (err)
    log_fatal ("serializing %s packet: %s\n",
               t == PKT_PUBLIC_KEY ? "public key" : "subkey",
               gpg_strerror (err));

  debug ("Wrote %s packet:\n",
         t == PKT_PUBLIC_KEY ? "public key" : "subkey");
  dump_component (&components[c]);

  return processed;
}

struct signinfo
{
  /* Key with which to sign.  */
  kbnode_t issuer_kb;
  PKT_public_key *issuer_pk;

  /* Overrides the issuer's key id.  */
  u32 issuer_keyid[2];
  /* Sets the issuer's keyid to the primary key's key id.  */
  int issuer_keyid_self;

  /* Key to sign.  */
  PKT_public_key *pk;
  /* Subkey to sign.  */
  PKT_public_key *sk;
  /* User id to sign.  */
  PKT_user_id *uid;

  int class;
  int digest_algo;
  u32 timestamp;
  u32 key_expiration;

  byte *cipher_algorithms;
  int cipher_algorithms_len;
  byte *digest_algorithms;
  int digest_algorithms_len;
  byte *compress_algorithms;
  int compress_algorithms_len;

  u32 expiration;

  int exportable_set;
  int exportable;

  int revocable_set;
  int revocable;

  int trust_level_set;
  byte trust_args[2];

  char *trust_scope;

  struct revocation_key *revocation_key;
  int nrevocation_keys;

  struct notation *notations;

  byte *key_server_preferences;
  int key_server_preferences_len;

  char *key_server;

  int primary_user_id_set;
  int primary_user_id;

  char *policy_uri;

  byte *key_flags;
  int key_flags_len;

  char *signers_user_id;

  byte reason_for_revocation_code;
  char *reason_for_revocation;

  byte *features;
  int features_len;

  /* Whether to corrupt the signature.  */
  int corrupt;
};

static int
sig_issuer (const char *option, int argc, char *argv[], void *cookie)
{
  gpg_error_t err;
  KEYDB_HANDLE hd;
  KEYDB_SEARCH_DESC desc;
  struct signinfo *si = cookie;

  if (argc == 0)
    log_fatal ("Usage: %s KEYID\n", option);

  if (si->issuer_pk)
    log_fatal ("%s: multiple keys provided\n", option);

  err = classify_user_id (argv[0], &desc, 0);
  if (err)
    log_fatal ("search terms '%s': %s\n", argv[0], gpg_strerror (err));

  hd = keydb_new ();

  err = keydb_search (hd, &desc, 1, NULL);
  if (err)
    log_fatal ("looking up '%s': %s\n", argv[0], gpg_strerror (err));

  err = keydb_get_keyblock (hd, &si->issuer_kb);
  if (err)
    log_fatal ("retrieving keyblock for '%s': %s\n",
               argv[0], gpg_strerror (err));

  keydb_release (hd);

  si->issuer_pk = si->issuer_kb->pkt->pkt.public_key;

  return 1;
}

static int
sig_issuer_keyid (const char *option, int argc, char *argv[], void *cookie)
{
  gpg_error_t err;
  KEYDB_SEARCH_DESC desc;
  struct signinfo *si = cookie;

  if (argc == 0)
    log_fatal ("Usage: %s KEYID|self\n", option);

  if (si->issuer_keyid[0] || si->issuer_keyid[1] || si->issuer_keyid_self)
    log_fatal ("%s given multiple times.\n", option);

  if (strcasecmp (argv[0], "self") == 0)
    {
      si->issuer_keyid_self = 1;
      return 1;
    }

  err = classify_user_id (argv[0], &desc, 0);
  if (err)
    log_fatal ("search terms '%s': %s\n", argv[0], gpg_strerror (err));

  if (desc.mode != KEYDB_SEARCH_MODE_LONG_KID)
    log_fatal ("%s is not a valid long key id.\n", argv[0]);

  keyid_copy (si->issuer_keyid, desc.u.kid);

  return 1;
}

static int
sig_pk (const char *option, int argc, char *argv[], void *cookie)
{
  struct signinfo *si = cookie;
  int i;
  char *tail = NULL;

  if (argc == 0)
    log_fatal ("Usage: %s COMPONENT_INDEX\n", option);

  errno = 0;
  i = strtoul (argv[0], &tail, 10);
  if (errno || (tail && *tail))
    log_fatal ("Invalid value passed to %s (%s)\n", option, argv[0]);

  if (i >= ncomponents)
    log_fatal ("%d: No such component (have %d components so far)\n",
               i, ncomponents);
  if (! (components[i].pkttype == PKT_PUBLIC_KEY
         || components[i].pkttype == PKT_PUBLIC_SUBKEY))
    log_fatal ("Component %d is not a public key or a subkey.", i);

  if (strcmp (option, "--pk") == 0)
    {
      if (si->pk)
        log_fatal ("%s already given.\n", option);
      si->pk = components[i].pkt.public_key;
    }
  else if (strcmp (option, "--sk") == 0)
    {
      if (si->sk)
        log_fatal ("%s already given.\n", option);
      si->sk = components[i].pkt.public_key;
    }
  else
    log_fatal ("Cannot handle %s\n", option);

  return 1;
}

static int
sig_user_id (const char *option, int argc, char *argv[], void *cookie)
{
  struct signinfo *si = cookie;
  int i;
  char *tail = NULL;

  if (argc == 0)
    log_fatal ("Usage: %s COMPONENT_INDEX\n", option);
  if (si->uid)
    log_fatal ("%s already given.\n", option);

  errno = 0;
  i = strtoul (argv[0], &tail, 10);
  if (errno || (tail && *tail))
    log_fatal ("Invalid value passed to %s (%s)\n", option, argv[0]);

  if (i >= ncomponents)
    log_fatal ("%d: No such component (have %d components so far)\n",
               i, ncomponents);
  if (! (components[i].pkttype != PKT_USER_ID
         || components[i].pkttype == PKT_ATTRIBUTE))
    log_fatal ("Component %d is not a public key or a subkey.", i);

  si->uid = components[i].pkt.user_id;

  return 1;
}

static int
sig_class (const char *option, int argc, char *argv[], void *cookie)
{
  struct signinfo *si = cookie;
  int i;
  char *tail = NULL;

  if (argc == 0)
    log_fatal ("Usage: %s CLASS\n", option);

  errno = 0;
  i = strtoul (argv[0], &tail, 0);
  if (errno || (tail && *tail))
    log_fatal ("Invalid value passed to %s (%s)\n", option, argv[0]);

  si->class = i;

  return 1;
}

static int
sig_digest (const char *option, int argc, char *argv[], void *cookie)
{
  struct signinfo *si = cookie;
  int i;
  char *tail = NULL;

  if (argc == 0)
    log_fatal ("Usage: %s DIGEST_ALGO\n", option);

  errno = 0;
  i = strtoul (argv[0], &tail, 10);
  if (errno || (tail && *tail))
    log_fatal ("Invalid value passed to %s (%s)\n", option, argv[0]);

  si->digest_algo = i;

  return 1;
}

static int
sig_timestamp (const char *option, int argc, char *argv[], void *cookie)
{
  struct signinfo *si = cookie;
  char *tail = NULL;

  if (argc == 0)
    log_fatal ("Usage: %s TIMESTAMP\n", option);

  errno = 0;
  si->timestamp = parse_timestamp (argv[0], &tail);
  if (errno || (tail && *tail))
    log_fatal ("Invalid value passed to %s (%s)\n", option, argv[0]);

  return 1;
}

static int
sig_expiration (const char *option, int argc, char *argv[], void *cookie)
{
  struct signinfo *si = cookie;
  int is_expiration = strcmp (option, "--expiration") == 0;
  u32 *i = is_expiration ? &si->expiration : &si->key_expiration;

  if (! is_expiration)
    log_assert (strcmp (option, "--key-expiration") == 0);

  if (argc == 0)
    log_fatal ("Usage: %s DURATION\n", option);

  *i = parse_expire_string (argv[0]);
  if (*i == (u32)-1)
    log_fatal ("Invalid value passed to %s (%s)\n", option, argv[0]);

  return 1;
}

static int
sig_int_list (const char *option, int argc, char *argv[], void *cookie)
{
  struct signinfo *si = cookie;
  int nvalues = 1;
  char *values = xmalloc (nvalues * sizeof (values[0]));
  char *tail = argv[0];
  int i;
  byte **a;
  int *n;

  if (argc == 0)
    log_fatal ("Usage: %s VALUE[,VALUE...]\n", option);

  for (i = 0; tail && *tail; i ++)
    {
      int v;
      char *old_tail = tail;

      errno = 0;
      v = strtol (tail, &tail, 0);
      if (errno || old_tail == tail || (tail && !(*tail == ',' || *tail == 0)))
        log_fatal ("Invalid value passed to %s (%s).  "
                   "Expected a list of comma separated numbers\n",
                   option, argv[0]);

      if (! (0 <= v && v <= 255))
        log_fatal ("%s: %d is out of range (Expected: 0-255)\n", option, v);

      if (i == nvalues)
        {
          nvalues *= 2;
          values = xrealloc (values, nvalues * sizeof (values[0]));
        }

      values[i] = v;

      if (*tail == ',')
        tail ++;
      else
        log_assert (*tail == 0);
    }

  if (strcmp ("--cipher-algos", option) == 0)
    {
      a = &si->cipher_algorithms;
      n = &si->cipher_algorithms_len;
    }
  else if (strcmp ("--digest-algos", option) == 0)
    {
      a = &si->digest_algorithms;
      n = &si->digest_algorithms_len;
    }
  else if (strcmp ("--compress-algos", option) == 0)
    {
      a = &si->compress_algorithms;
      n = &si->compress_algorithms_len;
    }
  else
    log_fatal ("Cannot handle %s\n", option);

  if (*a)
    log_fatal ("Option %s given multiple times.\n", option);

  *a = values;
  *n = i;

  return 1;
}

static int
sig_flag (const char *option, int argc, char *argv[], void *cookie)
{
  struct signinfo *si = cookie;
  int range[2] = {0, 255};
  char *tail;
  int v;

  if (strcmp (option, "--primary-user-id") == 0)
    range[1] = 1;

  if (argc <= 1)
    {
      if (range[0] == 0 && range[1] == 1)
        log_fatal ("Usage: %s 0|1\n", option);
      else
        log_fatal ("Usage: %s %d-%d\n", option, range[0], range[1]);
    }

  errno = 0;
  v = strtol (argv[0], &tail, 0);
  if (errno || (tail && *tail) || !(range[0] <= v && v <= range[1]))
    log_fatal ("Invalid value passed to %s (%s).  Expected %d-%d\n",
               option, argv[0], range[0], range[1]);

  if (strcmp (option, "--exportable") == 0)
    {
      si->exportable_set = 1;
      si->exportable = v;
    }
  else if (strcmp (option, "--revocable") == 0)
    {
      si->revocable_set = 1;
      si->revocable = v;
    }
  else if (strcmp (option, "--primary-user-id") == 0)
    {
      si->primary_user_id_set = 1;
      si->primary_user_id = v;
    }
  else
    log_fatal ("Cannot handle %s\n", option);

  return 1;
}

static int
sig_trust_level (const char *option, int argc, char *argv[], void *cookie)
{
  struct signinfo *si = cookie;
  int i;
  char *tail;

  if (argc <= 1)
    log_fatal ("Usage: %s DEPTH TRUST_AMOUNT\n", option);

  for (i = 0; i < sizeof (si->trust_args) / sizeof (si->trust_args[0]); i ++)
    {
      int v;

      errno = 0;
      v = strtol (argv[i], &tail, 0);
      if (errno || (tail && *tail) || !(0 <= v && v <= 255))
        log_fatal ("Invalid value passed to %s (%s).  Expected 0-255\n",
                   option, argv[i]);

      si->trust_args[i] = v;
    }

  si->trust_level_set = 1;

  return 2;
}

static int
sig_string_arg (const char *option, int argc, char *argv[], void *cookie)
{
  struct signinfo *si = cookie;
  char *p = argv[0];
  char **s;

  if (argc == 0)
    log_fatal ("Usage: %s STRING\n", option);

  if (strcmp (option, "--trust-scope") == 0)
    s = &si->trust_scope;
  else if (strcmp (option, "--key-server") == 0)
    s = &si->key_server;
  else if (strcmp (option, "--signers-user-id") == 0)
    s = &si->signers_user_id;
  else if (strcmp (option, "--policy-uri") == 0)
    s = &si->policy_uri;
  else
    log_fatal ("Cannot handle %s\n", option);

  if (*s)
    log_fatal ("%s already given.\n", option);

  *s = xstrdup (p);

  return 1;
}

static int
sig_revocation_key (const char *option, int argc, char *argv[], void *cookie)
{
  gpg_error_t err;
  struct signinfo *si = cookie;
  int v;
  char *tail;
  PKT_public_key pk;
  struct revocation_key *revkey;

  if (argc < 2)
    log_fatal ("Usage: %s CLASS KEYID\n", option);

  memset (&pk, 0, sizeof (pk));

  errno = 0;
  v = strtol (argv[0], &tail, 16);
  if (errno || (tail && *tail) || !(0 <= v && v <= 255))
    log_fatal ("%s: Invalid class value (%s).  Expected 0-255\n",
               option, argv[0]);

  pk.req_usage = PUBKEY_USAGE_SIG;
  err = get_pubkey_byname (NULL, GET_PUBKEY_NO_AKL,
                           NULL, &pk, argv[1], NULL, NULL, 1);
  if (err)
    log_fatal ("looking up key %s: %s\n", argv[1], gpg_strerror (err));

  si->nrevocation_keys ++;
  si->revocation_key = xrealloc (si->revocation_key,
                                 si->nrevocation_keys
                                 * sizeof (*si->revocation_key));
  revkey = &si->revocation_key[si->nrevocation_keys - 1];

  revkey->class = v;
  revkey->algid = pk.pubkey_algo;
  fingerprint_from_pk (&pk, revkey->fpr, NULL);

  release_public_key_parts (&pk);

  return 2;
}

static int
sig_notation (const char *option, int argc, char *argv[], void *cookie)
{
  struct signinfo *si = cookie;
  int is_blob = strcmp (option, "--notation") != 0;
  struct notation *notation;
  char *p = argv[0];
  int p_free = 0;
  char *data;
  int data_size;
  int data_len;

  if (argc == 0)
    log_fatal ("Usage: %s [!<]name=value\n", option);

  if ((p[0] == '!' && p[1] == '<') || p[0] == '<')
    /* Read from a file.  */
    {
      char *filename = NULL;
      iobuf_t in;
      int prefix;

      if (p[0] == '<')
        p ++;
      else
        {
          /* Remove the '<', which string_to_notation does not
             understand, and preserve the '!'.  */
          p = xstrdup (&p[1]);
          p_free = 1;
          p[0] = '!';
        }

      filename = strchr (p, '=');
      if (! filename)
        log_fatal ("No value specified.  Usage: %s [!<]name=value\n",
                   option);
      filename ++;

      prefix = (size_t) filename - (size_t) p;

      errno = 0;
      in = iobuf_open (filename);
      if (! in)
        log_fatal ("Opening '%s': %s\n",
                   filename, errno ? strerror (errno): "unknown error");

      /* A notation can be at most about a few dozen bytes short of
         64k.  Since this is relatively small, we just allocate that
         much instead of trying to dynamically size a buffer.  */
      data_size = 64 * 1024;
      data = xmalloc (data_size);
      log_assert (prefix <= data_size);
      memcpy (data, p, prefix);

      data_len = iobuf_read (in, &data[prefix], data_size - prefix - 1);
      if (data_len == -1)
        /* EOF => 0 bytes read.  */
        data_len = 0;

      if (data_len == data_size - prefix - 1)
        /* Technically, we should do another read and check for EOF,
           but what's one byte more or less?  */
        log_fatal ("Notation data doesn't fit in the packet.\n");

      iobuf_close (in);

      /* NUL terminate it.  */
      data[prefix + data_len] = 0;

      if (p_free)
        xfree (p);
      p = data;
      p_free = 1;
      data = &p[prefix];

      if (is_blob)
        p[prefix - 1] = 0;
    }
  else if (is_blob)
    {
      data = strchr (p, '=');
      if (! data)
        {
          data = p;
          data_len = 0;
        }
      else
        {
          p = xstrdup (p);
          p_free = 1;

          data = strchr (p, '=');
          log_assert (data);

          /* NUL terminate the name.  */
          *data = 0;
          data ++;
          data_len = strlen (data);
        }
    }

  if (is_blob)
    notation = blob_to_notation (p, data, data_len);
  else
    notation = string_to_notation (p, 1);
  if (! notation)
    log_fatal ("creating notation: an unknown error occurred.\n");
  notation->next = si->notations;
  si->notations = notation;

  if (p_free)
    xfree (p);

  return 1;
}

static int
sig_big_endian_arg (const char *option, int argc, char *argv[], void *cookie)
{
  struct signinfo *si = cookie;
  char *p = argv[0];
  int i;
  int l;
  char *bytes;

  if (argc == 0)
    log_fatal ("Usage: %s HEXDIGITS\n", option);

  /* Skip a leading "0x".  */
  if (p[0] == '0' && p[1] == 'x')
    p += 2;

  for (i = 0; i < strlen (p); i ++)
    if (!hexdigitp (&p[i]))
      log_fatal ("%s: argument ('%s') must consist of hex digits.\n",
                 option, p);
  if (strlen (p) % 2 != 0)
      log_fatal ("%s: argument ('%s') must contain an even number of hex digits.\n",
                 option, p);

  l = strlen (p) / 2;
  bytes = xmalloc (l);
  hex2bin (p, bytes, l);

  if (strcmp (option, "--key-server-preferences") == 0)
    {
      if (si->key_server_preferences)
        log_fatal ("%s given multiple times.\n", option);
      si->key_server_preferences = bytes;
      si->key_server_preferences_len = l;
    }
  else if (strcmp (option, "--key-flags") == 0)
    {
      if (si->key_flags)
        log_fatal ("%s given multiple times.\n", option);
      si->key_flags = bytes;
      si->key_flags_len = l;
    }
  else if (strcmp (option, "--features") == 0)
    {
      if (si->features)
        log_fatal ("%s given multiple times.\n", option);
      si->features = bytes;
      si->features_len = l;
    }
  else
    log_fatal ("Cannot handle %s\n", option);

  return 1;
}

static int
sig_reason_for_revocation (const char *option, int argc, char *argv[], void *cookie)
{
  struct signinfo *si = cookie;
  int v;
  char *tail;

  if (argc < 2)
    log_fatal ("Usage: %s REASON_CODE REASON_STRING\n", option);

  errno = 0;
  v = strtol (argv[0], &tail, 16);
  if (errno || (tail && *tail) || !(0 <= v && v <= 255))
    log_fatal ("%s: Invalid reason code (%s).  Expected 0-255\n",
               option, argv[0]);

  if (si->reason_for_revocation)
    log_fatal ("%s given multiple times.\n", option);

  si->reason_for_revocation_code = v;
  si->reason_for_revocation = xstrdup (argv[1]);

  return 2;
}

static int
sig_corrupt (const char *option, int argc, char *argv[], void *cookie)
{
  struct signinfo *si = cookie;

  (void) option;
  (void) argc;
  (void) argv;
  (void) cookie;

  si->corrupt = 1;

  return 0;
}

static struct option sig_options[] = {
  { "--issuer", sig_issuer,
    "The key to use to generate the signature."},
  { "--issuer-keyid", sig_issuer_keyid,
    "Set the issuer's key id.  This is useful for creating a "
    "self-signature.  As a special case, the value \"self\" refers "
    "to the primary key's key id.  "
    "(RFC 4880, Section 5.2.3.5)" },
  { "--pk", sig_pk,
    "The primary keyas an index into the components (keys and uids) "
    "created so far where the first component has the index 0." },
  { "--sk", sig_pk,
    "The subkey as an index into the components (keys and uids) created "
    "so far where the first component has the index 0.  Only needed for "
    "0x18, 0x19, and 0x28 signatures." },
  { "--user-id", sig_user_id,
    "The user id as an index into the components (keys and uids) created "
    "so far where the first component has the index 0.  Only needed for "
    "0x10-0x13 and 0x30 signatures." },
  { "--class", sig_class,
    "The signature's class.  Valid values are "
    "0x10-0x13 (user id and primary-key certification), "
    "0x18 (subkey binding), "
    "0x19 (primary key binding), "
    "0x1f (direct primary key signature), "
    "0x20 (key revocation), "
    "0x28 (subkey revocation), and "
    "0x30 (certification revocation)."
  },
  { "--digest", sig_digest, "The digest algorithm" },
  { "--timestamp", sig_timestamp,
    "The signature's creation time.  " TIMESTAMP_HELP "  0 means now.  "
    "(RFC 4880, Section 5.2.3.4)" },
  { "--key-expiration", sig_expiration,
    "The number of days until the associated key expires.  To specify "
    "seconds, prefix the value with \"seconds=\".  It is also possible "
    "to use 'y', 'm' and 'w' as simple multipliers.  For instance, 2y "
    "means 2 years, etc.  "
    "(RFC 4880, Section 5.2.3.6)" },
  { "--cipher-algos", sig_int_list,
    "A comma separated list of the preferred cipher algorithms (identified by "
    "their number, see RFC 4880, Section 9).  "
    "(RFC 4880, Section 5.2.3.7)" },
  { "--digest-algos", sig_int_list,
    "A comma separated list of the preferred algorithms (identified by "
    "their number, see RFC 4880, Section 9).  "
    "(RFC 4880, Section 5.2.3.8)" },
  { "--compress-algos", sig_int_list,
    "A comma separated list of the preferred algorithms (identified by "
    "their number, see RFC 4880, Section 9)."
    "(RFC 4880, Section 5.2.3.9)" },
  { "--expiration", sig_expiration,
    "The number of days until the signature expires.  To specify seconds, "
    "prefix the value with \"seconds=\".  It is also possible to use 'y', "
    "'m' and 'w' as simple multipliers.  For instance, 2y means 2 years, "
    "etc.  "
    "(RFC 4880, Section 5.2.3.10)" },
  { "--exportable", sig_flag,
    "Mark this signature as exportable (1) or local (0).  "
    "(RFC 4880, Section 5.2.3.11)" },
  { "--revocable", sig_flag,
    "Mark this signature as revocable (1, revocations are ignored) "
    "or non-revocable (0).  "
    "(RFC 4880, Section 5.2.3.12)" },
  { "--trust-level", sig_trust_level,
    "Set the trust level.  This takes two integer arguments (0-255): "
    "the trusted-introducer level and the degree of trust.  "
    "(RFC 4880, Section 5.2.3.13.)" },
  { "--trust-scope", sig_string_arg,
    "A regular expression that limits the scope of --trust-level.  "
    "(RFC 4880, Section 5.2.3.14.)" },
  { "--revocation-key", sig_revocation_key,
    "Specify a designated revoker.  Takes two arguments: the class "
    "(normally 0x80 or 0xC0 (sensitive)) and the key id of the "
    "designatured revoker.  May be given multiple times.  "
    "(RFC 4880, Section 5.2.3.15)" },
  { "--notation", sig_notation,
    "Add a human-readable notation of the form \"[!<]name=value\" where "
    "\"!\" means that the critical flag should be set and \"<\" means "
    "that VALUE is a file to read the data from.  "
    "(RFC 4880, Section 5.2.3.16)" },
  { "--notation-binary", sig_notation,
    "Add a binary notation of the form \"[!<]name=value\" where "
    "\"!\" means that the critical flag should be set and \"<\" means "
    "that VALUE is a file to read the data from.  "
    "(RFC 4880, Section 5.2.3.16)" },
  { "--key-server-preferences", sig_big_endian_arg,
    "Big-endian number encoding the keyserver preferences. "
    "(RFC 4880, Section 5.2.3.17)" },
  { "--key-server", sig_string_arg,
    "The preferred keyserver.  (RFC 4880, Section 5.2.3.18)" },
  { "--primary-user-id", sig_flag,
    "Sets the primary user id flag.  (RFC 4880, Section 5.2.3.19)" },
  { "--policy-uri", sig_string_arg,
    "URI of a document that describes the issuer's signing policy.  "
    "(RFC 4880, Section 5.2.3.20)" },
  { "--key-flags", sig_big_endian_arg,
    "Big-endian number encoding the key flags. "
    "(RFC 4880, Section 5.2.3.21)" },
  { "--signers-user-id", sig_string_arg,
    "The user id (as a string) responsible for the signing.  "
    "(RFC 4880, Section 5.2.3.22)" },
  { "--reason-for-revocation", sig_reason_for_revocation,
    "Takes two arguments: a reason for revocation code and a "
    "user-provided string.  "
    "(RFC 4880, Section 5.2.3.23)" },
  { "--features", sig_big_endian_arg,
    "Big-endian number encoding the feature flags. "
    "(RFC 4880, Section 5.2.3.24)" },
  { "--signature-target", NULL,
    "Takes three arguments: the target signature's public key algorithm "
    " (as an integer), the hash algorithm (as an integer) and the hash "
    " (as a hexadecimal string).  "
    "(RFC 4880, Section 5.2.3.25)" },
  { "--embedded-signature", NULL,
    "An embedded signature.  This must be immediately followed by a "
    "signature packet (created using --signature ...) or a filename "
    "containing the packet."
    "(RFC 4880, Section 5.2.3.26)" },
  { "--hashed", NULL,
    "The following attributes will be placed in the hashed area of "
    "the signature.  (This is the default and it reset at the end of"
    "each signature.)" },
  { "--unhashed", NULL,
    "The following attributes will be placed in the unhashed area of "
    "the signature (and thus not integrity protected)." },
  { "--corrupt", sig_corrupt,
    "Corrupt the signature." },
  { NULL, NULL,
    "Example:\n\n"
    "  $ gpgcompose --public-key $KEYID --user-id USERID \\\n"
    "  --signature --class 0x10 --issuer $KEYID --issuer-keyid self \\\n"
    "  | " GPG_NAME " --list-packets"}
};

static int
mksubpkt_callback (PKT_signature *sig, void *cookie)
{
  struct signinfo *si = cookie;
  int i;

  if (si->key_expiration)
    {
      char buf[4];
      buf[0] = (si->key_expiration >> 24) & 0xff;
      buf[1] = (si->key_expiration >> 16) & 0xff;
      buf[2] = (si->key_expiration >>  8) & 0xff;
      buf[3] = si->key_expiration & 0xff;
      build_sig_subpkt (sig, SIGSUBPKT_KEY_EXPIRE, buf, 4);
    }

  if (si->cipher_algorithms)
    build_sig_subpkt (sig, SIGSUBPKT_PREF_SYM,
                      si->cipher_algorithms,
                      si->cipher_algorithms_len);

  if (si->digest_algorithms)
    build_sig_subpkt (sig, SIGSUBPKT_PREF_HASH,
                      si->digest_algorithms,
                      si->digest_algorithms_len);

  if (si->compress_algorithms)
    build_sig_subpkt (sig, SIGSUBPKT_PREF_COMPR,
                      si->compress_algorithms,
                      si->compress_algorithms_len);

  if (si->exportable_set)
    {
      char buf = si->exportable;
      build_sig_subpkt (sig, SIGSUBPKT_EXPORTABLE, &buf, 1);
    }

  if (si->trust_level_set)
    build_sig_subpkt (sig, SIGSUBPKT_TRUST,
                      si->trust_args, sizeof (si->trust_args));

  if (si->trust_scope)
    build_sig_subpkt (sig, SIGSUBPKT_REGEXP,
                      si->trust_scope, strlen (si->trust_scope));

  for (i = 0; i < si->nrevocation_keys; i ++)
    {
      struct revocation_key *revkey = &si->revocation_key[i];
      gpg_error_t err = keygen_add_revkey (sig, revkey);
      if (err)
        {
          u32 keyid[2];
          keyid_from_fingerprint (global_ctrl, revkey->fpr, 20, keyid);
          log_fatal ("adding revocation key %s: %s\n",
                     keystr (keyid), gpg_strerror (err));
        }
    }

  /* keygen_add_revkey sets revocable=0 so be sure to do this after
     adding the rev keys.  */
  if (si->revocable_set)
    {
      char buf = si->revocable;
      build_sig_subpkt (sig, SIGSUBPKT_REVOCABLE, &buf, 1);
    }

  keygen_add_notations (sig, si->notations);

  if (si->key_server_preferences)
    build_sig_subpkt (sig, SIGSUBPKT_KS_FLAGS,
                      si->key_server_preferences,
                      si->key_server_preferences_len);

  if (si->key_server)
    build_sig_subpkt (sig, SIGSUBPKT_PREF_KS,
                      si->key_server, strlen (si->key_server));

  if (si->primary_user_id_set)
    {
      char buf = si->primary_user_id;
      build_sig_subpkt (sig, SIGSUBPKT_PRIMARY_UID, &buf, 1);
    }

  if (si->policy_uri)
    build_sig_subpkt (sig, SIGSUBPKT_POLICY,
                      si->policy_uri, strlen (si->policy_uri));

  if (si->key_flags)
    build_sig_subpkt (sig, SIGSUBPKT_KEY_FLAGS,
                      si->key_flags, si->key_flags_len);

  if (si->signers_user_id)
    build_sig_subpkt (sig, SIGSUBPKT_SIGNERS_UID,
                      si->signers_user_id, strlen (si->signers_user_id));

  if (si->reason_for_revocation)
    {
      int len = 1 + strlen (si->reason_for_revocation);
      char *buf;

      buf = xmalloc (len);

      buf[0] = si->reason_for_revocation_code;
      memcpy (&buf[1], si->reason_for_revocation, len - 1);

      build_sig_subpkt (sig, SIGSUBPKT_REVOC_REASON, buf, len);

      xfree (buf);
    }

  if (si->features)
    build_sig_subpkt (sig, SIGSUBPKT_FEATURES,
                      si->features, si->features_len);

  return 0;
}

static int
signature (const char *option, int argc, char *argv[], void *cookie)
{
  gpg_error_t err;
  iobuf_t out = cookie;
  struct signinfo si;
  int processed;
  PKT_public_key *pk;
  PKT_signature *sig;
  PACKET pkt;
  u32 keyid_orig[2], keyid[2];

  (void) option;

  memset (&si, 0, sizeof (si));
  memset (&pkt, 0, sizeof (pkt));

  processed = process_options (option,
                               major_options,
                               sig_options, &si,
                               global_options, NULL,
                               argc, argv);

  if (ncomponents)
    {
      int pkttype = components[ncomponents - 1].pkttype;

      if (pkttype == PKT_PUBLIC_KEY)
        {
          if (! si.class)
            /* Direct key sig.  */
            si.class = 0x1F;
        }
      else if (pkttype == PKT_PUBLIC_SUBKEY)
        {
          if (! si.sk)
            si.sk = components[ncomponents - 1].pkt.public_key;
          if (! si.class)
            /* Subkey binding sig.  */
            si.class = 0x18;
        }
      else if (pkttype == PKT_USER_ID)
        {
          if (! si.uid)
            si.uid = components[ncomponents - 1].pkt.user_id;
          if (! si.class)
            /* Certification of a user id and public key packet.  */
            si.class = 0x10;
        }
    }

  pk = NULL;
  if (! si.pk || ! si.issuer_pk)
    /* No primary key specified.  Default to the first one that we
       find.  */
    {
      int i;
      for (i = 0; i < ncomponents; i ++)
        if (components[i].pkttype == PKT_PUBLIC_KEY)
          {
            pk = components[i].pkt.public_key;
            break;
          }
    }

  if (! si.pk)
    {
      if (! pk)
        log_fatal ("%s: no primary key given and no primary key available",
                   "--pk");
      si.pk = pk;
    }
  if (! si.issuer_pk)
    {
      if (! pk)
        log_fatal ("%s: no issuer key given and no primary key available",
                   "--issuer");
      si.issuer_pk = pk;
    }

  if (si.class == 0x18 || si.class == 0x19 || si.class == 0x28)
    /* Requires the primary key and a subkey.  */
    {
      if (! si.sk)
        log_fatal ("sig class 0x%x requires a subkey (--sk)\n", si.class);
    }
  else if (si.class == 0x10
           || si.class == 0x11
           || si.class == 0x12
           || si.class == 0x13
           || si.class == 0x30)
    /* Requires the primary key and a user id.  */
    {
      if (! si.uid)
        log_fatal ("sig class 0x%x requires a uid (--uid)\n", si.class);
    }
  else if (si.class == 0x1F || si.class == 0x20)
    /* Just requires the primary key.  */
    ;
  else
    log_fatal ("Unsupported signature class: 0x%x\n", si.class);

  sig = xmalloc_clear (sizeof (*sig));

  /* Save SI.ISSUER_PK->KEYID.  */
  keyid_copy (keyid_orig, pk_keyid (si.issuer_pk));
  if (si.issuer_keyid[0] || si.issuer_keyid[1])
    keyid_copy (si.issuer_pk->keyid, si.issuer_keyid);
  else if (si.issuer_keyid_self)
    {
      PKT_public_key *pripk = primary_key();
      if (! pripk)
        log_fatal ("--issuer-keyid self given, but no primary key available.\n");
      keyid_copy (si.issuer_pk->keyid, pk_keyid (pripk));
    }

  /* Changing the issuer's key id is fragile.  Check to make sure
     make_keysig_packet didn't recompute the keyid.  */
  keyid_copy (keyid, si.issuer_pk->keyid);
  err = make_keysig_packet (global_ctrl,
                            &sig, si.pk, si.uid, si.sk, si.issuer_pk,
                            si.class, si.digest_algo,
                            si.timestamp, si.expiration,
                            mksubpkt_callback, &si, NULL);
  log_assert (keyid_cmp (keyid, si.issuer_pk->keyid) == 0);
  if (err)
    log_fatal ("Generating signature: %s\n", gpg_strerror (err));

  /* Restore SI.PK->KEYID.  */
  keyid_copy (si.issuer_pk->keyid, keyid_orig);

  if (si.corrupt)
    {
      /* Set the top 32-bits to 0xBAD0DEAD.  */
      int bits = gcry_mpi_get_nbits (sig->data[0]);
      gcry_mpi_t x = gcry_mpi_new (0);
      gcry_mpi_add_ui (x, x, 0xBAD0DEAD);
      gcry_mpi_lshift (x, x, bits > 32 ? bits - 32 : bits);
      gcry_mpi_clear_highbit (sig->data[0], bits > 32 ? bits - 32 : 0);
      gcry_mpi_add (sig->data[0], sig->data[0], x);
      gcry_mpi_release (x);
    }

  pkt.pkttype = PKT_SIGNATURE;
  pkt.pkt.signature = sig;

  err = build_packet (out, &pkt);
  if (err)
    log_fatal ("serializing public key packet: %s\n", gpg_strerror (err));

  debug ("Wrote signature packet:\n");
  dump_component (&pkt);

  free_seckey_enc (sig);
  release_kbnode (si.issuer_kb);
  xfree (si.revocation_key);

  return processed;
}

struct sk_esk_info
{
  /* The cipher used for encrypting the session key (when a session
     key is used).  */
  int cipher;
  /* The cipher used for encryping the SED packet.  */
  int sed_cipher;

  /* S2K related data.  */
  int hash;
  int mode;
  int mode_set;
  byte salt[8];
  int salt_set;
  int iterations;

  /* If applying the S2K function to the passphrase is the session key
     or if it is the decryption key for the session key.  */
  int s2k_is_session_key;
  /* Generate a new, random session key.  */
  int new_session_key;

  /* The unencrypted session key.  */
  int session_key_len;
  char *session_key;

  char *password;
};

static int
sk_esk_cipher (const char *option, int argc, char *argv[], void *cookie)
{
  struct sk_esk_info *si = cookie;
  char *usage = "integer|IDEA|3DES|CAST5|BLOWFISH|AES|AES192|AES256|CAMELLIA128|CAMELLIA192|CAMELLIA256";
  int cipher;

  if (argc == 0)
    log_fatal ("Usage: %s %s\n", option, usage);

  if (strcasecmp (argv[0], "IDEA") == 0)
    cipher = CIPHER_ALGO_IDEA;
  else if (strcasecmp (argv[0], "3DES") == 0)
    cipher = CIPHER_ALGO_3DES;
  else if (strcasecmp (argv[0], "CAST5") == 0)
    cipher = CIPHER_ALGO_CAST5;
  else if (strcasecmp (argv[0], "BLOWFISH") == 0)
    cipher = CIPHER_ALGO_BLOWFISH;
  else if (strcasecmp (argv[0], "AES") == 0)
    cipher = CIPHER_ALGO_AES;
  else if (strcasecmp (argv[0], "AES192") == 0)
    cipher = CIPHER_ALGO_AES192;
  else if (strcasecmp (argv[0], "TWOFISH") == 0)
    cipher = CIPHER_ALGO_TWOFISH;
  else if (strcasecmp (argv[0], "CAMELLIA128") == 0)
    cipher = CIPHER_ALGO_CAMELLIA128;
  else if (strcasecmp (argv[0], "CAMELLIA192") == 0)
    cipher = CIPHER_ALGO_CAMELLIA192;
  else if (strcasecmp (argv[0], "CAMELLIA256") == 0)
    cipher = CIPHER_ALGO_CAMELLIA256;
  else
    {
      char *tail;
      int v;

      errno = 0;
      v = strtol (argv[0], &tail, 0);
      if (errno || (tail && *tail) || ! valid_cipher (v))
        log_fatal ("Invalid or unsupported value.  Usage: %s %s\n",
                   option, usage);

      cipher = v;
    }

  if (strcmp (option, "--cipher") == 0)
    {
      if (si->cipher)
        log_fatal ("%s given multiple times.", option);
      si->cipher = cipher;
    }
  else if (strcmp (option, "--sed-cipher") == 0)
    {
      if (si->sed_cipher)
        log_fatal ("%s given multiple times.", option);
      si->sed_cipher = cipher;
    }

  return 1;
}

static int
sk_esk_mode (const char *option, int argc, char *argv[], void *cookie)
{
  struct sk_esk_info *si = cookie;
  char *usage = "integer|simple|salted|iterated";

  if (argc == 0)
    log_fatal ("Usage: %s %s\n", option, usage);

  if (si->mode)
    log_fatal ("%s given multiple times.", option);

  if (strcasecmp (argv[0], "simple") == 0)
    si->mode = 0;
  else if (strcasecmp (argv[0], "salted") == 0)
    si->mode = 1;
  else if (strcasecmp (argv[0], "iterated") == 0)
    si->mode = 3;
  else
    {
      char *tail;
      int v;

      errno = 0;
      v = strtol (argv[0], &tail, 0);
      if (errno || (tail && *tail) || ! (v == 0 || v == 1 || v == 3))
        log_fatal ("Invalid or unsupported value.  Usage: %s %s\n",
                   option, usage);

      si->mode = v;
    }

  si->mode_set = 1;

  return 1;
}

static int
sk_esk_hash_algorithm (const char *option, int argc, char *argv[], void *cookie)
{
  struct sk_esk_info *si = cookie;
  char *usage = "integer|MD5|SHA1|RMD160|SHA256|SHA384|SHA512|SHA224";

  if (argc == 0)
    log_fatal ("Usage: %s %s\n", option, usage);

  if (si->hash)
    log_fatal ("%s given multiple times.", option);

  if (strcasecmp (argv[0], "MD5") == 0)
    si->hash = DIGEST_ALGO_MD5;
  else if (strcasecmp (argv[0], "SHA1") == 0)
    si->hash = DIGEST_ALGO_SHA1;
  else if (strcasecmp (argv[0], "RMD160") == 0)
    si->hash = DIGEST_ALGO_RMD160;
  else if (strcasecmp (argv[0], "SHA256") == 0)
    si->hash = DIGEST_ALGO_SHA256;
  else if (strcasecmp (argv[0], "SHA384") == 0)
    si->hash = DIGEST_ALGO_SHA384;
  else if (strcasecmp (argv[0], "SHA512") == 0)
    si->hash = DIGEST_ALGO_SHA512;
  else if (strcasecmp (argv[0], "SHA224") == 0)
    si->hash = DIGEST_ALGO_SHA224;
  else
    {
      char *tail;
      int v;

      errno = 0;
      v = strtol (argv[0], &tail, 0);
      if (errno || (tail && *tail)
          || ! (v == DIGEST_ALGO_MD5
                || v == DIGEST_ALGO_SHA1
                || v == DIGEST_ALGO_RMD160
                || v == DIGEST_ALGO_SHA256
                || v == DIGEST_ALGO_SHA384
                || v == DIGEST_ALGO_SHA512
                || v == DIGEST_ALGO_SHA224))
        log_fatal ("Invalid or unsupported value.  Usage: %s %s\n",
                   option, usage);

      si->hash = v;
    }

  return 1;
}

static int
sk_esk_salt (const char *option, int argc, char *argv[], void *cookie)
{
  struct sk_esk_info *si = cookie;
  char *usage = "16-HEX-CHARACTERS";
  char *p = argv[0];

  if (argc == 0)
    log_fatal ("Usage: %s %s\n", option, usage);

  if (si->salt_set)
    log_fatal ("%s given multiple times.", option);

  if (p[0] == '0' && p[1] == 'x')
    p += 2;

  if (strlen (p) != 16)
    log_fatal ("%s: Salt must be exactly 16 hexadecimal characters (have: %zd)\n",
               option, strlen (p));

  if (hex2bin (p, si->salt, sizeof (si->salt)) == -1)
    log_fatal ("%s: Salt must only contain hexadecimal characters\n",
               option);

  si->salt_set = 1;

  return 1;
}

static int
sk_esk_iterations (const char *option, int argc, char *argv[], void *cookie)
{
  struct sk_esk_info *si = cookie;
  char *usage = "ITERATION-COUNT";
  char *tail;
  int v;

  if (argc == 0)
    log_fatal ("Usage: %s %s\n", option, usage);

  errno = 0;
  v = strtol (argv[0], &tail, 0);
  if (errno || (tail && *tail) || v < 0)
    log_fatal ("%s: Non-negative integer expected.\n", option);

  si->iterations = v;

  return 1;
}

static int
sk_esk_session_key (const char *option, int argc, char *argv[], void *cookie)
{
  struct sk_esk_info *si = cookie;
  char *usage = "HEX-CHARACTERS|auto|none";
  char *p = argv[0];
  struct session_key sk;

  if (argc == 0)
    log_fatal ("Usage: %s %s\n", option, usage);

  if (si->session_key || si->s2k_is_session_key
      || si->new_session_key)
    log_fatal ("%s given multiple times.", option);

  if (strcasecmp (p, "none") == 0)
    {
      si->s2k_is_session_key = 1;
      return 1;
    }
  if (strcasecmp (p, "new") == 0)
    {
      si->new_session_key = 1;
      return 1;
    }
  if (strcasecmp (p, "auto") == 0)
    return 1;

  sk = parse_session_key (option, p, 0);

  if (si->session_key)
    log_fatal ("%s given multiple times.", option);

  if (sk.algo)
    si->sed_cipher = sk.algo;

  si->session_key_len = sk.keylen;
  si->session_key = sk.key;

  return 1;
}

static int
sk_esk_password (const char *option, int argc, char *argv[], void *cookie)
{
  struct sk_esk_info *si = cookie;
  char *usage = "PASSWORD";

  if (argc == 0)
    log_fatal ("Usage: --sk-esk %s\n", usage);

  if (si->password)
    log_fatal ("%s given multiple times.", option);

  si->password = xstrdup (argv[0]);

  return 1;
}

static struct option sk_esk_options[] = {
  { "--cipher", sk_esk_cipher,
    "The encryption algorithm for encrypting the session key.  "
    "One of IDEA, 3DES, CAST5, BLOWFISH, AES (default), AES192, "
    "AES256, TWOFISH, CAMELLIA128, CAMELLIA192, or CAMELLIA256." },
  { "--sed-cipher", sk_esk_cipher,
    "The encryption algorithm for encrypting the SED packet.  "
    "One of IDEA, 3DES, CAST5, BLOWFISH, AES, AES192, "
    "AES256 (default), TWOFISH, CAMELLIA128, CAMELLIA192, or CAMELLIA256." },
  { "--mode", sk_esk_mode,
    "The S2K mode.  Either one of the strings \"simple\", \"salted\" "
    "or \"iterated\" or an integer." },
  { "--hash", sk_esk_hash_algorithm,
    "The hash algorithm to used to derive the key.  One of "
    "MD5, SHA1 (default), RMD160, SHA256, SHA384, SHA512, or SHA224." },
  { "--salt", sk_esk_salt,
    "The S2K salt encoded as 16 hexadecimal characters.  One needed "
    "if the S2K function is in salted or iterated mode." },
  { "--iterations", sk_esk_iterations,
    "The iteration count.  If not provided, a reasonable value is chosen.  "
    "Note: due to the encoding scheme, not every value is valid.  For "
    "convenience, the provided value will be rounded appropriately.  "
    "Only needed if the S2K function is in iterated mode." },
  { "--session-key", sk_esk_session_key,
    "The session key to be encrypted by the S2K function as a hexadecimal "
    "string.  If this is \"new\", then a new session key is generated."
    "If this is \"auto\", then either the last session key is "
    "used, if the was none, one is generated.  If this is \"none\", then "
    "the session key is the result of applying the S2K algorithms to the "
    "password.  The session key may be prefaced with an integer and a colon "
    "to indicate the cipher to use for the SED packet (making --sed-cipher "
    "unnecessary and allowing the direct use of the result of "
    "\"" GPG_NAME " --show-session-key\")." },
  { "", sk_esk_password, "The password." },
  { NULL, NULL,
    "Example:\n\n"
    "  $ gpgcompose --sk-esk foobar --encrypted \\\n"
    "  --literal --value foo | " GPG_NAME " --list-packets" }
};

static int
sk_esk (const char *option, int argc, char *argv[], void *cookie)
{
  iobuf_t out = cookie;
  gpg_error_t err;
  int processed;
  struct sk_esk_info si;
  DEK sesdek;
  DEK s2kdek;
  PKT_symkey_enc *ske;
  PACKET pkt;

  memset (&si, 0, sizeof (si));

  processed = process_options (option,
                               major_options,
                               sk_esk_options, &si,
                               global_options, NULL,
                               argc, argv);

  if (! si.password)
    log_fatal ("%s: missing password.  Usage: %s PASSWORD", option, option);

  /* Fill in defaults, if appropriate.  */
  if (! si.cipher)
    si.cipher = CIPHER_ALGO_AES;

  if (! si.sed_cipher)
    si.sed_cipher = CIPHER_ALGO_AES256;

  if (! si.hash)
    si.hash = DIGEST_ALGO_SHA1;

  if (! si.mode_set)
    /* Salted and iterated.  */
    si.mode = 3;

  if (si.mode != 0 && ! si.salt_set)
    /* Generate a salt.  */
    gcry_randomize (si.salt, 8, GCRY_STRONG_RANDOM);

  if (si.mode == 0)
    {
      if (si.iterations)
        log_info ("%s: --iterations provided, but not used for mode=0\n",
                  option);
      si.iterations = 0;
    }
  else if (! si.iterations)
    si.iterations = 10000;

  memset (&sesdek, 0, sizeof (sesdek));
  /* The session key is used to encrypt the SED packet.  */
  sesdek.algo = si.sed_cipher;
  if (si.session_key)
    /* Copy the unencrypted session key into SESDEK.  */
    {
      sesdek.keylen = openpgp_cipher_get_algo_keylen (sesdek.algo);
      if (sesdek.keylen != si.session_key_len)
        log_fatal ("%s: Cipher algorithm requires a %d byte session key, but provided session key is %d bytes.",
                   option, sesdek.keylen, si.session_key_len);

      log_assert (sesdek.keylen <= sizeof (sesdek.key));
      memcpy (sesdek.key, si.session_key, sesdek.keylen);
    }
  else if (! si.s2k_is_session_key || si.new_session_key)
    /* We need a session key, but one wasn't provided.  Generate it.  */
    make_session_key (&sesdek);

  /* The encrypted session key needs 1 + SESDEK.KEYLEN bytes of
     space.  */
  ske = xmalloc_clear (sizeof (*ske) + sesdek.keylen);

  ske->version = 4;
  ske->cipher_algo = si.cipher;

  ske->s2k.mode = si.mode;
  ske->s2k.hash_algo = si.hash;
  log_assert (sizeof (si.salt) == sizeof (ske->s2k.salt));
  memcpy (ske->s2k.salt, si.salt, sizeof (ske->s2k.salt));
  if (! si.s2k_is_session_key)
    /* 0 means get the default.  */
    ske->s2k.count = encode_s2k_iterations (si.iterations);


  /* Derive the symmetric key that is either the session key or the
     key used to encrypt the session key.  */
  memset (&s2kdek, 0, sizeof (s2kdek));

  s2kdek.algo = si.cipher;
  s2kdek.keylen = openpgp_cipher_get_algo_keylen (s2kdek.algo);

  err = gcry_kdf_derive (si.password, strlen (si.password),
                         ske->s2k.mode == 3 ? GCRY_KDF_ITERSALTED_S2K
                         : ske->s2k.mode == 1 ? GCRY_KDF_SALTED_S2K
                         : GCRY_KDF_SIMPLE_S2K,
                         ske->s2k.hash_algo, ske->s2k.salt, 8,
                         S2K_DECODE_COUNT (ske->s2k.count),
                         /* The size of the desired key and its
                            buffer.  */
                         s2kdek.keylen, s2kdek.key);
  if (err)
    log_fatal ("gcry_kdf_derive failed: %s", gpg_strerror (err));


  if (si.s2k_is_session_key)
    {
      ske->seskeylen = 0;
      session_key = s2kdek;
    }
  else
    /* Encrypt the session key using the s2k specifier.  */
    {
      DEK *sesdekp = &sesdek;

      /* Now encrypt the session key (or rather, the algorithm used to
         encrypt the SED plus the session key) using ENCKEY.  */
      ske->seskeylen = 1 + sesdek.keylen;
      encrypt_seskey (&s2kdek, &sesdekp, ske->seskey);

      /* Save the session key for later.  */
      session_key = sesdek;
    }

  pkt.pkttype = PKT_SYMKEY_ENC;
  pkt.pkt.symkey_enc = ske;

  err = build_packet (out, &pkt);
  if (err)
    log_fatal ("Serializing sym-key encrypted packet: %s\n",
               gpg_strerror (err));

  debug ("Wrote sym-key encrypted packet:\n");
  dump_component (&pkt);

  xfree (si.session_key);
  xfree (si.password);
  xfree (ske);

  return processed;
}

struct pk_esk_info
{
  int session_key_set;

  int new_session_key;

  int sed_cipher;
  int session_key_len;
  char *session_key;

  int throw_keyid;

  char *keyid;
};

static int
pk_esk_session_key (const char *option, int argc, char *argv[], void *cookie)
{
  struct pk_esk_info *pi = cookie;
  char *usage = "HEX-CHARACTERS|auto|none";
  char *p = argv[0];
  struct session_key sk;

  if (argc == 0)
    log_fatal ("Usage: %s %s\n", option, usage);

  if (pi->session_key_set)
    log_fatal ("%s given multiple times.", option);
  pi->session_key_set = 1;

  if (strcasecmp (p, "new") == 0)
    {
      pi->new_session_key = 1;
      return 1;
    }

  if (strcasecmp (p, "auto") == 0)
    return 1;

  sk = parse_session_key (option, p, 0);

  if (pi->session_key)
    log_fatal ("%s given multiple times.", option);

  if (sk.algo)
    pi->sed_cipher = sk.algo;

  pi->session_key_len = sk.keylen;
  pi->session_key = sk.key;

  return 1;
}

static int
pk_esk_throw_keyid (const char *option, int argc, char *argv[], void *cookie)
{
  struct pk_esk_info *pi = cookie;

  (void) option;
  (void) argc;
  (void) argv;

  pi->throw_keyid = 1;

  return 0;
}

static int
pk_esk_keyid (const char *option, int argc, char *argv[], void *cookie)
{
  struct pk_esk_info *pi = cookie;
  char *usage = "KEYID";

  if (argc == 0)
    log_fatal ("Usage: %s %s\n", option, usage);

  if (pi->keyid)
    log_fatal ("Multiple key ids given, but only one is allowed.");

  pi->keyid = xstrdup (argv[0]);

  return 1;
}

static struct option pk_esk_options[] = {
  { "--session-key", pk_esk_session_key,
    "The session key to be encrypted by the S2K function as a hexadecimal "
    "string.  If this is not given or is \"auto\", then the current "
    "session key is used.  If there is no session key or this is \"new\", "
    "then a new session key is generated.  The session key may be "
    "prefaced with an integer and a colon to indicate the cipher to use "
    "for the SED packet (making --sed-cipher unnecessary and allowing the "
    "direct use of the result of \"" GPG_NAME " --show-session-key\")." },
  { "--throw-keyid", pk_esk_throw_keyid,
    "Throw the keyid." },
  { "", pk_esk_keyid, "The key id." },
  { NULL, NULL,
    "Example:\n\n"
    "  $ gpgcompose --pk-esk $KEYID --encrypted --literal --value foo \\\n"
    "  | " GPG_NAME " --list-packets"}
};

static int
pk_esk (const char *option, int argc, char *argv[], void *cookie)
{
  iobuf_t out = cookie;
  gpg_error_t err;
  int processed;
  struct pk_esk_info pi;
  PKT_public_key pk;

  memset (&pi, 0, sizeof (pi));

  processed = process_options (option,
                               major_options,
                               pk_esk_options, &pi,
                               global_options, NULL,
                               argc, argv);

  if (! pi.keyid)
    log_fatal ("%s: missing keyid.  Usage: %s KEYID", option, option);

  memset (&pk, 0, sizeof (pk));
  pk.req_usage = PUBKEY_USAGE_ENC;
  err = get_pubkey_byname (NULL, GET_PUBKEY_NO_AKL,
                           NULL, &pk, pi.keyid, NULL, NULL, 1);
  if (err)
    log_fatal ("%s: looking up key %s: %s\n",
               option, pi.keyid, gpg_strerror (err));

  if (pi.sed_cipher)
    /* Have a session key.  */
    {
      session_key.algo = pi.sed_cipher;
      session_key.keylen = pi.session_key_len;
      log_assert (session_key.keylen <= sizeof (session_key.key));
      memcpy (session_key.key, pi.session_key, session_key.keylen);
    }

  if (pi.new_session_key || ! session_key.algo)
    {
      if (! pi.new_session_key)
        /* Default to AES256.  */
        session_key.algo = CIPHER_ALGO_AES256;
      make_session_key (&session_key);
    }

  err = write_pubkey_enc (global_ctrl, &pk, pi.throw_keyid, &session_key, out);
  if (err)
    log_fatal ("%s: writing pk_esk packet for %s: %s\n",
               option, pi.keyid, gpg_strerror (err));

  debug ("Wrote pk_esk packet for %s\n", pi.keyid);

  xfree (pi.keyid);
  xfree (pi.session_key);

  return processed;
}

struct encinfo
{
  int saw_session_key;
};

static int
encrypted_session_key (const char *option, int argc, char *argv[], void *cookie)
{
  struct encinfo *ei = cookie;
  char *usage = "HEX-CHARACTERS|auto";
  char *p = argv[0];
  struct session_key sk;

  if (argc == 0)
    log_fatal ("Usage: %s %s\n", option, usage);

  if (ei->saw_session_key)
    log_fatal ("%s given multiple times.", option);
  ei->saw_session_key = 1;

  if (strcasecmp (p, "auto") == 0)
    return 1;

  sk = parse_session_key (option, p, 1);

  session_key.algo = sk.algo;
  log_assert (sk.keylen <= sizeof (session_key.key));
  memcpy (session_key.key, sk.key, sk.keylen);
  xfree (sk.key);

  return 1;
}

static struct option encrypted_options[] = {
  { "--session-key", encrypted_session_key,
    "The session key to be encrypted by the S2K function as a hexadecimal "
    "string.  If this is not given or is \"auto\", then the last session key "
    "is used.  If there was none, then an error is raised.  The session key "
    "must be prefaced with an integer and a colon to indicate the cipher "
    "to use (this is format used by \"" GPG_NAME " --show-session-key\")." },
  { NULL, NULL,
    "After creating the packet, this command clears the current "
    "session key.\n\n"
    "Example: nested encryption packets:\n\n"
    "  $ gpgcompose --sk-esk foo --encrypted-mdc \\\n"
    "  --sk-esk bar --encrypted-mdc \\\n"
    "  --literal --value 123 --encrypted-pop --encrypted-pop | " GPG_NAME" -d" }
};

static int
encrypted (const char *option, int argc, char *argv[], void *cookie)
{
  iobuf_t out = cookie;
  int processed;
  struct encinfo ei;
  PKT_encrypted e;
  cipher_filter_context_t *cfx;

  memset (&ei, 0, sizeof (ei));

  processed = process_options (option,
                               major_options,
                               encrypted_options, &ei,
                               global_options, NULL,
                               argc, argv);

  if (! session_key.algo)
    log_fatal ("%s: no session key configured\n"
               "  (use e.g. --sk-esk PASSWORD or --pk-esk KEYID).\n",
               option);

  memset (&e, 0, sizeof (e));
  /* We only need to set E->LEN, E->EXTRALEN (if E->LEN is not
     0), and E->NEW_CTB.  */
  e.len = 0;
  e.new_ctb = 1;

  /* Register the cipher filter. */

  cfx = xmalloc_clear (sizeof (*cfx));

  /* Copy the session key.  */
  cfx->dek = xmalloc (sizeof (*cfx->dek));
  *cfx->dek = session_key;

  if (do_debug)
    {
      char *buf;

      buf = xmalloc (2 * session_key.keylen + 1);
      debug ("session key: algo: %d; keylen: %d; key: %s\n",
             session_key.algo, session_key.keylen,
             bin2hex (session_key.key, session_key.keylen, buf));
      xfree (buf);
    }

  if (strcmp (option, "--encrypted-mdc") == 0)
    cfx->dek->use_mdc = 1;
  else if (strcmp (option, "--encrypted") == 0)
    cfx->dek->use_mdc = 0;
  else
    log_fatal ("%s: option not handled by this function!\n", option);

  cfx->datalen = 0;

  filter_push (out, cipher_filter_cfb, cfx, PKT_ENCRYPTED, cfx->datalen == 0);

  debug ("Wrote encrypted packet:\n");

  /* Clear the current session key.  */
  memset (&session_key, 0, sizeof (session_key));

  return processed;
}

static struct option encrypted_pop_options[] = {
  { NULL, NULL,
    "Example:\n\n"
    "  $ gpgcompose --sk-esk PASSWORD \\\n"
    "    --encrypted-mdc \\\n"
    "      --literal --value foo \\\n"
    "    --encrypted-pop | " GPG_NAME " --list-packets" }
};

static int
encrypted_pop (const char *option, int argc, char *argv[], void *cookie)
{
  iobuf_t out = cookie;
  int processed;

  processed = process_options (option,
                               major_options,
                               encrypted_pop_options,
                               NULL,
                               global_options, NULL,
                               argc, argv);
  /* We only support a single option, --help, which causes the program
   * to exit.  */
  log_assert (processed == 0);

  filter_pop (out, PKT_ENCRYPTED);

  debug ("Popped encryption container.\n");

  return processed;
}

struct data
{
  int file;
  union
  {
    char *data;
    char *filename;
  };
  struct data *next;
};

/* This must be the first member of the struct to be able to use
   add_value!  */
struct datahead
{
  struct data *head;
  struct data **last_next;
};

static int
add_value (const char *option, int argc, char *argv[], void *cookie)
{
  struct datahead *dh = cookie;
  struct data *d = xmalloc_clear (sizeof (struct data));

  d->file = strcmp ("--file", option) == 0;
  if (! d->file)
    log_assert (strcmp ("--value", option) == 0);

  if (argc == 0)
    {
      if (d->file)
        log_fatal ("Usage: %s FILENAME\n", option);
      else
        log_fatal ("Usage: %s STRING\n", option);
    }

  if (! dh->last_next)
    /* First time through.  Initialize DH->LAST_NEXT.  */
    {
      log_assert (! dh->head);
      dh->last_next = &dh->head;
    }

  if (d->file)
    d->filename = argv[0];
  else
    d->data = argv[0];

  /* Append it.  */
  *dh->last_next = d;
  dh->last_next = &d->next;

  return 1;
}

struct litinfo
{
  /* This must be the first element for add_value to work!  */
  struct datahead data;

  int timestamp_set;
  u32 timestamp;
  char mode;
  int partial_body_length_encoding;
  char *name;
};

static int
literal_timestamp (const char *option, int argc, char *argv[], void *cookie)
{
  struct litinfo *li = cookie;

  char *tail = NULL;

  if (argc == 0)
    log_fatal ("Usage: %s TIMESTAMP\n", option);

  errno = 0;
  li->timestamp = parse_timestamp (argv[0], &tail);
  if (errno || (tail && *tail))
    log_fatal ("Invalid value passed to %s (%s)\n", option, argv[0]);
  li->timestamp_set = 1;

  return 1;
}

static int
literal_mode (const char *option, int argc, char *argv[], void *cookie)
{
  struct litinfo *li = cookie;

  if (argc == 0
      || ! (strcmp (argv[0], "b") == 0
            || strcmp (argv[0], "t") == 0
            || strcmp (argv[0], "u") == 0))
    log_fatal ("Usage: %s [btu]\n", option);

  li->mode = argv[0][0];

  return 1;
}

static int
literal_partial_body_length (const char *option, int argc, char *argv[],
                             void *cookie)
{
  struct litinfo *li = cookie;
  char *tail;
  int v;
  int range[2] = {0, 1};

  if (argc <= 1)
    log_fatal ("Usage: %s [0|1]\n", option);

  errno = 0;
  v = strtol (argv[0], &tail, 0);
  if (errno || (tail && *tail) || !(range[0] <= v && v <= range[1]))
    log_fatal ("Invalid value passed to %s (%s).  Expected %d-%d\n",
               option, argv[0], range[0], range[1]);

  li->partial_body_length_encoding = v;

  return 1;
}

static int
literal_name (const char *option, int argc, char *argv[], void *cookie)
{
  struct litinfo *li = cookie;

  if (argc <= 0)
    log_fatal ("Usage: %s NAME\n", option);

  if (strlen (argv[0]) > 255)
    log_fatal ("%s: name is too long (%zd > 255 characters).\n",
               option, strlen (argv[0]));

  li->name = argv[0];

  return 1;
}

static struct option literal_options[] = {
  { "--value", add_value,
    "A string to store in the literal packet." },
  { "--file", add_value,
    "A file to copy into the literal packet." },
  { "--timestamp", literal_timestamp,
    "The literal packet's time stamp.  This defaults to the current time." },
  { "--mode", literal_mode,
    "The content's mode (normally 'b' (default), 't' or 'u')." },
  { "--partial-body-length", literal_partial_body_length,
    "Force partial body length encoding." },
  { "--name", literal_name,
    "The literal's name." },
  { NULL, NULL,
    "Example:\n\n"
    "  $ gpgcompose --literal --value foobar | " GPG_NAME " -d"}
};

static int
literal (const char *option, int argc, char *argv[], void *cookie)
{
  iobuf_t out = cookie;
  gpg_error_t err;
  int processed;
  struct litinfo li;
  PKT_plaintext *pt;
  PACKET pkt;
  struct data *data;

  memset (&li, 0, sizeof (li));

  processed = process_options (option,
                               major_options,
                               literal_options, &li,
                               global_options, NULL,
                               argc, argv);

  if (! li.data.head)
    log_fatal ("%s: no data provided (use --value or --file)", option);

  pt = xmalloc_clear (sizeof (*pt) + (li.name ? strlen (li.name) : 0));
  pt->new_ctb = 1;

  if (li.timestamp_set)
    pt->timestamp = li.timestamp;
  else
    /* Default to the current time.  */
    pt->timestamp = make_timestamp ();

  pt->mode = li.mode;
  if (! pt->mode)
    /* Default to binary.  */
    pt->mode = 'b';

  if (li.name)
    {
      strcpy (pt->name, li.name);
      pt->namelen = strlen (pt->name);
    }

  pkt.pkttype = PKT_PLAINTEXT;
  pkt.pkt.plaintext = pt;

  if (! li.partial_body_length_encoding)
    /* Compute the amount of data.  */
    {
      pt->len = 0;
      for (data = li.data.head; data; data = data->next)
        {
          if (data->file)
            {
              iobuf_t in;
              int overflow;
              off_t off;

              in = iobuf_open (data->filename);
              if (! in)
                /* An error opening the file.  We do error handling
                   below so just break here.  */
                {
                  pt->len = 0;
                  break;
                }

              off = iobuf_get_filelength (in, &overflow);
              iobuf_close (in);

              if (overflow || off == 0)
                /* Length is unknown or there was an error
                   (unfortunately, iobuf_get_filelength doesn't
                   distinguish between 0 length files and an error!).
                   Fall back to partial body mode.  */
                {
                  pt->len = 0;
                  break;
                }

              pt->len += off;
            }
          else
            pt->len += strlen (data->data);
        }
    }

  err = build_packet (out, &pkt);
  if (err)
    log_fatal ("Serializing literal packet: %s\n", gpg_strerror (err));

  /* Write out the data.  */
  for (data = li.data.head; data; data = data->next)
    {
      if (data->file)
        {
          iobuf_t in;
          errno = 0;
          in = iobuf_open (data->filename);
          if (! in)
            log_fatal ("Opening '%s': %s\n",
                       data->filename,
                       errno ? strerror (errno): "unknown error");

          iobuf_copy (out, in);
          if (iobuf_error (in))
            log_fatal ("Reading from %s: %s\n",
                       data->filename,
                       gpg_strerror (iobuf_error (in)));
          if (iobuf_error (out))
            log_fatal ("Writing literal data from %s: %s\n",
                       data->filename,
                       gpg_strerror (iobuf_error (out)));

          iobuf_close (in);
        }
      else
        {
          err = iobuf_write (out, data->data, strlen (data->data));
          if (err)
            log_fatal ("Writing literal data: %s\n", gpg_strerror (err));
        }
    }

  if (! pt->len)
    {
      /* Disable partial body length mode.  */
      log_assert (pt->new_ctb == 1);
      iobuf_set_partial_body_length_mode (out, 0);
    }

  debug ("Wrote literal packet:\n");
  dump_component (&pkt);

  while (li.data.head)
    {
      data = li.data.head->next;
      xfree (li.data.head);
      li.data.head = data;
    }
  xfree (pt);

  return processed;
}

static int
copy_file (const char *option, int argc, char *argv[], void *cookie)
{
  char **filep = cookie;

  if (argc == 0)
    log_fatal ("Usage: %s FILENAME\n", option);

  *filep = argv[0];

  return 1;
}

static struct option copy_options[] = {
  { "", copy_file, "Copy the specified file to stdout." },
  { NULL, NULL,
    "Example:\n\n"
    "  $ gpgcompose --copy /etc/hostname\n\n"
    "This is particularly useful when combined with gpgsplit." }
};

static int
copy (const char *option, int argc, char *argv[], void *cookie)
{
  iobuf_t out = cookie;
  char *file = NULL;
  iobuf_t in;

  int processed;

  processed = process_options (option,
                               major_options,
                               copy_options, &file,
                               global_options, NULL,
                               argc, argv);
  if (! file)
    log_fatal ("Usage: %s FILE\n", option);

  errno = 0;
  in = iobuf_open (file);
  if (! in)
    log_fatal ("Error opening %s: %s.\n",
               file, errno ? strerror (errno): "unknown error");

  iobuf_copy (out, in);
  if (iobuf_error (out))
    log_fatal ("Copying data to destination: %s\n",
               gpg_strerror (iobuf_error (out)));
  if (iobuf_error (in))
    log_fatal ("Reading data from %s: %s\n",
               argv[0], gpg_strerror (iobuf_error (in)));

  iobuf_close (in);

  return processed;
}

int
main (int argc, char *argv[])
{
  const char *filename = "-";
  iobuf_t out;
  int preprocessed = 1;
  int processed;
  ctrl_t ctrl;

  opt.ignore_time_conflict = 1;
  /* Allow notations in the IETF space, for instance.  */
  opt.expert = 1;

  global_ctrl = ctrl = xcalloc (1, sizeof *ctrl);

  keydb_add_resource ("pubring" EXTSEP_S GPGEXT_GPG,
                      KEYDB_RESOURCE_FLAG_DEFAULT);

  if (argc == 1)
    /* Nothing to do.  */
    return 0;

  if (strcmp (argv[1], "--output") == 0
      || strcmp (argv[1], "-o") == 0)
    {
      filename = argv[2];
      log_info ("Writing to %s\n", filename);
      preprocessed += 2;
    }

  out = iobuf_create (filename, 0);
  if (! out)
    log_fatal ("Failed to open stdout for writing\n");

  processed = process_options (NULL, NULL,
                               major_options, out,
                               global_options, NULL,
                               argc - preprocessed, &argv[preprocessed]);
  if (processed != argc - preprocessed)
    log_fatal ("Didn't process %d options.\n", argc - preprocessed - processed);

  iobuf_close (out);

  return 0;
}

/* Stubs duplicated from gpg.c.  */

int g10_errors_seen = 0;

/* Note: This function is used by signal handlers!. */
static void
emergency_cleanup (void)
{
  gcry_control (GCRYCTL_TERM_SECMEM );
}

void
g10_exit( int rc )
{
  gcry_control (GCRYCTL_UPDATE_RANDOM_SEED_FILE);

  emergency_cleanup ();

  rc = rc? rc : log_get_errorcount(0)? 2 : g10_errors_seen? 1 : 0;
  exit (rc);
}

void
keyedit_menu (ctrl_t ctrl, const char *username, strlist_t locusr,
	      strlist_t commands, int quiet, int seckey_check)
{
  (void) ctrl;
  (void) username;
  (void) locusr;
  (void) commands;
  (void) quiet;
  (void) seckey_check;
}

void
show_basic_key_info (ctrl_t ctrl, KBNODE keyblock, int made_from_sec)
{
  (void)ctrl;
  (void)keyblock;
  (void)made_from_sec;
}

int
keyedit_print_one_sig (ctrl_t ctrl, estream_t fp,
                       int rc, kbnode_t keyblock, kbnode_t node,
		       int *inv_sigs, int *no_key, int *oth_err,
		       int is_selfsig, int print_without_key, int extended)
{
  (void) ctrl;
  (void) fp;
  (void) rc;
  (void) keyblock;
  (void) node;
  (void) inv_sigs;
  (void) no_key;
  (void) oth_err;
  (void) is_selfsig;
  (void) print_without_key;
  (void) extended;
  return 0;
}
