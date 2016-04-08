/* private-keys.c - Parser and writer for the extended private key format.
 *	Copyright (C) 2016 g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <assert.h>
#include <gcrypt.h>
#include <gpg-error.h>
#include <string.h>

#include "private-keys.h"
#include "mischelp.h"
#include "strlist.h"
#include "util.h"

struct private_key_container
{
  struct private_key_entry *first;
  struct private_key_entry *last;
};


struct private_key_entry
{
  struct private_key_entry *prev;
  struct private_key_entry *next;

  /* The name.  Comments and blank lines have NAME set to NULL.  */
  char *name;

  /* The value as stored in the file.  We store it when when we parse
     a file so that we can reproduce it.  */
  strlist_t raw_value;

  /* The decoded value.  */
  char *value;
};



/* Allocation and deallocation.  */

/* Allocate a private key container structure.  */
pkc_t
pkc_new (void)
{
  return xtrycalloc (1, sizeof (struct private_key_container));
}


static void
pke_release (pke_t entry)
{
  if (entry == NULL)
    return;

  xfree (entry->name);
  if (entry->value)
    wipememory (entry->value, strlen (entry->value));
  xfree (entry->value);
  free_strlist_wipe (entry->raw_value);
  xfree (entry);
}


/* Release a private key container structure.  */
void
pkc_release (pkc_t pk)
{
  pke_t e, next;

  if (pk == NULL)
    return;

  for (e = pk->first; e; e = next)
    {
      next = e->next;
      pke_release (e);
    }

  xfree (pk);
}



/* Dealing with names and values.  */

/* Check whether the given name is valid.  Valid names start with a
   letter, end with a colon, and contain only alphanumeric characters
   and the hyphen.  */
static int
valid_name (const char *name)
{
  size_t i, len = strlen (name);

  if (! alphap (name) || len == 0 || name[len - 1] != ':')
    return 0;

  for (i = 1; i < len - 1; i++)
    if (! alnump (&name[i]) && name[i] != '-')
      return 0;

  return 1;
}


/* Makes sure that ENTRY has a RAW_VALUE.  */
static gpg_error_t
assert_raw_value (pke_t entry)
{
  gpg_error_t err = 0;
  size_t len, offset;
#define LINELEN	70
  char buf[LINELEN+3];

  if (entry->raw_value)
    return 0;

  len = strlen (entry->value);
  offset = 0;
  while (len)
    {
      size_t amount, linelen = LINELEN;

      /* On the first line we need to subtract space for the name.  */
      if (entry->raw_value == NULL && strlen (entry->name) < linelen)
	linelen -= strlen (entry->name);

      /* See if the rest of the value fits in this line.  */
      if (len <= linelen)
	amount = len;
      else
	{
	  size_t i;

	  /* Find a suitable space to break on.  */
	  for (i = linelen - 1; linelen - i < 30 && linelen - i > offset; i--)
	    if (ascii_isspace (entry->value[i]))
	      break;

	  if (ascii_isspace (entry->value[i]))
	    {
	      /* Found one.  */
	      amount = i;
	    }
	  else
	    {
	      /* Just induce a hard break.  */
	      amount = linelen;
	    }
	}

      snprintf (buf, sizeof buf, " %.*s\n", (int) amount,
		&entry->value[offset]);
      if (append_to_strlist_try (&entry->raw_value, buf) == NULL)
	{
	  err = gpg_error_from_syserror ();
	  goto leave;
	}

      offset += amount;
      len -= amount;
    }

 leave:
  if (err)
    {
      free_strlist_wipe (entry->raw_value);
      entry->raw_value = NULL;
    }

  return err;
#undef LINELEN
}


/* Computes the length of the value encoded as continuation.  If
   *SWALLOW_WS is set, all whitespace at the beginning of S is
   swallowed.  If START is given, a pointer to the beginning of the
   value is stored there.  */
static size_t
continuation_length (const char *s, int *swallow_ws, const char **start)
{
  size_t len;

  if (*swallow_ws)
    {
      /* The previous line was a blank line and we inserted a newline.
	 Swallow all whitespace at the beginning of this line.  */
      while (ascii_isspace (*s))
	s++;
    }
  else
    {
      /* Iff a continuation starts with more than one space, it
	 encodes a space.  */
      if (ascii_isspace (*s))
	s++;
    }

  /* Strip whitespace at the end.  */
  len = strlen (s);
  while (len > 0 && ascii_isspace (s[len-1]))
    len--;

  if (len == 0)
    {
      /* Blank lines encode newlines.  */
      len = 1;
      s = "\n";
      *swallow_ws = 1;
    }
  else
    *swallow_ws = 0;

  if (start)
    *start = s;

  return len;
}


/* Makes sure that ENTRY has a VALUE.  */
static gpg_error_t
assert_value (pke_t entry)
{
  size_t len;
  int swallow_ws;
  strlist_t s;
  char *p;

  if (entry->value)
    return 0;

  len = 0;
  swallow_ws = 0;
  for (s = entry->raw_value; s; s = s->next)
    len += continuation_length (s->d, &swallow_ws, NULL);

  /* Add one for the terminating zero.  */
  len += 1;

  entry->value = p = xtrymalloc (len);
  if (entry->value == NULL)
    return gpg_error_from_syserror ();

  swallow_ws = 0;
  for (s = entry->raw_value; s; s = s->next)
    {
      const char *start;
      size_t l = continuation_length (s->d, &swallow_ws, &start);

      memcpy (p, start, l);
      p += l;
    }

  *p++ = 0;
  assert (p - entry->value == len);

  return 0;
}


/* Get the name.  */
char *
pke_name (pke_t pke)
{
  return pke->name;
}


/* Get the value.  */
char *
pke_value (pke_t pke)
{
  if (assert_value (pke))
    return NULL;
  return pke->value;
}



/* Adding and modifying values.  */

/* Add (NAME, VALUE, RAW_VALUE) to PK.  NAME may be NULL for comments
   and blank lines.  At least one of VALUE and RAW_VALUE must be
   given.  If PRESERVE_ORDER is not given, entries with the same name
   are grouped.  NAME, VALUE and RAW_VALUE is consumed.  */
static gpg_error_t
_pkc_add (pkc_t pk, char *name, char *value, strlist_t raw_value,
	  int preserve_order)
{
  gpg_error_t err = 0;
  pke_t e;

  assert (value || raw_value);

  if (name && ! valid_name (name))
    {
      err = gpg_error (GPG_ERR_INV_NAME);
      goto leave;
    }

  if (name && strcasecmp (name, "Key:") == 0 && pkc_lookup (pk, "Key:"))
    {
      err = gpg_error (GPG_ERR_INV_NAME);
      goto leave;
    }

  e = xtrycalloc (1, sizeof *e);
  if (e == NULL)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  e->name = name;
  e->value = value;
  e->raw_value = raw_value;

  if (pk->first)
    {
      pke_t last;

      if (preserve_order)
	last = pk->last;
      else
	{
	  /* See if there is already an entry with NAME.  */
	  last = pkc_lookup (pk, name);

	  /* If so, find the last in that block.  */
	  if (last)
	    while (last->next)
	      {
		pke_t next = last->next;

		if (next->name && strcasecmp (next->name, name) == 0)
		  last = next;
		else
		  break;
	      }
	  /* Otherwise, just find the last entry.  */
	  else
	    last = pk->last;
	}

      if (last->next)
	{
	  e->prev = last;
	  e->next = last->next;
	  last->next = e;
	  e->next->prev = e;
	}
      else
	{
	  e->prev = last;
	  last->next = e;
	  pk->last = e;
	}
    }
  else
    pk->first = pk->last = e;

 leave:
  if (err)
    {
      xfree (name);
      if (value)
	wipememory (value, strlen (value));
      xfree (value);
      free_strlist_wipe (raw_value);
    }

  return err;
}


/* Add (NAME, VALUE) to PK.  If an entry with NAME already exists, it
   is not updated but the new entry is appended.  */
gpg_error_t
pkc_add (pkc_t pk, const char *name, const char *value)
{
  char *k, *v;

  k = xtrystrdup (name);
  if (k == NULL)
    return gpg_error_from_syserror ();

  v = xtrystrdup (value);
  if (v == NULL)
    {
      xfree (k);
      return gpg_error_from_syserror ();
    }

  return _pkc_add (pk, k, v, NULL, 0);
}


/* Add (NAME, VALUE) to PK.  If an entry with NAME already exists, it
   is updated with VALUE.  If multiple entries with NAME exist, the
   first entry is updated.  */
gpg_error_t
pkc_set (pkc_t pk, const char *name, const char *value)
{
  pke_t e;

  if (! valid_name (name))
    return GPG_ERR_INV_NAME;

  e = pkc_lookup (pk, name);
  if (e)
    {
      char *v;

      v = xtrystrdup (value);
      if (v == NULL)
	return gpg_error_from_syserror ();

      free_strlist_wipe (e->raw_value);
      e->raw_value = NULL;
      if (e->value)
	wipememory (e->value, strlen (e->value));
      xfree (e->value);
      e->value = v;

      return 0;
    }
  else
    return pkc_add (pk, name, value);
}


/* Delete the given entry from PK.  */
void
pkc_delete (pkc_t pk, pke_t entry)
{
  if (entry->prev)
    entry->prev->next = entry->next;
  else
    pk->first = entry->next;

  if (entry->next)
    entry->next->prev = entry->prev;
  else
    pk->last = entry->prev;

  pke_release (entry);
}



/* Lookup and iteration.  */

/* Get the first non-comment entry.  */
pke_t
pkc_first (pkc_t pk)
{
  pke_t entry;
  for (entry = pk->first; entry; entry = entry->next)
    if (entry->name)
      return entry;
  return NULL;
}


/* Get the first entry with the given name.  */
pke_t
pkc_lookup (pkc_t pk, const char *name)
{
  pke_t entry;
  for (entry = pk->first; entry; entry = entry->next)
    if (entry->name && strcasecmp (entry->name, name) == 0)
      return entry;
  return NULL;
}


/* Get the next non-comment entry.  */
pke_t
pke_next (pke_t entry)
{
  for (entry = entry->next; entry; entry = entry->next)
    if (entry->name)
      return entry;
  return NULL;
}


/* Get the next entry with the given name.  */
pke_t
pke_next_value (pke_t entry, const char *name)
{
  for (entry = entry->next; entry; entry = entry->next)
    if (entry->name && strcasecmp (entry->name, name) == 0)
      return entry;
  return NULL;
}



/* Private key handling.  */

/* Get the private key.  */
gpg_error_t
pkc_get_private_key (pkc_t pk, gcry_sexp_t *retsexp)
{
  gpg_error_t err;
  pke_t e;

  e = pkc_lookup (pk, "Key:");
  if (e == NULL)
    return gpg_error (GPG_ERR_MISSING_KEY);

  err = assert_value (e);
  if (err)
    return err;

  return gcry_sexp_sscan (retsexp, NULL, e->value, strlen (e->value));
}


/* Set the private key.  */
gpg_error_t
pkc_set_private_key (pkc_t pk, gcry_sexp_t sexp)
{
  gpg_error_t err;
  char *raw, *clean, *p;
  size_t len, i;

  len = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);

  raw = xtrymalloc (len);
  if (raw == NULL)
    return gpg_error_from_syserror ();

  clean = xtrymalloc (len);
  if (clean == NULL)
    {
      xfree (raw);
      return gpg_error_from_syserror ();
    }

  gcry_sexp_sprint (sexp, GCRYSEXP_FMT_ADVANCED, raw, len);

  /* Strip any whitespace at the end.  */
  i = strlen (raw) - 1;
  while (i && ascii_isspace (raw[i]))
    {
      raw[i] = 0;
      i--;
    }

  /* Replace any newlines with spaces, remove superfluous whitespace.  */
  len = strlen (raw);
  for (p = clean, i = 0; i < len; i++)
    {
      char c = raw[i];

      /* Collapse contiguous and superfluous spaces.  */
      if (ascii_isspace (c) && i > 0
	  && (ascii_isspace (raw[i-1]) || raw[i-1] == '(' || raw[i-1] == ')'))
	continue;

      if (c == '\n')
	c = ' ';

      *p++ = c;
    }
  *p = 0;

  err = pkc_set (pk, "Key:", clean);
  xfree (raw);
  xfree (clean);
  return err;
}



/* Parsing and serialization.  */

/* Parse STREAM and return a newly allocated private key container
   structure in RESULT.  If ERRLINEP is given, the line number the
   parser was last considering is stored there.  */
gpg_error_t
pkc_parse (pkc_t *result, int *errlinep, estream_t stream)
{
  gpg_error_t err = 0;
  gpgrt_ssize_t len;
  char *buf = NULL;
  size_t buf_len = 0;
  char *name = NULL;
  strlist_t raw_value = NULL;


  *result = pkc_new ();
  if (*result == NULL)
    return gpg_error_from_syserror ();

  if (errlinep)
    *errlinep = 0;
  while ((len = es_read_line (stream, &buf, &buf_len, NULL)))
    {
      char *p;
      if (errlinep)
	*errlinep += 1;

      /* Skip any whitespace.  */
      for (p = buf; *p && ascii_isspace (*p); p++)
	/* Do nothing.  */;

      if (name && (spacep (buf) || *p == 0))
	{
	  /* A continuation.  */
	  if (append_to_strlist_try (&raw_value, buf) == NULL)
	    {
	      err = gpg_error_from_syserror ();
	      goto leave;
	    }
	  continue;
	}

      /* No continuation.  Add the current entry if any.  */
      if (raw_value)
	{
	  err = _pkc_add (*result, name, NULL, raw_value, 1);
	  if (err)
	    goto leave;
	}

      /* And prepare for the next one.  */
      name = NULL;
      raw_value = NULL;

      if (*p != 0 && *p != '#')
	{
	  char *colon, *value, tmp;

	  colon = strchr (buf, ':');
	  if (colon == NULL)
	    {
	      err = gpg_error (GPG_ERR_INV_VALUE);
	      goto leave;
	    }

	  value = colon + 1;
	  tmp = *value;
	  *value = 0;
	  name = xstrdup (p);
	  *value = tmp;

	  if (name == NULL)
	    {
	      err = gpg_error_from_syserror ();
	      goto leave;
	    }

	  if (append_to_strlist (&raw_value, value) == NULL)
	    {
	      err = gpg_error_from_syserror ();
	      goto leave;
	    }
	  continue;
	}

      if (append_to_strlist (&raw_value, buf) == NULL)
	{
	  err = gpg_error_from_syserror ();
	  goto leave;
	}
    }

  /* Add the final entry.  */
  if (raw_value)
    err = _pkc_add (*result, name, NULL, raw_value, 1);

 leave:
  gpgrt_free (buf);
  if (err)
    {
      pkc_release (*result);
      *result = NULL;
    }

  return err;
}


/* Write a representation of PK to STREAM.  */
gpg_error_t
pkc_write (pkc_t pk, estream_t stream)
{
  gpg_error_t err;
  pke_t entry;
  strlist_t s;

  for (entry = pk->first; entry; entry = entry->next)
    {
      if (entry->name)
	es_fputs (entry->name, stream);

      err = assert_raw_value (entry);
      if (err)
	return err;

      for (s = entry->raw_value; s; s = s->next)
	es_fputs (s->d, stream);

      if (es_ferror (stream))
	return gpg_error_from_syserror ();
    }

  return 0;
}
