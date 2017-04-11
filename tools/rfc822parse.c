/* rfc822parse.c - Simple mail and MIME parser
 *	Copyright (C) 1999, 2000 Werner Koch, Duesseldorf
 *      Copyright (C) 2003, 2004 g10 Code GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <https://www.gnu.org/licenses/>.
 */


/* According to RFC822 binary zeroes are allowed at many places. We do
 * not handle this correct especially in the field parsing code.  It
 * should be easy to fix and the API provides a interfaces which
 * returns the length but in addition makes sure that returned strings
 * are always ended by a \0.
 *
 * Furthermore, the case of field names is changed and thus it is not
 * always a good idea to use these modified header
 * lines (e.g. signatures may break).
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <assert.h>

#include "rfc822parse.h"

enum token_type
  {
    tSPACE,
    tATOM,
    tQUOTED,
    tDOMAINLIT,
    tSPECIAL
  };

/* For now we directly use our TOKEN as the parse context */
typedef struct rfc822parse_field_context *TOKEN;
struct rfc822parse_field_context
{
  TOKEN next;
  enum token_type type;
  struct {
    unsigned int cont:1;
    unsigned int lowered:1;
  } flags;
  /*TOKEN owner_pantry; */
  char data[1];
};

struct hdr_line
{
  struct hdr_line *next;
  int cont;     /* This is a continuation of the previous line. */
  unsigned char line[1];
};

typedef struct hdr_line *HDR_LINE;


struct part
{
  struct part *right;     /* The next part. */
  struct part *down;      /* A contained part. */
  HDR_LINE hdr_lines;       /* Header lines os that part. */
  HDR_LINE *hdr_lines_tail; /* Helper for adding lines. */
  char *boundary;           /* Only used in the first part. */
};
typedef struct part *part_t;

struct rfc822parse_context
{
  rfc822parse_cb_t callback;
  void *callback_value;
  int callback_error;
  int in_body;
  int in_preamble;      /* Wether we are before the first boundary. */
  part_t parts;         /* The tree of parts. */
  part_t current_part;  /* Whom we are processing (points into parts). */
  const char *boundary; /* Current boundary. */
};

static HDR_LINE find_header (rfc822parse_t msg, const char *name,
			     int which, HDR_LINE * rprev);


static size_t
length_sans_trailing_ws (const unsigned char *line, size_t len)
{
  const unsigned char *p, *mark;
  size_t n;

  for (mark=NULL, p=line, n=0; n < len; n++, p++)
    {
      if (strchr (" \t\r\n", *p ))
        {
          if( !mark )
            mark = p;
        }
      else
        mark = NULL;
    }

  if (mark)
    return mark - line;
  return len;
}


static void
lowercase_string (unsigned char *string)
{
  for (; *string; string++)
    if (*string >= 'A' && *string <= 'Z')
      *string = *string - 'A' + 'a';
}

/* Transform a header name into a standard capitalized format; i.e
   "Content-Type".  Conversion stops at the colon.  As usual we don't
   use the localized versions of ctype.h.
 */
static void
capitalize_header_name (unsigned char *name)
{
  int first = 1;

  for (; *name && *name != ':'; name++)
    if (*name == '-')
      first = 1;
    else if (first)
      {
        if (*name >= 'a' && *name <= 'z')
          *name = *name - 'a' + 'A';
        first = 0;
      }
    else if (*name >= 'A' && *name <= 'Z')
      *name = *name - 'A' + 'a';
}

#ifndef HAVE_STPCPY
static char *
my_stpcpy (char *a,const char *b)
{
  while (*b)
    *a++ = *b++;
  *a = 0;

  return (char*)a;
}
#define stpcpy my_stpcpy
#endif


/* If a callback has been registerd, call it for the event of type
   EVENT. */
static int
do_callback (rfc822parse_t msg, rfc822parse_event_t event)
{
  int rc;

  if (!msg->callback || msg->callback_error)
    return 0;
  rc = msg->callback (msg->callback_value, event, msg);
  if (rc)
    msg->callback_error = rc;
  return rc;
}

static part_t
new_part (void)
{
  part_t part;

  part = calloc (1, sizeof *part);
  if (part)
    {
      part->hdr_lines_tail = &part->hdr_lines;
    }
  return part;
}


static void
release_part (part_t part)
{
  part_t tmp;
  HDR_LINE hdr, hdr2;

  for (; part; part = tmp)
    {
      tmp = part->right;
      if (part->down)
        release_part (part->down);
      for (hdr = part->hdr_lines; hdr; hdr = hdr2)
        {
          hdr2 = hdr->next;
          free (hdr);
        }
      free (part->boundary);
      free (part);
    }
}


static void
release_handle_data (rfc822parse_t msg)
{
  release_part (msg->parts);
  msg->parts = NULL;
  msg->current_part = NULL;
  msg->boundary = NULL;
}


/* Create a new parsing context for an entire rfc822 message and
   return it.  CB and CB_VALUE may be given to callback for certain
   events.  NULL is returned on error with errno set appropriately. */
rfc822parse_t
rfc822parse_open (rfc822parse_cb_t cb, void *cb_value)
{
  rfc822parse_t msg = calloc (1, sizeof *msg);
  if (msg)
    {
      msg->parts = msg->current_part = new_part ();
      if (!msg->parts)
        {
          free (msg);
          msg = NULL;
        }
      else
        {
          msg->callback = cb;
          msg->callback_value = cb_value;
          if (do_callback (msg, RFC822PARSE_OPEN))
            {
              release_handle_data (msg);
              free (msg);
              msg = NULL;
            }
        }
    }
  return msg;
}


void
rfc822parse_cancel (rfc822parse_t msg)
{
  if (msg)
    {
      do_callback (msg, RFC822PARSE_CANCEL);
      release_handle_data (msg);
      free (msg);
    }
}


void
rfc822parse_close (rfc822parse_t msg)
{
  if (msg)
    {
      do_callback (msg, RFC822PARSE_CLOSE);
      release_handle_data (msg);
      free (msg);
    }
}

static part_t
find_parent (part_t tree, part_t target)
{
  part_t part;

  for (part = tree->down; part; part = part->right)
    {
      if (part == target)
        return tree; /* Found. */
      if (part->down)
        {
          part_t tmp = find_parent (part, target);
          if (tmp)
            return tmp;
        }
    }
  return NULL;
}

static void
set_current_part_to_parent (rfc822parse_t msg)
{
  part_t parent;

  assert (msg->current_part);
  parent = find_parent (msg->parts, msg->current_part);
  if (!parent)
    return; /* Already at the top. */

#ifndef NDEBUG
  {
    part_t part;
    for (part = parent->down; part; part = part->right)
      if (part == msg->current_part)
        break;
    assert (part);
  }
#endif
  msg->current_part = parent;

  parent = find_parent (msg->parts, parent);
  msg->boundary = parent? parent->boundary: NULL;
}



/****************
 * We have read in all header lines and are about to receive the body
 * part.  The delimiter line has already been processed.
 *
 * FIXME: we's better return an error in case of memory failures.
 */
static int
transition_to_body (rfc822parse_t msg)
{
  rfc822parse_field_t ctx;
  int rc;

  rc = do_callback (msg, RFC822PARSE_T2BODY);
  if (!rc)
    {
      /* Store the boundary if we have multipart type. */
      ctx = rfc822parse_parse_field (msg, "Content-Type", -1);
      if (ctx)
        {
          const char *s;

          s = rfc822parse_query_media_type (ctx, NULL);
          if (s && !strcmp (s,"multipart"))
            {
              s = rfc822parse_query_parameter (ctx, "boundary", 0);
              if (s)
                {
                  assert (!msg->current_part->boundary);
                  msg->current_part->boundary = malloc (strlen (s) + 1);
                  if (msg->current_part->boundary)
                    {
                      part_t part;

                      strcpy (msg->current_part->boundary, s);
                      msg->boundary = msg->current_part->boundary;
                      part = new_part ();
                      if (!part)
                        {
                          int save_errno = errno;
                          rfc822parse_release_field (ctx);
                          errno = save_errno;
                          return -1;
                        }
                      rc = do_callback (msg, RFC822PARSE_LEVEL_DOWN);
                      assert (!msg->current_part->down);
                      msg->current_part->down = part;
                      msg->current_part = part;
                      msg->in_preamble = 1;
                    }
                }
            }
          rfc822parse_release_field (ctx);
        }
    }

  return rc;
}

/* We have just passed a MIME boundary and need to prepare for new part.
   headers. */
static int
transition_to_header (rfc822parse_t msg)
{
  part_t part;

  assert (msg->current_part);
  assert (!msg->current_part->right);

  part = new_part ();
  if (!part)
    return -1;

  msg->current_part->right = part;
  msg->current_part = part;
  return 0;
}


static int
insert_header (rfc822parse_t msg, const unsigned char *line, size_t length)
{
  HDR_LINE hdr;

  assert (msg->current_part);
  if (!length)
    {
      msg->in_body = 1;
      return transition_to_body (msg);
    }

  if (!msg->current_part->hdr_lines)
    do_callback (msg, RFC822PARSE_BEGIN_HEADER);

  length = length_sans_trailing_ws (line, length);
  hdr = malloc (sizeof (*hdr) + length);
  if (!hdr)
    return -1;
  hdr->next = NULL;
  hdr->cont = (*line == ' ' || *line == '\t');
  memcpy (hdr->line, line, length);
  hdr->line[length] = 0; /* Make it a string. */

  /* Transform a field name into canonical format. */
  if (!hdr->cont && strchr (line, ':'))
     capitalize_header_name (hdr->line);

  *msg->current_part->hdr_lines_tail = hdr;
  msg->current_part->hdr_lines_tail = &hdr->next;

  /* Lets help the caller to prevent mail loops and issue an event for
   * every Received header. */
  if (length >= 9 && !memcmp (line, "Received:", 9))
     do_callback (msg, RFC822PARSE_RCVD_SEEN);
  return 0;
}


/****************
 * Note: We handle the body transparent to allow binary zeroes in it.
 */
static int
insert_body (rfc822parse_t msg, const unsigned char *line, size_t length)
{
  int rc = 0;

  if (length > 2 && *line == '-' && line[1] == '-' && msg->boundary)
    {
      size_t blen = strlen (msg->boundary);

      if (length == blen + 2
          && !memcmp (line+2, msg->boundary, blen))
        {
          rc = do_callback (msg, RFC822PARSE_BOUNDARY);
          msg->in_body = 0;
          if (!rc && !msg->in_preamble)
            rc = transition_to_header (msg);
          msg->in_preamble = 0;
        }
      else if (length == blen + 4
          && line[length-2] =='-' && line[length-1] == '-'
          && !memcmp (line+2, msg->boundary, blen))
        {
          rc = do_callback (msg, RFC822PARSE_LAST_BOUNDARY);
          msg->boundary = NULL; /* No current boundary anymore. */
          set_current_part_to_parent (msg);

          /* Fixme: The next should actually be send right before the
             next boundary, so that we can mark the epilogue. */
          if (!rc)
            rc = do_callback (msg, RFC822PARSE_LEVEL_UP);
        }
    }
  if (msg->in_preamble && !rc)
    rc = do_callback (msg, RFC822PARSE_PREAMBLE);

  return rc;
}

/* Insert the next line into the parser. Return 0 on success or true
   on error with errno set appropriately. */
int
rfc822parse_insert (rfc822parse_t msg, const unsigned char *line, size_t length)
{
  return (msg->in_body
          ? insert_body (msg, line, length)
          : insert_header (msg, line, length));
}


/* Tell the parser that we have finished the message. */
int
rfc822parse_finish (rfc822parse_t msg)
{
  return do_callback (msg, RFC822PARSE_FINISH);
}



/****************
 * Get a copy of a header line. The line is returned as one long
 * string with LF to separate the continuation line. Caller must free
 * the return buffer.  WHICH may be used to enumerate over all lines.
 * Wildcards are allowed.  This function works on the current headers;
 * i.e. the regular mail headers or the MIME headers of the current
 * part.
 *
 * WHICH gives the mode:
 *  -1 := Take the last occurrence
 *   n := Take the n-th  one.
 *
 * Returns a newly allocated buffer or NULL on error.  errno is set in
 * case of a memory failure or set to 0 if the requested field is not
 * available.
 *
 * If VALUEOFF is not NULL it will receive the offset of the first non
 * space character in the value part of the line (i.e. after the first
 * colon).
 */
char *
rfc822parse_get_field (rfc822parse_t msg, const char *name, int which,
                       size_t *valueoff)
{
  HDR_LINE h, h2;
  char *buf, *p;
  size_t n;

  h = find_header (msg, name, which, NULL);
  if (!h)
    {
      errno = 0;
      return NULL; /* no such field */
    }

  n = strlen (h->line) + 1;
  for (h2 = h->next; h2 && h2->cont; h2 = h2->next)
    n += strlen (h2->line) + 1;

  buf = p = malloc (n);
  if (buf)
    {
      p = stpcpy (p, h->line);
      *p++ = '\n';
      for (h2 = h->next; h2 && h2->cont; h2 = h2->next)
        {
          p = stpcpy (p, h2->line);
          *p++ = '\n';
        }
      p[-1] = 0;
    }

  if (valueoff)
    {
      p = strchr (buf, ':');
      if (!p)
        *valueoff = 0; /* Oops: should never happen. */
      else
        {
          p++;
          while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
            p++;
          *valueoff = p - buf;
        }
    }

  return buf;
}


/****************
 * Enumerate all header.  Caller has to provide the address of a pointer
 * which has to be initialzed to NULL, the caller should then never change this
 * pointer until he has closed the enumeration by passing again the address
 * of the pointer but with msg set to NULL.
 * The function returns pointers to all the header lines or NULL when
 * all lines have been enumerated or no headers are available.
 */
const char *
rfc822parse_enum_header_lines (rfc822parse_t msg, void **context)
{
  HDR_LINE l;

  if (!msg) /* Close. */
    return NULL;

  if (*context == msg || !msg->current_part)
    return NULL;

  l = *context ? (HDR_LINE) *context : msg->current_part->hdr_lines;

  if (l)
    {
      *context = l->next ? (void *) (l->next) : (void *) msg;
      return l->line;
    }
  *context = msg; /* Mark end of list. */
  return NULL;
}



/****************
 * Find a header field.  If the Name does end in an asterisk this is meant
 * to be a wildcard.
 *
 *  which  -1 : Retrieve the last field
 *	   >0 : Retrieve the n-th field

 * RPREV may be used to return the predecessor of the returned field;
 * which may be NULL for the very first one. It has to be initialzed
 * to either NULL in which case the search start at the first header line,
 * or it may point to a headerline, where the search should start
 */
static HDR_LINE
find_header (rfc822parse_t msg, const char *name, int which, HDR_LINE *rprev)
{
  HDR_LINE hdr, prev = NULL, mark = NULL;
  unsigned char *p;
  size_t namelen, n;
  int found = 0;
  int glob = 0;

  if (!msg->current_part)
    return NULL;

  namelen = strlen (name);
  if (namelen && name[namelen - 1] == '*')
    {
      namelen--;
      glob = 1;
    }

  hdr = msg->current_part->hdr_lines;
  if (rprev && *rprev)
    {
      /* spool forward to the requested starting place.
       * we cannot simply set this as we have to return
       * the previous list element too */
      for (; hdr && hdr != *rprev; prev = hdr, hdr = hdr->next)
	;
    }

  for (; hdr; prev = hdr, hdr = hdr->next)
    {
      if (hdr->cont)
	continue;
      if (!(p = strchr (hdr->line, ':')))
	continue;		/* invalid header, just skip it. */
      n = p - hdr->line;
      if (!n)
	continue;		/* invalid name */
      if ((glob ? (namelen <= n) : (namelen == n))
	  && !memcmp (hdr->line, name, namelen))
	{
	  found++;
	  if (which == -1)
	    mark = hdr;
	  else if (found == which)
	    {
	      if (rprev)
		*rprev = prev;
	      return hdr;
	    }
	}
    }
  if (mark && rprev)
    *rprev = prev;
  return mark;
}



static const char *
skip_ws (const char *s)
{
  while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
    s++;
  return s;
}


static void
release_token_list (TOKEN t)
{
  while (t)
    {
      TOKEN t2 = t->next;
      /* fixme: If we have owner_pantry, put the token back to
       * this pantry so that it can be reused later */
      free (t);
      t = t2;
    }
}


static TOKEN
new_token (enum token_type type, const char *buf, size_t length)
{
  TOKEN t;

  /* fixme: look through our pantries to find a suitable
   * token for reuse */
  t = malloc (sizeof *t + length);
  if (t)
    {
      t->next = NULL;
      t->type = type;
      memset (&t->flags, 0, sizeof (t->flags));
      t->data[0] = 0;
      if (buf)
        {
          memcpy (t->data, buf, length);
          t->data[length] = 0;	/* Make sure it is a C string. */
        }
      else
        t->data[0] = 0;
    }
  return t;
}

static TOKEN
append_to_token (TOKEN old, const char *buf, size_t length)
{
  size_t n = strlen (old->data);
  TOKEN t;

  t = malloc (sizeof *t + n + length);
  if (t)
    {
      t->next = old->next;
      t->type = old->type;
      t->flags = old->flags;
      memcpy (t->data, old->data, n);
      memcpy (t->data + n, buf, length);
      t->data[n + length] = 0;
      old->next = NULL;
      release_token_list (old);
    }
  return t;
}



/*
   Parse a field into tokens as defined by rfc822.
 */
static TOKEN
parse_field (HDR_LINE hdr)
{
  static const char specials[] = "<>@.,;:\\[]\"()";
  static const char specials2[] = "<>@.,;:";
  static const char tspecials[] = "/?=<>@,;:\\[]\"()";
  static const char tspecials2[] = "/?=<>@.,;:";  /* FIXME: really
                                                     include '.'?*/
  static struct
  {
    const unsigned char *name;
    size_t namelen;
  } tspecial_header[] = {
    { "Content-Type", 12},
    { "Content-Transfer-Encoding", 25},
    { "Content-Disposition", 19},
    { NULL, 0}
  };
  const char *delimiters;
  const char *delimiters2;
  const unsigned char *line, *s, *s2;
  size_t n;
  int i, invalid = 0;
  TOKEN t, tok, *tok_tail;

  errno = 0;
  if (!hdr)
    return NULL;

  tok = NULL;
  tok_tail = &tok;

  line = hdr->line;
  if (!(s = strchr (line, ':')))
    return NULL; /* oops */

  n = s - line;
  if (!n)
    return NULL; /* oops: invalid name */

  delimiters = specials;
  delimiters2 = specials2;
  for (i = 0; tspecial_header[i].name; i++)
    {
      if (n == tspecial_header[i].namelen
	  && !memcmp (line, tspecial_header[i].name, n))
	{
	  delimiters = tspecials;
	  delimiters2 = tspecials2;
	  break;
	}
    }

  s++; /* Move over the colon. */
  for (;;)
    {
      while (!*s)
	{
	  if (!hdr->next || !hdr->next->cont)
            return tok; /* Ready.  */

          /* Next item is a header continuation line.  */
	  hdr = hdr->next;
	  s = hdr->line;
	}

      if (*s == '(')
	{
	  int level = 1;
	  int in_quote = 0;

	  invalid = 0;
	  for (s++;; s++)
	    {
	      while (!*s)
		{
		  if (!hdr->next || !hdr->next->cont)
		    goto oparen_out;
                  /* Next item is a header continuation line.  */
		  hdr = hdr->next;
		  s = hdr->line;
		}

	      if (in_quote)
		{
		  if (*s == '\"')
		    in_quote = 0;
		  else if (*s == '\\' && s[1])	/* what about continuation? */
		    s++;
		}
	      else if (*s == ')')
		{
		  if (!--level)
		    break;
		}
	      else if (*s == '(')
		level++;
	      else if (*s == '\"')
		in_quote = 1;
	    }
        oparen_out:
	  if (!*s)
	    ; /* Actually this is an error, but we don't care about it. */
	  else
	    s++;
	}
      else if (*s == '\"' || *s == '[')
	{
	  /* We do not check for non-allowed nesting of domainliterals */
	  int term = *s == '\"' ? '\"' : ']';
	  invalid = 0;
	  s++;
	  t = NULL;

	  for (;;)
	    {
	      for (s2 = s; *s2; s2++)
		{
		  if (*s2 == term)
		    break;
		  else if (*s2 == '\\' && s2[1]) /* what about continuation? */
		    s2++;
		}

	      t = (t
                   ? append_to_token (t, s, s2 - s)
                   : new_token (term == '\"'? tQUOTED : tDOMAINLIT, s, s2 - s));
              if (!t)
                goto failure;

	      if (*s2 || !hdr->next || !hdr->next->cont)
		break;
              /* Next item is a header continuation line.  */
	      hdr = hdr->next;
	      s = hdr->line;
	    }
	  *tok_tail = t;
	  tok_tail = &t->next;
	  s = s2;
	  if (*s)
	    s++; /* skip the delimiter */
	}
      else if ((s2 = strchr (delimiters2, *s)))
	{ /* Special characters which are not handled above. */
	  invalid = 0;
	  t = new_token (tSPECIAL, s, 1);
          if (!t)
            goto failure;
	  *tok_tail = t;
	  tok_tail = &t->next;
	  s++;
	}
      else if (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
	{
	  invalid = 0;
	  s = skip_ws (s + 1);
	}
      else if (*s > 0x20 && !(*s & 128))
	{ /* Atom. */
	  invalid = 0;
	  for (s2 = s + 1; *s2 > 0x20
	       && !(*s2 & 128) && !strchr (delimiters, *s2); s2++)
	    ;
	  t = new_token (tATOM, s, s2 - s);
          if (!t)
            goto failure;
	  *tok_tail = t;
	  tok_tail = &t->next;
	  s = s2;
	}
      else
	{ /* Invalid character. */
	  if (!invalid)
	    { /* For parsing we assume only one space. */
	      t = new_token (tSPACE, NULL, 0);
              if (!t)
                goto failure;
	      *tok_tail = t;
	      tok_tail = &t->next;
	      invalid = 1;
	    }
	  s++;
	}
    }
  /*NOTREACHED*/

 failure:
  {
    int save = errno;
    release_token_list (tok);
    errno = save;
  }
  return NULL;
}




/****************
 * Find and parse a header field.
 * WHICH indicates what to do if there are multiple instance of the same
 * field (like "Received"); the following value are defined:
 *  -1 := Take the last occurrence
 *   0 := Reserved
 *   n := Take the n-th one.
 * Returns a handle for further operations on the parse context of the field
 * or NULL if the field was not found.
 */
rfc822parse_field_t
rfc822parse_parse_field (rfc822parse_t msg, const char *name, int which)
{
  HDR_LINE hdr;

  if (!which)
    return NULL;

  hdr = find_header (msg, name, which, NULL);
  if (!hdr)
    return NULL;
  return parse_field (hdr);
}

void
rfc822parse_release_field (rfc822parse_field_t ctx)
{
  if (ctx)
    release_token_list (ctx);
}



/****************
 * Check whether T points to a parameter.
 * A parameter starts with a semicolon and it is assumed that t
 * points to exactly this one.
 */
static int
is_parameter (TOKEN t)
{
  t = t->next;
  if (!t || t->type != tATOM)
    return 0;
  t = t->next;
  if (!t || !(t->type == tSPECIAL && t->data[0] == '='))
    return 0;
  t = t->next;
  if (!t)
    return 1; /* We assume that an non existing value is an empty one. */
  return t->type == tQUOTED || t->type == tATOM;
}

/*
   Some header (Content-type) have a special syntax where attribute=value
   pairs are used after a leading semicolon.  The parse_field code
   knows about these fields and changes the parsing to the one defined
   in RFC2045.
   Returns a pointer to the value which is valid as long as the
   parse context is valid; NULL is returned in case that attr is not
   defined in the header, a missing value is reppresented by an empty string.

   With LOWER_VALUE set to true, a matching field valuebe be
   lowercased.

   Note, that ATTR should be lowercase.
 */
const char *
rfc822parse_query_parameter (rfc822parse_field_t ctx, const char *attr,
                             int lower_value)
{
  TOKEN t, a;

  for (t = ctx; t; t = t->next)
    {
      /* skip to the next semicolon */
      for (; t && !(t->type == tSPECIAL && t->data[0] == ';'); t = t->next)
	;
      if (!t)
	return NULL;
      if (is_parameter (t))
	{ /* Look closer. */
	  a = t->next; /* We know that this is an atom */
          if ( !a->flags.lowered )
            {
              lowercase_string (a->data);
              a->flags.lowered = 1;
            }
	  if (!strcmp (a->data, attr))
	    { /* found */
	      t = a->next->next;
	      /* Either T is now an atom, a quoted string or NULL in
	       * which case we return an empty string. */

              if ( lower_value && t && !t->flags.lowered )
                {
                  lowercase_string (t->data);
                  t->flags.lowered = 1;
                }
	      return t ? t->data : "";
	    }
	}
    }
  return NULL;
}

/****************
 * This function may be used for the Content-Type header to figure out
 * the media type and subtype.  Note, that the returned strings are
 * guaranteed to be lowercase as required by MIME.
 *
 * Returns: a pointer to the media type and if subtype is not NULL,
 *	    a pointer to the subtype.
 */
const char *
rfc822parse_query_media_type (rfc822parse_field_t ctx, const char **subtype)
{
  TOKEN t = ctx;
  const char *type;

  if (t->type != tATOM)
    return NULL;
  if (!t->flags.lowered)
    {
      lowercase_string (t->data);
      t->flags.lowered = 1;
    }
  type = t->data;
  t = t->next;
  if (!t || t->type != tSPECIAL || t->data[0] != '/')
    return NULL;
  t = t->next;
  if (!t || t->type != tATOM)
    return NULL;

  if (subtype)
    {
      if (!t->flags.lowered)
        {
          lowercase_string (t->data);
          t->flags.lowered = 1;
        }
      *subtype = t->data;
    }
  return type;
}





#ifdef TESTING

/* Internal debug function to print the structure of the message. */
static void
dump_structure (rfc822parse_t msg, part_t part, int indent)
{
  if (!part)
    {
      printf ("*** Structure of this message:\n");
      part = msg->parts;
    }

  for (; part; part = part->right)
    {
      rfc822parse_field_t ctx;
      part_t save_part; /* ugly hack - we should have a function to
                           get part information. */
      const char *s;

      save_part = msg->current_part;
      msg->current_part = part;
      ctx = rfc822parse_parse_field (msg, "Content-Type", -1);
      msg->current_part = save_part;
      if (ctx)
        {
          const char *s1, *s2;
          s1 = rfc822parse_query_media_type (ctx, &s2);
          if (s1)
            printf ("***   %*s %s/%s", indent*2, "", s1, s2);
          else
            printf ("***   %*s [not found]", indent*2, "");

          s = rfc822parse_query_parameter (ctx, "boundary", 0);
          if (s)
            printf (" (boundary=\"%s\")", s);
          rfc822parse_release_field (ctx);
        }
      else
        printf ("***   %*s text/plain [assumed]", indent*2, "");
      putchar('\n');

      if (part->down)
        dump_structure (msg, part->down, indent + 1);
    }

}



static void
show_param (rfc822parse_field_t ctx, const char *name)
{
  const char *s;

  if (!ctx)
    return;
  s = rfc822parse_query_parameter (ctx, name, 0);
  if (s)
    printf ("***   %s: '%s'\n", name, s);
}



static void
show_event (rfc822parse_event_t event)
{
  const char *s;

  switch (event)
    {
    case RFC822PARSE_OPEN: s= "Open"; break;
    case RFC822PARSE_CLOSE: s= "Close"; break;
    case RFC822PARSE_CANCEL: s= "Cancel"; break;
    case RFC822PARSE_T2BODY: s= "T2Body"; break;
    case RFC822PARSE_FINISH: s= "Finish"; break;
    case RFC822PARSE_RCVD_SEEN: s= "Rcvd_Seen"; break;
    case RFC822PARSE_LEVEL_DOWN: s= "Level_Down"; break;
    case RFC822PARSE_LEVEL_UP:   s= "Level_Up"; break;
    case RFC822PARSE_BOUNDARY: s= "Boundary"; break;
    case RFC822PARSE_LAST_BOUNDARY: s= "Last_Boundary"; break;
    case RFC822PARSE_BEGIN_HEADER: s= "Begin_Header"; break;
    case RFC822PARSE_PREAMBLE: s= "Preamble"; break;
    case RFC822PARSE_EPILOGUE: s= "Epilogue"; break;
    default: s= "***invalid event***"; break;
    }
  printf ("*** got RFC822 event %s\n", s);
}

static int
msg_cb (void *dummy_arg, rfc822parse_event_t event, rfc822parse_t msg)
{
  show_event (event);
  if (event == RFC822PARSE_T2BODY)
    {
      rfc822parse_field_t ctx;
      void *ectx;
      const char *line;

      for (ectx=NULL; (line = rfc822parse_enum_header_lines (msg, &ectx)); )
        {
          printf ("*** HDR: %s\n", line);
	}
      rfc822parse_enum_header_lines (NULL, &ectx); /* Close enumerator. */

      ctx = rfc822parse_parse_field (msg, "Content-Type", -1);
      if (ctx)
        {
          const char *s1, *s2;
          s1 = rfc822parse_query_media_type (ctx, &s2);
          if (s1)
            printf ("***   media: '%s/%s'\n", s1, s2);
          else
            printf ("***   media: [not found]\n");
          show_param (ctx, "boundary");
          show_param (ctx, "protocol");
          rfc822parse_release_field (ctx);
        }
      else
        printf ("***   media: text/plain [assumed]\n");

    }


  return 0;
}



int
main (int argc, char **argv)
{
  char line[5000];
  size_t length;
  rfc822parse_t msg;

  msg = rfc822parse_open (msg_cb, NULL);
  if (!msg)
    abort ();

  while (fgets (line, sizeof (line), stdin))
    {
      length = strlen (line);
      if (length && line[length - 1] == '\n')
	line[--length] = 0;
      if (length && line[length - 1] == '\r')
	line[--length] = 0;
      if (rfc822parse_insert (msg, line, length))
	abort ();
    }

  dump_structure (msg, NULL, 0);

  rfc822parse_close (msg);
  return 0;
}
#endif

/*
Local Variables:
compile-command: "gcc -Wall -Wno-pointer-sign -g -DTESTING -o rfc822parse rfc822parse.c"
End:
*/
