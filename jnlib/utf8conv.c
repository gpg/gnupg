/* utf8conf.c -  UTF8 character set conversion
 * Copyright (C) 1994, 1998, 1999, 2000, 2001,
 *               2003  Free Software Foundation, Inc.
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

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#ifdef HAVE_LANGINFO_CODESET
#include <langinfo.h>
#endif

#include "libjnlib-config.h"
#include "stringhelp.h"
#include "utf8conv.h"


static ushort koi8_unicode[128] = {
  0x2500, 0x2502, 0x250c, 0x2510, 0x2514, 0x2518, 0x251c, 0x2524,
  0x252c, 0x2534, 0x253c, 0x2580, 0x2584, 0x2588, 0x258c, 0x2590,
  0x2591, 0x2592, 0x2593, 0x2320, 0x25a0, 0x2219, 0x221a, 0x2248,
  0x2264, 0x2265, 0x00a0, 0x2321, 0x00b0, 0x00b2, 0x00b7, 0x00f7,
  0x2550, 0x2551, 0x2552, 0x0451, 0x2553, 0x2554, 0x2555, 0x2556,
  0x2557, 0x2558, 0x2559, 0x255a, 0x255b, 0x255c, 0x255d, 0x255e,
  0x255f, 0x2560, 0x2561, 0x0401, 0x2562, 0x2563, 0x2564, 0x2565,
  0x2566, 0x2567, 0x2568, 0x2569, 0x256a, 0x256b, 0x256c, 0x00a9,
  0x044e, 0x0430, 0x0431, 0x0446, 0x0434, 0x0435, 0x0444, 0x0433,
  0x0445, 0x0438, 0x0439, 0x043a, 0x043b, 0x043c, 0x043d, 0x043e,
  0x043f, 0x044f, 0x0440, 0x0441, 0x0442, 0x0443, 0x0436, 0x0432,
  0x044c, 0x044b, 0x0437, 0x0448, 0x044d, 0x0449, 0x0447, 0x044a,
  0x042e, 0x0410, 0x0411, 0x0426, 0x0414, 0x0415, 0x0424, 0x0413,
  0x0425, 0x0418, 0x0419, 0x041a, 0x041b, 0x041c, 0x041d, 0x041e,
  0x041f, 0x042f, 0x0420, 0x0421, 0x0422, 0x0423, 0x0416, 0x0412,
  0x042c, 0x042b, 0x0417, 0x0428, 0x042d, 0x0429, 0x0427, 0x042a
};

static ushort latin2_unicode[128] = {
  0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087,
  0x0088, 0x0089, 0x008A, 0x008B, 0x008C, 0x008D, 0x008E, 0x008F,
  0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,
  0x0098, 0x0099, 0x009A, 0x009B, 0x009C, 0x009D, 0x009E, 0x009F,
  0x00A0, 0x0104, 0x02D8, 0x0141, 0x00A4, 0x013D, 0x015A, 0x00A7,
  0x00A8, 0x0160, 0x015E, 0x0164, 0x0179, 0x00AD, 0x017D, 0x017B,
  0x00B0, 0x0105, 0x02DB, 0x0142, 0x00B4, 0x013E, 0x015B, 0x02C7,
  0x00B8, 0x0161, 0x015F, 0x0165, 0x017A, 0x02DD, 0x017E, 0x017C,
  0x0154, 0x00C1, 0x00C2, 0x0102, 0x00C4, 0x0139, 0x0106, 0x00C7,
  0x010C, 0x00C9, 0x0118, 0x00CB, 0x011A, 0x00CD, 0x00CE, 0x010E,
  0x0110, 0x0143, 0x0147, 0x00D3, 0x00D4, 0x0150, 0x00D6, 0x00D7,
  0x0158, 0x016E, 0x00DA, 0x0170, 0x00DC, 0x00DD, 0x0162, 0x00DF,
  0x0155, 0x00E1, 0x00E2, 0x0103, 0x00E4, 0x013A, 0x0107, 0x00E7,
  0x010D, 0x00E9, 0x0119, 0x00EB, 0x011B, 0x00ED, 0x00EE, 0x010F,
  0x0111, 0x0144, 0x0148, 0x00F3, 0x00F4, 0x0151, 0x00F6, 0x00F7,
  0x0159, 0x016F, 0x00FA, 0x0171, 0x00FC, 0x00FD, 0x0163, 0x02D9
};


static const char *active_charset_name = "iso-8859-1";
static ushort *active_charset = NULL;
static int no_translation = 0;

int
set_native_charset (const char *newset)
{
  if (!newset)
#ifdef HAVE_LANGINFO_CODESET
    newset = nl_langinfo (CODESET);
#else
    newset = "8859-1";
#endif

  if (strlen (newset) > 3 && !ascii_memcasecmp (newset, "iso", 3))
    {
      newset += 3;
      if (*newset == '-' || *newset == '_')
	newset++;
    }

  if (!*newset
      || !ascii_strcasecmp (newset, "8859-1")
      || !ascii_strcasecmp (newset, "8859-15"))
    {
      active_charset_name = "iso-8859-1";
      no_translation = 0;
      active_charset = NULL;
    }
  else if (!ascii_strcasecmp (newset, "8859-2"))
    {
      active_charset_name = "iso-8859-2";
      no_translation = 0;
      active_charset = latin2_unicode;
    }
  else if (!ascii_strcasecmp (newset, "koi8-r"))
    {
      active_charset_name = "koi8-r";
      no_translation = 0;
      active_charset = koi8_unicode;
    }
  else if (!ascii_strcasecmp (newset, "utf8")
	   || !ascii_strcasecmp (newset, "utf-8"))
    {
      active_charset_name = "utf-8";
      no_translation = 1;
      active_charset = NULL;
    }
  else
    return -1;
  return 0;
}

const char *
get_native_charset ()
{
  return active_charset_name;
}

/****************
 * Convert string, which is in native encoding to UTF8 and return the
 * new allocated UTF8 string.
 */
char *
native_to_utf8 (const char *string)
{
  const byte *s;
  char *buffer;
  byte *p;
  size_t length = 0;

  if (no_translation)
    {
      buffer = jnlib_xstrdup (string);
    }
  else if (active_charset)
    {
      for (s = string; *s; s++)
	{
	  length++;
	  if (*s & 0x80)
	    length += 2;	/* we may need 3 bytes */
	}
      buffer = jnlib_xmalloc (length + 1);
      for (p = buffer, s = string; *s; s++)
	{
	  if ((*s & 0x80))
	    {
	      ushort val = active_charset[*s & 0x7f];
	      if (val < 0x0800)
		{
		  *p++ = 0xc0 | ((val >> 6) & 0x1f);
		  *p++ = 0x80 | (val & 0x3f);
		}
	      else
		{
		  *p++ = 0xe0 | ((val >> 12) & 0x0f);
		  *p++ = 0x80 | ((val >> 6) & 0x3f);
		  *p++ = 0x80 | (val & 0x3f);
		}
	    }
	  else
	    *p++ = *s;
	}
      *p = 0;
    }
  else
    {
      for (s = string; *s; s++)
	{
	  length++;
	  if (*s & 0x80)
	    length++;
	}
      buffer = jnlib_xmalloc (length + 1);
      for (p = buffer, s = string; *s; s++)
	{
	  if (*s & 0x80)
	    {
	      *p++ = 0xc0 | ((*s >> 6) & 3);
	      *p++ = 0x80 | (*s & 0x3f);
	    }
	  else
	    *p++ = *s;
	}
      *p = 0;
    }
  return buffer;
}


/* Convert string, which is in UTF8 to native encoding.  Replace
 * illegal encodings by some "\xnn" and quote all control
 * characters. A character with value DELIM will always be quoted, it
 * must be a vanilla ASCII character.  */
char *
utf8_to_native (const char *string, size_t length, int delim)
{
  int nleft;
  int i;
  byte encbuf[8];
  int encidx;
  const byte *s;
  size_t n;
  byte *buffer = NULL, *p = NULL;
  unsigned long val = 0;
  size_t slen;
  int resync = 0;

  /* 1. pass (p==NULL): count the extended utf-8 characters */
  /* 2. pass (p!=NULL): create string */
  for (;;)
    {
      for (slen = length, nleft = encidx = 0, n = 0, s = string; slen;
	   s++, slen--)
	{
	  if (resync)
	    {
	      if (!(*s < 128 || (*s >= 0xc0 && *s <= 0xfd)))
		{
		  /* still invalid */
		  if (p)
		    {
		      sprintf (p, "\\x%02x", *s);
		      p += 4;
		    }
		  n += 4;
		  continue;
		}
	      resync = 0;
	    }
	  if (!nleft)
	    {
	      if (!(*s & 0x80))
		{		/* plain ascii */
		  if (*s < 0x20 || *s == 0x7f || *s == delim ||
		      (delim && *s == '\\'))
		    {
		      n++;
		      if (p)
			*p++ = '\\';
		      switch (*s)
			{
			case '\n':
			  n++;
			  if (p)
			    *p++ = 'n';
			  break;
			case '\r':
			  n++;
			  if (p)
			    *p++ = 'r';
			  break;
			case '\f':
			  n++;
			  if (p)
			    *p++ = 'f';
			  break;
			case '\v':
			  n++;
			  if (p)
			    *p++ = 'v';
			  break;
			case '\b':
			  n++;
			  if (p)
			    *p++ = 'b';
			  break;
			case 0:
			  n++;
			  if (p)
			    *p++ = '0';
			  break;
			default:
			  n += 3;
			  if (p)
			    {
			      sprintf (p, "x%02x", *s);
			      p += 3;
			    }
			  break;
			}
		    }
		  else
		    {
		      if (p)
			*p++ = *s;
		      n++;
		    }
		}
	      else if ((*s & 0xe0) == 0xc0)
		{		/* 110x xxxx */
		  val = *s & 0x1f;
		  nleft = 1;
		  encidx = 0;
		  encbuf[encidx++] = *s;
		}
	      else if ((*s & 0xf0) == 0xe0)
		{		/* 1110 xxxx */
		  val = *s & 0x0f;
		  nleft = 2;
		  encidx = 0;
		  encbuf[encidx++] = *s;
		}
	      else if ((*s & 0xf8) == 0xf0)
		{		/* 1111 0xxx */
		  val = *s & 0x07;
		  nleft = 3;
		  encidx = 0;
		  encbuf[encidx++] = *s;
		}
	      else if ((*s & 0xfc) == 0xf8)
		{		/* 1111 10xx */
		  val = *s & 0x03;
		  nleft = 4;
		  encidx = 0;
		  encbuf[encidx++] = *s;
		}
	      else if ((*s & 0xfe) == 0xfc)
		{		/* 1111 110x */
		  val = *s & 0x01;
		  nleft = 5;
		  encidx = 0;
		  encbuf[encidx++] = *s;
		}
	      else
		{		/* invalid encoding: print as \xnn */
		  if (p)
		    {
		      sprintf (p, "\\x%02x", *s);
		      p += 4;
		    }
		  n += 4;
		  resync = 1;
		}
	    }
	  else if (*s < 0x80 || *s >= 0xc0)
	    {			/* invalid */
	      if (p)
		{
		  for (i = 0; i < encidx; i++)
		    {
		      sprintf (p, "\\x%02x", encbuf[i]);
		      p += 4;
		    }
		  sprintf (p, "\\x%02x", *s);
		  p += 4;
		}
	      n += 4 + 4 * encidx;
	      nleft = 0;
	      encidx = 0;
	      resync = 1;
	    }
	  else
	    {
	      encbuf[encidx++] = *s;
	      val <<= 6;
	      val |= *s & 0x3f;
	      if (!--nleft)
		{		/* ready */
		  if (no_translation)
		    {
		      if (p)
			{
			  for (i = 0; i < encidx; i++)
			    *p++ = encbuf[i];
			}
		      n += encidx;
		      encidx = 0;
		    }
		  else if (active_charset)
		    {		/* table lookup */
		      for (i = 0; i < 128; i++)
			{
			  if (active_charset[i] == val)
			    break;
			}
		      if (i < 128)
			{	/* we can print this one */
			  if (p)
			    *p++ = i + 128;
			  n++;
			}
		      else
			{	/* we do not have a translation: print utf8 */
			  if (p)
			    {
			      for (i = 0; i < encidx; i++)
				{
				  sprintf (p, "\\x%02x", encbuf[i]);
				  p += 4;
				}
			    }
			  n += encidx * 4;
			  encidx = 0;
			}
		    }
		  else
		    {		/* native set */
		      if (val >= 0x80 && val < 256)
			{
			  n++;	/* we can simply print this character */
			  if (p)
			    *p++ = val;
			}
		      else
			{	/* we do not have a translation: print utf8 */
			  if (p)
			    {
			      for (i = 0; i < encidx; i++)
				{
				  sprintf (p, "\\x%02x", encbuf[i]);
				  p += 4;
				}
			    }
			  n += encidx * 4;
			  encidx = 0;
			}
		    }
		}

	    }
	}
      if (!buffer)
	{			/* allocate the buffer after the first pass */
	  buffer = p = jnlib_xmalloc (n + 1);
	}
      else
	{
	  *p = 0;		/* make a string */
	  return buffer;
	}
    }
}
