/* w32-cmdline.c - Command line helper functions needed in Windows
 * Copyright (C) 2021 g10 Code GmbH
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
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>

#ifdef HAVE_W32_SYSTEM
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
#endif /*!HAVE_W32_SYSTEM*/

#include "util.h"
#include "w32help.h"


/* Helper object for add_arg.  */
struct add_arg_s
{
  char **argv; /* Calloced array.  */
  int argc;    /* Number of items in argc. */
  int size;    /* Allocated size of argv.  */
};


/* Add STRING to the argv of PARM.  Returns 0 on success; on error
 * sets ERRNO and returns -1.  */
static int
add_arg (struct add_arg_s *parm, const char *string)
{
  if (parm->argc == parm->size)
    {
      char **newargv;
      int newsize;

      if (parm->size < 256)
        newsize = ((parm->size + 31) / 32 + 1) * 32;
      else
        newsize = ((parm->size + 255) / 256 + 1) * 256;
      /* We allocate one more item for the trailing NULL.  */
      newargv = xtryreallocarray (parm->argv, parm->size, newsize+1,
                                  sizeof *newargv);
      if (!newargv)
        return -1;
      parm->argv = newargv;
      parm->size = newsize;
    }
  parm->argv[parm->argc] = xtrystrdup (string);
  if (!parm->argv[parm->argc])
    return -1;
  parm->argc++;
  return 0;
}


/* Glob PATTERN and add to the argv of PARM.  Returns 0 on success; on
 * error sets ERRNO and returns -1.  */
static int
glob_arg (struct add_arg_s *parm, const char *pattern)
{
  int rc;
  const char *s;

#ifdef HAVE_W32_SYSTEM
  HANDLE hd;
  WIN32_FIND_DATAW dir;
  uintptr_t pos;  /* Offset to the last slash in pattern/buffer or 0.  */
  char *buffer, *p;
  int any = 0;

  s = strpbrk (pattern, "*?");
  if (!s)
    {
      /* Called without wildcards.  */
      return add_arg (parm, pattern);
    }
  for (; s != pattern && *s != '/' && *s != '\\'; s--)
    ;
  pos = s - pattern;
  if (*s == '/' || *s == L'\\')
    pos++;

  {
    wchar_t *wpattern;

    wpattern = utf8_to_wchar (pattern);
    if (!wpattern)
      return -1;

    hd = FindFirstFileW (wpattern, &dir);
    xfree (wpattern);
  }
  if (hd == INVALID_HANDLE_VALUE)
    return add_arg (parm, pattern);

  /* We allocate enough space to hold all kind of UTF-8 strings.  */
  buffer = xtrymalloc (strlen (pattern) + MAX_PATH*6 + 1);
  if (!buffer)
    {
      FindClose (hd);
      return -1;
    }
  mem2str (buffer, pattern, pos+1);
  for (p=buffer; *p; p++)
    if (*p == '\\')
      *p = '/';

  do
    {
      if (!(dir.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        {
          char *name;

          name = wchar_to_utf8 (dir.cFileName);
          if (!name)
            rc = -1;
          else
            {
              mem2str (buffer + pos, name, MAX_PATH*6);
              xfree (name);
              rc = add_arg (parm, buffer);
            }
          if (rc)
            {
              FindClose (hd);
              xfree (buffer);
              return rc;
            }
          any = 1;
        }
    }
  while (FindNextFileW (hd, &dir));

  FindClose (hd);
  xfree (buffer);

  rc = any? 0 : add_arg (parm, pattern);

#else /* Unix */

  /* We use some dummy code here because this is only used in the Unix
   * test suite.  */
  s = strpbrk (pattern, "*?");
  if (!s)
    {
      /* Called without wildcards.  */
      return add_arg (parm, pattern);
    }

  if (strchr (pattern, '?'))
    rc = add_arg (parm, "[? follows]");
  else if (strchr (pattern, '*'))
    rc = add_arg (parm, "[* follows]");
  else
    rc = add_arg (parm, "[no glob!]");  /* Should not happen.  */
  if (!rc)
    rc = add_arg (parm, pattern);

#endif /* Unix */

  return rc;
}


/* Return the number of backslashes.  */
static unsigned int
count_backslashes (const char *s)
{
  unsigned int count = 0;

  for ( ;*s == '\\'; s++)
    count++;
  return count;
}


static void
strip_one_arg (char *string, int endquote)
{
  char *s, *d;
  unsigned int n, i;

  for (s=d=string; *s; s++)
    if (*s == '\\')
      {
        n = count_backslashes (s);
        if (s[n] == '"')
          {
            for (i=0; i < n/2; i++)
              *d++ = '\\';
            if ((n&1)) /* Odd number of backslashes.  */
              *d++ = '"';  /* Print the quote.  */
          }
        else if (!s[n] && endquote)
          {
            for (i=0; i < n/2; i++)
              *d++ = '\\';
            s--;
          }
        else /* Print all backslashes.  */
          {
            for (i=0; i < n; i++)
              *d++ = '\\';
            n--; /* Adjust for the increment in the for.  */
          }
        s += n;
      }
    else if (*s == '"' && s[1])
      *d++ = *++s;
    else
      *d++ = *s;
  *d = 0;
}


/* Helper for parse_w32_commandline.  If ARGV and ARGVFLAGS are not
 * NULL, ARGVFLAGS is expected to be allocated at the same size of
 * ARGV and zeroed; on return 1 is stored for all arguments which are
 * quoted (args like (foo"bar"baz") also count as quoted.  */
static int
parse_cmdstring (char *string, char **argv, unsigned char *argvflags)
{
  int argc = 0;
  int inquote = 0;
  char *p0, *p;
  unsigned int n;

  p0 = string;
  for (p=string; *p; p++)
    {
      if (inquote)
        {
          if (*p == '\\' && p[1] == '"')
            p++;
          else if (*p == '\\' && p[1] == '\\')
            p++;
          else if (*p == '"')
            {
              if (p[1] == ' ' || p[1] == '\t' || !p[1])
                {
                  if (argv)
                    {
                      *p = 0;
                      strip_one_arg (p0, 1);
                      argv[argc] = p0;
                      if (argvflags)
                        argvflags[argc] = 1;
                    }
                  argc++;
                  p0 = NULL;
                }
              inquote = 0;
            }
        }
      else if (*p == '\\' && (n=count_backslashes (p)))
        {
          if (!p0) /* First non-WS; set start.  */
            p0 = p;
          if (p[n] == '"')
            {
              if (!(n&1)) /* Even number.  */
                inquote = 1;
              p++;
            }
          p += n;
        }
      else if (*p == '"')
        {
          inquote = 1;
          if (!p0 || p == string) /* First non-WS or first char; set start.  */
            p0 = p + 1;
        }
      else if (*p == ' ' || *p == '\t')
        {
          if (p0) /* We are in an argument and reached WS.  */
            {
              if (argv)
                {
                  *p = 0;
                  strip_one_arg (p0, inquote);
                  argv[argc] = p0;
                  if (argvflags && inquote)
                    argvflags[argc] = 1;
                }
              argc++;
              p0 = NULL;
            }
        }
      else if (!p0) /* First non-WS; set start.  */
        p0 = p;
    }

  if (inquote || p0)
    {
      /* Closing quote missing (we accept this as argument anyway) or
       * an open argument.  */
      if (argv)
        {
          *p = 0;
          strip_one_arg (p0, inquote);
          argv[argc] = p0;
          if (argvflags && inquote)
            argvflags[argc] = 1;
        }
      argc++;
    }

  return argc;
}

/* This is a Windows command line parser, returning an array with
 * strings and its count.  The argument CMDLINE is expected to be
 * utf-8 encoded and may be modified after returning from this
 * function.  The returned array points into CMDLINE, so this should
 * not be freed.  If GLOBING is set to true globing is done for all
 * items.  Returns NULL on error.  The number of items in the array is
 * returned at R_ARGC.  If R_ITEMSALLOCED is NOT NULL, it's value is
 * set to true if the items at R_ALLOC are allocated and not point
 * into to CMDLINE.  */
char **
w32_parse_commandline (char *cmdline, int globing, int *r_argc,
                       int *r_itemsalloced)
{
  int argc, i;
  char **argv;
  char *argvflags;

  if (r_itemsalloced)
    *r_itemsalloced = 0;

  argc = parse_cmdstring (cmdline, NULL, NULL);
  if (!argc)
    {
      log_error ("%s failed: %s\n", __func__, "internal error");
      return NULL;  /* Ooops.  */
    }
  argv = xtrycalloc (argc+1, sizeof *argv);
  if (!argv)
    {
      log_error ("%s failed: %s\n", __func__,
                 gpg_strerror (gpg_error_from_syserror ()));
      return NULL;  /* Ooops.  */
    }
  if (globing)
    {
      argvflags = xtrycalloc (argc+1, sizeof *argvflags);
      if (!argvflags)
        {
          log_error ("%s failed: %s\n", __func__,
                     gpg_strerror (gpg_error_from_syserror ()));
          xfree (argv);
          return NULL;  /* Ooops.  */
        }
    }
  else
    argvflags = NULL;

  i = parse_cmdstring (cmdline, argv, argvflags);
  if (argc != i)
    {
      log_error ("%s failed (argc=%d i=%d)\n", __func__, argc, i);
      xfree (argv);
      xfree (argvflags);
      return NULL;  /* Ooops.  */
    }

  if (globing)
    {
      for (i=0; i < argc; i++)
        if (argvflags[i] != 1 && strpbrk (argv[i], "*?"))
          break;
      if (i < argc)
        {
          /* Indeed some unquoted arguments contain wildcards.  We
           * need to do the globing and thus a dynamically re-allocate
           * the argv array and strdup all items.  */
          struct add_arg_s parm;
          int rc;

          if (argc < 32)
            parm.size = ((argc + 31) / 32 + 1) * 32;
          else
            parm.size = ((argc + 255) / 256 + 1) * 256;
          parm.argc = 0;
          /* We allocate one more item for the trailing NULL.  */
          parm.argv = xtryreallocarray (NULL, 0, parm.size + 1,
                                        sizeof *parm.argv);
          if (!parm.argv)
            {
              log_error ("%s: error allocating array: %s\n", __func__,
                         gpg_strerror (gpg_error_from_syserror ()));
              xfree (argv);
              xfree (argvflags);
              return NULL;  /* Ooops.  */
            }
          rc = 0;
          for (i=0; i < argc; i++)
            {
              if (argvflags[i] != 1)
                rc = glob_arg (&parm, argv[i]);
              else
                rc = add_arg (&parm, argv[i]);
              if (rc)
                {
                  log_error ("%s: error adding or blobing: %s\n", __func__,
                             gpg_strerror (gpg_error_from_syserror ()));
                  for (i=0; i < parm.argc; i++)
                    xfree (parm.argv[i]);
                  xfree (parm.argv);
                  xfree (argv);
                  xfree (argvflags);
                  return NULL;  /* Ooops.  */
                }
            }
          xfree (argv);
          argv = parm.argv;
          argc = parm.argc;
          if (r_itemsalloced)
            *r_itemsalloced = 1;
        }
    }

  xfree (argvflags);
  *r_argc = argc;
  return argv;
}
