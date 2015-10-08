/* mkdir_p.c - Create a directory and any missing parents.
 * Copyright (C) 2015 g10 Code GmbH
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

#include <config.h>
#include <sys/stat.h>
#include <errno.h>
#include <assert.h>
#include <stdarg.h>

#include "mkdir_p.h"
#include "stringhelp.h"
#include "logging.h"
#include "util.h"

#define DEBUG 0

int
amkdir_p (char **directory_components)
{
  int count;
  char **dirs;
  int i;
  int rc = 0;

  for (count = 0; directory_components[count]; count ++)
    ;

  if (DEBUG)
    log_debug ("%s: %d directory components.\n", __func__, count);

  dirs = xcalloc (count, sizeof (char *));
  for (i = 0; directory_components[i]; i ++)
    {
      if (i == 0)
	dirs[i] = directory_components[i];
      else
	dirs[i] = make_filename (dirs[i - 1], directory_components[i], NULL);

      if (DEBUG)
	log_debug ("%s: Directory %d: `%s'.\n", __func__, i, dirs[i]);
    }

  for (i = count - 1; i >= 0; i --)
    {
      struct stat s;

      if (DEBUG)
	log_debug ("%s: stat(%s)\n", __func__, dirs[i]);

      rc = stat (dirs[i], &s);
      if (rc == 0 && ! S_ISDIR (s.st_mode))
	{
	  if (DEBUG)
	    log_debug ("%s: %s exists, but is not a directory!\n",
		       __func__, dirs[i]);
	  rc = gpg_error (GPG_ERR_ENOTDIR);
	  goto out;
	}
      else if (rc == 0)
	{
	  /* Got a directory.  */
	  if (DEBUG)
	    log_debug ("%s: %s exists and is a directory!\n",
		       __func__, dirs[i]);
	  break;
	}
      else if (errno == ENOENT)
	/* This directory does not exist yet.  Continue walking up the
	   hierarchy.  */
	{
	  if (DEBUG)
	    log_debug ("%s: %s does not exist!\n",
		       __func__, dirs[i]);
	  continue;
	}
      else
	/* Some other error code.  Die.  Note: this could be ENOTDIR
	   (we return this above), which means that a component of the
	   path prefix is not a directory.  */
	{
	  if (DEBUG)
	    log_debug ("%s: stat(%s) => %s!\n",
		       __func__, dirs[i], strerror (errno));
	  rc = gpg_error_from_syserror ();
	  goto out;
	}
    }

  assert (i >= -1);
  /* DIRS[I] exists.  Start with the following entry.  */
  i ++;

  for (; i < count; i ++)
    {
      if (DEBUG)
	log_debug ("Creating directory: %s\n", dirs[i]);

      rc = mkdir (dirs[i], S_IRUSR | S_IWUSR | S_IXUSR);
      if (rc)
	{
	  rc = gpg_error_from_syserror ();
	  goto out;
	}
    }

 out:
  for (i = 1; i < count; i ++)
    xfree (dirs[i]);
  xfree (dirs);

  if (DEBUG)
    log_debug ("%s: Returning %s\n", __func__, gpg_strerror (rc));

  return rc;
}

int
mkdir_p (char *directory_component, ...)
{
  va_list ap;
  int i;
  int space = 1;
  char **dirs = xmalloc (space * sizeof (char *));
  int rc;

  dirs[0] = directory_component;

  va_start (ap, directory_component);
  for (i = 1; dirs[i - 1]; i ++)
    {
      if (i == space)
	{
	  space = 2 * space;
	  dirs = xrealloc (dirs, space * sizeof (char *));
	}
      dirs[i] = va_arg (ap, char *);
    }
  va_end (ap);

  rc = amkdir_p (dirs);

  xfree (dirs);

  return rc;
}
