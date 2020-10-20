/* mkdir_p.c - Create a directory and any missing parents.
 * Copyright (C) 2015 g10 Code GmbH
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
#include <sys/stat.h>
#include <errno.h>
#include <assert.h>
#include <stdarg.h>

#include "util.h"
#include "stringhelp.h"
#include "logging.h"
#include "sysutils.h"
#include "mkdir_p.h"


gpg_error_t
gnupg_amkdir_p (const char **directory_components)
{
  gpg_error_t err = 0;
  int count;
  char **dirs;
  int i;

  for (count = 0; directory_components[count]; count ++)
    ;

  /* log_debug ("%s: %d directory components.\n", __func__, count); */

  dirs = xtrycalloc (count, sizeof *dirs);
  if (!dirs)
    return gpg_err_make (default_errsource, gpg_err_code_from_syserror ());

  for (i = 0; directory_components[i]; i ++)
    {
      if (i == 0)
	dirs[i] = make_filename_try (directory_components[i], NULL);
      else
	dirs[i] = make_filename_try (dirs[i-1], directory_components[i], NULL);
      if (!dirs[i])
        {
          err = gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
          goto out;
        }

      /* log_debug ("%s: Directory %d: `%s'.\n", __func__, i, dirs[i]); */
    }

  for (i = count - 1; i >= 0; i --)
    {
      struct stat s;

      /* log_debug ("%s: stat(%s)\n", __func__, dirs[i]); */

      if (!gnupg_stat (dirs[i], &s))
        {
          if ( ! S_ISDIR (s.st_mode))
            {
              /* log_debug ("%s: %s exists, but is not a directory!\n", */
              /*            __func__, dirs[i]); */
              err = gpg_err_make (default_errsource, GPG_ERR_ENOTDIR);
              goto out;
            }
          else
            {
              /* Got a directory.  */
              /* log_debug ("%s: %s exists and is a directory!\n",  */
              /*            __func__, dirs[i]); */
              err = 0;
              break;
            }
        }
      else if (errno == ENOENT)
	/* This directory does not exist yet.  Continue walking up the
	   hierarchy.  */
	{
          /* log_debug ("%s: %s does not exist!\n", */
          /*            __func__, dirs[i]); */
	  continue;
	}
      else
	/* Some other error code.  Die.  Note: this could be ENOTDIR
	   (we return this above), which means that a component of the
	   path prefix is not a directory.  */
	{
          /* log_debug ("%s: stat(%s) => %s!\n", */
          /*            __func__, dirs[i], strerror (errno)); */
	  err = gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
	  goto out;
	}
    }

  assert (i >= -1);
  /* DIRS[I] exists.  Start with the following entry.  */
  i ++;

  for (; i < count; i ++)
    {
      /* log_debug ("Creating directory: %s\n", dirs[i]); */

      if (gnupg_mkdir (dirs[i], "-rwx"))
	{
	  err = gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
	  goto out;
	}
    }

 out:
  for (i = 0; i < count; i ++)
    xfree (dirs[i]);
  xfree (dirs);

  /* log_debug ("%s: Returning %s\n", __func__, gpg_strerror (rc)); */

  return err;
}


gpg_error_t
gnupg_mkdir_p (const char *directory_component, ...)
{
  va_list ap;
  gpg_error_t err = 0;
  int i;
  int space = 1;
  const char **dirs;

  dirs = xtrymalloc (space * sizeof (char *));
  if (!dirs)
    return gpg_err_make (default_errsource, gpg_err_code_from_syserror ());

  dirs[0] = directory_component;

  va_start (ap, directory_component);
  for (i = 1; dirs[i - 1]; i ++)
    {
      if (i == space)
	{
          const char **tmp_dirs;

	  space = 2 * space;
	  tmp_dirs = xtryrealloc (dirs, space * sizeof (char *));
          if (!tmp_dirs)
            {
              err = gpg_err_make (default_errsource,
                                  gpg_err_code_from_syserror ());
              break;
            }
          dirs = tmp_dirs;
	}
      dirs[i] = va_arg (ap, char *);
    }
  va_end (ap);

  if (!err)
    err = gnupg_amkdir_p (dirs);

  xfree (dirs);

  return err;
}
