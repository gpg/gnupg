/* session-env.c - Session environment helper functions.
 * Copyright (C) 2009 Free Software Foundation, Inc.
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
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>

#include "util.h"
#include "session-env.h"


struct variable_s
{
  char *value;    /* Pointer into NAME to the Nul terminated value. */
  int is_default; /* The value is a default one.  */
  char name[1];   /* Nul terminated Name and space for the value.  */
};



/* The session environment object.  */
struct session_environment_s
{
  size_t arraysize;          /* Allocated size or ARRAY.  */
  size_t arrayused;          /* Used size of ARRAY.  */
  struct variable_s **array; /* Array of variables.  NULL slots are unused.  */
};


/* A list of environment variables we pass from the actual user
  (e.g. gpgme) down to the pinentry.  We do not handle the locale
  settings because they do not only depend on envvars.  */
static struct
{
  const char *name;
  const char *assname;  /* Name used by Assuan or NULL.  */
} stdenvnames[] = {
  { "GPG_TTY", "ttyname" },      /* GnuPG specific envvar.  */
  { "TERM",    "ttytype" },      /* Used to set ttytype. */
  { "DISPLAY", "display" },      /* The X-Display.  */
  { "XAUTHORITY","xauthority"},  /* Xlib Authentication.  */
  { "XMODIFIERS" },              /* Used by Xlib to select X input
                                      modules (eg "@im=SCIM").  */
  { "WAYLAND_DISPLAY" },         /* For the Wayland display engine.  */
  { "XDG_SESSION_TYPE" },        /* Used by Qt and other non-GTK toolkits
                                    to check for x11 or wayland.  */
  { "QT_QPA_PLATFORM" },         /* Used by Qt to explicitly request
                                    x11 or wayland; in particular, needed
                                    to make Qt use Wayland on Gnome.  */
  { "GTK_IM_MODULE" },           /* Used by gtk to select gtk input
                                    modules (eg "scim-bridge").  */
  { "DBUS_SESSION_BUS_ADDRESS" },/* Used by GNOME3 to talk to gcr over
                                    dbus */
  { "QT_IM_MODULE" },            /* Used by Qt to select qt input
                                      modules (eg "xim").  */
  { "INSIDE_EMACS" },            /* Set by Emacs before running a
                                    process.  */
  { "PINENTRY_USER_DATA", "pinentry-user-data"}
                                 /* Used for communication with
                                    non-standard Pinentries.  */
};


/* Track last allocated arraysize of all objects ever created.  If
   nothing has ever been allocated we use INITIAL_ARRAYSIZE and we
   will never use more than MAXDEFAULT_ARRAYSIZE for initial
   allocation.  Note that this is not reentrant if used with a
   preemptive thread model.  */
static size_t lastallocatedarraysize;
#define INITIAL_ARRAYSIZE 8  /* Let's use the number of stdenvnames.  */
#define CHUNK_ARRAYSIZE 10
#define MAXDEFAULT_ARRAYSIZE (INITIAL_ARRAYSIZE + CHUNK_ARRAYSIZE * 5)


/* Return the names of standard environment variables one after the
   other.  The caller needs to set the value at the address of
   ITERATOR initially to 0 and then call this function until it returns
   NULL.  */
const char *
session_env_list_stdenvnames (int *iterator, const char **r_assname)
{
  int idx = *iterator;

  if (idx < 0 || idx >= DIM (stdenvnames))
    return NULL;
  *iterator = idx + 1;
  if (r_assname)
    *r_assname = stdenvnames[idx].assname;
  return stdenvnames[idx].name;
}


/* Create a new session environment object.  Return NULL and sets
   ERRNO on failure. */
session_env_t
session_env_new (void)
{
  session_env_t se;

  se = xtrycalloc (1, sizeof *se);
  if (se)
    {
      se->arraysize = (lastallocatedarraysize?
                       lastallocatedarraysize : INITIAL_ARRAYSIZE);
      se->array = xtrycalloc (se->arraysize, sizeof *se->array);
      if (!se->array)
        {
          xfree (se);
          se = NULL;
        }
    }

  return se;
}


/* Release a session environment object.  */
void
session_env_release (session_env_t se)
{
  int idx;

  if (!se)
    return;

  if (se->arraysize > INITIAL_ARRAYSIZE
      && se->arraysize <= MAXDEFAULT_ARRAYSIZE
      && se->arraysize > lastallocatedarraysize)
    lastallocatedarraysize = se->arraysize;

  for (idx=0; idx < se->arrayused; idx++)
    if (se->array[idx])
      xfree (se->array[idx]);
  xfree (se->array);
  xfree (se);
}


static gpg_error_t
delete_var (session_env_t se, const char *name)
{
  int idx;

  for (idx=0; idx < se->arrayused; idx++)
    if (se->array[idx] && !strcmp (se->array[idx]->name, name))
      {
        xfree (se->array[idx]);
        se->array[idx] = NULL;
      }
  return 0;
}


static gpg_error_t
update_var (session_env_t se, const char *string, size_t namelen,
            const char *explicit_value, int set_default)
{
  int idx;
  int freeidx = -1;
  const char *value;
  size_t valuelen;
  struct variable_s *var;

  if (explicit_value)
    value = explicit_value;
  else
    value = string + namelen + 1;
  valuelen = strlen (value);

  for (idx=0; idx < se->arrayused; idx++)
    {
      if (!se->array[idx])
        freeidx = idx;
      else if (!strncmp (se->array[idx]->name, string, namelen)
               && strlen (se->array[idx]->name) == namelen)
        {
          if (strlen (se->array[idx]->value) == valuelen)
            {
              /* The new value has the same length.  We can update it
                 in-place.  */
              memcpy (se->array[idx]->value, value, valuelen);
              se->array[idx]->is_default = !!set_default;
              return 0;
            }
          /* Prepare for update.  */
          freeidx = idx;
        }
    }

  if (freeidx == -1)
    {
      if (se->arrayused == se->arraysize)
        {
          /* Reallocate the array. */
          size_t newsize;
          struct variable_s **newarray;

          newsize = se->arraysize + CHUNK_ARRAYSIZE;
          newarray = xtrycalloc (newsize, sizeof *newarray);
          if (!newarray)
            return gpg_error_from_syserror ();
          for (idx=0; idx < se->arrayused; idx++)
            newarray[idx] = se->array[idx];
          se->arraysize = newsize;
          xfree (se->array);
          se->array = newarray;
        }
      freeidx = se->arrayused++;
    }

  /* Allocate new memory and return an error if that didn't worked.
     Allocating it first allows us to keep the old value; it doesn't
     matter that arrayused has already been incremented in case of a
     new entry - it will then pint to a NULL slot.  */
  var = xtrymalloc (sizeof *var + namelen + 1 + valuelen);
  if (!var)
    return gpg_error_from_syserror ();
  var->is_default = !!set_default;
  memcpy (var->name, string, namelen);
  var->name[namelen] = '\0';
  var->value = var->name + namelen + 1;
  strcpy (var->value, value);

  xfree (se->array[freeidx]);
  se->array[freeidx] = var;
  return 0;
}


/* Set or update an environment variable of the session environment.
   String is similar to the putval(3) function but it is reentrant and
   takes a copy.  In particular it exhibits this behaviour:

          <NAME>            Delete envvar NAME
          <KEY>=            Set envvar NAME to the empty string
          <KEY>=<VALUE>     Set envvar NAME to VALUE

   On success 0 is returned; on error an gpg-error code.  */
gpg_error_t
session_env_putenv (session_env_t se, const char *string)
{
  const char *s;

  if (!string || !*string)
    return gpg_error (GPG_ERR_INV_VALUE);
  s = strchr (string, '=');
  if (s == string)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!s)
    return delete_var (se, string);
  else
    return update_var (se, string, s - string, NULL, 0);
}


/* Same as session_env_putenv but with name and value given as distict
   values.  */
gpg_error_t
session_env_setenv (session_env_t se, const char *name, const char *value)
{
  if (!name || !*name)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!value)
    return delete_var (se, name);
  else
    return update_var (se, name, strlen (name), value, 0);
}




/* Return the value of the environment variable NAME from the SE
   object.  If the variable does not exist, NULL is returned.  The
   returned value is valid as long as SE is valid and as long it has
   not been removed or updated by a call to session_env_putenv.  The
   caller MUST not change the returned value. */
char *
session_env_getenv (session_env_t se, const char *name)
{
  int idx;

  if (!se || !name || !*name)
    return NULL;

  for (idx=0; idx < se->arrayused; idx++)
    if (se->array[idx] && !strcmp (se->array[idx]->name, name))
      return se->array[idx]->is_default? NULL : se->array[idx]->value;
  return NULL;
}


/* Return the value of the environment variable NAME from the SE
   object.  The returned value is valid as long as SE is valid and as
   long it has not been removed or updated by a call to
   session_env_putenv.  If the variable does not exist, the function
   tries to return the value trough a call to getenv; if that returns
   a value, this value is recorded and used.  If no value could be
   found, returns NULL.  The caller must not change the returned
   value. */
char *
session_env_getenv_or_default (session_env_t se, const char *name,
                               int *r_default)
{
  int idx;
  char *defvalue;

  if (r_default)
    *r_default = 0;
  if (!se || !name || !*name)
    return NULL;

  for (idx=0; idx < se->arrayused; idx++)
    if (se->array[idx] && !strcmp (se->array[idx]->name, name))
      {
        if (r_default && se->array[idx]->is_default)
          *r_default = 1;
        return se->array[idx]->value;
      }

  /* Get the default value with an additional fallback for GPG_TTY.  */
  defvalue = getenv (name);
  if ((!defvalue || !*defvalue) && !strcmp (name, "GPG_TTY")
      && gnupg_ttyname (0))
    {
      defvalue = gnupg_ttyname (0);
    }
  if (defvalue)
    {
      /* Record the default value for later use so that we are safe
         from later modifications of the environment.  We need to take
         a copy to better cope with the rules of putenv(3).  We ignore
         the error of the update function because we can't return an
         explicit error anyway and the following scan would then fail
         anyway. */
      update_var (se, name, strlen (name), defvalue, 1);

      for (idx=0; idx < se->arrayused; idx++)
        if (se->array[idx] && !strcmp (se->array[idx]->name, name))
          {
            if (r_default && se->array[idx]->is_default)
              *r_default = 1;
            return se->array[idx]->value;
          }
    }

  return NULL;
}


/* List the entire environment stored in SE.  The caller initially
   needs to set the value of ITERATOR to 0 and then call this function
   until it returns NULL.  The value is returned at R_VALUE.  If
   R_DEFAULT is not NULL, the default flag is stored on return.  The
   default flag indicates that the value has been taken from the
   process' environment.  The caller must not change the returned
   name or value.  */
char *
session_env_listenv (session_env_t se, int *iterator,
                     const char **r_value, int *r_default)
{
  int idx = *iterator;

  if (!se || idx < 0)
    return NULL;

  for (; idx < se->arrayused; idx++)
    if (se->array[idx])
      {
        *iterator = idx+1;
        if (r_default)
          *r_default = se->array[idx]->is_default;
        if (r_value)
          *r_value = se->array[idx]->value;
        return se->array[idx]->name;
      }
  return NULL;
}
