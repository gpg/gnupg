/* gpgconf-comp.c - Configuration utility for GnuPG.
   Copyright (C) 2003 g10 Code GmbH

   This file is part of GnuPG.
 
   GnuPG is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
 
   GnuPG is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with GnuPG; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
/* FIXME use gettext.h */
#include <libintl.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <time.h>

#include <error.h>

#include "gpgconf.h"


/* TODO:
   Portability - Add gnulib replacements for getline, error, etc.
   Backend: File backend must be able to write out changes !!!
   Components: Add more components and their options.
   Robustness: Do more validation.  Call programs to do validation for us.
*/


/* Backend configuration.  Backends are used to decide how the default
   and current value of an option can be determined, and how the
   option can be changed.  To every option in every component belongs
   exactly one backend that controls and determines the option.  Some
   backends are programs from the GPG system.  Others might be
   implemented by GPGConf itself.  If you change this enum, don't
   forget to update GC_BACKEND below.  */
typedef enum
  {
    /* Any backend, used for find_option ().  */
    GC_BACKEND_ANY,

    /* The Gnu Privacy Guard.  */
    GC_BACKEND_GPG,

    /* The Gnu Privacy Guard for S/MIME.  */
    GC_BACKEND_GPGSM,

    /* The GPG Agent.  */
    GC_BACKEND_GPG_AGENT,

    /* The Aegypten directory manager.  */
    GC_BACKEND_DIRMNGR,

    /* The LDAP server list file for the Aegypten director manager.  */
    GC_BACKEND_DIRMNGR_LDAP_SERVER_LIST,

    /* The number of the above entries.  */
    GC_BACKEND_NR
  } gc_backend_t;


/* To be able to implement generic algorithms for the various
   backends, we collect all information about them in this struct.  */
static struct
{
  /* The name of the backend.  */
  const char *name;

  /* The name of the program that acts as the backend.  Some backends
     don't have an associated program, but are implemented directly by
     GPGConf.  In this case, PROGRAM is NULL.  */
  char *program;

  /* The option name for the configuration filename of this backend.
     This must be an absolute pathname.  It can be an option from a
     different backend (but then ordering of the options might
     matter).  */
  const char *option_config_filename;

  /* If this is a file backend rather than a program backend, then
     this is the name of the option associated with the file.  */
  const char *option_name;
} gc_backend[GC_BACKEND_NR] =
  {
    { NULL, NULL, NULL },		/* GC_BACKEND_ANY dummy entry.  */
    { "GnuPG", "gpg", "gpgconf-config-file" },
    { "GPGSM", "gpgsm", "gpgconf-config-file" },
    { "GPG Agent", "gpg-agent", "gpgconf-config-file" },
    { "DirMngr", "dirmngr", "gpgconf-config-file" },
    { "DirMngr LDAP Server List", NULL, "ldapserverlist-file", "LDAP Server" },
  };


/* Option configuration.  */

/* An option might take an argument, or not.  Argument types can be
   basic or complex.  Basic types are generic and easy to validate.
   Complex types provide more specific information about the intended
   use, but can be difficult to validate.  If you add to this enum,
   don't forget to update GC_ARG_TYPE below.  YOU MUST NOT CHANGE THE
   NUMBERS OF THE EXISTING ENTRIES, AS THEY ARE PART OF THE EXTERNAL
   INTERFACE.  */
typedef enum
  {
    /* Basic argument types.  */

    /* No argument.  */
    GC_ARG_TYPE_NONE = 0,

    /* A String argument.  */
    GC_ARG_TYPE_STRING = 1,

    /* A signed integer argument.  */
    GC_ARG_TYPE_INT32 = 2,

    /* An unsigned integer argument.  */
    GC_ARG_TYPE_UINT32 = 3,


    /* Complex argument types.  */

    /* A complete pathname.  */
    GC_ARG_TYPE_PATHNAME = 4,

    /* An LDAP server in the format
       HOSTNAME:PORT:USERNAME:PASSWORD:BASE_DN.  */
    GC_ARG_TYPE_LDAP_SERVER = 5,

    /* A 40 character fingerprint.  */
    GC_ARG_TYPE_KEY_FPR = 6,

    /* ADD NEW ENTRIES HERE.  */

    /* The number of the above entries.  */
    GC_ARG_TYPE_NR
  } gc_arg_type_t;


/* For every argument, we record some information about it in the
   following struct.  */
static struct
{
  /* For every argument type exists a basic argument type that can be
     used as a fallback for input and validation purposes.  */
  gc_arg_type_t fallback;

  /* Human-readable name of the type.  */
  const char *name;
} gc_arg_type[GC_ARG_TYPE_NR] =
  {
    /* The basic argument types have their own types as fallback.  */
    { GC_ARG_TYPE_NONE, "none" },
    { GC_ARG_TYPE_STRING, "string" },
    { GC_ARG_TYPE_INT32, "int32" },
    { GC_ARG_TYPE_UINT32, "uint32" },

    /* The complex argument types have a basic type as fallback.  */
    { GC_ARG_TYPE_STRING, "pathname" },
    { GC_ARG_TYPE_STRING, "ldap server" },
    { GC_ARG_TYPE_STRING, "key fpr" },
  };


/* Every option has an associated expert level, than can be used to
   hide advanced and expert options from beginners.  If you add to
   this list, don't forget to update GC_LEVEL below.  YOU MUST NOT
   CHANGE THE NUMBERS OF THE EXISTING ENTRIES, AS THEY ARE PART OF THE
   EXTERNAL INTERFACE.  */
typedef enum
  {
    /* The basic options should always be displayed.  */
    GC_LEVEL_BASIC,

    /* The advanced options may be hidden from beginners.  */
    GC_LEVEL_ADVANCED,

    /* The expert options should only be displayed to experts.  */
    GC_LEVEL_EXPERT,

    /* The invisible options should normally never be displayed.  */
    GC_LEVEL_INVISIBLE,

    /* The internal options are never exported, they mark options that
       are recorded for internal use only.  */
    GC_LEVEL_INTERNAL,

    /* ADD NEW ENTRIES HERE.  */

    /* The number of the above entries.  */
    GC_LEVEL_NR
  } gc_expert_level_t;

/* A description for each expert level.  */
static struct
{
  const char *name;
} gc_level[] =
  {
    { "basic" },
    { "advanced" },
    { "expert" },
    { "invisible" },
    { "internal" }
  };


/* Option flags.  YOU MUST NOT CHANGE THE NUMBERS OF THE EXISTING
   FLAGS, AS THEY ARE PART OF THE EXTERNAL INTERFACE.  */
#define GC_OPT_FLAG_NONE	0
/* Some entries in the option list are not options, but mark the
   beginning of a new group of options.  These entries have the GROUP
   flag set.  */
#define GC_OPT_FLAG_GROUP	(1 << 0)
/* The ARG_OPT flag for an option indicates that the argument is
   optional.  */
#define GC_OPT_FLAG_ARG_OPT	(1 << 1)
/* The LIST flag for an option indicates that the option can occur
   several times.  A comma separated list of arguments is used as the
   argument value.  */
#define GC_OPT_FLAG_LIST	(1 << 2)
/* The RUNTIME flag for an option indicates that the option can be
   changed at runtime.  */
#define GC_OPT_FLAG_RUNTIME	(1 << 3)

/* A human-readable description for each flag.  */
static struct
{
  const char *name;
} gc_flag[] =
  {
    { "group" },
    { "optional arg" },
    { "list" },
    { "runtime" }
  };


/* To each option, or group marker, the information in the GC_OPTION
   struct is provided.  If you change this, don't forget to update the
   option list of each component.  */
struct gc_option
{
  /* If this is NULL, then this is a terminator in an array of unknown
     length.  Otherwise, if this entry is a group marker (see FLAGS),
     then this is the name of the group described by this entry.
     Otherwise it is the name of the option described by this
     entry.  The name must not contain a colon.  */
  const char *name;

  /* The option flags.  If the GROUP flag is set, then this entry is a
     group marker, not an option, and only the fields LEVEL,
     DESC_DOMAIN and DESC are valid.  In all other cases, this entry
     describes a new option and all fields are valid.  */
  unsigned int flags;

  /* The expert level.  This field is valid for options and groups.  A
     group has the expert level of the lowest-level option in the
     group.  */
  gc_expert_level_t level;

  /* A gettext domain in which the following description can be found.
     If this is NULL, then DESC is not translated.  Valid for groups
     and options.  */
  const char *desc_domain;

  /* A gettext description for this group or option.  If it starts
     with a '|', then the string up to the next '|' describes the
     argument, and the description follows the second '|'.  */
  const char *desc;

  /* The following fields are only valid for options.  */

  /* The type of the option argument.  */
  gc_arg_type_t arg_type;

  /* The backend that implements this option.  */
  gc_backend_t backend;

  /* The following fields are set to NULL at startup (because all
     option's are declared as static variables).  They are at the end
     of the list so that they can be omitted from the option
     declarations.  */

  /* The default value for this option.  This is NULL if the option is
     not present in the backend, the empty string if no default is
     available, and otherwise a quoted string.  */
  char *default_value;

  /* The current value of this option.  */
  char *value;

  /* The new value of this option.  */
  char *new_value;
};
typedef struct gc_option gc_option_t;

/* Use this macro to terminate an option list.  */
#define GC_OPTION_NULL { NULL }


/* The options of the GC_COMPONENT_GPG_AGENT component.  */
static gc_option_t gc_options_gpg_agent[] =
 {
   GC_OPTION_NULL
 };


/* The options of the GC_COMPONENT_DIRMNGR component.  */
static gc_option_t gc_options_dirmngr[] =
 {
   /* The configuration file to which we write the changes.  */
   { "gpgconf-config-file", GC_OPT_FLAG_NONE, GC_LEVEL_INTERNAL,
     NULL, NULL, GC_ARG_TYPE_PATHNAME, GC_BACKEND_DIRMNGR },

   { "Monitor",
     GC_OPT_FLAG_GROUP, GC_LEVEL_BASIC,
     NULL, "Options controlling the diagnostic output" },
   { "verbose", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "dirmngr", "verbose",
     GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },
   { "quiet", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "dirmngr", "be somewhat more quiet",
     GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },
   { "no-greeting", GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE,
     NULL, NULL,
     GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },

   { "Format",
     GC_OPT_FLAG_GROUP, GC_LEVEL_BASIC,
     NULL, "Options controlling the format of the output" },
   { "sh", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "dirmngr", "sh-style command output",
     GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },
   { "csh", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "dirmngr", "csh-style command output",
     GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },
   
   { "Configuration",
     GC_OPT_FLAG_GROUP, GC_LEVEL_EXPERT,
     NULL, "Options controlling the configuration" },
   { "options", GC_OPT_FLAG_NONE, GC_LEVEL_EXPERT,
     "dirmngr", "|FILE|read options from FILE",
     GC_ARG_TYPE_PATHNAME, GC_BACKEND_DIRMNGR },

   { "Debug",
     GC_OPT_FLAG_GROUP, GC_LEVEL_ADVANCED,
     "dirmngr", "Options useful for debugging" },
   { "debug", GC_OPT_FLAG_ARG_OPT, GC_LEVEL_ADVANCED,
     "dirmngr", "|FLAGS|set the debugging FLAGS",
     GC_ARG_TYPE_UINT32, GC_BACKEND_DIRMNGR },
   { "debug-all", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
     "dirmngr", "set all debugging flags",
     GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },
   { "no-detach", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
     "dirmngr", "do not detach from the console",
     GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },
   { "log-file", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
     "dirmngr", "|FILE|write logs to FILE",
     GC_ARG_TYPE_PATHNAME, GC_BACKEND_DIRMNGR },
   { "debug-wait", GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE,
     NULL, NULL,
     GC_ARG_TYPE_UINT32, GC_BACKEND_DIRMNGR },
   { "faked-system-time", GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE,
     NULL, NULL,
     GC_ARG_TYPE_UINT32, GC_BACKEND_DIRMNGR },

   { "Enforcement",
     GC_OPT_FLAG_GROUP, GC_LEVEL_BASIC,
     NULL, "Options controlling the interactivity and enforcement" },
   { "batch", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "dirmngr", "run without asking a user",
     GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },
   { "force", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "dirmngr", "force loading of outdated CRLs",
     GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },

   { "LDAP",
     GC_OPT_FLAG_GROUP, GC_LEVEL_BASIC,
     NULL, "Configuration of LDAP servers to use" },
   { "add-servers", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "dirmngr", "add new servers discovered in CRL distribution points"
     " to serverlist", GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },
   { "ldaptimeout", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "dirmngr", "|N|set LDAP timeout to N seconds",
     GC_ARG_TYPE_UINT32, GC_BACKEND_DIRMNGR },
   /* The following entry must not be removed, as it is required for
      the GC_BACKEND_DIRMNGR_LDAP_SERVER_LIST.  */
   { "ldapserverlist-file",
     GC_OPT_FLAG_NONE, GC_LEVEL_INTERNAL,
     "dirmngr", "|FILE|read LDAP server list from FILE",
     GC_ARG_TYPE_PATHNAME, GC_BACKEND_DIRMNGR },
   /* This entry must come after at least one entry for
      GC_BACKEND_DIRMNGR in this component, so that the entry for
      "ldapserverlist-file will be initialized before this one.  */
   { "LDAP Server", GC_OPT_FLAG_LIST, GC_LEVEL_BASIC,
     NULL, "LDAP server list",
     GC_ARG_TYPE_LDAP_SERVER, GC_BACKEND_DIRMNGR_LDAP_SERVER_LIST },

   { "CRL",
     GC_OPT_FLAG_GROUP, GC_LEVEL_BASIC,
     NULL, "Configuration of the CRL" },
   { "max-replies", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "dirmngr", "|N|do not return more than N items in one query",
     GC_ARG_TYPE_UINT32, GC_BACKEND_DIRMNGR },

   GC_OPTION_NULL
 };


/* Component system.  Each component is a set of options that can be
   configured at the same time.  If you change this, don't forget to
   update GC_COMPONENT below.  */
typedef enum
  {
    /* The GPG Agent.  */
    GC_COMPONENT_GPG_AGENT,

    /* The LDAP Directory Manager for CRLs.  */
    GC_COMPONENT_DIRMNGR,

    /* The number of components.  */
    GC_COMPONENT_NR
  } gc_component_t;


/* The information associated with each component.  */
static struct
{
  /* The name of this component.  Must not contain a colon (':')
     character.  */
  const char *name;

  /* The gettext domain for the description DESC.  If this is NULL,
     then the description is not translated.  */
  const char *desc_domain;

  /* The description for this domain.  */
  const char *desc;

  /* The list of options for this component, terminated by
     GC_OPTION_NULL.  */
  gc_option_t *options;
} gc_component[] =
  {
    { "gpg-agent", NULL, "GPG Agent", gc_options_gpg_agent },
    { "dirmngr", NULL, "CRL Manager", gc_options_dirmngr }
  };


/* Robust version of dgettext.  */
static const char *
my_dgettext (const char *domain, const char *msgid)
{
  if (domain)
    {
      char *text = dgettext (domain, msgid);
      return text ? text : msgid;
    }
  else
    return msgid;
}


/* Percent-Escape special characters.  The string is valid until the
   next invocation of the function.  */
static char *
percent_escape (const char *src)
{
  static char *esc_str;
  static int esc_str_len;
  int new_len = 3 * strlen (src) + 1;
  char *dst;

  if (esc_str_len < new_len)
    {
      char *new_esc_str = realloc (esc_str, new_len);
      if (!new_esc_str)
	error (1, 1, "Can not escape string");
      esc_str = new_esc_str;
      esc_str_len = new_len;
    }

  dst = esc_str;
  while (*src)
    {
      if (*src == '%')
	{
	  *(dst++) = '%';
	  *(dst++) = '2';
	  *(dst++) = '5';
	}	  
      else if (*src == ':')
	{
	  /* The colon is used as field separator.  */
	  *(dst++) = '%';
	  *(dst++) = '3';
	  *(dst++) = 'a';
	}
      else if (*src == ',')
	{
	  /* The comma is used as list separator.  */
	  *(dst++) = '%';
	  *(dst++) = '2';
	  *(dst++) = 'c';
	}
      else
	*(dst++) = *(src);
      src++;
    }
  *dst = '\0';
  return esc_str;
}



/* List all components that are available.  */
void
gc_component_list_components (FILE *out)
{
  gc_component_t idx;

  for (idx = 0; idx < GC_COMPONENT_NR; idx++)
    {
      const char *desc = gc_component[idx].desc;
      desc = my_dgettext (gc_component[idx].desc_domain, desc);
      fprintf (out, "%s:%s\n", gc_component[idx].name, percent_escape (desc));
    }
}


/* Find the component with the name NAME.  Returns -1 if not
   found.  */
int
gc_component_find (const char *name)
{
  gc_component_t idx;

  for (idx = 0; idx < GC_COMPONENT_NR; idx++)
    {
      if (!strcmp (name, gc_component[idx].name))
	return idx;
    }
  return -1;
}


/* List all options of the component COMPONENT.  */
void
gc_component_list_options (int component, FILE *out)
{  
  const gc_option_t *option = gc_component[component].options;

  while (option->name)
    {
      const char *desc = NULL;
      char *arg_name = NULL;

      /* Do not output unknown or internal options.  */
      if (!option->default_value || option->level == GC_LEVEL_INTERNAL)
	{
	  option++;
	  continue;
	}

      if (option->desc)
	{
	  desc = my_dgettext (option->desc_domain, option->desc);

	  if (*desc == '|')
	    {
	      const char *arg_tail = strchr (&desc[1], '|');

	      if (arg_tail)
		{
		  int arg_len = arg_tail - &desc[1];
		  arg_name = malloc (arg_len + 1);
		  if (!arg_name)
		    error (1, 1, "Can not build argument name");
		  memcpy (arg_name, &desc[1], arg_len);
		  arg_name[arg_len] = '\0';
		  desc = arg_tail + 1;
		}
	    }
	}

      /* YOU MUST NOT REORDER THE FIELDS IN THIS OUTPUT, AS THEIR
	 ORDER IS PART OF THE EXTERNAL INTERFACE.  YOU MUST NOT REMOVE
	 ANY FIELDS.  */

      /* The name field.  */
      fprintf (out, "%s", option->name);

      /* The flags field.  */
      fprintf (out, ":%u", option->flags);
      if (opt.verbose)
	{
	  putc (' ', out);
	  
	  if (!option->flags)
	    fprintf (out, "none");
	  else
	    {
	      unsigned int flags = option->flags;
	      unsigned int flag = 0;
	      unsigned int first = 1;

	      while (flags)
		{
		  if (flags & 1)
		    {
		      if (first)
			first = 0;
		      else
			putc (',', out);
		      fprintf (out, "%s", gc_flag[flag].name);
		    }
		  flags >>= 1;
		  flag++;
		}
	    }
	}

      /* The level field.  */
      fprintf (out, ":%u", option->level);
      if (opt.verbose)
	fprintf (out, " %s", gc_level[option->level].name);

      /* The description field.  */
      fprintf (out, ":%s", desc ? percent_escape (desc) : "");

      /* The type field.  */
      fprintf (out, ":%u", option->arg_type);
      if (opt.verbose)
	fprintf (out, " %s", gc_arg_type[option->arg_type].name);

      /* The alternate type field.  */
      fprintf (out, ":%u", gc_arg_type[option->arg_type].fallback);
      if (opt.verbose)
	fprintf (out, " %s",
		 gc_arg_type[gc_arg_type[option->arg_type].fallback].name);

      /* The argument name field.  */
      fprintf (out, ":%s", arg_name ? percent_escape (arg_name) : "");
      if (arg_name)
	free (arg_name);

      /* The default value field.  */
      fprintf (out, ":%s", option->default_value ? option->default_value : "");

      /* The value field.  */
      fprintf (out, ":%s", option->value ? option->value : "");

      /* ADD NEW FIELDS HERE.  */

      putc ('\n', out);
      option++;
    }
}


/* Find the option NAME in component COMPONENT, for the backend
   BACKEND.  If BACKEND is GC_BACKEND_ANY, any backend will match.  */
static gc_option_t *
find_option (gc_component_t component, const char *name,
	     gc_backend_t backend)
{
  gc_option_t *option = gc_component[component].options;
  while (option->name)
    {
      if (!(option->flags & GC_OPT_FLAG_GROUP)
	  && !strcmp (option->name, name)
	  && (backend == GC_BACKEND_ANY || option->backend == backend))
	break;
      option++;
    }
  return option->name ? option : NULL;
}


/* Determine the configuration pathname for the component COMPONENT
   and backend BACKEND.  */
static char *
get_config_pathname (gc_component_t component, gc_backend_t backend)
{
  char *pathname;
  gc_option_t *option = find_option
    (component, gc_backend[backend].option_config_filename, GC_BACKEND_ANY);
  assert (option);

  if (!option->default_value)
    error (1, 0, "Option %s, needed by backend %s, was not initialized",
	   gc_backend[backend].option_config_filename,
	   gc_backend[backend].name);
  if (*option->value)
    pathname = option->value;
  else
    pathname = option->default_value;

  if (*pathname != '/')
    error (1, 0, "Option %s, needed by backend %s, is not absolute",
	   gc_backend[backend].option_config_filename,
	   gc_backend[backend].name);

  return pathname;
}


/* Retrieve the options for the component COMPONENT from backend
   BACKEND, which we already know is a program-type backend.  */
static void
retrieve_options_from_program (gc_component_t component, gc_backend_t backend)
{
  char *cmd_line;
  char *line = NULL;
  size_t line_len = 0;
  ssize_t length;
  FILE *output;

  asprintf (&cmd_line, "%s --gpgconf-list", gc_backend[backend].program);
  if (!cmd_line)
    error (1, 1, "Can not construct command line");

  output = popen (cmd_line, "r");
  if (!output)
    error (1, 1, "Could not gather active options from %s", cmd_line);

  while ((length = getline (&line, &line_len, output)) > 0)
    {
      gc_option_t *option;
      char *default_value;
      char *value;

      /* Strip newline and carriage return, if present.  */
      while (length > 0
	     && (line[length - 1] == '\n' || line[length - 1] == '\r'))
	line[--length] = '\0';

      /* Extract default value and value, if present.  Default to
	 empty if not.  */
      default_value = strchr (line, ':');
      if (!default_value)
	{
	  default_value = "";
	  value = "";
	}
      else
	{
	  *(default_value++) = '\0';
	  value = strchr (default_value, ':');
	  if (!value)
	    value = "";
	  else
	    {
	      char *end;

	      *(value++) = '\0';
	      end = strchr (value, ':');
	      if (end)
		*end = '\0';
	    }
	}

      /* Look up the option in the component and install the
	 configuration data.  */
      option = find_option (component, line, backend);
      if (option)
	{
	  if (option->default_value)
	    error (1, 1, "Option %s returned twice from %s",
		   line, cmd_line);
	  option->default_value = strdup (default_value);
	  option->value = strdup (value);
	  if (!option->default_value || !option->value)
	    error (1, 1, "Could not store options");
	}
    }
  if (ferror (output))
    error (1, 1, "Error reading from %s", cmd_line);
  if (fclose (output) && ferror (output))
    error (1, 1, "Error closing %s", cmd_line);
  free (cmd_line);
}


/* Retrieve the options for the component COMPONENT from backend
   BACKEND, which we already know is of type file list.  */ 
static void
retrieve_options_from_file (gc_component_t component, gc_backend_t backend)
{
  gc_option_t *list_option;
  char *list_pathname;
  FILE *list_file;
  char *line = NULL;
  size_t line_len = 0;
  ssize_t length;
  char *list;

  list_option = find_option (component,
			     gc_backend[backend].option_name, GC_BACKEND_ANY);
  assert (list_option);

  list_pathname = get_config_pathname (component, backend);

  list_file = fopen (list_pathname, "r");
  if (ferror (list_file))
    error (1, 1, "Can not open list file %s", list_pathname);

  list = strdup ("\"");
  if (!list)
    error (1, 1, "Can not allocate initial list string");

  while ((length = getline (&line, &line_len, list_file)) > 0)
    {
      char *start;
      char *end;
      char *new_list;

      start = line;
      while (*start == ' ' || *start == '\t')
	start++;
      if (!*start || *start == '#' || *start == '\r' || *start == '\n')
	continue;

      end = start;
      while (*end && *end != '#' && *end != '\r' && *end != '\n')
	end++;
      /* Walk back to skip trailing white spaces.  Looks evil, but
	 works because of the conditions on START and END imposed
	 at this point (END is at least START + 1, and START is
	 not a whitespace character).  */
      while (*(end - 1) == ' ' || *(end - 1) == '\t')
	end--;
      *end = '\0';
      /* FIXME: Oh, no!  This is so lame!  Use realloc and really
	 append.  */
      if (list)
	{
	  asprintf (&new_list, "%s,%s", list, percent_escape (start));
	  free (list);
	  list = new_list;
	}
      if (!list)
	error (1, 1, "Can not construct list");
    }
  if (ferror (list_file))
    error (1, 1, "Can not read list file %s", list_pathname);
  list_option->default_value = "";
  list_option->value = list;
}


/* Retrieve the currently active options and their defaults from all
   involved backends for this component.  */
void
gc_component_retrieve_options (int component)
{
  int backend_seen[GC_BACKEND_NR];
  gc_backend_t backend;
  gc_option_t *option = gc_component[component].options;

  for (backend = 0; backend < GC_BACKEND_NR; backend++)
    backend_seen[backend] = 0;

  while (option->name)
    {
      if (!(option->flags & GC_OPT_FLAG_GROUP))
	{
	  backend = option->backend;

	  if (backend_seen[backend])
	    {
	      option++;
	      continue;
	    }
	  backend_seen[backend] = 1;

	  assert (backend != GC_BACKEND_ANY);

	  if (gc_backend[backend].program)
	    retrieve_options_from_program (component, backend);
	  else
	    retrieve_options_from_file (component, backend);
	}
      option++;
    }
}


/* Perform a simple validity check based on the type.  */
static void
option_check_validity (gc_option_t *option, const char *new_value)
{
  if (option->new_value)
    error (1, 0, "Option %s already changed", option->name);

  if (!*new_value)
    return;

  /* FIXME.  Verify that lists are lists, numbers are numbers, strings
     are strings, etc.  */
}


/* Create and verify the new configuration file for the specified
   backend and component.  Returns 0 on success and -1 on error.  */
static int
change_options_file (gc_component_t component, gc_backend_t backend,
		     char **src_filenamep, char **dest_filenamep,
		     char **orig_filenamep)
{
  /* FIXME.  */
  assert (!"Not implemented.");
  return -1;
}


/* Create and verify the new configuration file for the specified
   backend and component.  Returns 0 on success and -1 on error.  */
static int
change_options_program (gc_component_t component, gc_backend_t backend,
			char **src_filenamep, char **dest_filenamep,
			char **orig_filenamep)
{
  static const char marker[] = "###+++--- GPGConf ---+++###";
  /* True if we are within the marker in the config file.  */
  int in_marker = 0;
  gc_option_t *option;
#define LINE_LEN 4096
  char line[LINE_LEN];
  int res;
  int fd;
  FILE *src_file = NULL;
  FILE *dest_file = NULL;
  char *src_filename;
  char *dest_filename;
  char *orig_filename;

  /* FIXME.  Throughout the function, do better error reporting.  */
  dest_filename = strdup (get_config_pathname (component, backend));
  if (!dest_filename)
    return -1;
  asprintf (&src_filename, "%s.gpgconf.%i.new", dest_filename, getpid ());
  if (!src_filename)
    return -1;
  asprintf (&orig_filename, "%s.gpgconf.%i.bak", dest_filename, getpid ());
  if (!orig_filename)
    return -1;

  res = link (dest_filename, orig_filename);
  if (res < 0 && errno != ENOENT)
    return -1;
  if (res < 0)
    {
      free (orig_filename);
      orig_filename = NULL;
    }
  /* We now initialize the return strings, so the caller can do the
     cleanup for us.  */
  *src_filenamep = src_filename;
  *dest_filenamep = dest_filename;
  *orig_filenamep = orig_filename;

  /* Use open() so that we can use O_EXCL.  */
  fd = open (src_filename, O_CREAT | O_EXCL | O_WRONLY, 0644);
  if (fd < 0)
    return -1;
  src_file = fdopen (fd, "w");
  res = errno;
  if (!src_file)
    {
      errno = res;
      return -1;
    }

  /* Only if ORIG_FILENAME is not NULL did the configuration file
     exist already.  In this case, we will copy its content into the
     new configuration file, changing it to our liking in the
     process.  */
  if (orig_filename)
    {
      dest_file = fopen (dest_filename, "r");
      if (!dest_file)
	goto change_one_err;

      while (fgets (line, LINE_LEN, dest_file))
	{
	  int length;
	  int disable = 0;
	  char *start;
	  char *end;

	  line[LINE_LEN - 1] = '\0';
	  length = strlen (line);
	  if (length == LINE_LEN - 1)
	    {
	      /* FIXME */
	      errno = ENAMETOOLONG;
	      goto change_one_err;
	    }

	  if (!strncmp (marker, line, sizeof (marker) - 1))
	    {
	      if (!in_marker)
		in_marker = 1;
	      else
		break;
	    }

	  start = line;
	  while (*start == ' ' || *start == '\t')
	    start++;
	  if (*start && *start != '\r' && *start != '\n' && *start != '#')
	    {
	      char saved_end;

	      end = start;
	      while (*end && *end != ' ' && *end != '\t'
		     && *end != '\r' && *end != '\n' && *end != '#')
		end++;
	      saved_end = *end;
	      *end = '\0';

	      option = find_option (component, start, backend);
	      *end = saved_end;
	      if (option && option->new_value)
		disable = 1;
	    }
	  if (disable)
	    {
	      if (!in_marker)
		{
		  fprintf (src_file,
			   "# GPGConf disabled this option here at FIXME\n");
		  if (ferror (src_file))
		    goto change_one_err;
		  fprintf (src_file, "# %s", line);
		  if (ferror (src_file))
		    goto change_one_err;
		}
	    }
	  else
	    {
	      fprintf (src_file, "%s", line);
	      if (ferror (src_file))
		goto change_one_err;
	    }
	}
      if (ferror (dest_file))
	goto change_one_err;
    }

  if (!in_marker)
    {
      /* There was no marker.  This is the first time we edit the
	 file.  We add our own marker at the end of the file and
	 proceed.  Note that we first write a newline, this guards us
	 against files which lack the newline at the end of the last
	 line, while it doesn't hurt us in all other cases.  */
      fprintf (src_file, "\n%s\n", marker);
      if (ferror (src_file))
	goto change_one_err;
    }
  /* At this point, we have copied everything up to the end marker
     into the new file, except for the options we are going to change.
     Now, dump the changed options (except for those we are going to
     revert to their default), and write the end marker, possibly
     followed by the rest of the original file.  */
  option = gc_component[component].options;
  while (option->name)
    {
      if (!(option->flags & GC_OPT_FLAG_GROUP)
	  && option->backend == backend
	  && option->new_value
	  && *option->new_value)
	{
	  if (gc_arg_type[option->arg_type].fallback == GC_ARG_TYPE_STRING)
	    fprintf (src_file, "%s %s\n", option->name, &option->new_value[1]);
	  else if (option->arg_type == GC_ARG_TYPE_NONE)
	    fprintf (src_file, "%s\n", option->name);
	  else
	    fprintf (src_file, "%s %s\n", option->name, option->new_value);
	  if (ferror (src_file))
	    goto change_one_err;
	}
      option++;
    }
  {
    time_t cur_time = time (NULL);
    
    /* asctime() returns a string that ends with a newline
       character!  */
    fprintf (src_file, "%s %s", marker, asctime (localtime (&cur_time)));
    if (ferror (src_file))
      goto change_one_err;
  }
  if (!in_marker)
    {
      fprintf (src_file, "# GPGConf edited this configuration file.\n");
      if (ferror (src_file))
	goto change_one_err;
      fprintf (src_file, "# It will disable options before this marked "
	       "block, but it will\n");
      if (ferror (src_file))
	goto change_one_err;
      fprintf (src_file, "# never change anything below these lines.\n");
      if (ferror (src_file))
	goto change_one_err;
    }
  if (dest_file)
    {
      while (fgets (line, LINE_LEN, dest_file))
	{
	  int length;

	  line[LINE_LEN - 1] = '\0';
	  length = strlen (line);
	  if (length == LINE_LEN - 1)
	    {
	      /* FIXME */
	      errno = ENAMETOOLONG;
	      goto change_one_err;
	    }
	  fprintf (src_file, "%s", line);
	  if (ferror (src_file))
	    goto change_one_err;
	}
      if (ferror (dest_file))
	goto change_one_err;
    }
  res = fclose (src_file);
  if (res)
    {
      res = errno;
      close (fd);
      if (dest_file)
	fclose (dest_file);
      errno = res;
      return -1;
    }
  close (fd);
  if (dest_file)
    {
      res = fclose (dest_file);
      if (res)
	return -1;
    }
  return 0;

 change_one_err:
  res = errno;
  if (src_file)
    {
      fclose (src_file);
      close (fd);
    }
  if (dest_file)
    fclose (dest_file);
  errno = res;
  return -1;
}

/* Read the modifications from IN and apply them.  */
void
gc_component_change_options (int component, FILE *in)
{
  int err = 0;
  char *src_pathname[GC_BACKEND_NR];
  char *dest_pathname[GC_BACKEND_NR];
  char *orig_pathname[GC_BACKEND_NR];
  gc_backend_t backend;
  gc_option_t *option;
  char *line = NULL;
  size_t line_len = 0;
  ssize_t length;

  for (backend = 0; backend < GC_BACKEND_NR; backend++)
    {
      src_pathname[backend] = NULL;
      dest_pathname[backend] = NULL;
      orig_pathname[backend] = NULL;
    }

  while ((length = getline (&line, &line_len, in)) > 0)
    {
      char *value;

      /* Strip newline and carriage return, if present.  */
      while (length > 0
	     && (line[length - 1] == '\n' || line[length - 1] == '\r'))
	line[--length] = '\0';

      value = strchr (line, ':');
      if (!value)
	value = "";
      else
	{
	  char *end;

	  *(value++) = '\0';
	  end = strchr (value, ':');
	  if (end)
	    *end = '\0';
	}

      option = find_option (component, line, GC_BACKEND_ANY);
      if (!option)
	error (1, 0, "Unknown option %s", line);

      option_check_validity (option, value);
      option->new_value = strdup (value);
    }

  /* Now that we have collected and locally verified the changes,
     write them out to new configuration files, verify them
     externally, and then commit them.  */
  option = gc_component[component].options;
  while (option->name)
    {
      /* Go on if we have already seen this backend, or if there is
	 nothing to do.  */
      if (src_pathname[option->backend] || !option->new_value)
	{
	  option++;
	  continue;
	}

      if (gc_backend[option->backend].program)
	err = change_options_program (component, option->backend,
				      &src_pathname[component],
				      &dest_pathname[component],
				      &orig_pathname[component]);
      else
	err = change_options_file (component, option->backend,
				   &src_pathname[component],
				   &dest_pathname[component],
				   &orig_pathname[component]);
	
      if (err)
	break;
	  
      option++;
    }
  if (!err)
    {
      int i;

      for (i = 0; i < GC_COMPONENT_NR; i++)
	{
	  if (src_pathname[i])
	    {
	      /* FIXME: Make a verification here.  */

	      assert (dest_pathname[i]);

	      if (orig_pathname[i])
		err = rename (src_pathname[i], dest_pathname[i]);
	      else
		{
		  /* This is a bit safer than rename() because we
		     expect DEST_PATHNAME not to be there.  If it
		     happens to be there, this will fail.  */
		  err = link (src_pathname[i], dest_pathname[i]);
		  if (!err)
		    unlink (src_pathname[i]);
		}
	      if (err)
		break;
	      src_pathname[i] = NULL;
	    }
	}
    }

  if (err)
    {
      int i;
      int res = errno;

      /* An error occured.  */
      for (i = 0; i < GC_COMPONENT_NR; i++)
	{
	  if (src_pathname[i])
	    {
	      /* The change was not yet committed.  */
	      unlink (src_pathname[i]);
	      if (orig_pathname[i])
		unlink (orig_pathname[i]);
	    }
	  else
	    {
	      /* The changes were already committed.  FIXME: This is a
		 tad dangerous, as we don't know if we don't overwrite
		 a version of the file that is even newer than the one
		 we just installed.  */
	      if (orig_pathname[i])
		rename (orig_pathname[i], dest_pathname[i]);
	      else
		unlink (dest_pathname[i]);
	    }
	}
      errno = res;
      error (1, 1, "Could not commit changes");
    }
}
