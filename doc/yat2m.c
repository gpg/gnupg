/* yat2m.c - Yet Another Texi 2 Man converter
 *	Copyright (C) 2005 g10 Code GmbH
 *      Copyright (C) 2006 2006 Free Software Foundation, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
    This is a simple textinfo to man page converter.  It needs some
    special markup in th e texinfo and tries best to get a create man
    page.  It has been designed for the GnuPG man pages and thus only
    a few texinfo commands are supported.

    To use this you need to add the following macros into your texinfo
    source:

      @macro manpage {a}
      @end macro
      @macro mansect {a}
      @end macro
      @macro manpause 
      @end macro
      @macro mancont
      @end macro
      
    They are used by yat2m to select parts of the Texinfo which should
    go into the man page. These macros need to be used without leading
    left space. Processing starts after a "manpage" macro has been
    seen.  "mansect" identifies the section and yat2m make sure to
    emit the sections in the proper order.  Note that @mansect skips
    the next input line if that line begins with @section, @subsection or
    @chapheading.

    To insert verbatim troff markup, the follwing texinfo code may be
    used:

      @ifset manverb
      .B whateever you want
      @end ifset

    alternativly a special comment may be used:

      @c man:.B whatever you want

    This is useful in case you need just one line. If you want to
    include parts only in the man page but keep the texinfo
    translation you may use:

      @ifset isman
      stuff to be rendered only on man pages
      @end ifset

    or to exclude stuff from man pages:

      @ifclear isman
      stuff not to be rendered on man pages
      @end ifclear

    the keyword @section is ignored, however @subsection gets rendered
    as ".SS".  @menu is completely skipped. Several man pages may be
    extracted from one file, either using the --store or the --select
    option.


*/

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <assert.h>
#include <ctype.h>
#include <time.h>


#define PGM "yat2m"
#define VERSION "0.5"

/* The maximum length of a line including the linefeed and one extra
   character. */
#define LINESIZE 1024

/* Option flags. */
static int verbose;
static int quiet;
static int debug;
static const char *opt_source; 
static const char *opt_release; 
static const char *opt_select;
static const char *opt_include;
static int opt_store;

/* The only define we understand is -D gpgone.  Thus we need a simple
   boolean tro track it. */
static int gpgone_defined;

/* Flag to keep track whether any error occurred.  */
static int any_error;


/* Object to keep macro definitions.  */
struct macro_s
{
  struct macro_s *next;
  char *value;  /* Malloced value. */
  char name[1];
};
typedef struct macro_s *macro_t;

/* List of all defined macros. */
static macro_t macrolist;


/* Object to store one line of content.  */
struct line_buffer_s
{
  struct line_buffer_s *next;
  int verbatim;  /* True if LINE contains verbatim data.  The default
                    is Texinfo source.  */
  char *line;
};
typedef struct line_buffer_s *line_buffer_t;


/* Object to collect the data of a section.  */
struct section_buffer_s
{
  char *name;           /* Malloced name of the section. This may be
                           NULL to indicate this slot is not used.  */
  line_buffer_t lines;  /* Linked list with the lines of the section.  */
  line_buffer_t *lines_tail; /* Helper for faster appending to the
                                linked list.  */
  line_buffer_t last_line;   /* Points to the last line appended.  */
};
typedef struct section_buffer_s *section_buffer_t;

/* Variable to keep info about the current page together.  */
static struct 
{
  /* Filename of the current page or NULL if no page is active.  Malloced. */
  char *name;

  /* Number of allocated elements in SECTIONS below.  */
  size_t n_sections;       
  /* Array with the data of the sections.  */
  section_buffer_t sections; 

} thepage;


/* The list of standard section names.  COMMANDS and ASSUAN are GnuPG
   specific. */
static const char * const standard_sections[] = 
  { "NAME",  "SYNOPSIS",  "DESCRIPTION",
    "RETURN VALUE", "EXIT STATUS", "ERROR HANDLING", "ERRORS",
    "COMMANDS", "OPTIONS", "USAGE", "EXAMPLES", "FILES",
    "ENVIRONMENT", "DIAGNOSTICS", "SECURITY", "CONFORMING TO",
    "ASSUAN", "NOTES", "BUGS", "AUTHOR", "SEE ALSO", NULL };


/*-- Local prototypes.  --*/
static void proc_texi_buffer (FILE *fp, const char *line, size_t len,
                              int *table_level, int *eol_action);



/* Print diagnostic message and exit with failure. */
static void
die (const char *format, ...)
{
  va_list arg_ptr;

  fflush (stdout);
  fprintf (stderr, "%s: ", PGM);

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  putc ('\n', stderr);

  exit (1);
}


/* Print diagnostic message. */
static void
err (const char *format, ...)
{
  va_list arg_ptr;

  fflush (stdout);
  if (strncmp (format, "%s:%d:", 6))
    fprintf (stderr, "%s: ", PGM);

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  putc ('\n', stderr);
  any_error = 1;
}

/* Print diagnostic message. */
static void
inf (const char *format, ...)
{
  va_list arg_ptr;

  fflush (stdout);
  fprintf (stderr, "%s: ", PGM);

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  putc ('\n', stderr);
}


static void *
xmalloc (size_t n)
{
  void *p = malloc (n);
  if (!p)
    die ("out of core: %s", strerror (errno));
  return p;
}

static void *
xcalloc (size_t n, size_t m)
{
  void *p = calloc (n, m);
  if (!p)
    die ("out of core: %s", strerror (errno));
  return p;
}

static void *
xrealloc (void *old, size_t n)
{
  void *p = realloc (old, n);
  if (!p)
    die ("out of core: %s", strerror (errno));
  return p;
}

static char *
xstrdup (const char *string)
{
  void *p = malloc (strlen (string)+1);
  if (!p)
    die ("out of core: %s", strerror (errno));
  strcpy (p, string);
  return p;
}


/* Uppercase the ascii characters in STRING.  */
static char *
ascii_strupr (char *string)
{
  char *p;

  for (p = string; *p; p++)
    if (!(*p & 0x80))
      *p = toupper (*p);
  return string;
}


/* Return the current date as an ISO string.  */
const char *
isodatestring (void)
{
  static char buffer[11+5];
  struct tm *tp;
  time_t atime = time (NULL);
  
  if (atime < 0)
    strcpy (buffer, "????" "-??" "-??");
  else
    {
      tp = gmtime (&atime);
      sprintf (buffer,"%04d-%02d-%02d",
               1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday );
    }
  return buffer;
}



/* Return a section buffer for the section NAME.  Allocate a new buffer
   if this is a new section.  Keep track of the sections in THEPAGE.
   This function may reallocate the section array in THEPAGE.  */
static section_buffer_t
get_section_buffer (const char *name)
{
  int i;
  section_buffer_t sect; 

  /* If there is no section we put everything into the required NAME
     section.  Given that this is the first one listed it is likely
     that error are easily visible.  */
  if (!name)
    name = "NAME";

  for (i=0; i < thepage.n_sections; i++)
    {
      sect = thepage.sections + i;
      if (sect->name && !strcmp (name, sect->name))
        return sect;
    }
  for (i=0; i < thepage.n_sections; i++)
    if (!thepage.sections[i].name)
      break;
  if (i < thepage.n_sections)
    sect = thepage.sections + i;
  else
    {
      /* We need to allocate or reallocate the section array.  */
      size_t old_n = thepage.n_sections;
      size_t new_n = 20;

      if (!old_n)
        thepage.sections = xcalloc (new_n, sizeof *thepage.sections);
      else
        {
          thepage.sections = xrealloc (thepage.sections,
                                       ((old_n + new_n)
                                        * sizeof *thepage.sections));
          memset (thepage.sections + old_n, 0,
                  new_n * sizeof *thepage.sections);
        }
      thepage.n_sections += new_n;

      /* Setup the tail pointers.  */
      for (i=old_n; i < thepage.n_sections; i++)
        {
          sect = thepage.sections + i;
          sect->lines_tail = &sect->lines;
        }
      sect = thepage.sections + old_n;
    }

  /* Store the name.  */
  assert (!sect->name);
  sect->name = xstrdup (name);
  return sect;
}



/* Add the content of LINE to the section named SECTNAME.  */
static void
add_content (const char *sectname, char *line, int verbatim)
{
  section_buffer_t sect;
  line_buffer_t lb;

  sect = get_section_buffer (sectname);
  if (sect->last_line && !sect->last_line->verbatim == !verbatim)
    {
      /* Lets append that line to the last one.  We do this to keep
         all lines of the same kind (i.e.verbatim or not) together in
         one large buffer.  */
      size_t n1, n;

      lb = sect->last_line;
      n1 = strlen (lb->line);
      n = n1 + 1 + strlen (line) + 1;
      lb->line = xrealloc (lb->line, n);
      strcpy (lb->line+n1, "\n");
      strcpy (lb->line+n1+1, line);
    }
  else
    {
      lb = xcalloc (1, sizeof *lb);
      lb->verbatim = verbatim;
      lb->line = xstrdup (line);
      sect->last_line = lb;
      *sect->lines_tail = lb;
      sect->lines_tail = &lb->next;
    }
}


/* Prepare for a new man page using the filename NAME. */
static void
start_page (char *name)
{
  if (verbose)
    inf ("starting page `%s'", name);
  assert (!thepage.name);
  thepage.name = xstrdup (name);
  thepage.n_sections = 0;
}


/* Write the .TH entry of the current page.  Return -1 if there is a
   problem with the page. */
static int
write_th (FILE *fp)
{
  char *name, *p;

  name = ascii_strupr (xstrdup (thepage.name));
  p = strrchr (name, '.');
  if (!p || !p[1])
    {
      err ("no section name in man page `%s'", thepage.name);
      free (name);
      return -1;
    }
  *p++ = 0;
  fprintf (fp, ".TH %s %s %s \"%s\" \"%s\"\n",
           name, p, isodatestring (), opt_release, opt_source);
  return 0;
}


/* Process the texinfo command COMMAND (without the leading @) and
   write output if needed to FP. REST is the remainer of the line
   which should either point to an opening brace or to a white space.
   The function returns the number of characters already processed
   from REST.  LEN is the usable length of REST.  TABLE_LEVEL is used to
   control the indentation of tables.  */
static size_t
proc_texi_cmd (FILE *fp, const char *command, const char *rest, size_t len,
               int *table_level, int *eol_action)
{
  static struct {
    const char *name;    /* Name of the command.  */
    int what;            /* What to do with this command. */
    const char *lead_in; /* String to print with a opening brace.  */
    const char *lead_out;/* String to print with the closing brace. */
  } cmdtbl[] = {
    { "command", 0, "\\fB", "\\fR" },
    { "code",    0, "\\fB", "\\fR" },
    { "sc",      0, "\\fB", "\\fR" },
    { "var",     0, "\\fI", "\\fR" },
    { "samp",    0, "'",  "'"  },
    { "file",    0, "`\\fI","\\fR'" }, 
    { "env",     0, "`\\fI","\\fR'" }, 
    { "acronym", 0 },
    { "dfn",     0 },
    { "option",  0, "\\fB", "\\fR"   },
    { "example", 1, ".RS 2\n.nf\n" },
    { "smallexample", 1, ".RS 2\n.nf\n" },
    { "asis",    7 },
    { "anchor",  7 },
    { "cartouche", 1 },
    { "xref",    0, "see: [", "]" },
    { "pxref",   0, "see: [", "]" },
    { "uref",    0, "(\\fB", "\\fR)" },
    { "footnote",0, " ([", "])" },
    { "emph",    0, "\\fI", "\\fR" },
    { "w",       1 },                                 
    { "c",       5 },
    { "opindex", 1 },
    { "cpindex", 1 },
    { "cindex",  1 },
    { "noindent", 0 },
    { "section", 1 },
    { "chapter", 1 },
    { "subsection", 6, "\n.SS " },
    { "chapheading", 0},
    { "item",    2, ".TP\n.B " },
    { "itemx",   2, ".TP\n.B " },
    { "table",   3 }, 
    { "itemize",   3 }, 
    { "bullet",  0, "* " },
    { "end",     4 },
    { "quotation",1, ".RS\n\\fB" },
    { NULL }
  };
  size_t n;
  int i;
  const char *s;
  const char *lead_out = NULL;
  int ignore_args = 0;

  for (i=0; cmdtbl[i].name && strcmp (cmdtbl[i].name, command); i++)
    ;
  if (cmdtbl[i].name)
    {
      s = cmdtbl[i].lead_in;
      if (s)
        fputs (s, fp);
      lead_out = cmdtbl[i].lead_out;
      switch (cmdtbl[i].what)
        {
        case 1: /* Throw away the entire line.  */
          s = memchr (rest, '\n', len);
          return s? (s-rest)+1 : len;  
        case 2: /* Handle @item.  */
          break;
        case 3: /* Handle table.  */
          if (++(*table_level) > 1)
            fputs (".RS\n", fp);
          /* Now throw away the entire line. */
          s = memchr (rest, '\n', len);
          return s? (s-rest)+1 : len;  
          break;
        case 4: /* Handle end.  */
          for (s=rest, n=len; n && (*s == ' ' || *s == '\t'); s++, n--)
            ;
          if (n >= 5 && !memcmp (s, "table", 5)
              && (!n || s[5] == ' ' || s[5] == '\t' || s[5] == '\n'))
            {
              if ((*table_level)-- > 1)
                fputs (".RE\n", fp);
            }
          else if (n >= 7 && !memcmp (s, "example", 7)
              && (!n || s[7] == ' ' || s[7] == '\t' || s[7] == '\n'))
            {
              fputs (".fi\n.RE\n", fp);
            }
          else if (n >= 12 && !memcmp (s, "smallexample", 12)
              && (!n || s[12] == ' ' || s[12] == '\t' || s[12] == '\n'))
            {
              fputs (".fi\n.RE\n", fp);
            }
          else if (n >= 9 && !memcmp (s, "quotation", 9)
              && (!n || s[9] == ' ' || s[9] == '\t' || s[9] == '\n'))
            {
              fputs ("\\fR\n.RE\n", fp);
            }
          /* Now throw away the entire line. */
          s = memchr (rest, '\n', len);
          return s? (s-rest)+1 : len;  
        case 5: /* Handle special comments. */
          for (s=rest, n=len; n && (*s == ' ' || *s == '\t'); s++, n--)
            ;
          if (n >= 4 && !memcmp (s, "man:", 4))
            {
              for (s+=4, n-=4; n && *s != '\n'; n--, s++)
                putc (*s, fp);
              putc ('\n', fp);
            }
          /* Now throw away the entire line. */
          s = memchr (rest, '\n', len);
          return s? (s-rest)+1 : len;  
        case 6:
          *eol_action = 1;
          break;
        case 7:
          ignore_args = 1;
          break;
        default:
          break;
        }
    }
  else
    {
      macro_t m;

      for (m = macrolist; m ; m = m->next)
        if (!strcmp (m->name, command))
            break;
      if (m)
        {
          proc_texi_buffer (fp, m->value, strlen (m->value),
                            table_level, eol_action);
          ignore_args = 1; /* Parameterized macros are not yet supported. */
        }
      else
        inf ("texinfo command `%s' not supported (%.*s)", command,
             ((s = memchr (rest, '\n', len)), (s? (s-rest) : len)), rest);
    }

  if (*rest == '{')
    {
      /* Find matching closing brace.  */
      for (s=rest+1, n=1, i=1; i && *s && n < len; s++, n++)
        if (*s == '{')
          i++;
        else if (*s == '}')
          i--;
      if (i)
        {
          err ("closing brace for command `%s' not found", command);
          return len;
        }
      if (n > 2 && !ignore_args)
        proc_texi_buffer (fp, rest+1, n-2, table_level, eol_action);
    }
  else
    n = 0;

  if (lead_out)
    fputs (lead_out, fp);

  return n;
}



/* Process the string LINE with LEN bytes of Texinfo content. */
static void
proc_texi_buffer (FILE *fp, const char *line, size_t len,
                  int *table_level, int *eol_action)
{
  const char *s;
  char cmdbuf[256];
  int cmdidx = 0;
  int in_cmd = 0;
  size_t n;

  for (s=line; *s && len; s++, len--)
    {
      if (in_cmd)
        {
          if (in_cmd == 1)
            {
              switch (*s)
                {
                case '@': case '{': case '}': 
                  putc (*s, fp); in_cmd = 0; 
                  break;
                case ':': /* Not ending a sentence flag.  */
                  in_cmd = 0;
                  break;
                case '.': case '!': case '?': /* Ending a sentence. */
                  putc (*s, fp); in_cmd = 0; 
                  break;
                case ' ': case '\t': case '\n': /* Non collapsing spaces.  */
                  putc (*s, fp); in_cmd = 0; 
                  break;
                default:
                  cmdidx = 0;
                  cmdbuf[cmdidx++] = *s;
                  in_cmd++;
                  break;
                }
            }
          else if (*s == '{' || *s == ' ' || *s == '\t' || *s == '\n')
            {
              cmdbuf[cmdidx] = 0;
              n = proc_texi_cmd (fp, cmdbuf, s, len, table_level, eol_action);
              assert (n <= len);
              s += n; len -= n;
              s--; len++;
              in_cmd = 0;
            }
          else if (cmdidx < sizeof cmdbuf -1)  
            cmdbuf[cmdidx++] = *s;
          else
            {
              err ("texinfo command too long - ignored");
              in_cmd = 0;
            }
        }
      else if (*s == '@')
        in_cmd = 1;
      else if (*s == '\n')
        {
          switch (*eol_action)
            {
            case 1: /* Create a dummy paragraph. */
              fputs ("\n\\ \n", fp);
              break;
            default:
              putc (*s, fp);
            }
          *eol_action = 0;
        }
      else
        putc (*s, fp);
    }

  if (in_cmd > 1)
    {
      cmdbuf[cmdidx] = 0;
      n = proc_texi_cmd (fp, cmdbuf, s, len, table_level, eol_action);
      assert (n <= len);
      s += n; len -= n;
      s--; len++;
      in_cmd = 0;
    }
}


/* Do something with the Texinfo line LINE.  */
static void
parse_texi_line (FILE *fp, const char *line, int *table_level)
{
  int eol_action = 0;

  /* A quick test whether there are any texinfo commands.  */
  if (!strchr (line, '@'))
    {
      fputs (line, fp);
      putc ('\n', fp);
      return;
    }
  proc_texi_buffer (fp, line, strlen (line), table_level, &eol_action);
  putc ('\n', fp);
}


/* Write all the lines LINES to FP.  */
static void
write_content (FILE *fp, line_buffer_t lines)
{
  line_buffer_t line;
  int table_level = 0;

  for (line = lines; line; line = line->next)
    {
      if (line->verbatim)
        {
          fputs (line->line, fp);
          putc ('\n', fp);
        }
      else
        {
/*           fputs ("TEXI---", fp); */
/*           fputs (line->line, fp); */
/*           fputs ("---\n", fp); */
          parse_texi_line (fp, line->line, &table_level);
        }
    }  
}



static int
is_standard_section (const char *name)
{
  int i;
  const char *s;

  for (i=0; (s=standard_sections[i]); i++)
    if (!strcmp (s, name))
      return 1;
  return 0;
}


/* Finish a page; that is sort the data and write it out to the file.  */
static void
finish_page (void)
{
  FILE *fp;
  section_buffer_t sect = NULL;
  int idx;
  const char *s;
  int i;

  if (!thepage.name)
    return; /* No page active.  */

  if (verbose)
    inf ("finishing page `%s'", thepage.name);

  if (opt_select)
    {
      if (!strcmp (opt_select, thepage.name))
        {
          inf ("selected `%s'", thepage.name );
          fp = stdout;
        }
      else
        {
          fp = fopen ( "/dev/null", "w" );
          if (!fp)
            die ("failed to open /dev/null: %s\n", strerror (errno));
        }
    }
  else if (opt_store)
    {
      inf ("writing `%s'", thepage.name );
      fp = fopen ( thepage.name, "w" );
      if (!fp)
        die ("failed to create `%s': %s\n", thepage.name, strerror (errno));
    }
  else
    fp = stdout;

  if (write_th (fp))
    goto leave;

  for (idx=0; (s=standard_sections[idx]); idx++)
    {
      for (i=0; i < thepage.n_sections; i++)
        {
          sect = thepage.sections + i;
          if (sect->name && !strcmp (s, sect->name))
            break;
        }
      if (i == thepage.n_sections)
        sect = NULL;

      if (sect)
        {
          fprintf (fp, ".SH %s\n", sect->name);
          write_content (fp, sect->lines);
          /* Now continue with all non standard sections directly
             following this one. */
          for (i++; i < thepage.n_sections; i++)
            {
              sect = thepage.sections + i;
              if (sect->name && is_standard_section (sect->name))
                break;
              if (sect->name)
                {
                  fprintf (fp, ".SH %s\n", sect->name);
                  write_content (fp, sect->lines);
                }
            }
          
        }
    }


 leave:
  if (fp != stdout)
    fclose (fp);
  free (thepage.name);
  thepage.name = NULL;
  /* FIXME: Cleanup the content.  */
}




/* Parse one Texinfo file and create manpages according to the
   embedded instructions.  */
static void
parse_file (const char *fname, FILE *fp, char **section_name, int in_pause)
{
  char *line;
  int lnr = 0;
  /* Fixme: The follwing state variables don't carry over to include
     files. */
  int in_verbatim = 0;
  int skip_to_end = 0;        /* Used to skip over menu entries. */
  int skip_sect_line = 0;     /* Skip after @mansect.  */
  int ifset_nesting = 0;      /* How often a ifset has been seen. */
  int ifclear_nesting = 0;    /* How often a ifclear has been seen. */
  int in_gpgone = 0;          /* Keep track of "@ifset gpgone" parts.  */
  int not_in_gpgone = 0;      /* Keep track of "@ifclear gpgone" parts.  */
  int not_in_man = 0;         /* Keep track of "@ifclear isman" parts.  */

  /* Helper to define a macro. */
  char *macroname = NULL;     
  char *macrovalue = NULL; 
  size_t macrovaluesize = 0;
  size_t macrovalueused = 0;

  line = xmalloc (LINESIZE);
  while (fgets (line, LINESIZE, fp))
    {
      size_t n = strlen (line);
      int got_line = 0;
      char *p;

      lnr++;
      if (!n || line[n-1] != '\n')
        {
          err ("%s:%d: trailing linefeed missing, line too long or "
               "embedded Nul character", fname, lnr);
          break;
        }
      line[--n] = 0;

      if (*line == '@')
        {
          for (p=line+1, n=1; *p && *p != ' ' && *p != '\t'; p++)
            n++;
          while (*p == ' ' || *p == '\t')
            p++;
        }
      else
        p = line;

      /* Take action on macro.  */
      if (macroname)
        {
          if (n == 4 && !memcmp (line, "@end", 4)
              && (line[4]==' '||line[4]=='\t'||!line[4])
              && !strncmp (p, "macro", 5)
              && (p[5]==' '||p[5]=='\t'||!p[5]))
            {
              macro_t m;

              if (macrovalueused)
                macrovalue[--macrovalueused] = 0; /* Kill the last LF. */
              macrovalue[macrovalueused] = 0;     /* Terminate macro. */
              macrovalue = xrealloc (macrovalue, macrovalueused+1);
              
              for (m= macrolist; m; m = m->next)
                if (!strcmp (m->name, macroname))
                  break;
              if (m)
                free (m->value);
              else
                {
                  m = xcalloc (1, sizeof *m + strlen (macroname));
                  strcpy (m->name, macroname);
                  m->next = macrolist;
                  macrolist = m;
                }
              m->value = macrovalue;
              macrovalue = NULL;
              free (macroname);
              macroname = NULL;
            }
          else
            {
              if (macrovalueused + strlen (line) + 2 >= macrovaluesize)
                {
                  macrovaluesize += strlen (line) + 256;
                  macrovalue = xrealloc (macrovalue,  macrovaluesize);
                }
              strcpy (macrovalue+macrovalueused, line);
              macrovalueused += strlen (line);
              macrovalue[macrovalueused++] = '\n';
            }
          continue;
        }


      if (n >= 5 && !memcmp (line, "@node", 5)
          && (line[5]==' '||line[5]=='\t'||!line[5]))
        {
          /* Completey ignore @node lines.  */
          continue;
        }


      if (skip_sect_line)
        {
          skip_sect_line = 0;
          if (!strncmp (line, "@section", 8)
              || !strncmp (line, "@subsection", 11)
              || !strncmp (line, "@chapheading", 12))
            continue;
        }

      /* We only parse lines we need and ignore the rest.  There are a
         few macros used to control this as well as one @ifset
         command.  Parts we know about are saved away into containers
         separate for each section. */

      /* First process ifset/ifclear commands. */
      if (*line == '@')
        {
          if (n == 6 && !memcmp (line, "@ifset", 6)
                   && (line[6]==' '||line[6]=='\t'))
            {
              ifset_nesting++;

              if (!strncmp (p, "manverb", 7) && (p[7]==' '||p[7]=='\t'||!p[7]))
                {
                  if (in_verbatim)
                    err ("%s:%d: nested \"@ifset manverb\"", fname, lnr);
                  else
                    in_verbatim = ifset_nesting;
                }
              else if (!strncmp (p, "gpgone", 6)
                       && (p[6]==' '||p[6]=='\t'||!p[6]))
                {
                  if (in_gpgone)
                    err ("%s:%d: nested \"@ifset gpgone\"", fname, lnr);
                  else
                    in_gpgone = ifset_nesting;
                }
              continue;
            }
          else if (n == 4 && !memcmp (line, "@end", 4)
                   && (line[4]==' '||line[4]=='\t')
                   && !strncmp (p, "ifset", 5)
                   && (p[5]==' '||p[5]=='\t'||!p[5]))
            {
              if (in_verbatim && ifset_nesting == in_verbatim)
                in_verbatim = 0;
              if (in_gpgone && ifset_nesting == in_gpgone)
                in_gpgone = 0;

              if (ifset_nesting)
                ifset_nesting--;
              else
                err ("%s:%d: unbalanced \"@end ifset\"", fname, lnr);
              continue;
            }
          else if (n == 8 && !memcmp (line, "@ifclear", 8)
                   && (line[8]==' '||line[8]=='\t'))
            {
              ifclear_nesting++;

              if (!strncmp (p, "gpgone", 6)
                  && (p[6]==' '||p[6]=='\t'||!p[6]))
                {
                  if (not_in_gpgone)
                    err ("%s:%d: nested \"@ifclear gpgone\"", fname, lnr);
                  else
                    not_in_gpgone = ifclear_nesting;
                }

              else if (!strncmp (p, "isman", 5)
                       && (p[5]==' '||p[5]=='\t'||!p[5]))
                {
                  if (not_in_man)
                    err ("%s:%d: nested \"@ifclear isman\"", fname, lnr);
                  else
                    not_in_man = ifclear_nesting;
                }

              continue;
            }
          else if (n == 4 && !memcmp (line, "@end", 4)
                   && (line[4]==' '||line[4]=='\t')
                   && !strncmp (p, "ifclear", 7)
                   && (p[7]==' '||p[7]=='\t'||!p[7]))
            {
              if (not_in_gpgone && ifclear_nesting == not_in_gpgone)
                not_in_gpgone = 0;
              if (not_in_man && ifclear_nesting == not_in_man)
                not_in_man = 0;

              if (ifclear_nesting)
                ifclear_nesting--;
              else
                err ("%s:%d: unbalanced \"@end ifclear\"", fname, lnr);
              continue;
            }
        }

      /* Take action on ifset/ifclear.  */
      if ( (in_gpgone && !gpgone_defined)
           || (not_in_gpgone && gpgone_defined)
           || not_in_man)
        continue;

      /* Process commands. */
      if (*line == '@')
        {
          if (skip_to_end
              && n == 4 && !memcmp (line, "@end", 4)
              && (line[4]==' '||line[4]=='\t'||!line[4]))
            {
              skip_to_end = 0;
            }
          else if (in_verbatim)
            {
                got_line = 1;
            }
          else if (n == 6 && !memcmp (line, "@macro", 6))
            {
              macroname = xstrdup (p);
              macrovalue = xmalloc ((macrovaluesize = 1024));
              macrovalueused = 0;
            }
          else if (n == 8 && !memcmp (line, "@manpage", 8))
            {
              free (*section_name);
              *section_name = NULL;
              finish_page ();
              start_page (p);
              in_pause = 0;
            }
          else if (n == 8 && !memcmp (line, "@mansect", 8))
            {
              if (!thepage.name)
                err ("%s:%d: section outside of a man page", fname, lnr);
              else
                {
                  free (*section_name);
                  *section_name = ascii_strupr (xstrdup (p));
                  in_pause = 0;
                  skip_sect_line = 1;
                }
            }
          else if (n == 9 && !memcmp (line, "@manpause", 9))
            {
              if (!*section_name)
                err ("%s:%d: pausing outside of a man section", fname, lnr);
              else if (in_pause)
                err ("%s:%d: already pausing", fname, lnr);
              else
                in_pause = 1;
            }
          else if (n == 8 && !memcmp (line, "@mancont", 8))
            {
              if (!*section_name)
                err ("%s:%d: continue outside of a man section", fname, lnr);
              else if (!in_pause)
                err ("%s:%d: continue while not pausing", fname, lnr);
              else
                in_pause = 0;
            }
          else if (n == 5 && !memcmp (line, "@menu", 5)
                   && (line[5]==' '||line[5]=='\t'||!line[5]))
            {
              skip_to_end = 1;
            }
          else if (n == 8 && !memcmp (line, "@include", 8)
                   && (line[8]==' '||line[8]=='\t'||!line[8]))
            {
              char *incname = xstrdup (p);
              FILE *incfp = fopen (incname, "r");

              if (!incfp && opt_include && *opt_include && *p != '/')
                {
                  free (incname);
                  incname = xmalloc (strlen (opt_include) + 1
                                     + strlen (p) + 1);
                  strcpy (incname, opt_include);
                  if ( incname[strlen (incname)-1] != '/' )
                    strcat (incname, "/");
                  strcat (incname, p);
                  incfp = fopen (incname, "r");
                }

              if (!incfp)
                err ("can't open include file `%s':%s",
                     incname, strerror (errno));
              else
                {
                  parse_file (incname, incfp, section_name, in_pause);
                  fclose (incfp);
                }
              free (incname);
            }
          else if (n == 4 && !memcmp (line, "@bye", 4)
                   && (line[4]==' '||line[4]=='\t'||!line[4]))
            {
              break;
            }
          else if (!skip_to_end)
            got_line = 1;
        }
      else if (!skip_to_end)
        got_line = 1;

      if (got_line && in_verbatim)
        add_content (*section_name, line, 1);
      else if (got_line && thepage.name && *section_name && !in_pause)
        add_content (*section_name, line, 0);

    }
  if (ferror (fp))
    err ("%s:%d: read error: %s", fname, lnr, strerror (errno));
  free (macroname);
  free (macrovalue);
  free (line);
}


static void
top_parse_file (const char *fname, FILE *fp)
{
  char *section_name = NULL;  /* Name of the current section or NULL
                                 if not in a section.  */
  while (macrolist)
    {
      macro_t m = macrolist->next;
      free (m->value);
      free (m);
      macrolist = m;
    }

  parse_file (fname, fp, &section_name, 0);
  free (section_name);
  finish_page ();
}


int 
main (int argc, char **argv)
{
  int last_argc = -1;

  opt_source = "GNU";
  opt_release = "";

  if (argc)
    {
      argc--; argv++;
    }
  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--"))
        {
          argc--; argv++;
          break;
        }
      else if (!strcmp (*argv, "--help"))
        {
          puts (
                "Usage: " PGM " [OPTION] [FILE]\n"
                "Extract man pages from a Texinfo source.\n\n"
                "  --source NAME    use NAME as source field\n"
                "  --release STRING use STRING as the release field\n"
                "  --store          write output using @manpage name\n"
                "  --select NAME    only output pages with @manpage NAME\n"
                "  --verbose        enable extra informational output\n"
                "  --debug          enable additional debug output\n"
                "  --help           display this help and exit\n"
                "  -I DIR           also search in include DIR\n"
                "  -D gpgone        the only useable define\n\n"
                "With no FILE, or when FILE is -, read standard input.\n\n"
                "Report bugs to <bugs@g10code.com>.");
          exit (0);
        }
      else if (!strcmp (*argv, "--version"))
        {
          puts (PGM " " VERSION "\n"
               "Copyright (C) 2005 g10 Code GmbH\n"
               "This program comes with ABSOLUTELY NO WARRANTY.\n"
               "This is free software, and you are welcome to redistribute it\n"
                "under certain conditions. See the file COPYING for details.");
          exit (0);
        }
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--quiet"))
        {
          quiet = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          verbose = debug = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--source"))
        {
          argc--; argv++;
          if (argc)
            {
              opt_source = *argv;
              argc--; argv++;
            }
        }
      else if (!strcmp (*argv, "--release"))
        {
          argc--; argv++;
          if (argc)
            {
              opt_release = *argv;
              argc--; argv++;
            }
        }
      else if (!strcmp (*argv, "--store"))
        {
          opt_store = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--select"))
        {
          argc--; argv++;
          if (argc)
            {
              opt_select = strrchr (*argv, '/');
              if (opt_select)
                opt_select++;
              else 
                opt_select = *argv;
              argc--; argv++;
            }
        }
      else if (!strcmp (*argv, "-I"))
        {
          argc--; argv++;
          if (argc)
            {
              opt_include = *argv;
              argc--; argv++;
            }
        }
      else if (!strcmp (*argv, "-D"))
        {
          argc--; argv++;
          if (argc)
            {
              if (!strcmp (*argv, "gpgone"))
                gpgone_defined = 1;
              argc--; argv++;
            }
        }
    }          
 
  if (argc > 1)
    die ("usage: " PGM " [OPTION] [FILE] (try --help for more information)\n");

  /* Start processing. */
  if (argc && strcmp (*argv, "-"))
    {
      FILE *fp = fopen (*argv, "rb");
      if (!fp)
        die ("%s:0: can't open file: %s", *argv, strerror (errno));
      top_parse_file (*argv, fp);
      fclose (fp);
    }
  else
    top_parse_file ("-", stdin);

  return !!any_error;
}


/*
Local Variables:
compile-command: "gcc -Wall -g -Wall -o yat2m yat2m.c"
End:
*/
