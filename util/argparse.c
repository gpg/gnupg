/* [argparse.c wk 17.06.97] Argument Parser for option handling
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
 *  This file is part of WkLib.
 *
 *  WkLib is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  WkLib is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 *
 *
 * Note: This is an independent version of the one in WkLib
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"


/*********************************
 * @Summary arg_parse
 *  #include <wk/lib.h>
 *
 *  typedef struct {
 *	char *argc;		  pointer to argc (value subject to change)
 *	char ***argv;		  pointer to argv (value subject to change)
 *	unsigned flags; 	  Global flags (DO NOT CHANGE)
 *	int err;		  print error about last option
 *				  1 = warning, 2 = abort
 *	int r_opt;		  return option
 *	int r_type;		  type of return value (0 = no argument found)
 *	union {
 *	    int   ret_int;
 *	    long  ret_long
 *	    ulong ret_ulong;
 *	    char *ret_str;
 *	} r;			  Return values
 *	struct {
 *	    int index;
 *	    const char *last;
 *	} internal;		  DO NOT CHANGE
 *  } ARGPARSE_ARGS;
 *
 *  typedef struct {
 *	int	    short_opt;
 *	const char *long_opt;
 *	unsigned flags;
 *  } ARGPARSE_OPTS;
 *
 *  int arg_parse( ARGPARSE_ARGS *arg, ARGPARSE_OPTS *opts );
 *
 * @Description
 *  This is my replacement for getopt(). See the example for a typical usage.
 *  Global flags are:
 *     Bit 0 : Do not remove options form argv
 *     Bit 1 : Do not stop at last option but return other args
 *	       with r_opt set to -1.
 *     Bit 2 : Assume options and real args are mixed.
 *     Bit 3 : Do not use -- to stop option processing.
 *     Bit 4 : Do not skip the first arg.
 *     Bit 5 : allow usage of long option with only one dash
 *     all other bits must be set to zero, this value is modified by the function
 *     so assume this is write only.
 *  Local flags (for each option):
 *     Bit 2-0 : 0 = does not take an argument
 *		 1 = takes int argument
 *		 2 = takes string argument
 *		 3 = takes long argument
 *		 4 = takes ulong argument
 *     Bit 3 : argument is optional (r_type will the be set to 0)
 *     Bit 4 : allow 0x etc. prefixed values.
 *  If can stop the option processing by setting opts to NULL, the function will
 *  then return 0.
 * @Return Value
 *   Returns the args.r_opt or 0 if ready
 *   r_opt may be -2 to indicate an unknown option.
 * @See Also
 *   ArgExpand
 * @Notes
 *  You do not need to process the options 'h', '--help' or '--version'
 *  because this function includes standard help processing; but if you
 *  specify '-h', '--help' or '--version' you have to do it yourself.
 *  The option '--' stops argument processing; if bit 1 is set the function
 *  continues to return normal arguments.
 *  To process float args or unsigned args you must use a string args and do
 *  the conversion yourself.
 * @Example
 *
 *     ARGPARSE_OPTS opts[] = {
 *     { 'v', "verbose",   0 },
 *     { 'd', "debug",     0 },
 *     { 'o', "output",    2 },
 *     { 'c', "cross-ref", 2|8 },
 *     { 'm', "my-option", 1|8 },
 *     { 500, "have-no-short-option-for-this-long-option", 0 },
 *     {0} };
 *     ARGPARSE_ARGS pargs = { &argc, &argv, 0 }
 *
 *     while( ArgParse( &pargs, &opts) ) {
 *	   switch( pargs.r_opt ) {
 *	     case 'v': opt.verbose++; break;
 *	     case 'd': opt.debug++; break;
 *	     case 'o': opt.outfile = pargs.r.ret_str; break;
 *	     case 'c': opt.crf = pargs.r_type? pargs.r.ret_str:"a.crf"; break;
 *	     case 'm': opt.myopt = pargs.r_type? pargs.r.ret_int : 1; break;
 *	     case 500: opt.a_long_one++;  break
 *	     default : pargs.err = 1; break; -- force warning output --
 *	   }
 *     }
 *     if( argc > 1 )
 *	   log_fatal( "Too many args");
 *
 */


static void set_opt_arg(ARGPARSE_ARGS *arg, unsigned flags, char *s);
static void show_help(ARGPARSE_OPTS *opts, unsigned flags);
static void show_version(void);


int
arg_parse( ARGPARSE_ARGS *arg, ARGPARSE_OPTS *opts)
{
    int index;
    int argc;
    char **argv;
    char *s, *s2;
    int i;

    if( !(arg->flags & (1<<15)) ) { /* initialize this instance */
	arg->internal.index = 0;
	arg->internal.last = NULL;
	arg->internal.inarg = 0;
	arg->internal.stopped= 0;
	arg->err = 0;
	arg->flags |= 1<<15; /* mark initialized */
	if( *arg->argc < 0 )
	    log_bug("Invalid argument for ArgParse\n");
    }
    argc = *arg->argc;
    argv = *arg->argv;
    index = arg->internal.index;

    if( arg->err ) { /* last option was erroneous */
	if( arg->r_opt == -3 )
	    s = "Missing argument for option \"%.50s\"\n";
	else
	    s = "Invalid option \"%.50s\"\n";
	log_error(s, arg->internal.last? arg->internal.last:"[??]" );
	if( arg->err != 1 )
	    exit(2);
	arg->err = 0;
    }

    if( !index && argc && !(arg->flags & (1<<4)) ) { /* skip the first entry */
	argc--; argv++; index++;
    }

  next_one:
    if( !argc ) { /* no more args */
	arg->r_opt = 0;
	goto leave; /* ready */
    }

    s = *argv;
    arg->internal.last = s;

    if( arg->internal.stopped && (arg->flags & (1<<1)) ) {
	arg->r_opt = -1;  /* not an option but a argument */
	arg->r_type = 2;
	arg->r.ret_str = s;
	argc--; argv++; index++; /* set to next one */
    }
    else if( arg->internal.stopped ) { /* ready */
	arg->r_opt = 0;
	goto leave;
    }
    else if( *s == '-' && s[1] == '-' ) { /* long option */
	arg->internal.inarg = 0;
	if( !s[2] && !(arg->flags & (1<<3)) ) { /* stop option processing */
	    arg->internal.stopped = 1;
	    argc--; argv++; index++;
	    goto next_one;
	}

	for(i=0; opts[i].short_opt; i++ )
	    if( opts[i].long_opt && !strcmp( opts[i].long_opt, s+2) )
		break;

	if( !opts[i].short_opt && !strcmp( "help", s+2) )
	    show_help(opts, arg->flags);
	else if( !opts[i].short_opt && !strcmp( "version", s+2) )
	    show_version();
	else if( !opts[i].short_opt && !strcmp( "warranty", s+2) ) {
	    puts( strusage(10) );
	    puts( strusage(31) );
	    exit(0);
	}

	arg->r_opt = opts[i].short_opt;
	if( !opts[i].short_opt ) {
	    arg->r_opt = -2; /* unknown option */
	    arg->r.ret_str = s+2;
	}
	else if( (opts[i].flags & 7) ) {
	    s2 = argv[1];
	    if( !s2 && (opts[i].flags & 8) ) { /* no argument but it is okay*/
		arg->r_type = 0;	       /* because it is optional */
	    }
	    else if( !s2 ) {
		arg->r_opt = -3; /* missing argument */
	    }
	    else if( *s2 == '-' && (opts[i].flags & 8) ) {
		/* the argument is optional and the next seems to be
		 * an option. We do not check this possible option
		 * but assume no argument */
		arg->r_type = 0;
	    }
	    else {
		set_opt_arg(arg, opts[i].flags, s2);
		argc--; argv++; index++; /* skip one */
	    }
	}
	else { /* does not take an argument */
	    arg->r_type = 0;
	}
	argc--; argv++; index++; /* set to next one */
    }
    else if( (*s == '-' && s[1]) || arg->internal.inarg ) { /* short option */
	int dash_kludge = 0;
	i = 0;
	if( !arg->internal.inarg ) {
	    arg->internal.inarg++;
	    if( arg->flags & (1<<5) ) {
		for(i=0; opts[i].short_opt; i++ )
		    if( opts[i].long_opt && !strcmp( opts[i].long_opt, s+1)) {
			dash_kludge=1;
			break;
		    }
	    }
	}
	s += arg->internal.inarg;

	if( !dash_kludge ) {
	    for(i=0; opts[i].short_opt; i++ )
		if( opts[i].short_opt == *s )
		    break;
	}

	if( !opts[i].short_opt && *s == 'h' )
	    show_help(opts, arg->flags);

	arg->r_opt = opts[i].short_opt;
	if( !opts[i].short_opt ) {
	    arg->r_opt = -2; /* unknown option */
	    arg->internal.inarg++; /* point to the next arg */
	    arg->r.ret_str = s;
	}
	else if( (opts[i].flags & 7) ) {
	    if( s[1] && !dash_kludge ) {
		s2 = s+1;
		set_opt_arg(arg, opts[i].flags, s2);
	    }
	    else {
		s2 = argv[1];
		if( !s2 && (opts[i].flags & 8) ) { /* no argument but it is okay*/
		    arg->r_type = 0;		   /* because it is optional */
		}
		else if( !s2 ) {
		    arg->r_opt = -3; /* missing argument */
		}
		else if( *s2 == '-' && s2[1] && (opts[i].flags & 8) ) {
		    /* the argument is optional and the next seems to be
		     * an option. We do not check this possible option
		     * but assume no argument */
		    arg->r_type = 0;
		}
		else {
		    set_opt_arg(arg, opts[i].flags, s2);
		    argc--; argv++; index++; /* skip one */
		}
	    }
	    s = "x"; /* so that !s[1] yields false */
	}
	else { /* does not take an argument */
	    arg->r_type = 0;
	    arg->internal.inarg++; /* point to the next arg */
	}
	if( !s[1] || dash_kludge ) { /* no more concatenated short options */
	    arg->internal.inarg = 0;
	    argc--; argv++; index++;
	}
    }
    else if( arg->flags & (1<<2) ) {
	arg->r_opt = -1;  /* not an option but a argument */
	arg->r_type = 2;
	arg->r.ret_str = s;
	argc--; argv++; index++; /* set to next one */
    }
    else {
	arg->internal.stopped = 1; /* stop option processing */
	goto next_one;
    }

  leave:
    *arg->argc = argc;
    *arg->argv = argv;
    arg->internal.index = index;
    return arg->r_opt;
}



static void
set_opt_arg(ARGPARSE_ARGS *arg, unsigned flags, char *s)
{
    int base = (flags & 16)? 0 : 10;

    switch( arg->r_type = (flags & 7) ) {
      case 1: /* takes int argument */
	arg->r.ret_int = (int)strtol(s,NULL,base);
	break;
      default:
      case 2: /* takes string argument */
	arg->r.ret_str = s;
	break;
      case 3: /* takes long argument   */
	arg->r.ret_long= strtol(s,NULL,base);
	break;
      case 4: /* takes ulong argument  */
	arg->r.ret_ulong= strtoul(s,NULL,base);
	break;
    }
}

static void
show_help( ARGPARSE_OPTS *opts, unsigned flags )
{
    const char *s;

    puts( strusage(10) );
    s = strusage(12);
    if( *s == '\n' )
	s++;
    puts(s);
    if( opts[0].description ) { /* auto format the option description */
	int i,j, indent;
	/* get max. length of long options */
	for(i=indent=0; opts[i].short_opt; i++ ) {
	    if( opts[i].long_opt )
		if( (j=strlen(opts[i].long_opt)) > indent && j < 35 )
		    indent = j;
	}
	/* example: " -v, --verbose   Viele Sachen ausgeben" */
	indent += 10;
	puts("Options:");
	for(i=0; opts[i].short_opt; i++ ) {
	    if( opts[i].short_opt < 256 )
		printf(" -%c", opts[i].short_opt );
	    else
		fputs("   ", stdout);
	    j = 3;
	    if( opts[i].long_opt )
		j += printf("%c --%s   ", opts[i].short_opt < 256?',':' ',
					  opts[i].long_opt );
	    for(;j < indent; j++ )
		putchar(' ');
	    if( (s = opts[i].description) ) {
		for(; *s; s++ ) {
		    if( *s == '\n' ) {
			if( s[1] ) {
			    putchar('\n');
			    for(j=0;j < indent; j++ )
				putchar(' ');
			}
		    }
		    else
			putchar(*s);
		}
	    }
	    putchar('\n');
	}
	if( flags & 32 )
	    puts("\n(A single dash may be used instead of the double ones)");
    }
    if( *(s=strusage(26)) ) {  /* bug reports to ... */
	putchar('\n');
	fputs(s, stdout);
    }
    fflush(stdout);
    exit(0);
}

static void
show_version()
{
    const char *s;
    printf("%s version %s (%s", strusage(13), strusage(14), strusage(45) );
    if( (s = strusage(24)) && *s ) {
      #ifdef DEBUG
	printf(", %s, dbg)\n", s);
      #else
	printf(", %s)\n", s);
      #endif
    }
    else {
      #ifdef DEBUG
	printf(", dbg)\n");
      #else
	printf(")\n");
      #endif
    }
    fflush(stdout);
    exit(0);
}



void
usage( int level )
{
    static int sentinel=0;

    if( sentinel )
	return;

    sentinel++;
    if( !level ) {
	fputs( strusage(level), stderr ); putc( '\n', stderr );
	fputs( strusage(31), stderr);
      #if DEBUG
	fprintf(stderr, "%s (%s - Debug)\n", strusage(32), strusage(24) );
      #else
	fprintf(stderr, "%s (%s)\n", strusage(32), strusage(24) );
      #endif
	fflush(stderr);
    }
    else if( level == 1 ) {
	fputs(strusage(level),stderr);putc('\n',stderr);
	exit(2);}
    else if( level == 2 ) {
	puts(strusage(level)); exit(0);}
    sentinel--;
}


const char *
default_strusage( int level )
{
    const char *p;
    switch( level ) {
      case  0:	p = strusage(10); break;
      case  1:	p = strusage(11); break;
      case  2:	p = strusage(12); break;
      case 10:	p = "WkLib"
		  #if DOS386 && __WATCOMC__
		    " (DOS4G)"
		  #elif DOS386
		    " (DOSX)"
		  #elif DOS16RM
		    " (DOS16RM)"
		  #elif M_I86VM
		    " (VCM)"
		  #elif UNIX || POSIX
		    " (Posix)"
		  #elif OS2
		    " (OS/2)"
		  #elif WINNT && __CYGWIN32__
		    " (CygWin)"
		  #elif WINNT
		    " (WinNT)"
		  #elif NETWARE
		    " (Netware)"
		  #elif VMS
		    " (VMS)"
		  #endif
		    "; Copyright (c) 1997 by Werner Koch (dd9jn)" ; break;
      case 11:	p = "usage: ?"; break;
      case 16:
      case 15:	p = "[Untitled]"; break;
      case 23:	p = "[unknown]"; break;
      case 24:	p = ""; break;
      case 26:	p = ""; break;
      case 12:	p =
   "This is free software; you can redistribute it and/or modify\n"
   "it under the terms of the GNU General Public License as published by\n"
   "the Free Software Foundation; either version 2 of the License, or\n"
   "(at your option) any later version.\n\n"
   "WkLib is distributed in the hope that it will be useful,\n"
   "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
   "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
   "GNU General Public License for more details.\n\n"
   "You should have received a copy of the GNU General Public License\n"
   "along with this program; if not, write to the Free Software\n"
   "Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,"
								  " USA.\n" ;
	break;
      case 22:
	  #if MSDOS
	    #if USE_EMS
	      p = "MSDOS+EMS";
	    #else
	      p = "MSDOS";
	    #endif
	  #elif OS2
	    p = "OS/2";
	  #elif WINNT && __CYGWIN32__
	    p = "CygWin";
	  #elif WINNT
	    p = "WinNT";
	  #elif DOS386
	    p = "DOS386";
	  #elif EMX
	    p = "EMX";
	  #elif DOS16RM
	    p = "DOS16RM";
	  #elif NETWARE
	    p = "Netware";
	  #elif __linux__
	    p = "Linux";
	  #elif UNIX || M_UNIX || M_XENIX
	    p = "UNIX";
	  #elif VMS
	    p = "VMS";
	  #else
	    p = "UnknownOS";
	  #endif
	    break;
      case 31: p =
    "This program comes with ABSOLUTELY NO WARRANTY.\n"
    "This is free software, and you are welcome to redistribute it\n"
    "under certain conditions. See the file COPYING for details.\n";
	    break;
      case 32: p = "["
	  #if MSDOS
	      "MSDOS Version"
	  #elif DOS386 && __ZTC__
	    "32-Bit MSDOS Version (Zortech's DOSX)"
	  #elif DOS386
	    "32-Bit MSDOS Version"
	  #elif OS20 && EMX
	    "OS/2 2.x EMX Version"
	  #elif OS20
	    "OS/2 2.x Version"
	  #elif OS2
	    "OS/2 1.x Version"
	  #elif WINNT && __CYGWIN32__
	    "Cygnus WinAPI Version"
	  #elif WINNT
	    "Windoze NT Version"
	  #elif EMX
	    "EMX Version"
	  #elif NETWARE
	    "NLM Version"
	  #elif DOS16RM
	    "DOS16RM Version"
	  #elif __linux__
	    "Linux Version"
	  #elif VMS
	    "OpenVMS Version"
	  #elif POSIX
	    "POSIX Version"
	  #elif M_UNIX || M_XENIX
	    "*IX Version"
	  #endif
	    "]";
	    break;
      case 33: p =
	  #ifdef MULTI_THREADED
	    "mt"
	  #else
	    ""
	  #endif
	    ; break;
      case 42:
      case 43:
      case 44:
      case 45: p = ""; break;
      default: p = "?";
    }

    return p;
}



#ifdef TEST
static struct {
    int verbose;
    int debug;
    char *outfile;
    char *crf;
    int myopt;
    int echo;
    int a_long_one;
}opt;

int
main(int argc, char **argv)
{
    ARGPARSE_OPTS opts[] = {
    { 'v', "verbose",   0 , "Laut sein"},
    { 'e', "echo"   ,   0 , "Zeile ausgeben, damit wir sehen, was wir einegegeben haben"},
    { 'd', "debug",     0 , "Debug\nfalls mal etasws\nSchief geht"},
    { 'o', "output",    2   },
    { 'c', "cross-ref", 2|8, "cross-reference erzeugen\n" },
    { 'm', "my-option", 1|8 },
    { 500, "a-long-option", 0 },
    {0} };
    ARGPARSE_ARGS pargs = { &argc, &argv, 2|4|32 };
    int i;

    while( ArgParse( &pargs, opts) ) {
	switch( pargs.r_opt ) {
	  case -1 : printf( "arg='%s'\n", pargs.r.ret_str); break;
	  case 'v': opt.verbose++; break;
	  case 'e': opt.echo++; break;
	  case 'd': opt.debug++; break;
	  case 'o': opt.outfile = pargs.r.ret_str; break;
	  case 'c': opt.crf = pargs.r_type? pargs.r.ret_str:"a.crf"; break;
	  case 'm': opt.myopt = pargs.r_type? pargs.r.ret_int : 1; break;
	  case 500: opt.a_long_one++;  break;
	  default : pargs.err = 1; break; /* force warning output */
	}
    }
    for(i=0; i < argc; i++ )
	printf("%3d -> (%s)\n", i, argv[i] );
    puts("Options:");
    if( opt.verbose )
	printf("  verbose=%d\n", opt.verbose );
    if( opt.debug )
	printf("  debug=%d\n", opt.debug );
    if( opt.outfile )
	printf("  outfile='%s'\n", opt.outfile );
    if( opt.crf )
	printf("  crffile='%s'\n", opt.crf );
    if( opt.myopt )
	printf("  myopt=%d\n", opt.myopt );
    if( opt.a_long_one )
	printf("  a-long-one=%d\n", opt.a_long_one );
    if( opt.echo       )
	printf("  echo=%d\n", opt.echo );
    return 0;
}
#endif

/**** bottom of file ****/
