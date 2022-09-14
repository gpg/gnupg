/* T I N Y S C H E M E    1 . 4 1
 *   Dimitrios Souflis (dsouflis@acm.org)
 *   Based on MiniScheme (original credits follow)
 * (MINISCM)               coded by Atsushi Moriwaki (11/5/1989)
 * (MINISCM)           E-MAIL :  moriwaki@kurims.kurims.kyoto-u.ac.jp
 * (MINISCM) This version has been modified by R.C. Secrist.
 * (MINISCM)
 * (MINISCM) Mini-Scheme is now maintained by Akira KIDA.
 * (MINISCM)
 * (MINISCM) This is a revised and modified version by Akira KIDA.
 * (MINISCM)    current version is 0.85k4 (15 May 1994)
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#define _SCHEME_SOURCE
#include "scheme-private.h"
#ifndef WIN32
# include <unistd.h>
#endif
#ifdef WIN32
#define snprintf _snprintf
#endif
#if USE_DL
# include "dynload.h"
#endif
#if USE_MATH
# include <math.h>
#endif

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <float.h>
#include <ctype.h>

#if USE_STRCASECMP
#include <strings.h>
# ifndef __APPLE__
#  define stricmp strcasecmp
# endif
#endif

/* Used for documentation purposes, to signal functions in 'interface' */
#define INTERFACE

#define TOK_EOF     (-1)
#define TOK_LPAREN  0
#define TOK_RPAREN  1
#define TOK_DOT     2
#define TOK_ATOM    3
#define TOK_QUOTE   4
#define TOK_COMMENT 5
#define TOK_DQUOTE  6
#define TOK_BQUOTE  7
#define TOK_COMMA   8
#define TOK_ATMARK  9
#define TOK_SHARP   10
#define TOK_SHARP_CONST 11
#define TOK_VEC     12

#define BACKQUOTE '`'
#define DELIMITERS  "()\";\f\t\v\n\r "

/*
 *  Basic memory allocation units
 */

#define banner "TinyScheme 1.41"

#include <string.h>
#include <stddef.h>
#include <stdlib.h>

#ifdef __APPLE__
static int stricmp(const char *s1, const char *s2)
{
  unsigned char c1, c2;
  do {
    c1 = tolower(*s1);
    c2 = tolower(*s2);
    if (c1 < c2)
      return -1;
    else if (c1 > c2)
      return 1;
    s1++, s2++;
  } while (c1 != 0);
  return 0;
}
#endif /* __APPLE__ */

#if USE_STRLWR && !defined(HAVE_STRLWR)
static const char *strlwr(char *s) {
  const char *p=s;
  while(*s) {
    *s=tolower(*s);
    s++;
  }
  return p;
}
#endif

#ifndef prompt
# define prompt "ts> "
#endif

#ifndef InitFile
# define InitFile "init.scm"
#endif

#ifndef FIRST_CELLSEGS
# define FIRST_CELLSEGS 3
#endif



/* All types have the LSB set.  The garbage collector takes advantage
 * of that to identify types.  */
enum scheme_types {
  T_STRING =		 1 << 1 | 1,
  T_NUMBER =		 2 << 1 | 1,
  T_SYMBOL =		 3 << 1 | 1,
  T_PROC =		 4 << 1 | 1,
  T_PAIR =		 5 << 1 | 1,
  T_CLOSURE =		 6 << 1 | 1,
  T_CONTINUATION =	 7 << 1 | 1,
  T_FOREIGN =		 8 << 1 | 1,
  T_CHARACTER =		 9 << 1 | 1,
  T_PORT =		10 << 1 | 1,
  T_VECTOR =		11 << 1 | 1,
  T_MACRO =		12 << 1 | 1,
  T_PROMISE =		13 << 1 | 1,
  T_ENVIRONMENT =	14 << 1 | 1,
  T_FOREIGN_OBJECT =	15 << 1 | 1,
  T_BOOLEAN =		16 << 1 | 1,
  T_NIL =		17 << 1 | 1,
  T_EOF_OBJ =		18 << 1 | 1,
  T_SINK =		19 << 1 | 1,
  T_FRAME =		20 << 1 | 1,
  T_LAST_SYSTEM_TYPE =	20 << 1 | 1
};

static const char *
type_to_string (enum scheme_types typ)
{
     switch (typ)
     {
     case T_STRING: return "string";
     case T_NUMBER: return "number";
     case T_SYMBOL: return "symbol";
     case T_PROC: return "proc";
     case T_PAIR: return "pair";
     case T_CLOSURE: return "closure";
     case T_CONTINUATION: return "continuation";
     case T_FOREIGN: return "foreign";
     case T_CHARACTER: return "character";
     case T_PORT: return "port";
     case T_VECTOR: return "vector";
     case T_MACRO: return "macro";
     case T_PROMISE: return "promise";
     case T_ENVIRONMENT: return "environment";
     case T_FOREIGN_OBJECT: return "foreign object";
     case T_BOOLEAN: return "boolean";
     case T_NIL: return "nil";
     case T_EOF_OBJ: return "eof object";
     case T_SINK: return "sink";
     case T_FRAME: return "frame";
     }
     assert (! "not reached");
}

/* ADJ is enough slack to align cells in a TYPE_BITS-bit boundary */
#define TYPE_BITS	6
#define ADJ		(1 << TYPE_BITS)
#define T_MASKTYPE      (ADJ - 1)
                              /* 0000000000111111 */
#define T_TAGGED      1024    /* 0000010000000000 */
#define T_FINALIZE    2048    /* 0000100000000000 */
#define T_SYNTAX      4096    /* 0001000000000000 */
#define T_IMMUTABLE   8192    /* 0010000000000000 */
#define T_ATOM       16384    /* 0100000000000000 */   /* only for gc */
#define CLRATOM      49151    /* 1011111111111111 */   /* only for gc */
#define MARK         32768    /* 1000000000000000 */
#define UNMARK       32767    /* 0111111111111111 */


static num num_add(num a, num b);
static num num_mul(num a, num b);
static num num_div(num a, num b);
static num num_intdiv(num a, num b);
static num num_sub(num a, num b);
static num num_rem(num a, num b);
static num num_mod(num a, num b);
static int num_eq(num a, num b);
static int num_gt(num a, num b);
static int num_ge(num a, num b);
static int num_lt(num a, num b);
static int num_le(num a, num b);

#if USE_MATH
static double round_per_R5RS(double x);
#endif
static int is_zero_double(double x);
static INLINE int num_is_integer(pointer p) {
  return ((p)->_object._number.is_fixnum);
}

static const struct num num_zero = { 1, {0} };
static const struct num num_one  = { 1, {1} };

/* macros for cell operations */
#define typeflag(p)      ((p)->_flag)
#define type(p)          (typeflag(p)&T_MASKTYPE)
#define settype(p, typ)  (typeflag(p) = (typeflag(p) & ~T_MASKTYPE) | (typ))

INTERFACE INLINE int is_string(pointer p)     { return (type(p)==T_STRING); }
#define strvalue(p)      ((p)->_object._string._svalue)
#define strlength(p)        ((p)->_object._string._length)

INTERFACE static int is_list(scheme *sc, pointer p);
INTERFACE INLINE int is_vector(pointer p)    { return (type(p)==T_VECTOR); }
/* Given a vector, return it's length.  */
#define vector_length(v)	(v)->_object._vector._length
/* Given a vector length, compute the amount of cells required to
 * represent it.  */
#define vector_size(len)	(1 + ((len) - 1 + 2) / 3)
INTERFACE static void fill_vector(pointer vec, pointer obj);
INTERFACE static pointer *vector_elem_slot(pointer vec, int ielem);
INTERFACE static pointer vector_elem(pointer vec, int ielem);
INTERFACE static pointer set_vector_elem(pointer vec, int ielem, pointer a);
INTERFACE INLINE int is_number(pointer p)    { return (type(p)==T_NUMBER); }
INTERFACE INLINE int is_integer(pointer p) {
  if (!is_number(p))
      return 0;
  if (num_is_integer(p) || (double)ivalue(p) == rvalue(p))
      return 1;
  return 0;
}

INTERFACE INLINE int is_real(pointer p) {
  return is_number(p) && (!(p)->_object._number.is_fixnum);
}

INTERFACE INLINE int is_character(pointer p) { return (type(p)==T_CHARACTER); }
INTERFACE INLINE char *string_value(pointer p) { return strvalue(p); }
INLINE num nvalue(pointer p)       { return ((p)->_object._number); }
INTERFACE long ivalue(pointer p)      { return (num_is_integer(p)?(p)->_object._number.value.ivalue:(long)(p)->_object._number.value.rvalue); }
INTERFACE double rvalue(pointer p)    { return (!num_is_integer(p)?(p)->_object._number.value.rvalue:(double)(p)->_object._number.value.ivalue); }
#define ivalue_unchecked(p)       ((p)->_object._number.value.ivalue)
#define rvalue_unchecked(p)       ((p)->_object._number.value.rvalue)
#define set_num_integer(p)   (p)->_object._number.is_fixnum=1;
#define set_num_real(p)      (p)->_object._number.is_fixnum=0;
INTERFACE  long charvalue(pointer p)  { return ivalue_unchecked(p); }

INTERFACE INLINE int is_port(pointer p)     { return (type(p)==T_PORT); }
INTERFACE INLINE int is_inport(pointer p)  { return is_port(p) && p->_object._port->kind & port_input; }
INTERFACE INLINE int is_outport(pointer p) { return is_port(p) && p->_object._port->kind & port_output; }

INTERFACE INLINE int is_pair(pointer p)     { return (type(p)==T_PAIR); }
#define car(p)           ((p)->_object._cons._car)
#define cdr(p)           ((p)->_object._cons._cdr)
INTERFACE pointer pair_car(pointer p)   { return car(p); }
INTERFACE pointer pair_cdr(pointer p)   { return cdr(p); }
INTERFACE pointer set_car(pointer p, pointer q) { return car(p)=q; }
INTERFACE pointer set_cdr(pointer p, pointer q) { return cdr(p)=q; }

INTERFACE INLINE int is_symbol(pointer p)   { return (type(p)==T_SYMBOL); }
INTERFACE INLINE char *symname(pointer p)   { return strvalue(car(p)); }
#if USE_PLIST
SCHEME_EXPORT INLINE int hasprop(pointer p)     { return (is_symbol(p)); }
#define symprop(p)       cdr(p)
#endif

INTERFACE INLINE int is_syntax(pointer p)   { return (typeflag(p)&T_SYNTAX); }
INTERFACE INLINE int is_proc(pointer p)     { return (type(p)==T_PROC); }
INTERFACE INLINE int is_foreign(pointer p)  { return (type(p)==T_FOREIGN); }
INTERFACE INLINE char *syntaxname(pointer p) { return strvalue(car(p)); }
#define procnum(p)       ivalue_unchecked(p)
static const char *procname(pointer x);

INTERFACE INLINE int is_closure(pointer p)  { return (type(p)==T_CLOSURE); }
INTERFACE INLINE int is_macro(pointer p)    { return (type(p)==T_MACRO); }
INTERFACE INLINE pointer closure_code(pointer p)   { return car(p); }
INTERFACE INLINE pointer closure_env(pointer p)    { return cdr(p); }

INTERFACE INLINE int is_continuation(pointer p)    { return (type(p)==T_CONTINUATION); }
#define cont_dump(p)     cdr(p)

INTERFACE INLINE int is_foreign_object(pointer p) { return (type(p)==T_FOREIGN_OBJECT); }
INTERFACE const foreign_object_vtable *get_foreign_object_vtable(pointer p) {
  return p->_object._foreign_object._vtable;
}
INTERFACE void *get_foreign_object_data(pointer p) {
  return p->_object._foreign_object._data;
}

/* To do: promise should be forced ONCE only */
INTERFACE INLINE int is_promise(pointer p)  { return (type(p)==T_PROMISE); }

INTERFACE INLINE int is_environment(pointer p) { return (type(p)==T_ENVIRONMENT); }
#define setenvironment(p)    typeflag(p) = T_ENVIRONMENT

INTERFACE INLINE int is_frame(pointer p) { return (type(p) == T_FRAME); }
#define setframe(p)    settype(p, T_FRAME)

#define is_atom(p)       (typeflag(p)&T_ATOM)
#define setatom(p)       typeflag(p) |= T_ATOM
#define clratom(p)       typeflag(p) &= CLRATOM

#define is_mark(p)       (typeflag(p)&MARK)
#define setmark(p)       typeflag(p) |= MARK
#define clrmark(p)       typeflag(p) &= UNMARK

INTERFACE INLINE int is_immutable(pointer p) { return (typeflag(p)&T_IMMUTABLE); }
/*#define setimmutable(p)  typeflag(p) |= T_IMMUTABLE*/
INTERFACE INLINE void setimmutable(pointer p) { typeflag(p) |= T_IMMUTABLE; }

#define caar(p)          car(car(p))
#define cadr(p)          car(cdr(p))
#define cdar(p)          cdr(car(p))
#define cddr(p)          cdr(cdr(p))
#define cadar(p)         car(cdr(car(p)))
#define caddr(p)         car(cdr(cdr(p)))
#define cdaar(p)         cdr(car(car(p)))
#define cadaar(p)        car(cdr(car(car(p))))
#define cadddr(p)        car(cdr(cdr(cdr(p))))
#define cddddr(p)        cdr(cdr(cdr(cdr(p))))

#if USE_HISTORY
static pointer history_flatten(scheme *sc);
static void history_mark(scheme *sc);
#else
# define history_mark(SC)	(void) 0
# define history_flatten(SC)	(SC)->NIL
#endif

#if USE_CHAR_CLASSIFIERS
static INLINE int Cisalpha(int c) { return isascii(c) && isalpha(c); }
static INLINE int Cisdigit(int c) { return isascii(c) && isdigit(c); }
static INLINE int Cisspace(int c) { return isascii(c) && isspace(c); }
static INLINE int Cisupper(int c) { return isascii(c) && isupper(c); }
static INLINE int Cislower(int c) { return isascii(c) && islower(c); }
#endif

#if USE_ASCII_NAMES
static const char charnames[32][3]={
 "nul",
 "soh",
 "stx",
 "etx",
 "eot",
 "enq",
 "ack",
 "bel",
 "bs",
 "ht",
 "lf",
 "vt",
 "ff",
 "cr",
 "so",
 "si",
 "dle",
 "dc1",
 "dc2",
 "dc3",
 "dc4",
 "nak",
 "syn",
 "etb",
 "can",
 "em",
 "sub",
 "esc",
 "fs",
 "gs",
 "rs",
 "us"
};

static int is_ascii_name(const char *name, int *pc) {
  int i;
  for(i=0; i<32; i++) {
     if (strncasecmp(name, charnames[i], 3) == 0) {
          *pc=i;
          return 1;
     }
  }
  if (strcasecmp(name, "del") == 0) {
     *pc=127;
     return 1;
  }
  return 0;
}

#endif

static int file_push(scheme *sc, pointer fname);
static void file_pop(scheme *sc);
static int file_interactive(scheme *sc);
static INLINE int is_one_of(char *s, int c);
static int alloc_cellseg(scheme *sc, int n);
static long binary_decode(const char *s);
static INLINE pointer get_cell(scheme *sc, pointer a, pointer b);
static pointer _get_cell(scheme *sc, pointer a, pointer b);
static pointer reserve_cells(scheme *sc, int n);
static pointer get_consecutive_cells(scheme *sc, int n);
static pointer find_consecutive_cells(scheme *sc, int n);
static int finalize_cell(scheme *sc, pointer a);
static int count_consecutive_cells(pointer x, int needed);
static pointer find_slot_in_env(scheme *sc, pointer env, pointer sym, int all);
static pointer mk_number(scheme *sc, num n);
static char *store_string(scheme *sc, int len, const char *str, char fill);
static pointer mk_vector(scheme *sc, int len);
static pointer mk_atom(scheme *sc, char *q);
static pointer mk_sharp_const(scheme *sc, char *name);
static pointer mk_port(scheme *sc, port *p);
static pointer port_from_filename(scheme *sc, const char *fn, int prop);
static pointer port_from_file(scheme *sc, FILE *, int prop);
static pointer port_from_string(scheme *sc, char *start, char *past_the_end, int prop);
static port *port_rep_from_filename(scheme *sc, const char *fn, int prop);
static port *port_rep_from_file(scheme *sc, FILE *, int prop);
static port *port_rep_from_string(scheme *sc, char *start, char *past_the_end, int prop);
static void port_close(scheme *sc, pointer p, int flag);
static void mark(pointer a);
static void gc(scheme *sc, pointer a, pointer b);
static int basic_inchar(port *pt);
static int inchar(scheme *sc);
static void backchar(scheme *sc, int c);
static char   *readstr_upto(scheme *sc, char *delim);
static pointer readstrexp(scheme *sc);
static INLINE int skipspace(scheme *sc);
static int token(scheme *sc);
static void printslashstring(scheme *sc, char *s, int len);
static void atom2str(scheme *sc, pointer l, int f, char **pp, int *plen);
static void printatom(scheme *sc, pointer l, int f);
static pointer mk_proc(scheme *sc, enum scheme_opcodes op);
static pointer mk_closure(scheme *sc, pointer c, pointer e);
static pointer mk_continuation(scheme *sc, pointer d);
static pointer reverse(scheme *sc, pointer term, pointer list);
static pointer reverse_in_place(scheme *sc, pointer term, pointer list);
static pointer revappend(scheme *sc, pointer a, pointer b);
static void dump_stack_preallocate_frame(scheme *sc);
static void dump_stack_mark(scheme *);
struct op_code_info {
  char name[31];	/* strlen ("call-with-current-continuation") + 1 */
  unsigned char min_arity;
  unsigned char max_arity;
  char arg_tests_encoding[3];
};
static const struct op_code_info dispatch_table[];
static int check_arguments (scheme *sc, const struct op_code_info *pcd, char *msg, size_t msg_size);
static void Eval_Cycle(scheme *sc, enum scheme_opcodes op);
static void assign_syntax(scheme *sc, enum scheme_opcodes op, char *name);
static int syntaxnum(scheme *sc, pointer p);
static void assign_proc(scheme *sc, enum scheme_opcodes, const char *name);

#define num_ivalue(n)       (n.is_fixnum?(n).value.ivalue:(long)(n).value.rvalue)
#define num_rvalue(n)       (!n.is_fixnum?(n).value.rvalue:(double)(n).value.ivalue)

static num num_add(num a, num b) {
 num ret;
 ret.is_fixnum=a.is_fixnum && b.is_fixnum;
 if(ret.is_fixnum) {
     ret.value.ivalue= a.value.ivalue+b.value.ivalue;
 } else {
     ret.value.rvalue=num_rvalue(a)+num_rvalue(b);
 }
 return ret;
}

static num num_mul(num a, num b) {
 num ret;
 ret.is_fixnum=a.is_fixnum && b.is_fixnum;
 if(ret.is_fixnum) {
     ret.value.ivalue= a.value.ivalue*b.value.ivalue;
 } else {
     ret.value.rvalue=num_rvalue(a)*num_rvalue(b);
 }
 return ret;
}

static num num_div(num a, num b) {
 num ret;
 ret.is_fixnum=a.is_fixnum && b.is_fixnum && a.value.ivalue%b.value.ivalue==0;
 if(ret.is_fixnum) {
     ret.value.ivalue= a.value.ivalue/b.value.ivalue;
 } else {
     ret.value.rvalue=num_rvalue(a)/num_rvalue(b);
 }
 return ret;
}

static num num_intdiv(num a, num b) {
 num ret;
 ret.is_fixnum=a.is_fixnum && b.is_fixnum;
 if(ret.is_fixnum) {
     ret.value.ivalue= a.value.ivalue/b.value.ivalue;
 } else {
     ret.value.rvalue=num_rvalue(a)/num_rvalue(b);
 }
 return ret;
}

static num num_sub(num a, num b) {
 num ret;
 ret.is_fixnum=a.is_fixnum && b.is_fixnum;
 if(ret.is_fixnum) {
     ret.value.ivalue= a.value.ivalue-b.value.ivalue;
 } else {
     ret.value.rvalue=num_rvalue(a)-num_rvalue(b);
 }
 return ret;
}

static num num_rem(num a, num b) {
 num ret;
 long e1, e2, res;
 ret.is_fixnum=a.is_fixnum && b.is_fixnum;
 e1=num_ivalue(a);
 e2=num_ivalue(b);
 res=e1%e2;
 /* remainder should have same sign as second operand */
 if (res > 0) {
     if (e1 < 0) {
        res -= labs(e2);
     }
 } else if (res < 0) {
     if (e1 > 0) {
         res += labs(e2);
     }
 }
 ret.value.ivalue=res;
 return ret;
}

static num num_mod(num a, num b) {
 num ret;
 long e1, e2, res;
 ret.is_fixnum=a.is_fixnum && b.is_fixnum;
 e1=num_ivalue(a);
 e2=num_ivalue(b);
 res=e1%e2;
 /* modulo should have same sign as second operand */
 if (res * e2 < 0) {
    res += e2;
 }
 ret.value.ivalue=res;
 return ret;
}

static int num_eq(num a, num b) {
 int ret;
 int is_fixnum=a.is_fixnum && b.is_fixnum;
 if(is_fixnum) {
     ret= a.value.ivalue==b.value.ivalue;
 } else {
     ret=num_rvalue(a)==num_rvalue(b);
 }
 return ret;
}


static int num_gt(num a, num b) {
 int ret;
 int is_fixnum=a.is_fixnum && b.is_fixnum;
 if(is_fixnum) {
     ret= a.value.ivalue>b.value.ivalue;
 } else {
     ret=num_rvalue(a)>num_rvalue(b);
 }
 return ret;
}

static int num_ge(num a, num b) {
 return !num_lt(a,b);
}

static int num_lt(num a, num b) {
 int ret;
 int is_fixnum=a.is_fixnum && b.is_fixnum;
 if(is_fixnum) {
     ret= a.value.ivalue<b.value.ivalue;
 } else {
     ret=num_rvalue(a)<num_rvalue(b);
 }
 return ret;
}

static int num_le(num a, num b) {
 return !num_gt(a,b);
}

#if USE_MATH
/* Round to nearest. Round to even if midway */
static double round_per_R5RS(double x) {
 double fl=floor(x);
 double ce=ceil(x);
 double dfl=x-fl;
 double dce=ce-x;
 if(dfl>dce) {
     return ce;
 } else if(dfl<dce) {
     return fl;
 } else {
     if(fmod(fl,2.0)==0.0) {       /* I imagine this holds */
          return fl;
     } else {
          return ce;
     }
 }
}
#endif

static int is_zero_double(double x) {
 return x<DBL_MIN && x>-DBL_MIN;
}

static long binary_decode(const char *s) {
 long x=0;

 while(*s!=0 && (*s=='1' || *s=='0')) {
     x<<=1;
     x+=*s-'0';
     s++;
 }

 return x;
}



/*
 * Copying values.
 *
 * Occasionally, we need to copy a value from one location in the
 * storage to another.  Scheme objects are fine.  Some primitive
 * objects, however, require finalization, usually to free resources.
 *
 * For these values, we either make a copy or acquire a reference.
 */

/*
 * Copy SRC to DST.
 *
 * Copies the representation of SRC to DST.  This makes SRC
 * indistinguishable from DST from the perspective of a Scheme
 * expression modulo the fact that they reside at a different location
 * in the store.
 *
 * Conditions:
 *
 *     - SRC must not be a vector.
 *     - Caller must ensure that any resources associated with the
 *       value currently stored in DST is accounted for.
 */
static void
copy_value(scheme *sc, pointer dst, pointer src)
{
  memcpy(dst, src, sizeof *src);

  /* We may need to make a copy or acquire a reference.  */
  if (typeflag(dst) & T_FINALIZE)
    switch (type(dst)) {
    case T_STRING:
      strvalue(dst) = store_string(sc, strlength(dst), strvalue(dst), 0);
      break;
    case T_PORT:
      /* XXX acquire reference */
      assert (!"implemented");
      break;
    case T_FOREIGN_OBJECT:
      /* XXX acquire reference */
      assert (!"implemented");
      break;
     case T_VECTOR:
      assert (!"vectors cannot be copied");
    }
}



/* Tags are like property lists, but can be attached to arbitrary
 * values.  */

static pointer
mk_tagged_value(scheme *sc, pointer v, pointer tag_car, pointer tag_cdr)
{
  pointer r, t;

  assert(! is_vector(v));

  r = get_consecutive_cells(sc, 2);
  if (r == sc->sink)
    return sc->sink;

  copy_value(sc, r, v);
  typeflag(r) |= T_TAGGED;

  t = r + 1;
  typeflag(t) = T_PAIR;
  car(t) = tag_car;
  cdr(t) = tag_cdr;

  return r;
}

static INLINE int
has_tag(pointer v)
{
  return !! (typeflag(v) & T_TAGGED);
}

static INLINE pointer
get_tag(scheme *sc, pointer v)
{
  if (has_tag(v))
    return v + 1;
  return sc->NIL;
}



/* Low-level allocator.
 *
 * Memory is allocated in segments.  Every segment holds a fixed
 * number of cells.  Segments are linked into a list, sorted in
 * reverse address order (i.e. those with a higher address first).
 * This is used in the garbage collector to build the freelist in
 * address order.
 */

struct cell_segment
{
     struct cell_segment *next;
     void *alloc;
     pointer cells;
     size_t cells_len;
};

/* Allocate a new cell segment but do not make it available yet.  */
static int
_alloc_cellseg(scheme *sc, size_t len, struct cell_segment **segment)
{
  int adj = ADJ;
  void *cp;

  if (adj < sizeof(struct cell))
    adj = sizeof(struct cell);

  /* The segment header is conveniently allocated with the cells.  */
  cp = sc->malloc(sizeof **segment + len * sizeof(struct cell) + adj);
  if (cp == NULL)
    return 1;

  *segment = cp;
  (*segment)->next = NULL;
  (*segment)->alloc = cp;
  cp = (void *) ((uintptr_t) cp + sizeof **segment);

  /* adjust in TYPE_BITS-bit boundary */
  if (((uintptr_t) cp) % adj != 0)
    cp = (void *) (adj * ((uintptr_t) cp / adj + 1));

  (*segment)->cells = cp;
  (*segment)->cells_len = len;
  return 0;
}

/* Deallocate a cell segment.  Returns the next cell segment.
 * Convenient for deallocation in a loop.  */
static struct cell_segment *
_dealloc_cellseg(scheme *sc, struct cell_segment *segment)
{

  struct cell_segment *next;

  if (segment == NULL)
    return NULL;

  next = segment->next;
  sc->free(segment->alloc);
  return next;
}

/* allocate new cell segment */
static int alloc_cellseg(scheme *sc, int n) {
     pointer last;
     pointer p;
     int k;

     for (k = 0; k < n; k++) {
	 struct cell_segment *new, **s;
	 if (_alloc_cellseg(sc, CELL_SEGSIZE, &new)) {
	      return k;
	 }
	 /* insert new segment in reverse address order */
	 for (s = &sc->cell_segments;
	      *s && (uintptr_t) (*s)->alloc > (uintptr_t) new->alloc;
	      s = &(*s)->next) {
	     /* walk */
	 }
	 new->next = *s;
	 *s = new;

         sc->fcells += new->cells_len;
         last = new->cells + new->cells_len - 1;
          for (p = new->cells; p <= last; p++) {
              typeflag(p) = 0;
              cdr(p) = p + 1;
              car(p) = sc->NIL;
         }
         /* insert new cells in address order on free list */
         if (sc->free_cell == sc->NIL || p < sc->free_cell) {
              cdr(last) = sc->free_cell;
              sc->free_cell = new->cells;
         } else {
               p = sc->free_cell;
               while (cdr(p) != sc->NIL && (uintptr_t) new->cells > (uintptr_t) cdr(p))
                    p = cdr(p);
               cdr(last) = cdr(p);
               cdr(p) = new->cells;
         }
     }
     return n;
}



/* Controlling the garbage collector.
 *
 * Every time a cell is allocated, the interpreter may run out of free
 * cells and do a garbage collection.  This is problematic because it
 * might garbage collect objects that have been allocated, but are not
 * yet made available to the interpreter.
 *
 * Previously, we would plug such newly allocated cells into the list
 * of newly allocated objects rooted at car(sc->sink), but that
 * requires allocating yet another cell increasing pressure on the
 * memory management system.
 *
 * A faster alternative is to preallocate the cells needed for an
 * operation and make sure the garbage collection is not run until all
 * allocated objects are plugged in.  This can be done with gc_disable
 * and gc_enable.
 */

/* The garbage collector is enabled if the inhibit counter is
 * zero.  */
#define GC_ENABLED	0

/* For now we provide a way to disable this optimization for
 * benchmarking and because it produces slightly smaller code.  */
#ifndef USE_GC_LOCKING
# define USE_GC_LOCKING 1
#endif

/* To facilitate nested calls to gc_disable, functions that allocate
 * more than one cell may define a macro, e.g. foo_allocates.  This
 * macro can be used to compute the amount of preallocation at the
 * call site with the help of this macro.  */
#define gc_reservations(fn) fn ## _allocates

#if USE_GC_LOCKING

/* Report a shortage in reserved cells, and terminate the program.  */
static void
gc_reservation_failure(struct scheme *sc)
{
#ifdef NDEBUG
  fprintf(stderr,
	  "insufficient reservation\n");
#else
  fprintf(stderr,
	  "insufficient %s reservation in line %d\n",
	  sc->frame_freelist == sc->NIL ? "frame" : "cell",
	  sc->reserved_lineno);
#endif
  abort();
}

/* Disable the garbage collection and reserve the given number of
 * cells.  gc_disable may be nested, but the enclosing reservation
 * must include the reservations of all nested calls.  Note: You must
 * re-enable the gc before calling Error_X.  */
static void
_gc_disable(struct scheme *sc, size_t reserve, int lineno)
{
  if (sc->inhibit_gc == 0) {
    reserve_cells(sc, (reserve));
    sc->reserved_cells = (reserve);
#ifdef NDEBUG
    (void) lineno;
#else
    sc->reserved_lineno = lineno;
#endif
  } else if (sc->reserved_cells < (reserve))
    gc_reservation_failure (sc);
  sc->inhibit_gc += 1;
}
#define gc_disable(sc, reserve)			\
     do {					\
       if (sc->frame_freelist == sc->NIL) {	\
	 if (gc_enabled(sc))			\
	   dump_stack_preallocate_frame(sc);	\
	 else					\
	   gc_reservation_failure(sc);		\
       }					\
       _gc_disable (sc, reserve, __LINE__);	\
     } while (0)

/* Enable the garbage collector.  */
#define gc_enable(sc)				\
     do {					\
	  assert(sc->inhibit_gc);		\
	  sc->inhibit_gc -= 1;			\
     } while (0)

/* Test whether the garbage collector is enabled.  */
#define gc_enabled(sc)				\
     (sc->inhibit_gc == GC_ENABLED)

/* Consume a reserved cell.  */
#define gc_consume(sc)							\
     do {								\
	  assert(! gc_enabled (sc));					\
	  if (sc->reserved_cells == 0)					\
	       gc_reservation_failure (sc);				\
	  sc->reserved_cells -= 1;					\
     } while (0)

#else /* USE_GC_LOCKING */

#define gc_reservation_failure(sc)	(void) 0
#define gc_disable(sc, reserve)			\
     do {					\
       if (sc->frame_freelist == sc->NIL)	\
	 dump_stack_preallocate_frame(sc);	\
     } while (0)
#define gc_enable(sc)	(void) 0
#define gc_enabled(sc)	1
#define gc_consume(sc)	(void) 0

#endif /* USE_GC_LOCKING */

static INLINE pointer get_cell_x(scheme *sc, pointer a, pointer b) {
  if (! gc_enabled (sc) || sc->free_cell != sc->NIL) {
    pointer x = sc->free_cell;
    if (! gc_enabled (sc))
	 gc_consume (sc);
    sc->free_cell = cdr(x);
    --sc->fcells;
    return (x);
  }
  assert (gc_enabled (sc));
  return _get_cell (sc, a, b);
}


/* get new cell.  parameter a, b is marked by gc. */
static pointer _get_cell(scheme *sc, pointer a, pointer b) {
  pointer x;

  if(sc->no_memory) {
    return sc->sink;
  }

  assert (gc_enabled (sc));
  if (sc->free_cell == sc->NIL) {
    gc(sc,a, b);
    if (sc->free_cell == sc->NIL) {
	 sc->no_memory=1;
	 return sc->sink;
    }
  }
  x = sc->free_cell;
  sc->free_cell = cdr(x);
  --sc->fcells;
  return (x);
}

/* make sure that there is a given number of cells free */
static pointer reserve_cells(scheme *sc, int n) {
    if(sc->no_memory) {
        return sc->NIL;
    }

    /* Are there enough cells available? */
    if (sc->fcells < n) {
        /* If not, try gc'ing some */
        gc(sc, sc->NIL, sc->NIL);
        if (sc->fcells < n) {
            /* If there still aren't, try getting more heap */
            if (!alloc_cellseg(sc,1)) {
                sc->no_memory=1;
                return sc->NIL;
            }
        }
        if (sc->fcells < n) {
            /* If all fail, report failure */
            sc->no_memory=1;
            return sc->NIL;
        }
    }
    return (sc->T);
}

static pointer get_consecutive_cells(scheme *sc, int n) {
  pointer x;

  if(sc->no_memory) { return sc->sink; }

  /* Are there any cells available? */
  x=find_consecutive_cells(sc,n);
  if (x != sc->NIL) { return x; }

  /* If not, try gc'ing some */
  gc(sc, sc->NIL, sc->NIL);
  x=find_consecutive_cells(sc,n);
  if (x != sc->NIL) { return x; }

  /* If there still aren't, try getting more heap */
  if (!alloc_cellseg(sc,1))
    {
      sc->no_memory=1;
      return sc->sink;
    }

  x=find_consecutive_cells(sc,n);
  if (x != sc->NIL) { return x; }

  /* If all fail, report failure */
  sc->no_memory=1;
  return sc->sink;
}

static int count_consecutive_cells(pointer x, int needed) {
 int n=1;
 while(cdr(x)==x+1) {
     x=cdr(x);
     n++;
     if(n>needed) return n;
 }
 return n;
}

static pointer find_consecutive_cells(scheme *sc, int n) {
  pointer *pp;
  int cnt;

  pp=&sc->free_cell;
  while(*pp!=sc->NIL) {
    cnt=count_consecutive_cells(*pp,n);
    if(cnt>=n) {
      pointer x=*pp;
      *pp=cdr(*pp+n-1);
      sc->fcells -= n;
      return x;
    }
    pp=&cdr(*pp+cnt-1);
  }
  return sc->NIL;
}

/* Free a cell.  This is dangerous.  Only free cells that are not
 * referenced.  */
static INLINE void
free_cell(scheme *sc, pointer a)
{
  cdr(a) = sc->free_cell;
  sc->free_cell = a;
  sc->fcells += 1;
}

/* Free a cell and retrieve its content.  This is dangerous.  Only
 * free cells that are not referenced.  */
static INLINE void
free_cons(scheme *sc, pointer a, pointer *r_car, pointer *r_cdr)
{
  *r_car = car(a);
  *r_cdr = cdr(a);
  free_cell(sc, a);
}

/* To retain recent allocs before interpreter knows about them -
   Tehom */

static void push_recent_alloc(scheme *sc, pointer recent, pointer extra)
{
  pointer holder = get_cell_x(sc, recent, extra);
  typeflag(holder) = T_PAIR | T_IMMUTABLE;
  car(holder) = recent;
  cdr(holder) = car(sc->sink);
  car(sc->sink) = holder;
}

static INLINE void ok_to_freely_gc(scheme *sc)
{
  pointer a = car(sc->sink), next;
  car(sc->sink) = sc->NIL;
  while (a != sc->NIL)
    {
      next = cdr(a);
      free_cell(sc, a);
      a = next;
    }
}

static pointer get_cell(scheme *sc, pointer a, pointer b)
{
  pointer cell   = get_cell_x(sc, a, b);
  /* For right now, include "a" and "b" in "cell" so that gc doesn't
     think they are garbage. */
  /* Tentatively record it as a pair so gc understands it. */
  typeflag(cell) = T_PAIR;
  car(cell) = a;
  cdr(cell) = b;
  if (gc_enabled (sc))
    push_recent_alloc(sc, cell, sc->NIL);
  return cell;
}

static pointer get_vector_object(scheme *sc, int len, pointer init)
{
  pointer cells = get_consecutive_cells(sc, vector_size(len));
  int i;
  int alloc_len = 1 + 3 * (vector_size(len) - 1);
  if(sc->no_memory) { return sc->sink; }
  /* Record it as a vector so that gc understands it. */
  typeflag(cells) = (T_VECTOR | T_ATOM | T_FINALIZE);
  vector_length(cells) = len;
  fill_vector(cells,init);

  /* Initialize the unused slots at the end.  */
  assert (alloc_len - len < 3);
  for (i = len; i < alloc_len; i++)
    cells->_object._vector._elements[i] = sc->NIL;

  if (gc_enabled (sc))
    push_recent_alloc(sc, cells, sc->NIL);
  return cells;
}

/* Medium level cell allocation */

/* get new cons cell */
pointer _cons(scheme *sc, pointer a, pointer b, int immutable) {
  pointer x = get_cell(sc,a, b);

  typeflag(x) = T_PAIR;
  if(immutable) {
    setimmutable(x);
  }
  car(x) = a;
  cdr(x) = b;
  return (x);
}


/* ========== oblist implementation  ========== */

#ifndef USE_OBJECT_LIST

static int hash_fn(const char *key, int table_size);

static pointer oblist_initial_value(scheme *sc)
{
  /* There are about 768 symbols used after loading the
   * interpreter.  */
  return mk_vector(sc, 1009);
}

/* Lookup the symbol NAME.  Returns the symbol, or NIL if it does not
 * exist.  In that case, SLOT points to the point where the new symbol
 * is to be inserted.  */
static INLINE pointer
oblist_find_by_name(scheme *sc, const char *name, pointer **slot)
{
  int location;
  pointer x;
  char *s;
  int d;

  location = hash_fn(name, vector_length(sc->oblist));
  for (*slot = vector_elem_slot(sc->oblist, location), x = **slot;
       x != sc->NIL; *slot = &cdr(x), x = **slot) {
    s = symname(car(x));
    /* case-insensitive, per R5RS section 2. */
    d = stricmp(name, s);
    if (d == 0)
      return car(x);		/* Hit.  */
    else if (d > 0)
      break;			/* Miss.  */
  }
  return sc->NIL;
}

static pointer oblist_all_symbols(scheme *sc)
{
  int i;
  pointer x;
  pointer ob_list = sc->NIL;

  for (i = 0; i < vector_length(sc->oblist); i++) {
    for (x  = vector_elem(sc->oblist, i); x != sc->NIL; x = cdr(x)) {
      ob_list = cons(sc, x, ob_list);
    }
  }
  return ob_list;
}

#else

static pointer oblist_initial_value(scheme *sc)
{
  return sc->NIL;
}

/* Lookup the symbol NAME.  Returns the symbol, or NIL if it does not
 * exist.  In that case, SLOT points to the point where the new symbol
 * is to be inserted.  */
static INLINE pointer
oblist_find_by_name(scheme *sc, const char *name, pointer **slot)
{
     pointer x;
     char    *s;
     int     d;

     for (*slot = &sc->oblist, x = **slot; x != sc->NIL; *slot = &cdr(x), x = **slot) {
        s = symname(car(x));
        /* case-insensitive, per R5RS section 2. */
	d = stricmp(name, s);
        if (d == 0)
          return car(x);	/* Hit.  */
        else if (d > 0)
	  break;		/* Miss.  */
     }
     return sc->NIL;
}

static pointer oblist_all_symbols(scheme *sc)
{
  return sc->oblist;
}

#endif

/* Add a new symbol NAME at SLOT.  SLOT must be obtained using
 * oblist_find_by_name, and no insertion must be done between
 * obtaining the SLOT and calling this function.  Returns the new
 * symbol.  */
static pointer oblist_add_by_name(scheme *sc, const char *name, pointer *slot)
{
#define oblist_add_by_name_allocates	3
  pointer x;

  gc_disable(sc, gc_reservations (oblist_add_by_name));
  x = immutable_cons(sc, mk_string(sc, name), sc->NIL);
  typeflag(x) = T_SYMBOL;
  setimmutable(car(x));
  *slot = immutable_cons(sc, x, *slot);
  gc_enable(sc);
  return x;
}



static pointer mk_port(scheme *sc, port *p) {
  pointer x = get_cell(sc, sc->NIL, sc->NIL);

  typeflag(x) = T_PORT|T_ATOM|T_FINALIZE;
  x->_object._port=p;
  return (x);
}

pointer mk_foreign_func(scheme *sc, foreign_func f) {
  pointer x = get_cell(sc, sc->NIL, sc->NIL);

  typeflag(x) = (T_FOREIGN | T_ATOM);
  x->_object._ff=f;
  return (x);
}

pointer mk_foreign_object(scheme *sc, const foreign_object_vtable *vtable, void *data) {
  pointer x = get_cell(sc, sc->NIL, sc->NIL);

  typeflag(x) = (T_FOREIGN_OBJECT | T_ATOM | T_FINALIZE);
  x->_object._foreign_object._vtable=vtable;
  x->_object._foreign_object._data = data;
  return (x);
}

INTERFACE pointer mk_character(scheme *sc, int c) {
  pointer x = get_cell(sc,sc->NIL, sc->NIL);

  typeflag(x) = (T_CHARACTER | T_ATOM);
  ivalue_unchecked(x)= c;
  set_num_integer(x);
  return (x);
}



#if USE_SMALL_INTEGERS

static const struct cell small_integers[] = {
#define DEFINE_INTEGER(n) { T_NUMBER | T_ATOM | MARK, {{ 1, {n}}}},
#include "small-integers.h"
#undef DEFINE_INTEGER
     {0}
};

#define MAX_SMALL_INTEGER	(sizeof small_integers / sizeof *small_integers - 1)

static INLINE pointer
mk_small_integer(scheme *sc, long n)
{
#define mk_small_integer_allocates	0
  (void) sc;
  assert(0 <= n && n < MAX_SMALL_INTEGER);
  return (pointer) &small_integers[n];
}
#else

#define mk_small_integer_allocates	1
#define mk_small_integer	mk_integer

#endif

/* get number atom (integer) */
INTERFACE pointer mk_integer(scheme *sc, long n) {
  pointer x;

#if USE_SMALL_INTEGERS
  if (0 <= n && n < MAX_SMALL_INTEGER)
    return mk_small_integer(sc, n);
#endif

  x = get_cell(sc,sc->NIL, sc->NIL);
  typeflag(x) = (T_NUMBER | T_ATOM);
  ivalue_unchecked(x)= n;
  set_num_integer(x);
  return (x);
}



INTERFACE pointer mk_real(scheme *sc, double n) {
  pointer x = get_cell(sc,sc->NIL, sc->NIL);

  typeflag(x) = (T_NUMBER | T_ATOM);
  rvalue_unchecked(x)= n;
  set_num_real(x);
  return (x);
}

static pointer mk_number(scheme *sc, num n) {
 if(n.is_fixnum) {
     return mk_integer(sc,n.value.ivalue);
 } else {
     return mk_real(sc,n.value.rvalue);
 }
}

/* allocate name to string area */
static char *store_string(scheme *sc, int len_str, const char *str, char fill) {
     char *q;

     q=(char*)sc->malloc(len_str+1);
     if(q==0) {
          sc->no_memory=1;
          return sc->strbuff;
     }
     if(str!=0) {
	  memcpy (q, str, len_str);
          q[len_str]=0;
     } else {
          memset(q, fill, len_str);
          q[len_str]=0;
     }
     return (q);
}

/* get new string */
INTERFACE pointer mk_string(scheme *sc, const char *str) {
     return mk_counted_string(sc,str,strlen(str));
}

INTERFACE pointer mk_counted_string(scheme *sc, const char *str, int len) {
     pointer x = get_cell(sc, sc->NIL, sc->NIL);
     typeflag(x) = (T_STRING | T_ATOM | T_FINALIZE);
     strvalue(x) = store_string(sc,len,str,0);
     strlength(x) = len;
     return (x);
}

INTERFACE pointer mk_empty_string(scheme *sc, int len, char fill) {
     pointer x = get_cell(sc, sc->NIL, sc->NIL);
     typeflag(x) = (T_STRING | T_ATOM | T_FINALIZE);
     strvalue(x) = store_string(sc,len,0,fill);
     strlength(x) = len;
     return (x);
}

INTERFACE static pointer mk_vector(scheme *sc, int len)
{ return get_vector_object(sc,len,sc->NIL); }

INTERFACE static void fill_vector(pointer vec, pointer obj) {
     size_t i;
     assert (is_vector (vec));
     for(i = 0; i < vector_length(vec); i++) {
          vec->_object._vector._elements[i] = obj;
     }
}

INTERFACE static pointer *vector_elem_slot(pointer vec, int ielem) {
     assert (is_vector (vec));
     assert (ielem < vector_length(vec));
     return &vec->_object._vector._elements[ielem];
}

INTERFACE static pointer vector_elem(pointer vec, int ielem) {
     assert (is_vector (vec));
     assert (ielem < vector_length(vec));
     return vec->_object._vector._elements[ielem];
}

INTERFACE static pointer set_vector_elem(pointer vec, int ielem, pointer a) {
     assert (is_vector (vec));
     assert (ielem < vector_length(vec));
     vec->_object._vector._elements[ielem] = a;
     return a;
}

/* get new symbol */
INTERFACE pointer mk_symbol(scheme *sc, const char *name) {
#define mk_symbol_allocates	oblist_add_by_name_allocates
     pointer x;
     pointer *slot;

     /* first check oblist */
     x = oblist_find_by_name(sc, name, &slot);
     if (x != sc->NIL) {
          return (x);
     } else {
          x = oblist_add_by_name(sc, name, slot);
          return (x);
     }
}

INTERFACE pointer gensym(scheme *sc) {
     pointer x;
     pointer *slot;
     char name[40];

     for(; sc->gensym_cnt<LONG_MAX; sc->gensym_cnt++) {
          snprintf(name,40,"gensym-%ld",sc->gensym_cnt);

          /* first check oblist */
          x = oblist_find_by_name(sc, name, &slot);

          if (x != sc->NIL) {
               continue;
          } else {
	       x = oblist_add_by_name(sc, name, slot);
               return (x);
          }
     }

     return sc->NIL;
}

/* double the size of the string buffer */
static int expand_strbuff(scheme *sc) {
  size_t new_size = sc->strbuff_size * 2;
  char *new_buffer = sc->malloc(new_size);
  if (new_buffer == 0) {
    sc->no_memory = 1;
    return 1;
  }
  memcpy(new_buffer, sc->strbuff, sc->strbuff_size);
  sc->free(sc->strbuff);
  sc->strbuff = new_buffer;
  sc->strbuff_size = new_size;
  return 0;
}

/* make symbol or number atom from string */
static pointer mk_atom(scheme *sc, char *q) {
     char    c, *p;
     int has_dec_point=0;
     int has_fp_exp = 0;

#if USE_COLON_HOOK
     char *next;
     next = p = q;
     while ((next = strstr(next, "::")) != 0) {
	  /* Keep looking for the last occurrence.  */
	  p = next;
	  next = next + 2;
     }

     if (p != q) {
          *p=0;
          return cons(sc, sc->COLON_HOOK,
                          cons(sc,
                              cons(sc,
                                   sc->QUOTE,
                                   cons(sc, mk_symbol(sc, strlwr(p + 2)),
					sc->NIL)),
                              cons(sc, mk_atom(sc, q), sc->NIL)));
     }
#endif

     p = q;
     c = *p++;
     if ((c == '+') || (c == '-')) {
       c = *p++;
       if (c == '.') {
         has_dec_point=1;
         c = *p++;
       }
       if (!isdigit(c)) {
         return (mk_symbol(sc, strlwr(q)));
       }
     } else if (c == '.') {
       has_dec_point=1;
       c = *p++;
       if (!isdigit(c)) {
         return (mk_symbol(sc, strlwr(q)));
       }
     } else if (!isdigit(c)) {
       return (mk_symbol(sc, strlwr(q)));
     }

     for ( ; (c = *p) != 0; ++p) {
          if (!isdigit(c)) {
               if(c=='.') {
                    if(!has_dec_point) {
                         has_dec_point=1;
                         continue;
                    }
               }
               else if ((c == 'e') || (c == 'E')) {
                       if(!has_fp_exp) {
                          has_dec_point = 1; /* decimal point illegal
                                                from now on */
                          p++;
                          if ((*p == '-') || (*p == '+') || isdigit(*p)) {
                             continue;
                          }
                       }
               }
               return (mk_symbol(sc, strlwr(q)));
          }
     }
     if(has_dec_point) {
          return mk_real(sc,atof(q));
     }
     return (mk_integer(sc, atol(q)));
}

/* make constant */
static pointer mk_sharp_const(scheme *sc, char *name) {
     long    x;
     char    tmp[STRBUFFSIZE];

     if (!strcmp(name, "t"))
          return (sc->T);
     else if (!strcmp(name, "f"))
          return (sc->F);
     else if (*name == 'o') {/* #o (octal) */
          snprintf(tmp, STRBUFFSIZE, "0%s", name+1);
          sscanf(tmp, "%lo", (long unsigned *)&x);
          return (mk_integer(sc, x));
     } else if (*name == 'd') {    /* #d (decimal) */
          sscanf(name+1, "%ld", (long int *)&x);
          return (mk_integer(sc, x));
     } else if (*name == 'x') {    /* #x (hex) */
          snprintf(tmp, STRBUFFSIZE, "0x%s", name+1);
          sscanf(tmp, "%lx", (long unsigned *)&x);
          return (mk_integer(sc, x));
     } else if (*name == 'b') {    /* #b (binary) */
          x = binary_decode(name+1);
          return (mk_integer(sc, x));
     } else if (*name == '\\') { /* #\w (character) */
          int c=0;
          if(stricmp(name+1,"space")==0) {
               c=' ';
          } else if(stricmp(name+1,"newline")==0) {
               c='\n';
          } else if(stricmp(name+1,"return")==0) {
               c='\r';
          } else if(stricmp(name+1,"tab")==0) {
               c='\t';
     } else if(name[1]=='x' && name[2]!=0) {
          int c1=0;
          if(sscanf(name+2,"%x",(unsigned int *)&c1)==1 && c1 < UCHAR_MAX) {
               c=c1;
          } else {
               return sc->NIL;
     }
#if USE_ASCII_NAMES
          } else if(is_ascii_name(name+1,&c)) {
               /* nothing */
#endif
          } else if(name[2]==0) {
               c=name[1];
          } else {
               return sc->NIL;
          }
          return mk_character(sc,c);
     } else
          return (sc->NIL);
}

/* ========== garbage collector ========== */

const int frame_length;
static void dump_stack_deallocate_frame(scheme *sc, pointer frame);

/*--
 *  We use algorithm E (Knuth, The Art of Computer Programming Vol.1,
 *  sec. 2.3.5), the Schorr-Deutsch-Waite link-inversion algorithm,
 *  for marking.
 */
static void mark(pointer a) {
     pointer t, q, p;

     t = (pointer) 0;
     p = a;
E2:  if (! is_mark(p))
	  setmark(p);
     if (is_vector(p) || is_frame(p)) {
          int i;
	  int len = is_vector(p) ? vector_length(p) : frame_length;
          for (i = 0; i < len; i++) {
               mark(p->_object._vector._elements[i]);
          }
     }
#if SHOW_ERROR_LINE
     else if (is_port(p)) {
	  port *pt = p->_object._port;
	  mark(pt->curr_line);
	  mark(pt->filename);
     }
#endif
     /* Mark tag if p has one.  */
     if (has_tag(p))
       mark(p + 1);
     if (is_atom(p))
          goto E6;
     /* E4: down car */
     q = car(p);
     if (q && !is_mark(q)) {
          setatom(p);  /* a note that we have moved car */
          car(p) = t;
          t = p;
          p = q;
          goto E2;
     }
E5:  q = cdr(p); /* down cdr */
     if (q && !is_mark(q)) {
          cdr(p) = t;
          t = p;
          p = q;
          goto E2;
     }
E6:   /* up.  Undo the link switching from steps E4 and E5. */
     if (!t)
          return;
     q = t;
     if (is_atom(q)) {
          clratom(q);
          t = car(q);
          car(q) = p;
          p = q;
          goto E5;
     } else {
          t = cdr(q);
          cdr(q) = p;
          p = q;
          goto E6;
     }
}

/* garbage collection. parameter a, b is marked. */
static void gc(scheme *sc, pointer a, pointer b) {
  pointer p;
  struct cell_segment *s;
  int i;

  assert (gc_enabled (sc));

  if(sc->gc_verbose) {
    putstr(sc, "gc...");
  }

  /* mark system globals */
  mark(sc->oblist);
  mark(sc->global_env);

  /* mark current registers */
  mark(sc->args);
  mark(sc->envir);
  mark(sc->code);
  history_mark(sc);
  dump_stack_mark(sc);
  mark(sc->value);
  mark(sc->inport);
  mark(sc->save_inport);
  mark(sc->outport);
  mark(sc->loadport);
  for (i = 0; i <= sc->file_i; i++) {
    mark(sc->load_stack[i].filename);
    mark(sc->load_stack[i].curr_line);
  }

  /* Mark recent objects the interpreter doesn't know about yet. */
  mark(car(sc->sink));
  /* Mark any older stuff above nested C calls */
  mark(sc->c_nest);

  /* mark variables a, b */
  mark(a);
  mark(b);

  /* garbage collect */
  clrmark(sc->NIL);
  sc->fcells = 0;
  sc->free_cell = sc->NIL;
  /* free-list is kept sorted by address so as to maintain consecutive
     ranges, if possible, for use with vectors. Here we scan the cells
     (which are also kept sorted by address) downwards to build the
     free-list in sorted order.
  */
  for (s = sc->cell_segments; s; s = s->next) {
    p = s->cells + s->cells_len;
    while (--p >= s->cells) {
      if ((typeflag(p) & 1) == 0)
	/* All types have the LSB set.  This is not a typeflag.  */
	continue;
      if (is_mark(p)) {
    clrmark(p);
      } else {
	/* reclaim cell */
        if ((typeflag(p) & T_FINALIZE) == 0
	    || finalize_cell(sc, p)) {
	  /* Reclaim cell.  */
	  ++sc->fcells;
	  typeflag(p) = 0;
	  car(p) = sc->NIL;
	  cdr(p) = sc->free_cell;
	  sc->free_cell = p;
	}
      }
    }
  }

  if (sc->gc_verbose) {
    char msg[80];
    snprintf(msg,80,"done: %ld cells were recovered.\n", sc->fcells);
    putstr(sc,msg);
  }

  /* if only a few recovered, get more to avoid fruitless gc's */
  if (sc->fcells < CELL_MINRECOVER
       && alloc_cellseg(sc, 1) == 0)
       sc->no_memory = 1;
}

/* Finalize A.  Returns true if a can be added to the list of free
 * cells.  */
static int
finalize_cell(scheme *sc, pointer a)
{
  switch (type(a)) {
  case T_STRING:
    sc->free(strvalue(a));
    break;

  case T_PORT:
    if(a->_object._port->kind&port_file
       && a->_object._port->rep.stdio.closeit) {
      port_close(sc,a,port_input|port_output);
    } else if (a->_object._port->kind & port_srfi6) {
      sc->free(a->_object._port->rep.string.start);
    }
    sc->free(a->_object._port);
    break;

  case T_FOREIGN_OBJECT:
    a->_object._foreign_object._vtable->finalize(sc, a->_object._foreign_object._data);
    break;

  case T_VECTOR:
    do {
      int i;
      for (i = vector_size(vector_length(a)) - 1; i > 0; i--) {
	pointer p = a + i;
	typeflag(p) = 0;
	car(p) = sc->NIL;
	cdr(p) = sc->free_cell;
	sc->free_cell = p;
	sc->fcells += 1;
      }
    } while (0);
    break;

  case T_FRAME:
    dump_stack_deallocate_frame(sc, a);
    return 0;	/* Do not free cell.  */
  }

  return 1;	/* Free cell.  */
}

#if SHOW_ERROR_LINE
static void
port_clear_location (scheme *sc, port *p)
{
  p->curr_line = sc->NIL;
  p->filename = sc->NIL;
}

static void
port_increment_current_line (scheme *sc, port *p, long delta)
{
  if (delta == 0)
    return;

  p->curr_line =
    mk_integer(sc, ivalue_unchecked(p->curr_line) + delta);
}

static void
port_init_location (scheme *sc, port *p, pointer name)
{
  p->curr_line = mk_integer(sc, 0);
  p->filename = name ? name : mk_string(sc, "<unknown>");
}

#else

static void
port_clear_location (scheme *sc, port *p)
{
}

static void
port_increment_current_line (scheme *sc, port *p, long delta)
{
}

static void
port_init_location (scheme *sc, port *p, pointer name)
{
}

#endif

/* ========== Routines for Reading ========== */

static int file_push(scheme *sc, pointer fname) {
  FILE *fin = NULL;

  if (sc->file_i == MAXFIL-1)
     return 0;
  fin = fopen(string_value(fname), "r");
  if(fin!=0) {
    sc->file_i++;
    sc->load_stack[sc->file_i].kind=port_file|port_input;
    sc->load_stack[sc->file_i].rep.stdio.file=fin;
    sc->load_stack[sc->file_i].rep.stdio.closeit=1;
    sc->nesting_stack[sc->file_i]=0;
    sc->loadport->_object._port=sc->load_stack+sc->file_i;
    port_init_location(sc, &sc->load_stack[sc->file_i], fname);
  }
  return fin!=0;
}

static void file_pop(scheme *sc) {
 if(sc->file_i != 0) {
   sc->nesting=sc->nesting_stack[sc->file_i];
   port_close(sc,sc->loadport,port_input);
   port_clear_location(sc, &sc->load_stack[sc->file_i]);
   sc->file_i--;
   sc->loadport->_object._port=sc->load_stack+sc->file_i;
 }
}

static int file_interactive(scheme *sc) {
 return sc->file_i==0 && sc->load_stack[0].rep.stdio.file==stdin
     && sc->inport->_object._port->kind&port_file;
}

static port *port_rep_from_filename(scheme *sc, const char *fn, int prop) {
  FILE *f;
  char *rw;
  port *pt;
  if(prop==(port_input|port_output)) {
    rw="a+";
  } else if(prop==port_output) {
    rw="w";
  } else {
    rw="r";
  }
  f=fopen(fn,rw);
  if(f==0) {
    return 0;
  }
  pt=port_rep_from_file(sc,f,prop);
  pt->rep.stdio.closeit=1;
  port_init_location(sc, pt, mk_string(sc, fn));
  return pt;
}

static pointer port_from_filename(scheme *sc, const char *fn, int prop) {
  port *pt;
  pt=port_rep_from_filename(sc,fn,prop);
  if(pt==0) {
    return sc->NIL;
  }
  return mk_port(sc,pt);
}

static port *port_rep_from_file(scheme *sc, FILE *f, int prop)
{
    port *pt;

    pt = (port *)sc->malloc(sizeof *pt);
    if (pt == NULL) {
        return NULL;
    }
    pt->kind = port_file | prop;
    pt->rep.stdio.file = f;
    pt->rep.stdio.closeit = 0;
    port_init_location(sc, pt, NULL);
    return pt;
}

static pointer port_from_file(scheme *sc, FILE *f, int prop) {
  port *pt;
  pt=port_rep_from_file(sc,f,prop);
  if(pt==0) {
    return sc->NIL;
  }
  return mk_port(sc,pt);
}

static port *port_rep_from_string(scheme *sc, char *start, char *past_the_end, int prop) {
  port *pt;
  pt=(port*)sc->malloc(sizeof(port));
  if(pt==0) {
    return 0;
  }
  pt->kind=port_string|prop;
  pt->rep.string.start=start;
  pt->rep.string.curr=start;
  pt->rep.string.past_the_end=past_the_end;
  port_init_location(sc, pt, NULL);
  return pt;
}

static pointer port_from_string(scheme *sc, char *start, char *past_the_end, int prop) {
  port *pt;
  pt=port_rep_from_string(sc,start,past_the_end,prop);
  if(pt==0) {
    return sc->NIL;
  }
  return mk_port(sc,pt);
}

#define BLOCK_SIZE 256

static port *port_rep_from_scratch(scheme *sc) {
  port *pt;
  char *start;
  pt=(port*)sc->malloc(sizeof(port));
  if(pt==0) {
    return 0;
  }
  start=sc->malloc(BLOCK_SIZE);
  if(start==0) {
    return 0;
  }
  memset(start,' ',BLOCK_SIZE-1);
  start[BLOCK_SIZE-1]='\0';
  pt->kind=port_string|port_output|port_srfi6;
  pt->rep.string.start=start;
  pt->rep.string.curr=start;
  pt->rep.string.past_the_end=start+BLOCK_SIZE-1;
  port_init_location(sc, pt, NULL);
  return pt;
}

static pointer port_from_scratch(scheme *sc) {
  port *pt;
  pt=port_rep_from_scratch(sc);
  if(pt==0) {
    return sc->NIL;
  }
  return mk_port(sc,pt);
}

static void port_close(scheme *sc, pointer p, int flag) {
  port *pt=p->_object._port;
  pt->kind&=~flag;
  if((pt->kind & (port_input|port_output))==0) {
    /* Cleanup is here so (close-*-port) functions could work too */
    port_clear_location(sc, pt);
    if(pt->kind&port_file) {
      fclose(pt->rep.stdio.file);
    }
    pt->kind=port_free;
  }
}

/* get new character from input file */
static int inchar(scheme *sc) {
  int c;
  port *pt;

  pt = sc->inport->_object._port;
  if(pt->kind & port_saw_EOF)
    { return EOF; }
  c = basic_inchar(pt);
  if(c == EOF && sc->inport == sc->loadport) {
    /* Instead, set port_saw_EOF */
    pt->kind |= port_saw_EOF;

    /* file_pop(sc); */
    return EOF;
    /* NOTREACHED */
  }
  return c;
}

static int basic_inchar(port *pt) {
  if(pt->kind & port_file) {
    return fgetc(pt->rep.stdio.file);
  } else {
    if(*pt->rep.string.curr == 0 ||
       pt->rep.string.curr == pt->rep.string.past_the_end) {
      return EOF;
    } else {
      return *pt->rep.string.curr++;
    }
  }
}

/* back character to input buffer */
static void backchar(scheme *sc, int c) {
  port *pt;
  if(c==EOF) return;
  pt=sc->inport->_object._port;
  if(pt->kind&port_file) {
    ungetc(c,pt->rep.stdio.file);
  } else {
    if(pt->rep.string.curr!=pt->rep.string.start) {
      --pt->rep.string.curr;
    }
  }
}

static int realloc_port_string(scheme *sc, port *p)
{
  char *start=p->rep.string.start;
  size_t old_size = p->rep.string.past_the_end - start;
  size_t new_size=p->rep.string.past_the_end-start+1+BLOCK_SIZE;
  char *str=sc->malloc(new_size);
  if(str) {
    memset(str,' ',new_size-1);
    str[new_size-1]='\0';
    memcpy(str, start, old_size);
    p->rep.string.start=str;
    p->rep.string.past_the_end=str+new_size-1;
    p->rep.string.curr-=start-str;
    sc->free(start);
    return 1;
  } else {
    return 0;
  }
}

INTERFACE void putstr(scheme *sc, const char *s) {
  port *pt=sc->outport->_object._port;
  if(pt->kind&port_file) {
    fputs(s,pt->rep.stdio.file);
  } else {
    for(;*s;s++) {
      if(pt->rep.string.curr!=pt->rep.string.past_the_end) {
        *pt->rep.string.curr++=*s;
      } else if(pt->kind&port_srfi6&&realloc_port_string(sc,pt)) {
        *pt->rep.string.curr++=*s;
      }
    }
  }
}

static void putchars(scheme *sc, const char *s, int len) {
  port *pt=sc->outport->_object._port;
  if(pt->kind&port_file) {
    fwrite(s,1,len,pt->rep.stdio.file);
  } else {
    for(;len;len--) {
      if(pt->rep.string.curr!=pt->rep.string.past_the_end) {
        *pt->rep.string.curr++=*s++;
      } else if(pt->kind&port_srfi6&&realloc_port_string(sc,pt)) {
        *pt->rep.string.curr++=*s++;
      }
    }
  }
}

INTERFACE void putcharacter(scheme *sc, int c) {
  port *pt=sc->outport->_object._port;
  if(pt->kind&port_file) {
    fputc(c,pt->rep.stdio.file);
  } else {
    if(pt->rep.string.curr!=pt->rep.string.past_the_end) {
      *pt->rep.string.curr++=c;
    } else if(pt->kind&port_srfi6&&realloc_port_string(sc,pt)) {
        *pt->rep.string.curr++=c;
    }
  }
}

/* read characters up to delimiter, but cater to character constants */
static char *readstr_upto(scheme *sc, char *delim) {
  char *p = sc->strbuff;

  while ((p - sc->strbuff < sc->strbuff_size) &&
         !is_one_of(delim, (*p++ = inchar(sc))));

  if(p == sc->strbuff+2 && p[-2] == '\\') {
    *p=0;
  } else {
    backchar(sc,p[-1]);
    *--p = '\0';
  }
  return sc->strbuff;
}

/* read string expression "xxx...xxx" */
static pointer readstrexp(scheme *sc) {
  char *p = sc->strbuff;
  int c;
  int c1=0;
  enum { st_ok, st_bsl, st_x1, st_x2, st_oct1, st_oct2 } state=st_ok;

  for (;;) {
    c=inchar(sc);
    if(c == EOF) {
      return sc->F;
    }
    if(p-sc->strbuff > (sc->strbuff_size)-1) {
      ptrdiff_t offset = p - sc->strbuff;
      if (expand_strbuff(sc) != 0) {
        return sc->F;
      }
      p = sc->strbuff + offset;
    }
    switch(state) {
        case st_ok:
            switch(c) {
                case '\\':
                    state=st_bsl;
                    break;
                case '"':
                    *p=0;
                    return mk_counted_string(sc,sc->strbuff,p-sc->strbuff);
                default:
                    *p++=c;
                    break;
            }
            break;
        case st_bsl:
            switch(c) {
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                        state=st_oct1;
                        c1=c-'0';
                        break;
                case 'x':
                case 'X':
                    state=st_x1;
                    c1=0;
                    break;
                case 'n':
                    *p++='\n';
                    state=st_ok;
                    break;
                case 't':
                    *p++='\t';
                    state=st_ok;
                    break;
                case 'r':
                    *p++='\r';
                    state=st_ok;
                    break;
                case '"':
                    *p++='"';
                    state=st_ok;
                    break;
                default:
                    *p++=c;
                    state=st_ok;
                    break;
            }
            break;
        case st_x1:
        case st_x2:
            c=toupper(c);
            if(c>='0' && c<='F') {
                if(c<='9') {
                    c1=(c1<<4)+c-'0';
                } else {
                    c1=(c1<<4)+c-'A'+10;
                }
                if(state==st_x1) {
                    state=st_x2;
                } else {
                    *p++=c1;
                    state=st_ok;
                }
            } else {
                return sc->F;
            }
            break;
        case st_oct1:
        case st_oct2:
            if (c < '0' || c > '7')
            {
                   *p++=c1;
                   backchar(sc, c);
                   state=st_ok;
            }
            else
            {
                if (state==st_oct2 && c1 >= 32)
                    return sc->F;

                   c1=(c1<<3)+(c-'0');

                if (state == st_oct1)
                        state=st_oct2;
                else
                {
                        *p++=c1;
                        state=st_ok;
                   }
            }
            break;

    }
  }
}

/* check c is in chars */
static INLINE int is_one_of(char *s, int c) {
     if(c==EOF) return 1;
     while (*s)
          if (*s++ == c)
               return (1);
     return (0);
}

/* skip white characters */
static INLINE int skipspace(scheme *sc) {
     int c = 0, curr_line = 0;

     do {
         c=inchar(sc);
#if SHOW_ERROR_LINE
         if(c=='\n')
           curr_line++;
#endif
     } while (isspace(c));

     /* record it */
     port_increment_current_line(sc, &sc->load_stack[sc->file_i], curr_line);

     if(c!=EOF) {
          backchar(sc,c);
      return 1;
     }
     else
       { return EOF; }
}

/* get token */
static int token(scheme *sc) {
     int c;
     c = skipspace(sc);
     if(c == EOF) { return (TOK_EOF); }
     switch (c=inchar(sc)) {
     case EOF:
          return (TOK_EOF);
     case '(':
          return (TOK_LPAREN);
     case ')':
          return (TOK_RPAREN);
     case '.':
          c=inchar(sc);
          if(is_one_of(" \n\t",c)) {
               return (TOK_DOT);
          } else {
               backchar(sc,c);
               backchar(sc,'.');
               return TOK_ATOM;
          }
     case '\'':
          return (TOK_QUOTE);
     case ';':
           while ((c=inchar(sc)) != '\n' && c!=EOF)
             ;

           if(c == '\n')
             port_increment_current_line(sc, &sc->load_stack[sc->file_i], 1);

       if(c == EOF)
         { return (TOK_EOF); }
       else
         { return (token(sc));}
     case '"':
          return (TOK_DQUOTE);
     case BACKQUOTE:
          return (TOK_BQUOTE);
     case ',':
         if ((c=inchar(sc)) == '@') {
               return (TOK_ATMARK);
         } else {
               backchar(sc,c);
               return (TOK_COMMA);
         }
     case '#':
          c=inchar(sc);
          if (c == '(') {
               return (TOK_VEC);
          } else if(c == '!') {
               while ((c=inchar(sc)) != '\n' && c!=EOF)
                   ;

           if(c == '\n')
             port_increment_current_line(sc, &sc->load_stack[sc->file_i], 1);

           if(c == EOF)
             { return (TOK_EOF); }
           else
             { return (token(sc));}
          } else {
               backchar(sc,c);
               if(is_one_of(" tfodxb\\",c)) {
                    return TOK_SHARP_CONST;
               } else {
                    return (TOK_SHARP);
               }
          }
     default:
          backchar(sc,c);
          return (TOK_ATOM);
     }
}

/* ========== Routines for Printing ========== */
#define   ok_abbrev(x)   (is_pair(x) && cdr(x) == sc->NIL)

static void printslashstring(scheme *sc, char *p, int len) {
  int i;
  unsigned char *s=(unsigned char*)p;
  putcharacter(sc,'"');
  for ( i=0; i<len; i++) {
    if(*s==0xff || *s=='"' || *s<' ' || *s=='\\') {
      putcharacter(sc,'\\');
      switch(*s) {
      case '"':
        putcharacter(sc,'"');
        break;
      case '\n':
        putcharacter(sc,'n');
        break;
      case '\t':
        putcharacter(sc,'t');
        break;
      case '\r':
        putcharacter(sc,'r');
        break;
      case '\\':
        putcharacter(sc,'\\');
        break;
      default: {
          int d=*s/16;
          putcharacter(sc,'x');
          if(d<10) {
            putcharacter(sc,d+'0');
          } else {
            putcharacter(sc,d-10+'A');
          }
          d=*s%16;
          if(d<10) {
            putcharacter(sc,d+'0');
          } else {
            putcharacter(sc,d-10+'A');
          }
        }
      }
    } else {
      putcharacter(sc,*s);
    }
    s++;
  }
  putcharacter(sc,'"');
}


/* print atoms */
static void printatom(scheme *sc, pointer l, int f) {
  char *p;
  int len;
  atom2str(sc,l,f,&p,&len);
  putchars(sc,p,len);
}


/* Uses internal buffer unless string pointer is already available */
static void atom2str(scheme *sc, pointer l, int f, char **pp, int *plen) {
     char *p;

     if (l == sc->NIL) {
          p = "()";
     } else if (l == sc->T) {
          p = "#t";
     } else if (l == sc->F) {
          p = "#f";
     } else if (l == sc->EOF_OBJ) {
          p = "#<EOF>";
     } else if (is_port(l)) {
          p = "#<PORT>";
     } else if (is_number(l)) {
          p = sc->strbuff;
          if (f <= 1 || f == 10) /* f is the base for numbers if > 1 */ {
              if(num_is_integer(l)) {
                   snprintf(p, STRBUFFSIZE, "%ld", ivalue_unchecked(l));
              } else {
                   snprintf(p, STRBUFFSIZE, "%.10g", rvalue_unchecked(l));
                   /* r5rs says there must be a '.' (unless 'e'?) */
                   f = strcspn(p, ".e");
                   if (p[f] == 0) {
                        p[f] = '.'; /* not found, so add '.0' at the end */
                        p[f+1] = '0';
                        p[f+2] = 0;
                   }
              }
          } else {
              long v = ivalue(l);
              if (f == 16) {
                  if (v >= 0)
                    snprintf(p, STRBUFFSIZE, "%lx", v);
                  else
                    snprintf(p, STRBUFFSIZE, "-%lx", -v);
              } else if (f == 8) {
                  if (v >= 0)
                    snprintf(p, STRBUFFSIZE, "%lo", v);
                  else
                    snprintf(p, STRBUFFSIZE, "-%lo", -v);
              } else if (f == 2) {
                  unsigned long b = (v < 0) ? -v : v;
                  p = &p[STRBUFFSIZE-1];
                  *p = 0;
                  do { *--p = (b&1) ? '1' : '0'; b >>= 1; } while (b != 0);
                  if (v < 0) *--p = '-';
              }
          }
     } else if (is_string(l)) {
          if (!f) {
               *pp = strvalue(l);
	       *plen = strlength(l);
	       return;
          } else { /* Hack, uses the fact that printing is needed */
               *pp=sc->strbuff;
               *plen=0;
               printslashstring(sc, strvalue(l), strlength(l));
               return;
          }
     } else if (is_character(l)) {
          int c=charvalue(l);
          p = sc->strbuff;
          if (!f) {
               p[0]=c;
               p[1]=0;
          } else {
               switch(c) {
               case ' ':
                    p = "#\\space";
                    break;
               case '\n':
                    p = "#\\newline";
                    break;
               case '\r':
                    p = "#\\return";
                    break;
               case '\t':
                    p = "#\\tab";
                    break;
               default:
#if USE_ASCII_NAMES
                    if(c==127) {
                         p = "#\\del";
                         break;
                    } else if(c<32) {
                         snprintf(p,STRBUFFSIZE, "#\\%s",charnames[c]);
                         break;
                    }
#else
                    if(c<32) {
                      snprintf(p,STRBUFFSIZE,"#\\x%x",c);
                      break;
                    }
#endif
                    snprintf(p,STRBUFFSIZE,"#\\%c",c);
                    break;
               }
          }
     } else if (is_symbol(l)) {
          p = symname(l);
     } else if (is_proc(l)) {
          p = sc->strbuff;
          snprintf(p,STRBUFFSIZE,"#<%s PROCEDURE %ld>", procname(l),procnum(l));
     } else if (is_macro(l)) {
          p = "#<MACRO>";
     } else if (is_closure(l)) {
          p = "#<CLOSURE>";
     } else if (is_promise(l)) {
          p = "#<PROMISE>";
     } else if (is_foreign(l)) {
          p = sc->strbuff;
          snprintf(p,STRBUFFSIZE,"#<FOREIGN PROCEDURE %ld>", procnum(l));
     } else if (is_continuation(l)) {
          p = "#<CONTINUATION>";
     } else if (is_foreign_object(l)) {
          p = sc->strbuff;
          l->_object._foreign_object._vtable->to_string(sc, p, STRBUFFSIZE, l->_object._foreign_object._data);
     } else {
          p = "#<ERROR>";
     }
     *pp=p;
     *plen=strlen(p);
}
/* ========== Routines for Evaluation Cycle ========== */

/* make closure. c is code. e is environment */
static pointer mk_closure(scheme *sc, pointer c, pointer e) {
     pointer x = get_cell(sc, c, e);

     typeflag(x) = T_CLOSURE;
     car(x) = c;
     cdr(x) = e;
     return (x);
}

/* make continuation. */
static pointer mk_continuation(scheme *sc, pointer d) {
     pointer x = get_cell(sc, sc->NIL, d);

     typeflag(x) = T_CONTINUATION;
     cont_dump(x) = d;
     return (x);
}

static pointer list_star(scheme *sc, pointer d) {
  pointer p, q;
  if(cdr(d)==sc->NIL) {
    return car(d);
  }
  p=cons(sc,car(d),cdr(d));
  q=p;
  while(cdr(cdr(p))!=sc->NIL) {
    d=cons(sc,car(p),cdr(p));
    if(cdr(cdr(p))!=sc->NIL) {
      p=cdr(d);
    }
  }
  cdr(p)=car(cdr(p));
  return q;
}

/* reverse list -- produce new list */
static pointer reverse(scheme *sc, pointer term, pointer list) {
/* a must be checked by gc */
     pointer a = list, p = term;

     for ( ; is_pair(a); a = cdr(a)) {
          p = cons(sc, car(a), p);
     }
     return (p);
}

/* reverse list --- in-place */
static pointer reverse_in_place(scheme *sc, pointer term, pointer list) {
     pointer p = list, result = term, q;

     while (p != sc->NIL) {
          q = cdr(p);
          cdr(p) = result;
          result = p;
          p = q;
     }
     return (result);
}

/* append list -- produce new list (in reverse order) */
static pointer revappend(scheme *sc, pointer a, pointer b) {
    pointer result = a;
    pointer p = b;

    while (is_pair(p)) {
        result = cons(sc, car(p), result);
        p = cdr(p);
    }

    if (p == sc->NIL) {
        return result;
    }

    return sc->F;   /* signal an error */
}

/* equivalence of atoms */
int eqv(pointer a, pointer b) {
     if (is_string(a)) {
          if (is_string(b))
               return (strvalue(a) == strvalue(b));
          else
               return (0);
     } else if (is_number(a)) {
          if (is_number(b)) {
               if (num_is_integer(a) == num_is_integer(b))
                    return num_eq(nvalue(a),nvalue(b));
          }
          return (0);
     } else if (is_character(a)) {
          if (is_character(b))
               return charvalue(a)==charvalue(b);
          else
               return (0);
     } else if (is_port(a)) {
          if (is_port(b))
               return a==b;
          else
               return (0);
     } else if (is_proc(a)) {
          if (is_proc(b))
               return procnum(a)==procnum(b);
          else
               return (0);
     } else {
          return (a == b);
     }
}

/* true or false value macro */
/* () is #t in R5RS */
#define is_true(p)       ((p) != sc->F)
#define is_false(p)      ((p) == sc->F)


/* ========== Environment implementation  ========== */

#if !defined(USE_ALIST_ENV) || !defined(USE_OBJECT_LIST)

static int hash_fn(const char *key, int table_size)
{
  unsigned int hashed = 0;
  const char *c;
  int bits_per_int = sizeof(unsigned int)*8;

  for (c = key; *c; c++) {
    /* letters have about 5 bits in them */
    hashed = (hashed<<5) | (hashed>>(bits_per_int-5));
    hashed ^= *c;
  }
  return hashed % table_size;
}
#endif

/* Compares A and B.  Returns an integer less than, equal to, or
 * greater than zero if A is stored at a memory location that is
 * numerical less than, equal to, or greater than that of B.  */
static int
pointercmp(pointer a, pointer b)
{
  uintptr_t a_n = (uintptr_t) a;
  uintptr_t b_n = (uintptr_t) b;

  if (a_n < b_n)
    return -1;
  if (a_n > b_n)
    return 1;
  return 0;
}

#ifndef USE_ALIST_ENV

/*
 * In this implementation, each frame of the environment may be
 * a hash table: a vector of alists hashed by variable name.
 * In practice, we use a vector only for the initial frame;
 * subsequent frames are too small and transient for the lookup
 * speed to out-weigh the cost of making a new vector.
 */

static void new_frame_in_env(scheme *sc, pointer old_env)
{
  pointer new_frame;

  /* The interaction-environment has about 480 variables in it. */
  if (old_env == sc->NIL) {
    new_frame = mk_vector(sc, 751);
  } else {
    new_frame = sc->NIL;
  }

  gc_disable(sc, 1);
  sc->envir = immutable_cons(sc, new_frame, old_env);
  gc_enable(sc);
  setenvironment(sc->envir);
}

/* Find the slot in ENV under the key HDL.  If ALL is given, look in
 * all environments enclosing ENV.  If the lookup fails, and SSLOT is
 * given, the position where the new slot has to be inserted is stored
 * at SSLOT.  */
static pointer
find_slot_spec_in_env(scheme *sc, pointer env, pointer hdl, int all, pointer **sslot)
{
  pointer x,y;
  int location;
  pointer *sl;
  int d;
  assert(is_symbol(hdl));

  for (x = env; x != sc->NIL; x = cdr(x)) {
    if (is_vector(car(x))) {
      location = hash_fn(symname(hdl), vector_length(car(x)));
      sl = vector_elem_slot(car(x), location);
    } else {
      sl = &car(x);
    }
    for (y = *sl ; y != sc->NIL; sl = &cdr(y), y = *sl) {
      d = pointercmp(caar(y), hdl);
      if (d == 0)
	return car(y);		/* Hit.  */
      else if (d > 0)
	break;			/* Miss.  */
    }

    if (x == env && sslot)
      *sslot = sl;		/* Insert here.  */

    if (!all)
      return sc->NIL;		/* Miss, and stop looking.  */
  }

  return sc->NIL;		/* Not found in any environment.  */
}

#else /* USE_ALIST_ENV */

static INLINE void new_frame_in_env(scheme *sc, pointer old_env)
{
  sc->envir = immutable_cons(sc, sc->NIL, old_env);
  setenvironment(sc->envir);
}

/* Find the slot in ENV under the key HDL.  If ALL is given, look in
 * all environments enclosing ENV.  If the lookup fails, and SSLOT is
 * given, the position where the new slot has to be inserted is stored
 * at SSLOT.  */
static pointer
find_slot_spec_in_env(scheme *sc, pointer env, pointer hdl, int all, pointer **sslot)
{
    pointer x,y;
    pointer *sl;
    int d;
    assert(is_symbol(hdl));

    for (x = env; x != sc->NIL; x = cdr(x)) {
      for (sl = &car(x), y = *sl; y != sc->NIL; sl = &cdr(y), y = *sl) {
	d = pointercmp(caar(y), hdl);
	if (d == 0)
	  return car(y);	/* Hit.  */
	else if (d > 0)
	  break;		/* Miss.  */
      }

      if (x == env && sslot)
	*sslot = sl;		/* Insert here.  */

      if (!all)
	return sc->NIL;		/* Miss, and stop looking.  */
    }

    return sc->NIL;		/* Not found in any environment.  */
}

#endif /* USE_ALIST_ENV else */

static pointer find_slot_in_env(scheme *sc, pointer env, pointer hdl, int all)
{
  return find_slot_spec_in_env(sc, env, hdl, all, NULL);
}

/* Insert (VARIABLE, VALUE) at SSLOT.  SSLOT must be obtained using
 * find_slot_spec_in_env, and no insertion must be done between
 * obtaining SSLOT and the call to this function.  */
static INLINE void new_slot_spec_in_env(scheme *sc,
                                        pointer variable, pointer value,
					pointer *sslot)
{
#define new_slot_spec_in_env_allocates	2
  pointer slot;
  gc_disable(sc, gc_reservations (new_slot_spec_in_env));
  slot = immutable_cons(sc, variable, value);
  *sslot = immutable_cons(sc, slot, *sslot);
  gc_enable(sc);
}

static INLINE void new_slot_in_env(scheme *sc, pointer variable, pointer value)
{
#define new_slot_in_env_allocates	new_slot_spec_in_env_allocates
  pointer slot;
  pointer *sslot;
  assert(is_symbol(variable));
  slot = find_slot_spec_in_env(sc, sc->envir, variable, 0, &sslot);
  assert(slot == sc->NIL);
  new_slot_spec_in_env(sc, variable, value, sslot);
}

static INLINE void set_slot_in_env(scheme *sc, pointer slot, pointer value)
{
  (void)sc;
  cdr(slot) = value;
}

static INLINE pointer slot_value_in_env(pointer slot)
{
  return cdr(slot);
}


/* ========== Evaluation Cycle ========== */


static enum scheme_opcodes
_Error_1(scheme *sc, const char *s, pointer a) {
     const char *str = s;
     pointer history;
#if USE_ERROR_HOOK
     pointer x;
     pointer hdl=sc->ERROR_HOOK;
#endif

#if SHOW_ERROR_LINE
     char sbuf[STRBUFFSIZE];
#endif

     history = history_flatten(sc);

#if SHOW_ERROR_LINE
     /* make sure error is not in REPL */
     if (((sc->load_stack[sc->file_i].kind & port_file) == 0
	  || sc->load_stack[sc->file_i].rep.stdio.file != stdin)) {
       pointer tag;
       const char *fname;
       int ln;

       if (history != sc->NIL && has_tag(car(history))
	   && (tag = get_tag(sc, car(history)))
	   && is_string(car(tag)) && is_integer(cdr(tag))) {
	 fname = string_value(car(tag));
	 ln = ivalue_unchecked(cdr(tag));
       } else {
	 fname = string_value(sc->load_stack[sc->file_i].filename);
	 ln = ivalue_unchecked(sc->load_stack[sc->file_i].curr_line);
       }

       /* should never happen */
       if(!fname) fname = "<unknown>";

       /* we started from 0 */
       ln++;
       snprintf(sbuf, STRBUFFSIZE, "%s:%i: %s", fname, ln, s);

       str = (const char*)sbuf;
     }
#endif

#if USE_ERROR_HOOK
     x=find_slot_in_env(sc,sc->envir,hdl,1);
    if (x != sc->NIL) {
	 sc->code = cons(sc, cons(sc, sc->QUOTE,
				  cons(sc, history, sc->NIL)),
			 sc->NIL);
         if(a!=0) {
	   sc->code = cons(sc, cons(sc, sc->QUOTE, cons(sc, a, sc->NIL)),
	                   sc->code);
         } else {
	   sc->code = cons(sc, sc->F, sc->code);
	 }
         sc->code = cons(sc, mk_string(sc, str), sc->code);
         setimmutable(car(sc->code));
         sc->code = cons(sc, slot_value_in_env(x), sc->code);
         return OP_EVAL;
    }
#endif

    if(a!=0) {
          sc->args = cons(sc, (a), sc->NIL);
    } else {
          sc->args = sc->NIL;
    }
    sc->args = cons(sc, mk_string(sc, str), sc->args);
    setimmutable(car(sc->args));
    return OP_ERR0;
}
#define Error_1(sc,s, a) { op = _Error_1(sc,s,a); goto dispatch; }
#define Error_0(sc,s)    { op = _Error_1(sc,s,0); goto dispatch; }

/* Too small to turn into function */
# define  BEGIN     do {
# define  END  } while (0)



/* Flags.  The interpreter has a flags field.  When the interpreter
 * pushes a frame to the dump stack, it is encoded with the opcode.
 * Therefore, we do not use the least significant byte.  */

/* Masks used to encode and decode opcode and flags.  */
#define S_OP_MASK	0x000000ff
#define S_FLAG_MASK	0xffffff00

/* Set if the interpreter evaluates an expression in a tail context
 * (see R5RS, section 3.5).  If a function, procedure, or continuation
 * is invoked while this flag is set, the call is recorded as tail
 * call in the history buffer.  */
#define S_FLAG_TAIL_CONTEXT	0x00000100

/* Set flag F.  */
#define s_set_flag(sc, f)			\
	   BEGIN				\
	   (sc)->flags |= S_FLAG_ ## f;		\
	   END

/* Clear flag F.  */
#define s_clear_flag(sc, f)			\
	   BEGIN				\
	   (sc)->flags &= ~ S_FLAG_ ## f;	\
	   END

/* Check if flag F is set.  */
#define s_get_flag(sc, f)			\
	   !!((sc)->flags & S_FLAG_ ## f)



/* Bounce back to Eval_Cycle and execute A.  */
#define s_goto(sc, a) { op = (a); goto dispatch; }

#if USE_THREADED_CODE

/* Do not bounce back to Eval_Cycle but execute A by jumping directly
 * to it.  */
#define s_thread_to(sc, a)	\
     BEGIN			\
     op = (a);			\
     goto a;			\
     END

/* Define a label OP and emit a case statement for OP.  For use in the
 * dispatch function.  The slightly peculiar goto that is never
 * executed avoids warnings about unused labels.  */
#if __GNUC__ > 6
#define CASE(OP)	OP: __attribute__((unused)); case OP
#else
#define CASE(OP)	case OP: if (0) goto OP; OP
#endif

#else	/* USE_THREADED_CODE */
#define s_thread_to(sc, a)	s_goto(sc, a)
#define CASE(OP)		case OP
#endif	/* USE_THREADED_CODE */

#if __GNUC__ > 6
#define FALLTHROUGH __attribute__ ((fallthrough))
#else
#define FALLTHROUGH /* fallthrough */
#endif

/* Return to the previous frame on the dump stack, setting the current
 * value to A.  */
#define s_return(sc, a)	s_goto(sc, _s_return(sc, a, 0))

/* Return to the previous frame on the dump stack, setting the current
 * value to A, and re-enable the garbage collector.  */
#define s_return_enable_gc(sc, a) s_goto(sc, _s_return(sc, a, 1))

static INLINE void dump_stack_reset(scheme *sc)
{
  sc->dump = sc->NIL;
}

static INLINE void dump_stack_initialize(scheme *sc)
{
  dump_stack_reset(sc);
  sc->frame_freelist = sc->NIL;
}

static void dump_stack_free(scheme *sc)
{
  dump_stack_initialize(sc);
}

const int frame_length = 4;

static pointer
dump_stack_make_frame(scheme *sc)
{
  pointer frame;

  frame = mk_vector(sc, frame_length);
  if (! sc->no_memory)
    setframe(frame);

  return frame;
}

static INLINE pointer *
frame_slots(pointer frame)
{
  return &frame->_object._vector._elements[0];
}

#define frame_payload	vector_length

static pointer
dump_stack_allocate_frame(scheme *sc)
{
  pointer frame = sc->frame_freelist;
  if (frame == sc->NIL) {
    if (gc_enabled(sc))
      frame = dump_stack_make_frame(sc);
    else
      gc_reservation_failure(sc);
  } else
    sc->frame_freelist = *frame_slots(frame);
  return frame;
}

static void
dump_stack_deallocate_frame(scheme *sc, pointer frame)
{
  pointer *p = frame_slots(frame);
  *p++ = sc->frame_freelist;
  *p++ = sc->NIL;
  *p++ = sc->NIL;
  *p++ = sc->NIL;
  sc->frame_freelist = frame;
}

static void
dump_stack_preallocate_frame(scheme *sc)
{
  pointer frame = dump_stack_make_frame(sc);
  if (! sc->no_memory)
    dump_stack_deallocate_frame(sc, frame);
}

static enum scheme_opcodes
_s_return(scheme *sc, pointer a, int enable_gc) {
  pointer dump = sc->dump;
  pointer *p;
  unsigned long v;
  enum scheme_opcodes next_op;
  sc->value = (a);
  if (enable_gc)
       gc_enable(sc);
  if (dump == sc->NIL)
    return OP_QUIT;
  v = frame_payload(dump);
  next_op = (int) (v & S_OP_MASK);
  sc->flags = v & S_FLAG_MASK;
  p = frame_slots(dump);
  sc->args = *p++;
  sc->envir = *p++;
  sc->code = *p++;
  sc->dump = *p++;
  dump_stack_deallocate_frame(sc, dump);
  return next_op;
}

static void s_save(scheme *sc, enum scheme_opcodes op, pointer args, pointer code) {
#define s_save_allocates	0
    pointer dump;
    pointer *p;
    gc_disable(sc, gc_reservations (s_save));
    dump = dump_stack_allocate_frame(sc);
    frame_payload(dump) = (size_t) (sc->flags | (unsigned long) op);
    p = frame_slots(dump);
    *p++ = args;
    *p++ = sc->envir;
    *p++ = code;
    *p++ = sc->dump;
    sc->dump = dump;
    gc_enable(sc);
}

static INLINE void dump_stack_mark(scheme *sc)
{
  mark(sc->dump);
  mark(sc->frame_freelist);
}



#if USE_HISTORY

static void
history_free(scheme *sc)
{
  sc->free(sc->history.m);
  sc->history.tailstacks = sc->NIL;
  sc->history.callstack = sc->NIL;
}

static pointer
history_init(scheme *sc, size_t N, size_t M)
{
  size_t i;
  struct history *h = &sc->history;

  h->N = N;
  h->mask_N = N - 1;
  h->n = N - 1;
  assert ((N & h->mask_N) == 0);

  h->M = M;
  h->mask_M = M - 1;
  assert ((M & h->mask_M) == 0);

  h->callstack = mk_vector(sc, N);
  if (h->callstack == sc->sink)
    goto fail;

  h->tailstacks = mk_vector(sc, N);
  for (i = 0; i < N; i++) {
    pointer tailstack = mk_vector(sc, M);
    if (tailstack == sc->sink)
      goto fail;
    set_vector_elem(h->tailstacks, i, tailstack);
  }

  h->m = sc->malloc(N * sizeof *h->m);
  if (h->m == NULL)
    goto fail;

  for (i = 0; i < N; i++)
    h->m[i] = 0;

  return sc->T;

fail:
  history_free(sc);
  return sc->F;
}

static void
history_mark(scheme *sc)
{
  struct history *h = &sc->history;
  mark(h->callstack);
  mark(h->tailstacks);
}

#define add_mod(a, b, mask)	(((a) + (b)) & (mask))
#define sub_mod(a, b, mask)	add_mod(a, (mask) + 1 - (b), mask)

static INLINE void
tailstack_clear(scheme *sc, pointer v)
{
  assert(is_vector(v));
  /* XXX optimize */
  fill_vector(v, sc->NIL);
}

static pointer
callstack_pop(scheme *sc)
{
  struct history *h = &sc->history;
  size_t n = h->n;
  pointer item;

  if (h->callstack == sc->NIL)
    return sc->NIL;

  item = vector_elem(h->callstack, n);
  /* Clear our frame so that it can be gc'ed and we don't run into it
   * when walking the history.  */
  set_vector_elem(h->callstack, n, sc->NIL);
  tailstack_clear(sc, vector_elem(h->tailstacks, n));

  /* Exit from the frame.  */
  h->n = sub_mod(h->n, 1, h->mask_N);

  return item;
}

static void
callstack_push(scheme *sc, pointer item)
{
  struct history *h = &sc->history;
  size_t n = h->n;

  if (h->callstack == sc->NIL)
    return;

  /* Enter a new frame.  */
  n = h->n = add_mod(n, 1, h->mask_N);

  /* Initialize tail stack.  */
  tailstack_clear(sc, vector_elem(h->tailstacks, n));
  h->m[n] = h->mask_M;

  set_vector_elem(h->callstack, n, item);
}

static void
tailstack_push(scheme *sc, pointer item)
{
  struct history *h = &sc->history;
  size_t n = h->n;
  size_t m = h->m[n];

  if (h->callstack == sc->NIL)
    return;

  /* Enter a new tail frame.  */
  m = h->m[n] = add_mod(m, 1, h->mask_M);
  set_vector_elem(vector_elem(h->tailstacks, n), m, item);
}

static pointer
tailstack_flatten(scheme *sc, pointer tailstack, size_t i, size_t n,
		  pointer acc)
{
  struct history *h = &sc->history;
  pointer frame;

  assert(i <= h->M);
  assert(n < h->M);

  if (acc == sc->sink)
    return sc->sink;

  if (i == 0) {
    /* We reached the end, but we did not see a unused frame.  Signal
       this using '... .  */
    return cons(sc, mk_symbol(sc, "..."), acc);
  }

  frame = vector_elem(tailstack, n);
  if (frame == sc->NIL) {
    /* A unused frame.  We reached the end of the history.  */
    return acc;
  }

  /* Add us.  */
  acc = cons(sc, frame, acc);

  return tailstack_flatten(sc, tailstack, i - 1, sub_mod(n, 1, h->mask_M),
			   acc);
}

static pointer
callstack_flatten(scheme *sc, size_t i, size_t n, pointer acc)
{
  struct history *h = &sc->history;
  pointer frame;

  assert(i <= h->N);
  assert(n < h->N);

  if (acc == sc->sink)
    return sc->sink;

  if (i == 0) {
    /* We reached the end, but we did not see a unused frame.  Signal
       this using '... .  */
    return cons(sc, mk_symbol(sc, "..."), acc);
  }

  frame = vector_elem(h->callstack, n);
  if (frame == sc->NIL) {
    /* A unused frame.  We reached the end of the history.  */
    return acc;
  }

  /* First, emit the tail calls.  */
  acc = tailstack_flatten(sc, vector_elem(h->tailstacks, n), h->M, h->m[n],
			  acc);

  /* Then us.  */
  acc = cons(sc, frame, acc);

  return callstack_flatten(sc, i - 1, sub_mod(n, 1, h->mask_N), acc);
}

static pointer
history_flatten(scheme *sc)
{
  struct history *h = &sc->history;
  pointer history;

  if (h->callstack == sc->NIL)
    return sc->NIL;

  history = callstack_flatten(sc, h->N, h->n, sc->NIL);
  if (history == sc->sink)
    return sc->sink;

  return reverse_in_place(sc, sc->NIL, history);
}

#undef add_mod
#undef sub_mod

#else	/* USE_HISTORY */

#define history_init(SC, A, B)	(void) 0
#define history_free(SC)	(void) 0
#define callstack_pop(SC)	(void) 0
#define callstack_push(SC, X)	(void) 0
#define tailstack_push(SC, X)	(void) 0

#endif	/* USE_HISTORY */



#if USE_PLIST
static pointer
get_property(scheme *sc, pointer obj, pointer key)
{
  pointer x;

  assert (is_symbol(obj));
  assert (is_symbol(key));

  for (x = symprop(obj); x != sc->NIL; x = cdr(x)) {
    if (caar(x) == key)
      break;
  }

  if (x != sc->NIL)
    return cdar(x);

  return sc->NIL;
}

static pointer
set_property(scheme *sc, pointer obj, pointer key, pointer value)
{
#define set_property_allocates	2
  pointer x;

  assert (is_symbol(obj));
  assert (is_symbol(key));

  for (x = symprop(obj); x != sc->NIL; x = cdr(x)) {
    if (caar(x) == key)
      break;
  }

  if (x != sc->NIL)
    cdar(x) = value;
  else {
    gc_disable(sc, gc_reservations(set_property));
    symprop(obj) = cons(sc, cons(sc, key, value), symprop(obj));
    gc_enable(sc);
  }

  return sc->T;
}
#endif



static int is_list(scheme *sc, pointer a)
{ return list_length(sc,a) >= 0; }

/* Result is:
   proper list: length
   circular list: -1
   not even a pair: -2
   dotted list: -2 minus length before dot
*/
int list_length(scheme *sc, pointer a) {
    int i=0;
    pointer slow, fast;

    slow = fast = a;
    while (1)
    {
        if (fast == sc->NIL)
                return i;
        if (!is_pair(fast))
                return -2 - i;
        fast = cdr(fast);
        ++i;
        if (fast == sc->NIL)
                return i;
        if (!is_pair(fast))
                return -2 - i;
        ++i;
        fast = cdr(fast);

        /* Safe because we would have already returned if `fast'
           encountered a non-pair. */
        slow = cdr(slow);
        if (fast == slow)
        {
            /* the fast pointer has looped back around and caught up
               with the slow pointer, hence the structure is circular,
               not of finite length, and therefore not a list */
            return -1;
        }
    }
}



#define s_retbool(tf)    s_return(sc,(tf) ? sc->T : sc->F)

/* kernel of this interpreter */
static void
Eval_Cycle(scheme *sc, enum scheme_opcodes op) {
  for (;;) {
     pointer x, y;
     pointer callsite;
     num v;
#if USE_MATH
     double dd;
#endif
     int (*comp_func)(num, num) = NULL;
     const struct op_code_info *pcd;

  dispatch:
     pcd = &dispatch_table[op];
     if (pcd->name[0] != 0) { /* if built-in function, check arguments */
       char msg[STRBUFFSIZE];
       if (! check_arguments (sc, pcd, msg, sizeof msg)) {
	 s_goto(sc, _Error_1(sc, msg, 0));
       }
     }

     if(sc->no_memory) {
       fprintf(stderr,"No memory!\n");
       exit(1);
     }
     ok_to_freely_gc(sc);

     switch (op) {
     CASE(OP_LOAD):       /* load */
          if(file_interactive(sc)) {
               fprintf(sc->outport->_object._port->rep.stdio.file,
               "Loading %s\n", strvalue(car(sc->args)));
          }
          if (!file_push(sc, car(sc->args))) {
               Error_1(sc,"unable to open", car(sc->args));
          }
      else
        {
          sc->args = mk_integer(sc,sc->file_i);
          s_thread_to(sc,OP_T0LVL);
        }

     CASE(OP_T0LVL): /* top level */
       /* If we reached the end of file, this loop is done. */
       if(sc->loadport->_object._port->kind & port_saw_EOF)
     {
       if(sc->file_i == 0)
         {
           sc->args=sc->NIL;
           sc->nesting = sc->nesting_stack[0];
           s_thread_to(sc,OP_QUIT);
         }
       else
         {
           file_pop(sc);
           s_return(sc,sc->value);
         }
       /* NOTREACHED */
     }

       /* If interactive, be nice to user. */
       if(file_interactive(sc))
     {
       sc->envir = sc->global_env;
       dump_stack_reset(sc);
       putstr(sc,"\n");
       putstr(sc,prompt);
     }

       /* Set up another iteration of REPL */
       sc->nesting=0;
       sc->save_inport=sc->inport;
       sc->inport = sc->loadport;
       s_save(sc,OP_T0LVL, sc->NIL, sc->NIL);
       s_save(sc,OP_VALUEPRINT, sc->NIL, sc->NIL);
       s_save(sc,OP_T1LVL, sc->NIL, sc->NIL);
       s_thread_to(sc,OP_READ_INTERNAL);

     CASE(OP_T1LVL): /* top level */
          sc->code = sc->value;
          sc->inport=sc->save_inport;
          s_thread_to(sc,OP_EVAL);

     CASE(OP_READ_INTERNAL):       /* internal read */
          sc->tok = token(sc);
          if(sc->tok==TOK_EOF)
        { s_return(sc,sc->EOF_OBJ); }
          s_thread_to(sc,OP_RDSEXPR);

     CASE(OP_GENSYM):
          s_return(sc, gensym(sc));

     CASE(OP_VALUEPRINT): /* print evaluation result */
          /* OP_VALUEPRINT is always pushed, because when changing from
             non-interactive to interactive mode, it needs to be
             already on the stack */
       if(sc->tracing) {
         putstr(sc,"\nGives: ");
       }
       if(file_interactive(sc)) {
         sc->print_flag = 1;
         sc->args = sc->value;
         s_thread_to(sc,OP_P0LIST);
       } else {
         s_return(sc,sc->value);
       }

     CASE(OP_EVAL):       /* main part of evaluation */
#if USE_TRACING
       if(sc->tracing) {
         /*s_save(sc,OP_VALUEPRINT,sc->NIL,sc->NIL);*/
         s_save(sc,OP_REAL_EVAL,sc->args,sc->code);
         sc->args=sc->code;
         putstr(sc,"\nEval: ");
         s_thread_to(sc,OP_P0LIST);
       }
       FALLTHROUGH;
     CASE(OP_REAL_EVAL):
#endif
          if (is_symbol(sc->code)) {    /* symbol */
               x=find_slot_in_env(sc,sc->envir,sc->code,1);
               if (x != sc->NIL) {
                    s_return(sc,slot_value_in_env(x));
               } else {
                    Error_1(sc, "eval: unbound variable", sc->code);
               }
          } else if (is_pair(sc->code)) {
               if (is_syntax(x = car(sc->code))) {     /* SYNTAX */
                    sc->code = cdr(sc->code);
                    s_goto(sc, syntaxnum(sc, x));
               } else {/* first, eval top element and eval arguments */
                    s_save(sc,OP_E0ARGS, sc->NIL, sc->code);
                    /* If no macros => s_save(sc,OP_E1ARGS, sc->NIL, cdr(sc->code));*/
                    sc->code = car(sc->code);
		    s_clear_flag(sc, TAIL_CONTEXT);
                    s_thread_to(sc,OP_EVAL);
               }
          } else {
               s_return(sc,sc->code);
          }

     CASE(OP_E0ARGS):     /* eval arguments */
          if (is_macro(sc->value)) {    /* macro expansion */
	       gc_disable(sc, 1 + gc_reservations (s_save));
               s_save(sc,OP_DOMACRO, sc->NIL, sc->NIL);
               sc->args = cons(sc,sc->code, sc->NIL);
	       gc_enable(sc);
               sc->code = sc->value;
	       s_clear_flag(sc, TAIL_CONTEXT);
               s_thread_to(sc,OP_APPLY);
          } else {
	       gc_disable(sc, 1);
	       sc->args = cons(sc, sc->code, sc->NIL);
	       gc_enable(sc);
	       sc->code = cdr(sc->code);
               s_thread_to(sc,OP_E1ARGS);
          }

     CASE(OP_E1ARGS):     /* eval arguments */
	  gc_disable(sc, 1);
	  sc->args = cons(sc, sc->value, sc->args);
	  gc_enable(sc);
          if (is_pair(sc->code)) { /* continue */
               s_save(sc,OP_E1ARGS, sc->args, cdr(sc->code));
               sc->code = car(sc->code);
               sc->args = sc->NIL;
	       s_clear_flag(sc, TAIL_CONTEXT);
               s_thread_to(sc,OP_EVAL);
          } else {  /* end */
               sc->args = reverse_in_place(sc, sc->NIL, sc->args);
               s_thread_to(sc,OP_APPLY_CODE);
          }

#if USE_TRACING
     CASE(OP_TRACING): {
       int tr=sc->tracing;
       sc->tracing=ivalue(car(sc->args));
       gc_disable(sc, 1);
       s_return_enable_gc(sc, mk_integer(sc, tr));
     }
#endif

#if USE_HISTORY
     CASE(OP_CALLSTACK_POP):      /* pop the call stack */
	  callstack_pop(sc);
	  s_return(sc, sc->value);
#endif

     CASE(OP_APPLY_CODE): /* apply 'cadr(args)' to 'cddr(args)',
			   * record in the history as invoked from
			   * 'car(args)' */
	  free_cons(sc, sc->args, &callsite, &sc->args);
	  sc->code = car(sc->args);
	  sc->args = cdr(sc->args);
	  FALLTHROUGH;

     CASE(OP_APPLY):      /* apply 'code' to 'args' */
#if USE_TRACING
       if(sc->tracing) {
         s_save(sc,OP_REAL_APPLY,sc->args,sc->code);
         sc->print_flag = 1;
         /*  sc->args=cons(sc,sc->code,sc->args);*/
         putstr(sc,"\nApply to: ");
         s_thread_to(sc,OP_P0LIST);
       }
       FALLTHROUGH;
     CASE(OP_REAL_APPLY):
#endif
#if USE_HISTORY
          if (op != OP_APPLY_CODE)
            callsite = sc->code;
          if (s_get_flag(sc, TAIL_CONTEXT)) {
            /* We are evaluating a tail call.  */
            tailstack_push(sc, callsite);
          } else {
            callstack_push(sc, callsite);
            s_save(sc, OP_CALLSTACK_POP, sc->NIL, sc->NIL);
          }
#endif

          if (is_proc(sc->code)) {
               s_goto(sc,procnum(sc->code));   /* PROCEDURE */
          } else if (is_foreign(sc->code))
            {
              /* Keep nested calls from GC'ing the arglist */
              push_recent_alloc(sc,sc->args,sc->NIL);
               x=sc->code->_object._ff(sc,sc->args);
               s_return(sc,x);
          } else if (is_closure(sc->code) || is_macro(sc->code)
             || is_promise(sc->code)) { /* CLOSURE */
        /* Should not accept promise */
               /* make environment */
               new_frame_in_env(sc, closure_env(sc->code));
               for (x = car(closure_code(sc->code)), y = sc->args;
                    is_pair(x); x = cdr(x), y = cdr(y)) {
                    if (y == sc->NIL) {
                         Error_1(sc, "not enough arguments, missing", x);
                    } else if (is_symbol(car(x))) {
                         new_slot_in_env(sc, car(x), car(y));
                    } else {
			 Error_1(sc, "syntax error in closure: not a symbol", car(x));
		    }
               }

               if (x == sc->NIL) {
                    if (y != sc->NIL) {
                      Error_0(sc, "too many arguments");
                    }
               } else if (is_symbol(x))
                    new_slot_in_env(sc, x, y);
               else {
                    Error_1(sc, "syntax error in closure: not a symbol", x);
               }
               sc->code = cdr(closure_code(sc->code));
               sc->args = sc->NIL;
	       s_set_flag(sc, TAIL_CONTEXT);
               s_thread_to(sc,OP_BEGIN);
          } else if (is_continuation(sc->code)) { /* CONTINUATION */
               sc->dump = cont_dump(sc->code);
               s_return(sc,sc->args != sc->NIL ? car(sc->args) : sc->NIL);
          } else {
               Error_1(sc,"illegal function",sc->code);
          }

     CASE(OP_DOMACRO):    /* do macro */
          sc->code = sc->value;
          s_thread_to(sc,OP_EVAL);

#if USE_COMPILE_HOOK
     CASE(OP_LAMBDA):     /* lambda */
          /* If the hook is defined, apply it to sc->code, otherwise
             set sc->value fall through */
          {
               pointer f=find_slot_in_env(sc,sc->envir,sc->COMPILE_HOOK,1);
               if(f==sc->NIL) {
                    sc->value = sc->code;
                    /* Fallthru */
               } else {
		    gc_disable(sc, 1 + gc_reservations (s_save));
                    s_save(sc,OP_LAMBDA1,sc->args,sc->code);
                    sc->args=cons(sc,sc->code,sc->NIL);
		    gc_enable(sc);
                    sc->code=slot_value_in_env(f);
                    s_thread_to(sc,OP_APPLY);
               }
          }
#else
     CASE(OP_LAMBDA):     /* lambda */
	  sc->value = sc->code;
#endif
	  FALLTHROUGH;

     CASE(OP_LAMBDA1):
	  gc_disable(sc, 1);
          s_return_enable_gc(sc, mk_closure(sc, sc->value, sc->envir));


     CASE(OP_MKCLOSURE): /* make-closure */
       x=car(sc->args);
       if(car(x)==sc->LAMBDA) {
         x=cdr(x);
       }
       if(cdr(sc->args)==sc->NIL) {
         y=sc->envir;
       } else {
         y=cadr(sc->args);
       }
       gc_disable(sc, 1);
       s_return_enable_gc(sc, mk_closure(sc, x, y));

     CASE(OP_QUOTE):      /* quote */
          s_return(sc,car(sc->code));

     CASE(OP_DEF0):  /* define */
          if(is_immutable(car(sc->code)))
            Error_1(sc,"define: unable to alter immutable", car(sc->code));

          if (is_pair(car(sc->code))) {
               x = caar(sc->code);
	       gc_disable(sc, 2);
               sc->code = cons(sc, sc->LAMBDA, cons(sc, cdar(sc->code), cdr(sc->code)));
	       gc_enable(sc);
          } else {
               x = car(sc->code);
               sc->code = cadr(sc->code);
          }
          if (!is_symbol(x)) {
               Error_0(sc,"variable is not a symbol");
          }
          s_save(sc,OP_DEF1, sc->NIL, x);
          s_thread_to(sc,OP_EVAL);

     CASE(OP_DEF1): { /* define */
	  pointer *sslot;
          x = find_slot_spec_in_env(sc, sc->envir, sc->code, 0, &sslot);
          if (x != sc->NIL) {
               set_slot_in_env(sc, x, sc->value);
          } else {
	       new_slot_spec_in_env(sc, sc->code, sc->value, sslot);
          }
          s_return(sc,sc->code);
     }

     CASE(OP_DEFP):  /* defined? */
          x=sc->envir;
          if(cdr(sc->args)!=sc->NIL) {
               x=cadr(sc->args);
          }
          s_retbool(find_slot_in_env(sc,x,car(sc->args),1)!=sc->NIL);

     CASE(OP_SET0):       /* set! */
          if(is_immutable(car(sc->code)))
                Error_1(sc,"set!: unable to alter immutable variable",car(sc->code));
          s_save(sc,OP_SET1, sc->NIL, car(sc->code));
          sc->code = cadr(sc->code);
          s_thread_to(sc,OP_EVAL);

     CASE(OP_SET1):       /* set! */
          y=find_slot_in_env(sc,sc->envir,sc->code,1);
          if (y != sc->NIL) {
               set_slot_in_env(sc, y, sc->value);
               s_return(sc,sc->value);
          } else {
               Error_1(sc, "set!: unbound variable", sc->code);
          }


     CASE(OP_BEGIN):      /* begin */
	  {
	    int last;

	    if (!is_pair(sc->code)) {
	      s_return(sc,sc->code);
	    }

	    last = cdr(sc->code) == sc->NIL;
	    if (!last) {
	      s_save(sc,OP_BEGIN, sc->NIL, cdr(sc->code));
	    }
	    sc->code = car(sc->code);
	    if (! last)
	      /* This is not the end of the list.  This is not a tail
	       * position.  */
	      s_clear_flag(sc, TAIL_CONTEXT);
	    s_thread_to(sc,OP_EVAL);
	  }

     CASE(OP_IF0):        /* if */
          s_save(sc,OP_IF1, sc->NIL, cdr(sc->code));
          sc->code = car(sc->code);
	  s_clear_flag(sc, TAIL_CONTEXT);
          s_thread_to(sc,OP_EVAL);

     CASE(OP_IF1):        /* if */
          if (is_true(sc->value))
               sc->code = car(sc->code);
          else
               sc->code = cadr(sc->code);  /* (if #f 1) ==> () because
                                            * car(sc->NIL) = sc->NIL */
          s_thread_to(sc,OP_EVAL);

     CASE(OP_LET0):       /* let */
          sc->args = sc->NIL;
          sc->value = sc->code;
          sc->code = is_symbol(car(sc->code)) ? cadr(sc->code) : car(sc->code);
          s_thread_to(sc,OP_LET1);

     CASE(OP_LET1):       /* let (calculate parameters) */
	  gc_disable(sc, 1 + (is_pair(sc->code) ? gc_reservations (s_save) : 0));
          sc->args = cons(sc, sc->value, sc->args);
          if (is_pair(sc->code)) { /* continue */
               if (!is_pair(car(sc->code)) || !is_pair(cdar(sc->code))) {
		    gc_enable(sc);
                    Error_1(sc, "Bad syntax of binding spec in let",
                            car(sc->code));
               }
               s_save(sc,OP_LET1, sc->args, cdr(sc->code));
	       gc_enable(sc);
               sc->code = cadar(sc->code);
               sc->args = sc->NIL;
	       s_clear_flag(sc, TAIL_CONTEXT);
               s_thread_to(sc,OP_EVAL);
          } else {  /* end */
	       gc_enable(sc);
               sc->args = reverse_in_place(sc, sc->NIL, sc->args);
               sc->code = car(sc->args);
               sc->args = cdr(sc->args);
               s_thread_to(sc,OP_LET2);
          }

     CASE(OP_LET2):       /* let */
          new_frame_in_env(sc, sc->envir);
          for (x = is_symbol(car(sc->code)) ? cadr(sc->code) : car(sc->code), y = sc->args;
               y != sc->NIL; x = cdr(x), y = cdr(y)) {
               new_slot_in_env(sc, caar(x), car(y));
          }
          if (is_symbol(car(sc->code))) {    /* named let */
               for (x = cadr(sc->code), sc->args = sc->NIL; x != sc->NIL; x = cdr(x)) {
                    if (!is_pair(x))
                        Error_1(sc, "Bad syntax of binding in let", x);
                    if (!is_list(sc, car(x)))
                        Error_1(sc, "Bad syntax of binding in let", car(x));
		    gc_disable(sc, 1);
                    sc->args = cons(sc, caar(x), sc->args);
		    gc_enable(sc);
               }
	       gc_disable(sc, 2 + gc_reservations (new_slot_in_env));
               x = mk_closure(sc, cons(sc, reverse_in_place(sc, sc->NIL, sc->args), cddr(sc->code)), sc->envir);
               new_slot_in_env(sc, car(sc->code), x);
	       gc_enable(sc);
               sc->code = cddr(sc->code);
               sc->args = sc->NIL;
          } else {
               sc->code = cdr(sc->code);
               sc->args = sc->NIL;
          }
          s_thread_to(sc,OP_BEGIN);

     CASE(OP_LET0AST):    /* let* */
          if (car(sc->code) == sc->NIL) {
               new_frame_in_env(sc, sc->envir);
               sc->code = cdr(sc->code);
               s_thread_to(sc,OP_BEGIN);
          }
          if(!is_pair(car(sc->code)) || !is_pair(caar(sc->code)) || !is_pair(cdaar(sc->code))) {
               Error_1(sc, "Bad syntax of binding spec in let*", car(sc->code));
          }
          s_save(sc,OP_LET1AST, cdr(sc->code), car(sc->code));
          sc->code = cadaar(sc->code);
	  s_clear_flag(sc, TAIL_CONTEXT);
          s_thread_to(sc,OP_EVAL);

     CASE(OP_LET1AST):    /* let* (make new frame) */
          new_frame_in_env(sc, sc->envir);
          s_thread_to(sc,OP_LET2AST);

     CASE(OP_LET2AST):    /* let* (calculate parameters) */
          new_slot_in_env(sc, caar(sc->code), sc->value);
          sc->code = cdr(sc->code);
          if (is_pair(sc->code)) { /* continue */
               s_save(sc,OP_LET2AST, sc->args, sc->code);
               sc->code = cadar(sc->code);
               sc->args = sc->NIL;
	       s_clear_flag(sc, TAIL_CONTEXT);
               s_thread_to(sc,OP_EVAL);
          } else {  /* end */
               sc->code = sc->args;
               sc->args = sc->NIL;
               s_thread_to(sc,OP_BEGIN);
          }

     CASE(OP_LET0REC):    /* letrec */
          new_frame_in_env(sc, sc->envir);
          sc->args = sc->NIL;
          sc->value = sc->code;
          sc->code = car(sc->code);
          s_thread_to(sc,OP_LET1REC);

     CASE(OP_LET1REC):    /* letrec (calculate parameters) */
	  gc_disable(sc, 1);
          sc->args = cons(sc, sc->value, sc->args);
	  gc_enable(sc);
          if (is_pair(sc->code)) { /* continue */
               if (!is_pair(car(sc->code)) || !is_pair(cdar(sc->code))) {
                    Error_1(sc, "Bad syntax of binding spec in letrec",
                            car(sc->code));
               }
               s_save(sc,OP_LET1REC, sc->args, cdr(sc->code));
               sc->code = cadar(sc->code);
               sc->args = sc->NIL;
	       s_clear_flag(sc, TAIL_CONTEXT);
               s_thread_to(sc,OP_EVAL);
          } else {  /* end */
               sc->args = reverse_in_place(sc, sc->NIL, sc->args);
               sc->code = car(sc->args);
               sc->args = cdr(sc->args);
               s_thread_to(sc,OP_LET2REC);
          }

     CASE(OP_LET2REC):    /* letrec */
          for (x = car(sc->code), y = sc->args; y != sc->NIL; x = cdr(x), y = cdr(y)) {
               new_slot_in_env(sc, caar(x), car(y));
          }
          sc->code = cdr(sc->code);
          sc->args = sc->NIL;
          s_thread_to(sc,OP_BEGIN);

     CASE(OP_COND0):      /* cond */
          if (!is_pair(sc->code)) {
               Error_0(sc,"syntax error in cond");
          }
          s_save(sc,OP_COND1, sc->NIL, sc->code);
          sc->code = caar(sc->code);
	  s_clear_flag(sc, TAIL_CONTEXT);
          s_thread_to(sc,OP_EVAL);

     CASE(OP_COND1):      /* cond */
          if (is_true(sc->value)) {
               if ((sc->code = cdar(sc->code)) == sc->NIL) {
                    s_return(sc,sc->value);
               }
               if(!sc->code || car(sc->code)==sc->FEED_TO) {
                    if(!is_pair(cdr(sc->code))) {
                         Error_0(sc,"syntax error in cond");
                    }
		    gc_disable(sc, 4);
                    x=cons(sc, sc->QUOTE, cons(sc, sc->value, sc->NIL));
                    sc->code=cons(sc,cadr(sc->code),cons(sc,x,sc->NIL));
		    gc_enable(sc);
                    s_thread_to(sc,OP_EVAL);
               }
               s_thread_to(sc,OP_BEGIN);
          } else {
               if ((sc->code = cdr(sc->code)) == sc->NIL) {
                    s_return(sc,sc->NIL);
               } else {
                    s_save(sc,OP_COND1, sc->NIL, sc->code);
                    sc->code = caar(sc->code);
		    s_clear_flag(sc, TAIL_CONTEXT);
                    s_thread_to(sc,OP_EVAL);
               }
          }

     CASE(OP_DELAY):      /* delay */
	  gc_disable(sc, 2);
          x = mk_closure(sc, cons(sc, sc->NIL, sc->code), sc->envir);
          typeflag(x)=T_PROMISE;
          s_return_enable_gc(sc,x);

     CASE(OP_AND0):       /* and */
          if (sc->code == sc->NIL) {
               s_return(sc,sc->T);
          }
          s_save(sc,OP_AND1, sc->NIL, cdr(sc->code));
	  if (cdr(sc->code) != sc->NIL)
	       s_clear_flag(sc, TAIL_CONTEXT);
          sc->code = car(sc->code);
          s_thread_to(sc,OP_EVAL);

     CASE(OP_AND1):       /* and */
          if (is_false(sc->value)) {
               s_return(sc,sc->value);
          } else if (sc->code == sc->NIL) {
               s_return(sc,sc->value);
          } else {
               s_save(sc,OP_AND1, sc->NIL, cdr(sc->code));
	       if (cdr(sc->code) != sc->NIL)
		    s_clear_flag(sc, TAIL_CONTEXT);
               sc->code = car(sc->code);
               s_thread_to(sc,OP_EVAL);
          }

     CASE(OP_OR0):        /* or */
          if (sc->code == sc->NIL) {
               s_return(sc,sc->F);
          }
          s_save(sc,OP_OR1, sc->NIL, cdr(sc->code));
	  if (cdr(sc->code) != sc->NIL)
	       s_clear_flag(sc, TAIL_CONTEXT);
          sc->code = car(sc->code);
          s_thread_to(sc,OP_EVAL);

     CASE(OP_OR1):        /* or */
          if (is_true(sc->value)) {
               s_return(sc,sc->value);
          } else if (sc->code == sc->NIL) {
               s_return(sc,sc->value);
          } else {
               s_save(sc,OP_OR1, sc->NIL, cdr(sc->code));
	       if (cdr(sc->code) != sc->NIL)
		    s_clear_flag(sc, TAIL_CONTEXT);
               sc->code = car(sc->code);
               s_thread_to(sc,OP_EVAL);
          }

     CASE(OP_C0STREAM):   /* cons-stream */
          s_save(sc,OP_C1STREAM, sc->NIL, cdr(sc->code));
          sc->code = car(sc->code);
          s_thread_to(sc,OP_EVAL);

     CASE(OP_C1STREAM):   /* cons-stream */
          sc->args = sc->value;  /* save sc->value to register sc->args for gc */
	  gc_disable(sc, 3);
          x = mk_closure(sc, cons(sc, sc->NIL, sc->code), sc->envir);
          typeflag(x)=T_PROMISE;
          s_return_enable_gc(sc, cons(sc, sc->args, x));

     CASE(OP_MACRO0):     /* macro */
          if (is_pair(car(sc->code))) {
               x = caar(sc->code);
	       gc_disable(sc, 2);
               sc->code = cons(sc, sc->LAMBDA, cons(sc, cdar(sc->code), cdr(sc->code)));
	       gc_enable(sc);
          } else {
               x = car(sc->code);
               sc->code = cadr(sc->code);
          }
          if (!is_symbol(x)) {
               Error_0(sc,"variable is not a symbol");
          }
          s_save(sc,OP_MACRO1, sc->NIL, x);
          s_thread_to(sc,OP_EVAL);

     CASE(OP_MACRO1): {   /* macro */
	  pointer *sslot;
          typeflag(sc->value) = T_MACRO;
          x = find_slot_spec_in_env(sc, sc->envir, sc->code, 0, &sslot);
          if (x != sc->NIL) {
               set_slot_in_env(sc, x, sc->value);
          } else {
	       new_slot_spec_in_env(sc, sc->code, sc->value, sslot);
          }
          s_return(sc,sc->code);
     }

     CASE(OP_CASE0):      /* case */
          s_save(sc,OP_CASE1, sc->NIL, cdr(sc->code));
          sc->code = car(sc->code);
	  s_clear_flag(sc, TAIL_CONTEXT);
          s_thread_to(sc,OP_EVAL);

     CASE(OP_CASE1):      /* case */
          for (x = sc->code; x != sc->NIL; x = cdr(x)) {
               if (!is_pair(y = caar(x))) {
                    break;
               }
               for ( ; y != sc->NIL; y = cdr(y)) {
                    if (eqv(car(y), sc->value)) {
                         break;
                    }
               }
               if (y != sc->NIL) {
                    break;
               }
          }
          if (x != sc->NIL) {
               if (is_pair(caar(x))) {
                    sc->code = cdar(x);
                    s_thread_to(sc,OP_BEGIN);
               } else {/* else */
                    s_save(sc,OP_CASE2, sc->NIL, cdar(x));
                    sc->code = caar(x);
                    s_thread_to(sc,OP_EVAL);
               }
          } else {
               s_return(sc,sc->NIL);
          }

     CASE(OP_CASE2):      /* case */
          if (is_true(sc->value)) {
               s_thread_to(sc,OP_BEGIN);
          } else {
               s_return(sc,sc->NIL);
          }

     CASE(OP_PAPPLY):     /* apply */
          sc->code = car(sc->args);
          sc->args = list_star(sc,cdr(sc->args));
          /*sc->args = cadr(sc->args);*/
          s_thread_to(sc,OP_APPLY);

     CASE(OP_PEVAL): /* eval */
          if(cdr(sc->args)!=sc->NIL) {
               sc->envir=cadr(sc->args);
          }
          sc->code = car(sc->args);
          s_thread_to(sc,OP_EVAL);

     CASE(OP_CONTINUATION):    /* call-with-current-continuation */
          sc->code = car(sc->args);
	  gc_disable(sc, 2);
          sc->args = cons(sc, mk_continuation(sc, sc->dump), sc->NIL);
	  gc_enable(sc);
          s_thread_to(sc,OP_APPLY);

#if USE_MATH
     CASE(OP_INEX2EX):    /* inexact->exact */
          x=car(sc->args);
          if(num_is_integer(x)) {
               s_return(sc,x);
          } else if(modf(rvalue_unchecked(x),&dd)==0.0) {
               s_return(sc,mk_integer(sc,ivalue(x)));
          } else {
               Error_1(sc, "inexact->exact: not integral", x);
          }

     CASE(OP_EXP):
          x=car(sc->args);
          s_return(sc, mk_real(sc, exp(rvalue(x))));

     CASE(OP_LOG):
          x=car(sc->args);
          s_return(sc, mk_real(sc, log(rvalue(x))));

     CASE(OP_SIN):
          x=car(sc->args);
          s_return(sc, mk_real(sc, sin(rvalue(x))));

     CASE(OP_COS):
          x=car(sc->args);
          s_return(sc, mk_real(sc, cos(rvalue(x))));

     CASE(OP_TAN):
          x=car(sc->args);
          s_return(sc, mk_real(sc, tan(rvalue(x))));

     CASE(OP_ASIN):
          x=car(sc->args);
          s_return(sc, mk_real(sc, asin(rvalue(x))));

     CASE(OP_ACOS):
          x=car(sc->args);
          s_return(sc, mk_real(sc, acos(rvalue(x))));

     CASE(OP_ATAN):
          x=car(sc->args);
          if(cdr(sc->args)==sc->NIL) {
               s_return(sc, mk_real(sc, atan(rvalue(x))));
          } else {
               pointer y=cadr(sc->args);
               s_return(sc, mk_real(sc, atan2(rvalue(x),rvalue(y))));
          }

     CASE(OP_SQRT):
          x=car(sc->args);
          s_return(sc, mk_real(sc, sqrt(rvalue(x))));

     CASE(OP_EXPT): {
          double result;
          int real_result=1;
          pointer y=cadr(sc->args);
          x=car(sc->args);
          if (num_is_integer(x) && num_is_integer(y))
             real_result=0;
          /* This 'if' is an R5RS compatibility fix. */
          /* NOTE: Remove this 'if' fix for R6RS.    */
          if (rvalue(x) == 0 && rvalue(y) < 0) {
             result = 0.0;
          } else {
             result = pow(rvalue(x),rvalue(y));
          }
          /* Before returning integer result make sure we can. */
          /* If the test fails, result is too big for integer. */
          if (!real_result)
          {
            long result_as_long = (long)result;
            if (result != (double)result_as_long)
              real_result = 1;
          }
          if (real_result) {
             s_return(sc, mk_real(sc, result));
          } else {
             s_return(sc, mk_integer(sc, result));
          }
     }

     CASE(OP_FLOOR):
          x=car(sc->args);
          s_return(sc, mk_real(sc, floor(rvalue(x))));

     CASE(OP_CEILING):
          x=car(sc->args);
          s_return(sc, mk_real(sc, ceil(rvalue(x))));

     CASE(OP_TRUNCATE ): {
          double rvalue_of_x ;
          x=car(sc->args);
          rvalue_of_x = rvalue(x) ;
          if (rvalue_of_x > 0) {
            s_return(sc, mk_real(sc, floor(rvalue_of_x)));
          } else {
            s_return(sc, mk_real(sc, ceil(rvalue_of_x)));
          }
     }

     CASE(OP_ROUND):
        x=car(sc->args);
        if (num_is_integer(x))
            s_return(sc, x);
        s_return(sc, mk_real(sc, round_per_R5RS(rvalue(x))));
#endif

     CASE(OP_ADD):        /* + */
       v=num_zero;
       for (x = sc->args; x != sc->NIL; x = cdr(x)) {
         v=num_add(v,nvalue(car(x)));
       }
       gc_disable(sc, 1);
       s_return_enable_gc(sc, mk_number(sc, v));

     CASE(OP_MUL):        /* * */
       v=num_one;
       for (x = sc->args; x != sc->NIL; x = cdr(x)) {
         v=num_mul(v,nvalue(car(x)));
       }
       gc_disable(sc, 1);
       s_return_enable_gc(sc, mk_number(sc, v));

     CASE(OP_SUB):        /* - */
       if(cdr(sc->args)==sc->NIL) {
         x=sc->args;
         v=num_zero;
       } else {
         x = cdr(sc->args);
         v = nvalue(car(sc->args));
       }
       for (; x != sc->NIL; x = cdr(x)) {
         v=num_sub(v,nvalue(car(x)));
       }
       gc_disable(sc, 1);
       s_return_enable_gc(sc, mk_number(sc, v));

     CASE(OP_DIV):        /* / */
       if(cdr(sc->args)==sc->NIL) {
         x=sc->args;
         v=num_one;
       } else {
         x = cdr(sc->args);
         v = nvalue(car(sc->args));
       }
       for (; x != sc->NIL; x = cdr(x)) {
         if (!is_zero_double(rvalue(car(x))))
           v=num_div(v,nvalue(car(x)));
         else {
           Error_0(sc,"/: division by zero");
         }
       }
       gc_disable(sc, 1);
       s_return_enable_gc(sc, mk_number(sc, v));

     CASE(OP_INTDIV):        /* quotient */
          if(cdr(sc->args)==sc->NIL) {
               x=sc->args;
               v=num_one;
          } else {
               x = cdr(sc->args);
               v = nvalue(car(sc->args));
          }
          for (; x != sc->NIL; x = cdr(x)) {
               if (ivalue(car(x)) != 0)
                    v=num_intdiv(v,nvalue(car(x)));
               else {
                    Error_0(sc,"quotient: division by zero");
               }
          }
	  gc_disable(sc, 1);
          s_return_enable_gc(sc, mk_number(sc, v));

     CASE(OP_REM):        /* remainder */
          v = nvalue(car(sc->args));
          if (ivalue(cadr(sc->args)) != 0)
               v=num_rem(v,nvalue(cadr(sc->args)));
          else {
               Error_0(sc,"remainder: division by zero");
          }
	  gc_disable(sc, 1);
          s_return_enable_gc(sc, mk_number(sc, v));

     CASE(OP_MOD):        /* modulo */
          v = nvalue(car(sc->args));
          if (ivalue(cadr(sc->args)) != 0)
               v=num_mod(v,nvalue(cadr(sc->args)));
          else {
               Error_0(sc,"modulo: division by zero");
          }
	  gc_disable(sc, 1);
          s_return_enable_gc(sc, mk_number(sc, v));

     CASE(OP_CAR):        /* car */
          s_return(sc,caar(sc->args));

     CASE(OP_CDR):        /* cdr */
          s_return(sc,cdar(sc->args));

     CASE(OP_CONS):       /* cons */
          cdr(sc->args) = cadr(sc->args);
          s_return(sc,sc->args);

     CASE(OP_SETCAR):     /* set-car! */
       if(!is_immutable(car(sc->args))) {
         caar(sc->args) = cadr(sc->args);
         s_return(sc,car(sc->args));
       } else {
         Error_0(sc,"set-car!: unable to alter immutable pair");
       }

     CASE(OP_SETCDR):     /* set-cdr! */
       if(!is_immutable(car(sc->args))) {
         cdar(sc->args) = cadr(sc->args);
         s_return(sc,car(sc->args));
       } else {
         Error_0(sc,"set-cdr!: unable to alter immutable pair");
       }

     CASE(OP_CHAR2INT): { /* char->integer */
          char c;
          c=(char)ivalue(car(sc->args));
	  gc_disable(sc, 1);
          s_return_enable_gc(sc, mk_integer(sc, (unsigned char) c));
     }

     CASE(OP_INT2CHAR): { /* integer->char */
          unsigned char c;
          c=(unsigned char)ivalue(car(sc->args));
	  gc_disable(sc, 1);
          s_return_enable_gc(sc, mk_character(sc, (char) c));
     }

     CASE(OP_CHARUPCASE): {
          unsigned char c;
          c=(unsigned char)ivalue(car(sc->args));
          c=toupper(c);
	  gc_disable(sc, 1);
          s_return_enable_gc(sc, mk_character(sc, (char) c));
     }

     CASE(OP_CHARDNCASE): {
          unsigned char c;
          c=(unsigned char)ivalue(car(sc->args));
          c=tolower(c);
	  gc_disable(sc, 1);
          s_return_enable_gc(sc, mk_character(sc, (char) c));
     }

     CASE(OP_STR2SYM):  /* string->symbol */
          gc_disable(sc, gc_reservations (mk_symbol));
          s_return_enable_gc(sc, mk_symbol(sc, strvalue(car(sc->args))));

     CASE(OP_STR2ATOM): /* string->atom */ {
          char *s=strvalue(car(sc->args));
          long pf = 0;
          if(cdr(sc->args)!=sc->NIL) {
            /* we know cadr(sc->args) is a natural number */
            /* see if it is 2, 8, 10, or 16, or error */
            pf = ivalue_unchecked(cadr(sc->args));
            if(pf == 16 || pf == 10 || pf == 8 || pf == 2) {
               /* base is OK */
            }
            else {
              pf = -1;
            }
          }
          if (pf < 0) {
            Error_1(sc, "string->atom: bad base", cadr(sc->args));
          } else if(*s=='#') /* no use of base! */ {
            s_return(sc, mk_sharp_const(sc, s+1));
          } else {
            if (pf == 0 || pf == 10) {
              s_return(sc, mk_atom(sc, s));
            }
            else {
              char *ep;
              long iv = strtol(s,&ep,(int )pf);
              if (*ep == 0) {
                s_return(sc, mk_integer(sc, iv));
              }
              else {
                s_return(sc, sc->F);
              }
            }
          }
        }

     CASE(OP_SYM2STR): /* symbol->string */
	  gc_disable(sc, 1);
          x=mk_string(sc,symname(car(sc->args)));
          setimmutable(x);
          s_return_enable_gc(sc, x);

     CASE(OP_ATOM2STR): /* atom->string */ {
          long pf = 0;
          x=car(sc->args);
          if(cdr(sc->args)!=sc->NIL) {
            /* we know cadr(sc->args) is a natural number */
            /* see if it is 2, 8, 10, or 16, or error */
            pf = ivalue_unchecked(cadr(sc->args));
            if(is_number(x) && (pf == 16 || pf == 10 || pf == 8 || pf == 2)) {
              /* base is OK */
            }
            else {
              pf = -1;
            }
          }
          if (pf < 0) {
            Error_1(sc, "atom->string: bad base", cadr(sc->args));
          } else if(is_number(x) || is_character(x) || is_string(x) || is_symbol(x)) {
            char *p;
            int len;
            atom2str(sc,x,(int )pf,&p,&len);
	    gc_disable(sc, 1);
            s_return_enable_gc(sc, mk_counted_string(sc, p, len));
          } else {
            Error_1(sc, "atom->string: not an atom", x);
          }
        }

     CASE(OP_MKSTRING): { /* make-string */
          int fill=' ';
          int len;

          len=ivalue(car(sc->args));

          if(cdr(sc->args)!=sc->NIL) {
               fill=charvalue(cadr(sc->args));
          }
	  gc_disable(sc, 1);
          s_return_enable_gc(sc, mk_empty_string(sc, len, (char) fill));
     }

     CASE(OP_STRLEN):  /* string-length */
	  gc_disable(sc, 1);
          s_return_enable_gc(sc, mk_integer(sc, strlength(car(sc->args))));

     CASE(OP_STRREF): { /* string-ref */
          char *str;
          int index;

          str=strvalue(car(sc->args));

          index=ivalue(cadr(sc->args));

          if(index>=strlength(car(sc->args))) {
               Error_1(sc, "string-ref: out of bounds", cadr(sc->args));
          }

	  gc_disable(sc, 1);
          s_return_enable_gc(sc,
			     mk_character(sc, ((unsigned char*) str)[index]));
     }

     CASE(OP_STRSET): { /* string-set! */
          char *str;
          int index;
          int c;

          if(is_immutable(car(sc->args))) {
               Error_1(sc, "string-set!: unable to alter immutable string",
		       car(sc->args));
          }
          str=strvalue(car(sc->args));

          index=ivalue(cadr(sc->args));
          if(index>=strlength(car(sc->args))) {
               Error_1(sc, "string-set!: out of bounds", cadr(sc->args));
          }

          c=charvalue(caddr(sc->args));

          str[index]=(char)c;
          s_return(sc,car(sc->args));
     }

     CASE(OP_STRAPPEND): { /* string-append */
       /* in 1.29 string-append was in Scheme in init.scm but was too slow */
       int len = 0;
       pointer newstr;
       char *pos;

       /* compute needed length for new string */
       for (x = sc->args; x != sc->NIL; x = cdr(x)) {
          len += strlength(car(x));
       }
       gc_disable(sc, 1);
       newstr = mk_empty_string(sc, len, ' ');
       /* store the contents of the argument strings into the new string */
       for (pos = strvalue(newstr), x = sc->args; x != sc->NIL;
           pos += strlength(car(x)), x = cdr(x)) {
           memcpy(pos, strvalue(car(x)), strlength(car(x)));
       }
       s_return_enable_gc(sc, newstr);
     }

     CASE(OP_SUBSTR): { /* substring */
          char *str;
          int index0;
          int index1;

          str=strvalue(car(sc->args));

          index0=ivalue(cadr(sc->args));

          if(index0>strlength(car(sc->args))) {
               Error_1(sc, "substring: start out of bounds", cadr(sc->args));
          }

          if(cddr(sc->args)!=sc->NIL) {
               index1=ivalue(caddr(sc->args));
               if(index1>strlength(car(sc->args)) || index1<index0) {
                    Error_1(sc, "substring: end out of bounds", caddr(sc->args));
               }
          } else {
               index1=strlength(car(sc->args));
          }

	  gc_disable(sc, 1);
          s_return_enable_gc(sc, mk_counted_string(sc, str + index0, index1 - index0));
     }

     CASE(OP_VECTOR): {   /* vector */
          int i;
          pointer vec;
          int len=list_length(sc,sc->args);
          if(len<0) {
               Error_1(sc, "vector: not a proper list", sc->args);
          }
          vec=mk_vector(sc,len);
          if(sc->no_memory) { s_return(sc, sc->sink); }
          for (x = sc->args, i = 0; is_pair(x); x = cdr(x), i++) {
               set_vector_elem(vec,i,car(x));
          }
          s_return(sc,vec);
     }

     CASE(OP_MKVECTOR): { /* make-vector */
          pointer fill=sc->NIL;
          int len;
          pointer vec;

          len=ivalue(car(sc->args));

          if(cdr(sc->args)!=sc->NIL) {
               fill=cadr(sc->args);
          }
          vec=mk_vector(sc,len);
          if(sc->no_memory) { s_return(sc, sc->sink); }
          if(fill!=sc->NIL) {
               fill_vector(vec,fill);
          }
          s_return(sc,vec);
     }

     CASE(OP_VECLEN):  /* vector-length */
	  gc_disable(sc, 1);
          s_return_enable_gc(sc, mk_integer(sc, vector_length(car(sc->args))));

     CASE(OP_VECREF): { /* vector-ref */
          int index;

          index=ivalue(cadr(sc->args));

          if(index >= vector_length(car(sc->args))) {
               Error_1(sc, "vector-ref: out of bounds", cadr(sc->args));
          }

          s_return(sc,vector_elem(car(sc->args),index));
     }

     CASE(OP_VECSET): {   /* vector-set! */
          int index;

          if(is_immutable(car(sc->args))) {
               Error_1(sc, "vector-set!: unable to alter immutable vector",
		       car(sc->args));
          }

          index=ivalue(cadr(sc->args));
          if(index >= vector_length(car(sc->args))) {
               Error_1(sc, "vector-set!: out of bounds", cadr(sc->args));
          }

          set_vector_elem(car(sc->args),index,caddr(sc->args));
          s_return(sc,car(sc->args));
     }

     CASE(OP_NOT):        /* not */
          s_retbool(is_false(car(sc->args)));
     CASE(OP_BOOLP):       /* boolean? */
          s_retbool(car(sc->args) == sc->F || car(sc->args) == sc->T);
     CASE(OP_EOFOBJP):       /* boolean? */
          s_retbool(car(sc->args) == sc->EOF_OBJ);
     CASE(OP_NULLP):       /* null? */
          s_retbool(car(sc->args) == sc->NIL);
     CASE(OP_NUMEQ):      /* = */
     CASE(OP_LESS):       /* < */
     CASE(OP_GRE):        /* > */
     CASE(OP_LEQ):        /* <= */
     CASE(OP_GEQ):        /* >= */
          switch(op) {
               case OP_NUMEQ: comp_func=num_eq; break;
               case OP_LESS:  comp_func=num_lt; break;
               case OP_GRE:   comp_func=num_gt; break;
               case OP_LEQ:   comp_func=num_le; break;
               case OP_GEQ:   comp_func=num_ge; break;
               default: assert (! "reached");
          }
          x=sc->args;
          v=nvalue(car(x));
          x=cdr(x);

          for (; x != sc->NIL; x = cdr(x)) {
               if(!comp_func(v,nvalue(car(x)))) {
                    s_retbool(0);
               }
           v=nvalue(car(x));
          }
          s_retbool(1);
     CASE(OP_SYMBOLP):     /* symbol? */
          s_retbool(is_symbol(car(sc->args)));
     CASE(OP_NUMBERP):     /* number? */
          s_retbool(is_number(car(sc->args)));
     CASE(OP_STRINGP):     /* string? */
          s_retbool(is_string(car(sc->args)));
     CASE(OP_INTEGERP):     /* integer? */
          s_retbool(is_integer(car(sc->args)));
     CASE(OP_REALP):     /* real? */
          s_retbool(is_number(car(sc->args))); /* All numbers are real */
     CASE(OP_CHARP):     /* char? */
          s_retbool(is_character(car(sc->args)));
#if USE_CHAR_CLASSIFIERS
     CASE(OP_CHARAP):     /* char-alphabetic? */
          s_retbool(Cisalpha(ivalue(car(sc->args))));
     CASE(OP_CHARNP):     /* char-numeric? */
          s_retbool(Cisdigit(ivalue(car(sc->args))));
     CASE(OP_CHARWP):     /* char-whitespace? */
          s_retbool(Cisspace(ivalue(car(sc->args))));
     CASE(OP_CHARUP):     /* char-upper-case? */
          s_retbool(Cisupper(ivalue(car(sc->args))));
     CASE(OP_CHARLP):     /* char-lower-case? */
          s_retbool(Cislower(ivalue(car(sc->args))));
#endif
     CASE(OP_PORTP):     /* port? */
          s_retbool(is_port(car(sc->args)));
     CASE(OP_INPORTP):     /* input-port? */
          s_retbool(is_inport(car(sc->args)));
     CASE(OP_OUTPORTP):     /* output-port? */
          s_retbool(is_outport(car(sc->args)));
     CASE(OP_PROCP):       /* procedure? */
          /*--
              * continuation should be procedure by the example
              * (call-with-current-continuation procedure?) ==> #t
                 * in R^3 report sec. 6.9
              */
          s_retbool(is_proc(car(sc->args)) || is_closure(car(sc->args))
                 || is_continuation(car(sc->args)) || is_foreign(car(sc->args)));
     CASE(OP_PAIRP):       /* pair? */
          s_retbool(is_pair(car(sc->args)));
     CASE(OP_LISTP):       /* list? */
       s_retbool(list_length(sc,car(sc->args)) >= 0);

     CASE(OP_ENVP):        /* environment? */
          s_retbool(is_environment(car(sc->args)));
     CASE(OP_VECTORP):     /* vector? */
          s_retbool(is_vector(car(sc->args)));
     CASE(OP_EQ):         /* eq? */
          s_retbool(car(sc->args) == cadr(sc->args));
     CASE(OP_EQV):        /* eqv? */
          s_retbool(eqv(car(sc->args), cadr(sc->args)));

     CASE(OP_FORCE):      /* force */
          sc->code = car(sc->args);
          if (is_promise(sc->code)) {
               /* Should change type to closure here */
               s_save(sc, OP_SAVE_FORCED, sc->NIL, sc->code);
               sc->args = sc->NIL;
               s_thread_to(sc,OP_APPLY);
          } else {
               s_return(sc,sc->code);
          }

     CASE(OP_SAVE_FORCED):     /* Save forced value replacing promise */
	  copy_value(sc, sc->code, sc->value);
          s_return(sc,sc->value);

     CASE(OP_WRITE):      /* write */
     CASE(OP_DISPLAY):    /* display */
     CASE(OP_WRITE_CHAR): /* write-char */
          if(is_pair(cdr(sc->args))) {
               if(cadr(sc->args)!=sc->outport) {
                    x=cons(sc,sc->outport,sc->NIL);
                    s_save(sc,OP_SET_OUTPORT, x, sc->NIL);
                    sc->outport=cadr(sc->args);
               }
          }
          sc->args = car(sc->args);
          if(op==OP_WRITE) {
               sc->print_flag = 1;
          } else {
               sc->print_flag = 0;
          }
          s_thread_to(sc,OP_P0LIST);

     CASE(OP_NEWLINE):    /* newline */
          if(is_pair(sc->args)) {
               if(car(sc->args)!=sc->outport) {
                    x=cons(sc,sc->outport,sc->NIL);
                    s_save(sc,OP_SET_OUTPORT, x, sc->NIL);
                    sc->outport=car(sc->args);
               }
          }
          putstr(sc, "\n");
          s_return(sc,sc->T);

     CASE(OP_ERR0):  /* error */
          sc->retcode=-1;
          if (!is_string(car(sc->args))) {
               sc->args=cons(sc,mk_string(sc," -- "),sc->args);
               setimmutable(car(sc->args));
          }
          putstr(sc, "Error: ");
          putstr(sc, strvalue(car(sc->args)));
          sc->args = cdr(sc->args);
          s_thread_to(sc,OP_ERR1);

     CASE(OP_ERR1):  /* error */
          putstr(sc, " ");
          if (sc->args != sc->NIL) {
               s_save(sc,OP_ERR1, cdr(sc->args), sc->NIL);
               sc->args = car(sc->args);
               sc->print_flag = 1;
               s_thread_to(sc,OP_P0LIST);
          } else {
               putstr(sc, "\n");
               if(sc->interactive_repl) {
                    s_thread_to(sc,OP_T0LVL);
               } else {
                    return;
               }
          }

     CASE(OP_REVERSE):   /* reverse */
          s_return(sc,reverse(sc, sc->NIL, car(sc->args)));

     CASE(OP_REVERSE_IN_PLACE):   /* reverse! */
          s_return(sc, reverse_in_place(sc, sc->NIL, car(sc->args)));

     CASE(OP_LIST_STAR): /* list* */
          s_return(sc,list_star(sc,sc->args));

     CASE(OP_APPEND):    /* append */
          x = sc->NIL;
          y = sc->args;
          if (y == x) {
              s_return(sc, x);
          }

          /* cdr() in the while condition is not a typo. If car() */
          /* is used (append '() 'a) will return the wrong result.*/
          while (cdr(y) != sc->NIL) {
              x = revappend(sc, x, car(y));
              y = cdr(y);
              if (x == sc->F) {
                  Error_0(sc, "non-list argument to append");
              }
          }

          s_return(sc, reverse_in_place(sc, car(y), x));

#if USE_PLIST
     CASE(OP_SET_SYMBOL_PROPERTY): /* set-symbol-property! */
	  gc_disable(sc, gc_reservations(set_property));
          s_return_enable_gc(sc,
			     set_property(sc, car(sc->args),
					  cadr(sc->args), caddr(sc->args)));

     CASE(OP_SYMBOL_PROPERTY):  /* symbol-property */
	  s_return(sc, get_property(sc, car(sc->args), cadr(sc->args)));
#endif /* USE_PLIST */

     CASE(OP_TAG_VALUE): {      /* not exposed */
	  /* This tags sc->value with car(sc->args).  Useful to tag
	   * results of opcode evaluations.  */
	  pointer a, b, c;
	  free_cons(sc, sc->args, &a, &b);
	  free_cons(sc, b, &b, &c);
	  assert(c == sc->NIL);
          s_return(sc, mk_tagged_value(sc, sc->value, a, b));
	}

     CASE(OP_MK_TAGGED):        /* make-tagged-value */
	  if (is_vector(car(sc->args)))
	       Error_0(sc, "cannot tag vector");
          s_return(sc, mk_tagged_value(sc, car(sc->args),
				       car(cadr(sc->args)),
				       cdr(cadr(sc->args))));

     CASE(OP_GET_TAG):        /* get-tag */
	  s_return(sc, get_tag(sc, car(sc->args)));

     CASE(OP_QUIT):       /* quit */
          if(is_pair(sc->args)) {
               sc->retcode=ivalue(car(sc->args));
          }
          return;

     CASE(OP_GC):         /* gc */
          gc(sc, sc->NIL, sc->NIL);
          s_return(sc,sc->T);

     CASE(OP_GCVERB):          /* gc-verbose */
     {    int  was = sc->gc_verbose;

          sc->gc_verbose = (car(sc->args) != sc->F);
          s_retbool(was);
     }

     CASE(OP_NEWSEGMENT): /* new-segment */
          if (!is_pair(sc->args) || !is_number(car(sc->args))) {
               Error_0(sc,"new-segment: argument must be a number");
          }
          alloc_cellseg(sc, (int) ivalue(car(sc->args)));
          s_return(sc,sc->T);

     CASE(OP_OBLIST): /* oblist */
          s_return(sc, oblist_all_symbols(sc));

     CASE(OP_CURR_INPORT): /* current-input-port */
          s_return(sc,sc->inport);

     CASE(OP_CURR_OUTPORT): /* current-output-port */
          s_return(sc,sc->outport);

     CASE(OP_OPEN_INFILE): /* open-input-file */
     CASE(OP_OPEN_OUTFILE): /* open-output-file */
     CASE(OP_OPEN_INOUTFILE): /* open-input-output-file */ {
          int prop=0;
          pointer p;
          switch(op) {
               case OP_OPEN_INFILE:     prop=port_input; break;
               case OP_OPEN_OUTFILE:    prop=port_output; break;
               case OP_OPEN_INOUTFILE: prop=port_input|port_output; break;
               default: assert (! "reached");
          }
          p=port_from_filename(sc,strvalue(car(sc->args)),prop);
          if(p==sc->NIL) {
               s_return(sc,sc->F);
          }
          s_return(sc,p);
	  break;
     }

#if USE_STRING_PORTS
     CASE(OP_OPEN_INSTRING): /* open-input-string */
     CASE(OP_OPEN_INOUTSTRING): /* open-input-output-string */ {
          int prop=0;
          pointer p;
          switch(op) {
               case OP_OPEN_INSTRING:     prop=port_input; break;
               case OP_OPEN_INOUTSTRING:  prop=port_input|port_output; break;
               default: assert (! "reached");
          }
          p=port_from_string(sc, strvalue(car(sc->args)),
                 strvalue(car(sc->args))+strlength(car(sc->args)), prop);
          if(p==sc->NIL) {
               s_return(sc,sc->F);
          }
          s_return(sc,p);
     }
     CASE(OP_OPEN_OUTSTRING): /* open-output-string */ {
          pointer p;
          if(car(sc->args)==sc->NIL) {
               p=port_from_scratch(sc);
               if(p==sc->NIL) {
                    s_return(sc,sc->F);
               }
          } else {
               p=port_from_string(sc, strvalue(car(sc->args)),
                      strvalue(car(sc->args))+strlength(car(sc->args)),
                          port_output);
               if(p==sc->NIL) {
                    s_return(sc,sc->F);
               }
          }
          s_return(sc,p);
     }
     CASE(OP_GET_OUTSTRING): /* get-output-string */ {
          port *p;

          if ((p=car(sc->args)->_object._port)->kind&port_string) {
	       gc_disable(sc, 1);
	       s_return_enable_gc(
		    sc,
		    mk_counted_string(sc,
				      p->rep.string.start,
				      p->rep.string.curr - p->rep.string.start));
          }
          s_return(sc,sc->F);
     }
#endif

     CASE(OP_CLOSE_INPORT): /* close-input-port */
          port_close(sc,car(sc->args),port_input);
          s_return(sc,sc->T);

     CASE(OP_CLOSE_OUTPORT): /* close-output-port */
          port_close(sc,car(sc->args),port_output);
          s_return(sc,sc->T);

     CASE(OP_INT_ENV): /* interaction-environment */
          s_return(sc,sc->global_env);

     CASE(OP_CURR_ENV): /* current-environment */
          s_return(sc,sc->envir);


     /* ========== reading part ========== */
     CASE(OP_READ):
          if(!is_pair(sc->args)) {
               s_thread_to(sc,OP_READ_INTERNAL);
          }
          if(!is_inport(car(sc->args))) {
               Error_1(sc, "read: not an input port", car(sc->args));
          }
          if(car(sc->args)==sc->inport) {
               s_thread_to(sc,OP_READ_INTERNAL);
          }
          x=sc->inport;
          sc->inport=car(sc->args);
          x=cons(sc,x,sc->NIL);
          s_save(sc,OP_SET_INPORT, x, sc->NIL);
          s_thread_to(sc,OP_READ_INTERNAL);

     CASE(OP_READ_CHAR): /* read-char */
     CASE(OP_PEEK_CHAR): /* peek-char */ {
          int c;
          if(is_pair(sc->args)) {
               if(car(sc->args)!=sc->inport) {
                    x=sc->inport;
                    x=cons(sc,x,sc->NIL);
                    s_save(sc,OP_SET_INPORT, x, sc->NIL);
                    sc->inport=car(sc->args);
               }
          }
          c=inchar(sc);
          if(c==EOF) {
               s_return(sc,sc->EOF_OBJ);
          }
          if(op==OP_PEEK_CHAR) {
               backchar(sc,c);
          }
          s_return(sc,mk_character(sc,c));
     }

     CASE(OP_CHAR_READY): /* char-ready? */ {
          pointer p=sc->inport;
          int res;
          if(is_pair(sc->args)) {
               p=car(sc->args);
          }
          res=p->_object._port->kind&port_string;
          s_retbool(res);
     }

     CASE(OP_SET_INPORT): /* set-input-port */
          sc->inport=car(sc->args);
          s_return(sc,sc->value);

     CASE(OP_SET_OUTPORT): /* set-output-port */
          sc->outport=car(sc->args);
          s_return(sc,sc->value);

     CASE(OP_RDSEXPR):
          switch (sc->tok) {
          case TOK_EOF:
               s_return(sc,sc->EOF_OBJ);
          /* NOTREACHED */
          case TOK_VEC:
               s_save(sc,OP_RDVEC,sc->NIL,sc->NIL);
               /* fall through */
          case TOK_LPAREN:
               sc->tok = token(sc);
               if (sc->tok == TOK_RPAREN) {
                    s_return(sc,sc->NIL);
               } else if (sc->tok == TOK_DOT) {
                    Error_0(sc,"syntax error: illegal dot expression");
               } else {
#if SHOW_ERROR_LINE
		    pointer filename;
		    pointer lineno;
#endif
                    sc->nesting_stack[sc->file_i]++;
#if SHOW_ERROR_LINE
		    filename = sc->load_stack[sc->file_i].filename;
		    lineno = sc->load_stack[sc->file_i].curr_line;

		    s_save(sc, OP_TAG_VALUE,
			   cons(sc, filename, cons(sc, lineno, sc->NIL)),
			   sc->NIL);
#endif
                    s_save(sc,OP_RDLIST, sc->NIL, sc->NIL);
                    s_thread_to(sc,OP_RDSEXPR);
               }
          case TOK_QUOTE:
               s_save(sc,OP_RDQUOTE, sc->NIL, sc->NIL);
               sc->tok = token(sc);
               s_thread_to(sc,OP_RDSEXPR);
          case TOK_BQUOTE:
               sc->tok = token(sc);
               if(sc->tok==TOK_VEC) {
                 s_save(sc,OP_RDQQUOTEVEC, sc->NIL, sc->NIL);
                 sc->tok=TOK_LPAREN;
                 s_thread_to(sc,OP_RDSEXPR);
               } else {
                 s_save(sc,OP_RDQQUOTE, sc->NIL, sc->NIL);
               }
               s_thread_to(sc,OP_RDSEXPR);
          case TOK_COMMA:
               s_save(sc,OP_RDUNQUOTE, sc->NIL, sc->NIL);
               sc->tok = token(sc);
               s_thread_to(sc,OP_RDSEXPR);
          case TOK_ATMARK:
               s_save(sc,OP_RDUQTSP, sc->NIL, sc->NIL);
               sc->tok = token(sc);
               s_thread_to(sc,OP_RDSEXPR);
          case TOK_ATOM:
               s_return(sc,mk_atom(sc, readstr_upto(sc, DELIMITERS)));
          case TOK_DQUOTE:
               x=readstrexp(sc);
               if(x==sc->F) {
                 Error_0(sc,"Error reading string");
               }
               setimmutable(x);
               s_return(sc,x);
          case TOK_SHARP: {
               pointer f=find_slot_in_env(sc,sc->envir,sc->SHARP_HOOK,1);
               if(f==sc->NIL) {
                    Error_0(sc,"undefined sharp expression");
               } else {
                    sc->code=cons(sc,slot_value_in_env(f),sc->NIL);
                    s_thread_to(sc,OP_EVAL);
               }
          }
          case TOK_SHARP_CONST:
               if ((x = mk_sharp_const(sc, readstr_upto(sc, DELIMITERS))) == sc->NIL) {
                    Error_0(sc,"undefined sharp expression");
               } else {
                    s_return(sc,x);
               }
          default:
               Error_0(sc,"syntax error: illegal token");
          }
          break;

     CASE(OP_RDLIST): {
	  gc_disable(sc, 1);
          sc->args = cons(sc, sc->value, sc->args);
	  gc_enable(sc);
          sc->tok = token(sc);
          if (sc->tok == TOK_EOF)
               { s_return(sc,sc->EOF_OBJ); }
          else if (sc->tok == TOK_RPAREN) {
               int c = inchar(sc);
               if (c != '\n')
                 backchar(sc,c);
	       else
		 port_increment_current_line(sc, &sc->load_stack[sc->file_i], 1);
               sc->nesting_stack[sc->file_i]--;
               s_return(sc,reverse_in_place(sc, sc->NIL, sc->args));
          } else if (sc->tok == TOK_DOT) {
               s_save(sc,OP_RDDOT, sc->args, sc->NIL);
               sc->tok = token(sc);
               s_thread_to(sc,OP_RDSEXPR);
          } else {
               s_save(sc,OP_RDLIST, sc->args, sc->NIL);;
               s_thread_to(sc,OP_RDSEXPR);
          }
     }

     CASE(OP_RDDOT):
          if (token(sc) != TOK_RPAREN) {
               Error_0(sc,"syntax error: illegal dot expression");
          } else {
               sc->nesting_stack[sc->file_i]--;
               s_return(sc,reverse_in_place(sc, sc->value, sc->args));
          }

     CASE(OP_RDQUOTE):
	  gc_disable(sc, 2);
          s_return_enable_gc(sc, cons(sc, sc->QUOTE,
				      cons(sc, sc->value, sc->NIL)));

     CASE(OP_RDQQUOTE):
	  gc_disable(sc, 2);
          s_return_enable_gc(sc, cons(sc, sc->QQUOTE,
				      cons(sc, sc->value, sc->NIL)));

     CASE(OP_RDQQUOTEVEC):
	  gc_disable(sc, 5 + 2 * gc_reservations (mk_symbol));
	  s_return_enable_gc(sc,cons(sc, mk_symbol(sc,"apply"),
           cons(sc, mk_symbol(sc,"vector"),
                 cons(sc,cons(sc, sc->QQUOTE,
                  cons(sc,sc->value,sc->NIL)),
                  sc->NIL))));

     CASE(OP_RDUNQUOTE):
	  gc_disable(sc, 2);
          s_return_enable_gc(sc, cons(sc, sc->UNQUOTE,
				      cons(sc, sc->value, sc->NIL)));

     CASE(OP_RDUQTSP):
	  gc_disable(sc, 2);
          s_return_enable_gc(sc, cons(sc, sc->UNQUOTESP,
				      cons(sc, sc->value, sc->NIL)));

     CASE(OP_RDVEC):
          /*sc->code=cons(sc,mk_proc(sc,OP_VECTOR),sc->value);
          s_thread_to(sc,OP_EVAL); Cannot be quoted*/
          /*x=cons(sc,mk_proc(sc,OP_VECTOR),sc->value);
          s_return(sc,x); Cannot be part of pairs*/
          /*sc->code=mk_proc(sc,OP_VECTOR);
          sc->args=sc->value;
          s_thread_to(sc,OP_APPLY);*/
          sc->args=sc->value;
          s_thread_to(sc,OP_VECTOR);

     /* ========== printing part ========== */
     CASE(OP_P0LIST):
          if(is_vector(sc->args)) {
               putstr(sc,"#(");
               sc->args=cons(sc,sc->args,mk_integer(sc,0));
               s_thread_to(sc,OP_PVECFROM);
          } else if(is_environment(sc->args)) {
               putstr(sc,"#<ENVIRONMENT>");
               s_return(sc,sc->T);
          } else if (!is_pair(sc->args)) {
               printatom(sc, sc->args, sc->print_flag);
               s_return(sc,sc->T);
          } else if (car(sc->args) == sc->QUOTE && ok_abbrev(cdr(sc->args))) {
               putstr(sc, "'");
               sc->args = cadr(sc->args);
               s_thread_to(sc,OP_P0LIST);
          } else if (car(sc->args) == sc->QQUOTE && ok_abbrev(cdr(sc->args))) {
               putstr(sc, "`");
               sc->args = cadr(sc->args);
               s_thread_to(sc,OP_P0LIST);
          } else if (car(sc->args) == sc->UNQUOTE && ok_abbrev(cdr(sc->args))) {
               putstr(sc, ",");
               sc->args = cadr(sc->args);
               s_thread_to(sc,OP_P0LIST);
          } else if (car(sc->args) == sc->UNQUOTESP && ok_abbrev(cdr(sc->args))) {
               putstr(sc, ",@");
               sc->args = cadr(sc->args);
               s_thread_to(sc,OP_P0LIST);
          } else {
               putstr(sc, "(");
               s_save(sc,OP_P1LIST, cdr(sc->args), sc->NIL);
               sc->args = car(sc->args);
               s_thread_to(sc,OP_P0LIST);
          }

     CASE(OP_P1LIST):
          if (is_pair(sc->args)) {
            s_save(sc,OP_P1LIST, cdr(sc->args), sc->NIL);
            putstr(sc, " ");
            sc->args = car(sc->args);
            s_thread_to(sc,OP_P0LIST);
          } else if(is_vector(sc->args)) {
            s_save(sc,OP_P1LIST,sc->NIL,sc->NIL);
            putstr(sc, " . ");
            s_thread_to(sc,OP_P0LIST);
          } else {
            if (sc->args != sc->NIL) {
              putstr(sc, " . ");
              printatom(sc, sc->args, sc->print_flag);
            }
            putstr(sc, ")");
            s_return(sc,sc->T);
          }
     CASE(OP_PVECFROM): {
          int i=ivalue_unchecked(cdr(sc->args));
          pointer vec=car(sc->args);
          int len = vector_length(vec);
          if(i==len) {
               putstr(sc,")");
               s_return(sc,sc->T);
          } else {
               pointer elem=vector_elem(vec,i);
               cdr(sc->args) = mk_integer(sc, i + 1);
               s_save(sc,OP_PVECFROM, sc->args, sc->NIL);
               sc->args=elem;
               if (i > 0)
                   putstr(sc," ");
               s_thread_to(sc,OP_P0LIST);
          }
     }

     CASE(OP_LIST_LENGTH): {   /* length */   /* a.k */
	  long l = list_length(sc, car(sc->args));
          if(l<0) {
               Error_1(sc, "length: not a list", car(sc->args));
          }
	  gc_disable(sc, 1);
          s_return_enable_gc(sc, mk_integer(sc, l));
     }
     CASE(OP_ASSQ):       /* assq */     /* a.k */
          x = car(sc->args);
          for (y = cadr(sc->args); is_pair(y); y = cdr(y)) {
               if (!is_pair(car(y))) {
                    Error_0(sc,"unable to handle non pair element");
               }
               if (x == caar(y))
                    break;
          }
          if (is_pair(y)) {
               s_return(sc,car(y));
          } else {
               s_return(sc,sc->F);
          }


     CASE(OP_GET_CLOSURE):     /* get-closure-code */   /* a.k */
          sc->args = car(sc->args);
          if (sc->args == sc->NIL) {
               s_return(sc,sc->F);
          } else if (is_closure(sc->args)) {
	       gc_disable(sc, 1);
               s_return_enable_gc(sc, cons(sc, sc->LAMBDA,
					   closure_code(sc->value)));
          } else if (is_macro(sc->args)) {
	       gc_disable(sc, 1);
               s_return_enable_gc(sc, cons(sc, sc->LAMBDA,
					   closure_code(sc->value)));
          } else {
               s_return(sc,sc->F);
          }
     CASE(OP_CLOSUREP):        /* closure? */
          /*
           * Note, macro object is also a closure.
           * Therefore, (closure? <#MACRO>) ==> #t
           */
          s_retbool(is_closure(car(sc->args)));
     CASE(OP_MACROP):          /* macro? */
          s_retbool(is_macro(car(sc->args)));
     CASE(OP_VM_HISTORY):          /* *vm-history* */
          s_return(sc, history_flatten(sc));
     default:
          snprintf(sc->strbuff,STRBUFFSIZE,"%d: illegal operator", op);
          Error_0(sc,sc->strbuff);
     }
  }
}

typedef int (*test_predicate)(pointer);

static int is_any(pointer p) {
   (void)p;
   return 1;
}

static int is_nonneg(pointer p) {
  return ivalue(p)>=0 && is_integer(p);
}

/* Correspond carefully with following defines! */
static const struct {
  test_predicate fct;
  const char *kind;
} tests[]={
  {0,0}, /* unused */
  {is_any, 0},
  {is_string, "string"},
  {is_symbol, "symbol"},
  {is_port, "port"},
  {is_inport,"input port"},
  {is_outport,"output port"},
  {is_environment, "environment"},
  {is_pair, "pair"},
  {0, "pair or '()"},
  {is_character, "character"},
  {is_vector, "vector"},
  {is_number, "number"},
  {is_integer, "integer"},
  {is_nonneg, "non-negative integer"}
};

#define TST_NONE 0
#define TST_ANY "\001"
#define TST_STRING "\002"
#define TST_SYMBOL "\003"
#define TST_PORT "\004"
#define TST_INPORT "\005"
#define TST_OUTPORT "\006"
#define TST_ENVIRONMENT "\007"
#define TST_PAIR "\010"
#define TST_LIST "\011"
#define TST_CHAR "\012"
#define TST_VECTOR "\013"
#define TST_NUMBER "\014"
#define TST_INTEGER "\015"
#define TST_NATURAL "\016"

#define INF_ARG 0xff

static const struct op_code_info dispatch_table[]= {
#define _OP_DEF(A,B,C,D,OP) {{A},B,C,{D}},
#include "opdefines.h"
#undef _OP_DEF
  {{0},0,0,{0}},
};

static const char *procname(pointer x) {
 int n=procnum(x);
 const char *name=dispatch_table[n].name;
 if (name[0] == 0) {
     name="ILLEGAL!";
 }
 return name;
}

static int
check_arguments (scheme *sc, const struct op_code_info *pcd, char *msg, size_t msg_size)
{
  int ok = 1;
  int n = list_length(sc, sc->args);

  /* Check number of arguments */
  if (n < pcd->min_arity) {
    ok = 0;
    snprintf(msg, msg_size, "%s: needs%s %d argument(s)",
	     pcd->name,
	     pcd->min_arity == pcd->max_arity ? "" : " at least",
	     pcd->min_arity);
  }
  if (ok && n>pcd->max_arity) {
    ok = 0;
    snprintf(msg, msg_size, "%s: needs%s %d argument(s)",
	     pcd->name,
	     pcd->min_arity == pcd->max_arity ? "" : " at most",
	     pcd->max_arity);
  }
  if (ok) {
    if (pcd->arg_tests_encoding[0] != 0) {
      int i = 0;
      int j;
      const char *t = pcd->arg_tests_encoding;
      pointer arglist = sc->args;

      do {
	pointer arg = car(arglist);
	j = (int)t[0];
	if (j == TST_LIST[0]) {
	  if (arg != sc->NIL && !is_pair(arg)) break;
	} else {
	  if (!tests[j].fct(arg)) break;
	}

	if (t[1] != 0 && i < sizeof pcd->arg_tests_encoding) {
	  /* last test is replicated as necessary */
	  t++;
	}
	arglist = cdr(arglist);
	i++;
      } while (i < n);

      if (i < n) {
	ok = 0;
	snprintf(msg, msg_size, "%s: argument %d must be: %s, got: %s",
		 pcd->name,
		 i + 1,
		 tests[j].kind,
		 type_to_string(type(car(arglist))));
      }
    }
  }

  return ok;
}

/* ========== Initialization of internal keywords ========== */

/* Symbols representing syntax are tagged with (OP . '()).  */
static void assign_syntax(scheme *sc, enum scheme_opcodes op, char *name) {
     pointer x, y;
     pointer *slot;

     x = oblist_find_by_name(sc, name, &slot);
     assert (x == sc->NIL);

     x = immutable_cons(sc, mk_string(sc, name), sc->NIL);
     typeflag(x) = T_SYMBOL | T_SYNTAX;
     setimmutable(car(x));
     y = mk_tagged_value(sc, x, mk_integer(sc, op), sc->NIL);
     free_cell(sc, x);
     setimmutable(get_tag(sc, y));
     *slot = immutable_cons(sc, y, *slot);
}

/* Returns the opcode for the syntax represented by P.  */
static int syntaxnum(scheme *sc, pointer p) {
  int op = ivalue_unchecked(car(get_tag(sc, p)));
  assert (op < OP_MAXDEFINED);
  return op;
}

static void assign_proc(scheme *sc, enum scheme_opcodes op, const char *name) {
     pointer x, y;

     x = mk_symbol(sc, name);
     y = mk_proc(sc,op);
     new_slot_in_env(sc, x, y);
}

static pointer mk_proc(scheme *sc, enum scheme_opcodes op) {
     pointer y;

     y = get_cell(sc, sc->NIL, sc->NIL);
     typeflag(y) = (T_PROC | T_ATOM);
     ivalue_unchecked(y) = (long) op;
     set_num_integer(y);
     return y;
}

/* initialization of TinyScheme */
#if USE_INTERFACE
INTERFACE static pointer s_cons(scheme *sc, pointer a, pointer b) {
 return cons(sc,a,b);
}
INTERFACE static pointer s_immutable_cons(scheme *sc, pointer a, pointer b) {
 return immutable_cons(sc,a,b);
}

static const struct scheme_interface vtbl = {
  scheme_define,
  s_cons,
  s_immutable_cons,
  reserve_cells,
  mk_integer,
  mk_real,
  mk_symbol,
  gensym,
  mk_string,
  mk_counted_string,
  mk_character,
  mk_vector,
  mk_foreign_func,
  mk_foreign_object,
  get_foreign_object_vtable,
  get_foreign_object_data,
  putstr,
  putcharacter,

  is_string,
  string_value,
  is_number,
  nvalue,
  ivalue,
  rvalue,
  is_integer,
  is_real,
  is_character,
  charvalue,
  is_list,
  is_vector,
  list_length,
  ivalue,
  fill_vector,
  vector_elem,
  set_vector_elem,
  is_port,
  is_pair,
  pair_car,
  pair_cdr,
  set_car,
  set_cdr,

  is_symbol,
  symname,

  is_syntax,
  is_proc,
  is_foreign,
  syntaxname,
  is_closure,
  is_macro,
  closure_code,
  closure_env,

  is_continuation,
  is_promise,
  is_environment,
  is_immutable,
  setimmutable,

  scheme_load_file,
  scheme_load_string,
  port_from_file
};
#endif

scheme *scheme_init_new(void) {
  scheme *sc=(scheme*)malloc(sizeof(scheme));
  if(!scheme_init(sc)) {
    free(sc);
    return 0;
  } else {
    return sc;
  }
}

scheme *scheme_init_new_custom_alloc(func_alloc malloc, func_dealloc free) {
  scheme *sc=(scheme*)malloc(sizeof(scheme));
  if(!scheme_init_custom_alloc(sc,malloc,free)) {
    free(sc);
    return 0;
  } else {
    return sc;
  }
}


int scheme_init(scheme *sc) {
 return scheme_init_custom_alloc(sc,malloc,free);
}

int scheme_init_custom_alloc(scheme *sc, func_alloc malloc, func_dealloc free) {
  int i, n=sizeof(dispatch_table)/sizeof(dispatch_table[0]);
  pointer x;

#if USE_INTERFACE
  sc->vptr=&vtbl;
#endif
  sc->gensym_cnt=0;
  sc->malloc=malloc;
  sc->free=free;
  sc->sink = &sc->_sink;
  sc->NIL = &sc->_NIL;
  sc->T = &sc->_HASHT;
  sc->F = &sc->_HASHF;
  sc->EOF_OBJ=&sc->_EOF_OBJ;

  sc->free_cell = &sc->_NIL;
  sc->fcells = 0;
  sc->inhibit_gc = GC_ENABLED;
  sc->reserved_cells = 0;
#ifndef NDEBUG
  sc->reserved_lineno = 0;
#endif
  sc->no_memory=0;
  sc->inport=sc->NIL;
  sc->outport=sc->NIL;
  sc->save_inport=sc->NIL;
  sc->loadport=sc->NIL;
  sc->nesting=0;
  memset (sc->nesting_stack, 0, sizeof sc->nesting_stack);
  sc->interactive_repl=0;
  sc->strbuff = sc->malloc(STRBUFFSIZE);
  if (sc->strbuff == 0) {
     sc->no_memory=1;
     return 0;
  }
  sc->strbuff_size = STRBUFFSIZE;

  sc->cell_segments = NULL;
  if (alloc_cellseg(sc,FIRST_CELLSEGS) != FIRST_CELLSEGS) {
    sc->no_memory=1;
    return 0;
  }
  sc->gc_verbose = 0;
  dump_stack_initialize(sc);
  sc->code = sc->NIL;
  sc->tracing=0;
  sc->flags = 0;

  /* init sc->NIL */
  typeflag(sc->NIL) = (T_NIL | T_ATOM | MARK);
  car(sc->NIL) = cdr(sc->NIL) = sc->NIL;
  /* init T */
  typeflag(sc->T) = (T_BOOLEAN | T_ATOM | MARK);
  car(sc->T) = cdr(sc->T) = sc->T;
  /* init F */
  typeflag(sc->F) = (T_BOOLEAN | T_ATOM | MARK);
  car(sc->F) = cdr(sc->F) = sc->F;
  /* init EOF_OBJ */
  typeflag(sc->EOF_OBJ) = (T_EOF_OBJ | T_ATOM | MARK);
  car(sc->EOF_OBJ) = cdr(sc->EOF_OBJ) = sc->EOF_OBJ;
  /* init sink */
  typeflag(sc->sink) = (T_SINK | T_PAIR | MARK);
  car(sc->sink) = cdr(sc->sink) = sc->NIL;
  /* init c_nest */
  sc->c_nest = sc->NIL;

  sc->oblist = oblist_initial_value(sc);
  /* init global_env */
  new_frame_in_env(sc, sc->NIL);
  sc->global_env = sc->envir;
  /* init else */
  x = mk_symbol(sc,"else");
  new_slot_in_env(sc, x, sc->T);

  assign_syntax(sc, OP_LAMBDA, "lambda");
  assign_syntax(sc, OP_QUOTE, "quote");
  assign_syntax(sc, OP_DEF0, "define");
  assign_syntax(sc, OP_IF0, "if");
  assign_syntax(sc, OP_BEGIN, "begin");
  assign_syntax(sc, OP_SET0, "set!");
  assign_syntax(sc, OP_LET0, "let");
  assign_syntax(sc, OP_LET0AST, "let*");
  assign_syntax(sc, OP_LET0REC, "letrec");
  assign_syntax(sc, OP_COND0, "cond");
  assign_syntax(sc, OP_DELAY, "delay");
  assign_syntax(sc, OP_AND0, "and");
  assign_syntax(sc, OP_OR0, "or");
  assign_syntax(sc, OP_C0STREAM, "cons-stream");
  assign_syntax(sc, OP_MACRO0, "macro");
  assign_syntax(sc, OP_CASE0, "case");

  for(i=0; i<n; i++) {
    if (dispatch_table[i].name[0] != 0) {
      assign_proc(sc, (enum scheme_opcodes)i, dispatch_table[i].name);
    }
  }

  history_init(sc, 8, 8);

  /* initialization of global pointers to special symbols */
  sc->LAMBDA = mk_symbol(sc, "lambda");
  sc->QUOTE = mk_symbol(sc, "quote");
  sc->QQUOTE = mk_symbol(sc, "quasiquote");
  sc->UNQUOTE = mk_symbol(sc, "unquote");
  sc->UNQUOTESP = mk_symbol(sc, "unquote-splicing");
  sc->FEED_TO = mk_symbol(sc, "=>");
  sc->COLON_HOOK = mk_symbol(sc,"*colon-hook*");
  sc->ERROR_HOOK = mk_symbol(sc, "*error-hook*");
  sc->SHARP_HOOK = mk_symbol(sc, "*sharp-hook*");
#if USE_COMPILE_HOOK
  sc->COMPILE_HOOK = mk_symbol(sc, "*compile-hook*");
#endif

  return !sc->no_memory;
}

void scheme_set_input_port_file(scheme *sc, FILE *fin) {
  sc->inport=port_from_file(sc,fin,port_input);
}

void scheme_set_input_port_string(scheme *sc, char *start, char *past_the_end) {
  sc->inport=port_from_string(sc,start,past_the_end,port_input);
}

void scheme_set_output_port_file(scheme *sc, FILE *fout) {
  sc->outport=port_from_file(sc,fout,port_output);
}

void scheme_set_output_port_string(scheme *sc, char *start, char *past_the_end) {
  sc->outport=port_from_string(sc,start,past_the_end,port_output);
}

void scheme_set_external_data(scheme *sc, void *p) {
 sc->ext_data=p;
}

void scheme_deinit(scheme *sc) {
  struct cell_segment *s;
  int i;

  sc->oblist=sc->NIL;
  sc->global_env=sc->NIL;
  dump_stack_free(sc);
  sc->envir=sc->NIL;
  sc->code=sc->NIL;
  history_free(sc);
  sc->args=sc->NIL;
  sc->value=sc->NIL;
  if(is_port(sc->inport)) {
    typeflag(sc->inport) = T_ATOM;
  }
  sc->inport=sc->NIL;
  sc->outport=sc->NIL;
  if(is_port(sc->save_inport)) {
    typeflag(sc->save_inport) = T_ATOM;
  }
  sc->save_inport=sc->NIL;
  if(is_port(sc->loadport)) {
    typeflag(sc->loadport) = T_ATOM;
  }
  sc->loadport=sc->NIL;

  for(i=0; i<=sc->file_i; i++) {
    port_clear_location(sc, &sc->load_stack[i]);
  }

  sc->gc_verbose=0;
  gc(sc,sc->NIL,sc->NIL);

  for (s = sc->cell_segments; s; s = _dealloc_cellseg(sc, s)) {
    /* nop */
  }
  sc->free(sc->strbuff);
}

void scheme_load_file(scheme *sc, FILE *fin)
{ scheme_load_named_file(sc,fin,0); }

void scheme_load_named_file(scheme *sc, FILE *fin, const char *filename) {
  dump_stack_reset(sc);
  sc->envir = sc->global_env;
  sc->file_i=0;
  sc->load_stack[0].kind=port_input|port_file;
  sc->load_stack[0].rep.stdio.file=fin;
  sc->loadport=mk_port(sc,sc->load_stack);
  sc->retcode=0;
  if(fin==stdin) {
    sc->interactive_repl=1;
  }

  port_init_location(sc, &sc->load_stack[0],
		     (fin != stdin && filename)
		     ? mk_string(sc, filename)
		     : NULL);

  sc->inport=sc->loadport;
  sc->args = mk_integer(sc,sc->file_i);
  Eval_Cycle(sc, OP_T0LVL);
  typeflag(sc->loadport)=T_ATOM;
  if(sc->retcode==0) {
    sc->retcode=sc->nesting!=0;
  }

  port_clear_location(sc, &sc->load_stack[0]);
}

void scheme_load_string(scheme *sc, const char *cmd) {
  scheme_load_memory(sc, cmd, strlen(cmd), NULL);
}

void scheme_load_memory(scheme *sc, const char *buf, size_t len, const char *filename) {
  dump_stack_reset(sc);
  sc->envir = sc->global_env;
  sc->file_i=0;
  sc->load_stack[0].kind=port_input|port_string;
  sc->load_stack[0].rep.string.start = (char *) buf; /* This func respects const */
  sc->load_stack[0].rep.string.past_the_end = (char *) buf + len;
  sc->load_stack[0].rep.string.curr = (char *) buf;
  port_init_location(sc, &sc->load_stack[0], filename ? mk_string(sc, filename) : NULL);
  sc->loadport=mk_port(sc,sc->load_stack);
  sc->retcode=0;
  sc->interactive_repl=0;
  sc->inport=sc->loadport;
  sc->args = mk_integer(sc,sc->file_i);
  Eval_Cycle(sc, OP_T0LVL);
  typeflag(sc->loadport)=T_ATOM;
  if(sc->retcode==0) {
    sc->retcode=sc->nesting!=0;
  }

  port_clear_location(sc, &sc->load_stack[0]);
}

void scheme_define(scheme *sc, pointer envir, pointer symbol, pointer value) {
     pointer x;
     pointer *sslot;
     x = find_slot_spec_in_env(sc, envir, symbol, 0, &sslot);
     if (x != sc->NIL) {
          set_slot_in_env(sc, x, value);
     } else {
          new_slot_spec_in_env(sc, symbol, value, sslot);
     }
}

#if !STANDALONE
void scheme_register_foreign_func(scheme * sc, scheme_registerable * sr)
{
  scheme_define(sc,
                sc->global_env,
                mk_symbol(sc,sr->name),
                mk_foreign_func(sc, sr->f));
}

void scheme_register_foreign_func_list(scheme * sc,
                                       scheme_registerable * list,
                                       int count)
{
  int i;
  for(i = 0; i < count; i++)
    {
      scheme_register_foreign_func(sc, list + i);
    }
}

pointer scheme_apply0(scheme *sc, const char *procname)
{ return scheme_eval(sc, cons(sc,mk_symbol(sc,procname),sc->NIL)); }

void save_from_C_call(scheme *sc)
{
  pointer saved_data =
    cons(sc,
         car(sc->sink),
         cons(sc,
              sc->envir,
              sc->dump));
  /* Push */
  sc->c_nest = cons(sc, saved_data, sc->c_nest);
  /* Truncate the dump stack so TS will return here when done, not
     directly resume pre-C-call operations. */
  dump_stack_reset(sc);
}
void restore_from_C_call(scheme *sc)
{
  car(sc->sink) = caar(sc->c_nest);
  sc->envir = cadar(sc->c_nest);
  sc->dump = cdr(cdar(sc->c_nest));
  /* Pop */
  sc->c_nest = cdr(sc->c_nest);
}

/* "func" and "args" are assumed to be already eval'ed. */
pointer scheme_call(scheme *sc, pointer func, pointer args)
{
  int old_repl = sc->interactive_repl;
  sc->interactive_repl = 0;
  save_from_C_call(sc);
  sc->envir = sc->global_env;
  sc->args = args;
  sc->code = func;
  sc->retcode = 0;
  Eval_Cycle(sc, OP_APPLY);
  sc->interactive_repl = old_repl;
  restore_from_C_call(sc);
  return sc->value;
}

pointer scheme_eval(scheme *sc, pointer obj)
{
  int old_repl = sc->interactive_repl;
  sc->interactive_repl = 0;
  save_from_C_call(sc);
  sc->args = sc->NIL;
  sc->code = obj;
  sc->retcode = 0;
  Eval_Cycle(sc, OP_EVAL);
  sc->interactive_repl = old_repl;
  restore_from_C_call(sc);
  return sc->value;
}


#endif

/* ========== Main ========== */

#if STANDALONE

#if defined(__APPLE__) && !defined (OSX)
int main()
{
     extern MacTS_main(int argc, char **argv);
     char**    argv;
     int argc = ccommand(&argv);
     MacTS_main(argc,argv);
     return 0;
}
int MacTS_main(int argc, char **argv) {
#else
int main(int argc, char **argv) {
#endif
  scheme sc;
  FILE *fin;
  char *file_name=InitFile;
  int retcode;
  int isfile=1;

  if(argc==1) {
    printf(banner);
  }
  if(argc==2 && strcmp(argv[1],"-?")==0) {
    printf("Usage: tinyscheme -?\n");
    printf("or:    tinyscheme [<file1> <file2> ...]\n");
    printf("followed by\n");
    printf("          -1 <file> [<arg1> <arg2> ...]\n");
    printf("          -c <Scheme commands> [<arg1> <arg2> ...]\n");
    printf("assuming that the executable is named tinyscheme.\n");
    printf("Use - as filename for stdin.\n");
    return 1;
  }
  if(!scheme_init(&sc)) {
    fprintf(stderr,"Could not initialize!\n");
    return 2;
  }
  scheme_set_input_port_file(&sc, stdin);
  scheme_set_output_port_file(&sc, stdout);
#if USE_DL
  scheme_define(&sc,sc.global_env,mk_symbol(&sc,"load-extension"),mk_foreign_func(&sc, scm_load_ext));
#endif
  argv++;
  if(access(file_name,0)!=0) {
    char *p=getenv("TINYSCHEMEINIT");
    if(p!=0) {
      file_name=p;
    }
  }
  do {
    if(strcmp(file_name,"-")==0) {
      fin=stdin;
    } else if(strcmp(file_name,"-1")==0 || strcmp(file_name,"-c")==0) {
      pointer args=sc.NIL;
      isfile=file_name[1]=='1';
      file_name=*argv++;
      if(strcmp(file_name,"-")==0) {
        fin=stdin;
      } else if(isfile) {
        fin=fopen(file_name,"r");
      }
      for(;*argv;argv++) {
        pointer value=mk_string(&sc,*argv);
        args=cons(&sc,value,args);
      }
      args=reverse_in_place(&sc,sc.NIL,args);
      scheme_define(&sc,sc.global_env,mk_symbol(&sc,"*args*"),args);

    } else {
      fin=fopen(file_name,"r");
    }
    if(isfile && fin==0) {
      fprintf(stderr,"Could not open file %s\n",file_name);
    } else {
      if(isfile) {
        scheme_load_named_file(&sc,fin,file_name);
      } else {
        scheme_load_string(&sc,file_name);
      }
      if(!isfile || fin!=stdin) {
        if(sc.retcode!=0) {
          fprintf(stderr,"Errors encountered reading %s\n",file_name);
        }
        if(isfile) {
          fclose(fin);
        }
      }
    }
    file_name=*argv++;
  } while(file_name!=0);
  if(argc==1) {
    scheme_load_named_file(&sc,stdin,0);
  }
  retcode=sc.retcode;
  scheme_deinit(&sc);

  return retcode;
}

#endif

/*
Local variables:
c-file-style: "k&r"
End:
*/
