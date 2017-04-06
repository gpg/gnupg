/* scheme-private.h */

#ifndef _SCHEME_PRIVATE_H
#define _SCHEME_PRIVATE_H

#include <stdint.h>
#include "scheme.h"
/*------------------ Ugly internals -----------------------------------*/
/*------------------ Of interest only to FFI users --------------------*/

#ifdef __cplusplus
extern "C" {
#endif

enum scheme_port_kind {
  port_free=0,
  port_file=1,
  port_string=2,
  port_srfi6=4,
  port_input=16,
  port_output=32,
  port_saw_EOF=64
};

typedef struct port {
  unsigned char kind;
  union {
    struct {
      FILE *file;
      int closeit;
    } stdio;
    struct {
      char *start;
      char *past_the_end;
      char *curr;
    } string;
  } rep;
#if SHOW_ERROR_LINE
  pointer curr_line;
  pointer filename;
#endif
} port;

/* cell structure */
struct cell {
  uintptr_t _flag;
  union {
    num _number;
    struct {
      char   *_svalue;
      int   _length;
    } _string;
    port *_port;
    foreign_func _ff;
    struct {
      struct cell *_car;
      struct cell *_cdr;
    } _cons;
    struct {
      size_t _length;
      pointer _elements[0];
    } _vector;
    struct {
         char *_data;
         const foreign_object_vtable *_vtable;
    } _foreign_object;
  } _object;
};

#if USE_HISTORY
/* The history is a two-dimensional ring buffer.  A donut-shaped data
 * structure.  This data structure is inspired by MIT/GNU Scheme.  */
struct history {
  /* Number of calls to store.  Must be a power of two.  */
  size_t N;

  /* Number of tail-calls to store in each call frame.  Must be a
   * power of two.  */
  size_t M;

  /* Masks for fast index calculations.  */
  size_t mask_N;
  size_t mask_M;

  /* A vector of size N containing calls.  */
  pointer callstack;

  /* A vector of size N containing vectors of size M containing tail
   * calls.  */
  pointer tailstacks;

  /* Our current position.  */
  size_t n;
  size_t *m;
};
#endif

struct scheme {
/* arrays for segments */
func_alloc malloc;
func_dealloc free;

/* return code */
int retcode;
int tracing;


#ifndef CELL_SEGSIZE
#define CELL_SEGSIZE    5000  /* # of cells in one segment */
#endif

/* If less than # of cells are recovered in a garbage collector run,
 * allocate a new cell segment to avoid fruitless collection cycles in
 * the near future.  */
#ifndef CELL_MINRECOVER
#define CELL_MINRECOVER    (CELL_SEGSIZE >> 2)
#endif
struct cell_segment *cell_segments;

/* We use 4 registers. */
pointer args;            /* register for arguments of function */
pointer envir;           /* stack register for current environment */
pointer code;            /* register for current code */
pointer dump;            /* stack register for next evaluation */
pointer frame_freelist;

#if USE_HISTORY
struct history history;  /* we keep track of the call history for
                          * error messages */
#endif

int interactive_repl;    /* are we in an interactive REPL? */

struct cell _sink;
pointer sink;            /* when mem. alloc. fails */
struct cell _NIL;
pointer NIL;             /* special cell representing empty cell */
struct cell _HASHT;
pointer T;               /* special cell representing #t */
struct cell _HASHF;
pointer F;               /* special cell representing #f */
struct cell _EOF_OBJ;
pointer EOF_OBJ;         /* special cell representing end-of-file object */
pointer oblist;          /* pointer to symbol table */
pointer global_env;      /* pointer to global environment */
pointer c_nest;          /* stack for nested calls from C */

/* global pointers to special symbols */
pointer LAMBDA;               /* pointer to syntax lambda */
pointer QUOTE;           /* pointer to syntax quote */

pointer QQUOTE;               /* pointer to symbol quasiquote */
pointer UNQUOTE;         /* pointer to symbol unquote */
pointer UNQUOTESP;       /* pointer to symbol unquote-splicing */
pointer FEED_TO;         /* => */
pointer COLON_HOOK;      /* *colon-hook* */
pointer ERROR_HOOK;      /* *error-hook* */
pointer SHARP_HOOK;  /* *sharp-hook* */
#if USE_COMPILE_HOOK
pointer COMPILE_HOOK;  /* *compile-hook* */
#endif

pointer free_cell;       /* pointer to top of free cells */
long    fcells;          /* # of free cells */
size_t  inhibit_gc;      /* nesting of gc_disable */
size_t  reserved_cells;  /* # of reserved cells */
#ifndef NDEBUG
int     reserved_lineno;   /* location of last reservation */
#endif

pointer inport;
pointer outport;
pointer save_inport;
pointer loadport;

#ifndef MAXFIL
#define MAXFIL 64
#endif
port load_stack[MAXFIL];     /* Stack of open files for port -1 (LOADing) */
int nesting_stack[MAXFIL];
int file_i;
int nesting;

char    gc_verbose;      /* if gc_verbose is not zero, print gc status */
char    no_memory;       /* Whether mem. alloc. has failed */

#ifndef LINESIZE
#define LINESIZE 1024
#endif
char    linebuff[LINESIZE];
#ifndef STRBUFFSIZE
#define STRBUFFSIZE 256
#endif
char    *strbuff;
size_t strbuff_size;
FILE *tmpfp;
int tok;
int print_flag;
pointer value;
unsigned int flags;

void *ext_data;     /* For the benefit of foreign functions */
long gensym_cnt;

const struct scheme_interface *vptr;
};

/* operator code */
enum scheme_opcodes {
#define _OP_DEF(A,B,C,D,OP) OP,
#include "opdefines.h"
  OP_MAXDEFINED
};


#define cons(sc,a,b) _cons(sc,a,b,0)
#define immutable_cons(sc,a,b) _cons(sc,a,b,1)

int is_string(pointer p);
char *string_value(pointer p);
int is_number(pointer p);
num nvalue(pointer p);
long ivalue(pointer p);
double rvalue(pointer p);
int is_integer(pointer p);
int is_real(pointer p);
int is_character(pointer p);
long charvalue(pointer p);
int is_vector(pointer p);

int is_port(pointer p);

int is_pair(pointer p);
pointer pair_car(pointer p);
pointer pair_cdr(pointer p);
pointer set_car(pointer p, pointer q);
pointer set_cdr(pointer p, pointer q);

int is_symbol(pointer p);
char *symname(pointer p);
int hasprop(pointer p);

int is_syntax(pointer p);
int is_proc(pointer p);
int is_foreign(pointer p);
char *syntaxname(pointer p);
int is_closure(pointer p);
#ifdef USE_MACRO
int is_macro(pointer p);
#endif
pointer closure_code(pointer p);
pointer closure_env(pointer p);

int is_continuation(pointer p);
int is_promise(pointer p);
int is_environment(pointer p);
int is_immutable(pointer p);
void setimmutable(pointer p);

int is_foreign_object(pointer p);
const foreign_object_vtable *get_foreign_object_vtable(pointer p);
void *get_foreign_object_data(pointer p);

#ifdef __cplusplus
}
#endif

#endif

/*
Local variables:
c-file-style: "k&r"
End:
*/
