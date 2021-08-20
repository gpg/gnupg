/* recsel.c - Record selection
 * Copyright (C) 2014, 2016 Werner Koch
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "util.h"
#include "recsel.h"

/* Select operators.  */
typedef enum
  {
    SELECT_SAME,
    SELECT_SUB,
    SELECT_NONEMPTY,
    SELECT_ISTRUE,
    SELECT_EQ, /* Numerically equal.  */
    SELECT_LE,
    SELECT_GE,
    SELECT_LT,
    SELECT_GT,
    SELECT_STRLE, /* String is less or equal.  */
    SELECT_STRGE,
    SELECT_STRLT,
    SELECT_STRGT
  } select_op_t;


/* Definition for a select expression.  */
struct recsel_expr_s
{
  recsel_expr_t next;
  select_op_t op;       /* Operation code.  */
  unsigned int not:1;   /* Negate operators. */
  unsigned int disjun:1;/* Start of a disjunction.  */
  unsigned int xcase:1; /* String match is case sensitive.  */
  const char *value;    /* (Points into NAME.)  */
  long numvalue;        /* strtol of VALUE.  */
  char name[1];         /* Name of the property.  */
};


/* Helper */
static inline gpg_error_t
my_error_from_syserror (void)
{
  return gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
}

/* Helper */
static inline gpg_error_t
my_error (gpg_err_code_t ec)
{
  return gpg_err_make (default_errsource, ec);
}


/* This is a case-sensitive version of our memistr.  I wonder why no
 * standard function memstr exists but I better do not use the name
 * memstr to avoid future conflicts.
 *
 * FIXME: Move this to a stringhelp.c
 */
static const char *
my_memstr (const void *buffer, size_t buflen, const char *sub)
{
  const unsigned char *buf = buffer;
  const unsigned char *t = (const unsigned char *)buf;
  const unsigned char *s = (const unsigned char *)sub;
  size_t n = buflen;

  for ( ; n ; t++, n-- )
    {
      if (*t == *s)
        {
          for (buf = t++, buflen = n--, s++; n && *t ==*s; t++, s++, n--)
            ;
          if (!*s)
            return (const char*)buf;
          t = (const unsigned char *)buf;
          s = (const unsigned char *)sub ;
          n = buflen;
	}
    }
  return NULL;
}


/* Return a pointer to the next logical connection operator or NULL if
 * none.  */
static char *
find_next_lc (char *string)
{
  char *p1, *p2;

  p1 = strchr (string, '&');
  if (p1 && p1[1] != '&')
    p1 = NULL;
  p2 = strchr (string, '|');
  if (p2 && p2[1] != '|')
    p2 = NULL;
  if (p1 && !p2)
    return p1;
  if (!p1)
    return p2;
  return p1 < p2 ? p1 : p2;
}


/* Parse an expression.  The expression syntax is:
 *
 *   [<lc>] {{<flag>} PROPNAME <op> VALUE [<lc>]}
 *
 * A [] indicates an optional part, a {} a repetition.  PROPNAME and
 * VALUE may not be the empty string.  White space between the
 * elements is ignored.  Numerical values are computed as long int;
 * standard C notation applies.  <lc> is the logical connection
 * operator; either "&&" for a conjunction or "||" for a disjunction.
 * A conjunction is assumed at the begin of an expression and
 * conjunctions have higher precedence than disjunctions.  If VALUE
 * starts with one of the characters used in any <op> a space after
 * the <op> is required.  A VALUE is terminated by an <lc> unless the
 * "--" <flag> is used in which case the VALUE spans to the end of the
 * expression.  <op> may be any of
 *
 *   =~  Substring must match
 *   !~  Substring must not match
 *   =   The full string must match
 *   <>  The full string must not match
 *   ==  The numerical value must match
 *   !=  The numerical value must not match
 *   <=  The numerical value of the field must be LE than the value.
 *   <   The numerical value of the field must be LT than the value.
 *   >=  The numerical value of the field must be GT than the value.
 *   >=  The numerical value of the field must be GE than the value.
 *   -n  True if value is not empty (no VALUE parameter allowed).
 *   -z  True if value is empty (no VALUE parameter allowed).
 *   -t  Alias for "PROPNAME != 0" (no VALUE parameter allowed).
 *   -f  Alias for "PROPNAME == 0" (no VALUE parameter allowed).
 *
 * Values for <flag> must be space separated and any of:
 *
 *   --  VALUE spans to the end of the expression.
 *   -c  The string match in this part is done case-sensitive.
 *   -t  Do not trim leading and trailing spaces from VALUE.
 *       Note that a space after <op> is here required.
 *
 * For example four calls to recsel_parse_expr() with these values for
 * EXPR
 *
 *  "uid =~ Alfa"
 *  "&& uid !~ Test"
 *  "|| uid =~ Alpha"
 *  "uid !~ Test"
 *
 * or the equivalent expression
 *
 *  "uid =~ Alfa" && uid !~ Test" || uid =~ Alpha" && "uid !~ Test"
 *
 * are making a selector for records where the "uid" property contains
 * the strings "Alfa" or "Alpha" but not the String "test".
 *
 * The caller must pass the address of a selector variable to this
 * function and initialize the value of the function to NULL before
 * the first call.  recset_release needs to be called to free the
 * selector.
 */
gpg_error_t
recsel_parse_expr (recsel_expr_t *selector, const char *expression)
{
  recsel_expr_t se_head = NULL;
  recsel_expr_t se, se2;
  char *expr_buffer;
  char *expr;
  char *s0, *s;
  int toend = 0;
  int xcase = 0;
  int notrim = 0;
  int disjun = 0;
  char *next_lc = NULL;

  while (*expression == ' ' || *expression == '\t')
    expression++;

  expr_buffer = xtrystrdup (expression);
  if (!expr_buffer)
    return my_error_from_syserror ();
  expr = expr_buffer;

  if (*expr == '|' && expr[1] == '|')
    {
      disjun = 1;
      expr += 2;
    }
  else if (*expr == '&' && expr[1] == '&')
    expr += 2;

 next_term:
  while (*expr == ' ' || *expr == '\t')
    expr++;

  while (*expr == '-')
    {
      switch (*++expr)
        {
        case '-': toend = 1; break;
        case 'c': xcase = 1; break;
        case 't': notrim = 1; break;
        default:
          log_error ("invalid flag '-%c' in expression\n", *expr);
          recsel_release (se_head);
          xfree (expr_buffer);
          return my_error (GPG_ERR_INV_FLAG);
        }
      expr++;
      while (*expr == ' ' || *expr == '\t')
        expr++;
    }

  next_lc = toend? NULL : find_next_lc (expr);
  if (next_lc)
    *next_lc = 0;  /* Terminate this term.  */

  se = xtrymalloc (sizeof *se + strlen (expr));
  if (!se)
    return my_error_from_syserror ();
  strcpy (se->name, expr);
  se->next = NULL;
  se->not = 0;
  se->disjun = disjun;
  se->xcase = xcase;

  if (!se_head)
    se_head = se;
  else
    {
      for (se2 = se_head; se2->next; se2 = se2->next)
        ;
      se2->next = se;
    }


  s = strpbrk (expr, "=<>!~-");
  if (!s || s == expr )
    {
      log_error ("no field name given in expression\n");
      recsel_release (se_head);
      xfree (expr_buffer);
      return my_error (GPG_ERR_NO_NAME);
    }
  s0 = s;

  if (!strncmp (s, "=~", 2))
    {
      se->op = SELECT_SUB;
      s += 2;
    }
  else if (!strncmp (s, "!~", 2))
    {
      se->op = SELECT_SUB;
      se->not = 1;
      s += 2;
    }
  else if (!strncmp (s, "<>", 2))
    {
      se->op = SELECT_SAME;
      se->not = 1;
      s += 2;
    }
  else if (!strncmp (s, "==", 2))
    {
      se->op = SELECT_EQ;
      s += 2;
    }
  else if (!strncmp (s, "!=", 2))
    {
      se->op = SELECT_EQ;
      se->not = 1;
      s += 2;
    }
  else if (!strncmp (s, "<=", 2))
    {
      se->op = SELECT_LE;
      s += 2;
    }
  else if (!strncmp (s, ">=", 2))
    {
      se->op = SELECT_GE;
      s += 2;
    }
  else if (!strncmp (s, "<", 1))
    {
      se->op = SELECT_LT;
      s += 1;
    }
  else if (!strncmp (s, ">", 1))
    {
      se->op = SELECT_GT;
      s += 1;
    }
  else if (!strncmp (s, "=", 1))
    {
      se->op = SELECT_SAME;
      s += 1;
    }
  else if (!strncmp (s, "-z", 2))
    {
      se->op = SELECT_NONEMPTY;
      se->not = 1;
      s += 2;
    }
  else if (!strncmp (s, "-n", 2))
    {
      se->op = SELECT_NONEMPTY;
      s += 2;
    }
  else if (!strncmp (s, "-f", 2))
    {
      se->op = SELECT_ISTRUE;
      se->not = 1;
      s += 2;
    }
  else if (!strncmp (s, "-t", 2))
    {
      se->op = SELECT_ISTRUE;
      s += 2;
    }
  else if (!strncmp (s, "-le", 3))
    {
      se->op = SELECT_STRLE;
      s += 3;
    }
  else if (!strncmp (s, "-ge", 3))
    {
      se->op = SELECT_STRGE;
      s += 3;
    }
  else if (!strncmp (s, "-lt", 3))
    {
      se->op = SELECT_STRLT;
      s += 3;
    }
  else if (!strncmp (s, "-gt", 3))
    {
      se->op = SELECT_STRGT;
      s += 3;
    }
  else
    {
      log_error ("invalid operator in expression\n");
      recsel_release (se_head);
      xfree (expr_buffer);
      return my_error (GPG_ERR_INV_OP);
    }

  /* We require that a space is used if the value starts with any of
     the operator characters.  */
  if (se->op == SELECT_NONEMPTY || se->op == SELECT_ISTRUE)
    ;
  else if (strchr ("=<>!~", *s))
    {
      log_error ("invalid operator in expression\n");
      recsel_release (se_head);
      xfree (expr_buffer);
      return my_error (GPG_ERR_INV_OP);
    }

  if (*s == ' ' || *s == '\t')
    s++;
  if (!notrim)
    while (*s == ' ' || *s == '\t')
      s++;

  if (se->op == SELECT_NONEMPTY || se->op == SELECT_ISTRUE)
    {
      if (*s)
        {
          log_error ("value given for -n or -z\n");
          recsel_release (se_head);
          xfree (expr_buffer);
          return my_error (GPG_ERR_SYNTAX);
        }
    }
  else
    {
      if (!*s)
        {
          log_error ("no value given in expression\n");
          recsel_release (se_head);
          xfree (expr_buffer);
          return my_error (GPG_ERR_MISSING_VALUE);
        }
    }

  se->name[s0 - expr] = 0;
  trim_spaces (se->name);
  if (!se->name[0])
    {
      log_error ("no field name given in expression\n");
      recsel_release (se_head);
      xfree (expr_buffer);
      return my_error (GPG_ERR_NO_NAME);
    }

  if (!notrim)
    trim_spaces (se->name + (s - expr));
  se->value = se->name + (s - expr);
  if (!se->value[0] && !(se->op == SELECT_NONEMPTY || se->op == SELECT_ISTRUE))
    {
      log_error ("no value given in expression\n");
      recsel_release (se_head);
      xfree (expr_buffer);
      return my_error (GPG_ERR_MISSING_VALUE);
    }

  se->numvalue = strtol (se->value, NULL, 0);

  if (next_lc)
    {
      disjun = next_lc[1] == '|';
      expr = next_lc + 2;
      goto next_term;
    }

  /* Read:y Append to passes last selector.  */
  if (!*selector)
    *selector = se_head;
  else
    {
      for (se2 = *selector; se2->next; se2 = se2->next)
        ;
      se2->next = se_head;
    }

  xfree (expr_buffer);
  return 0;
}


void
recsel_release (recsel_expr_t a)
{
  while (a)
    {
      recsel_expr_t tmp = a->next;
      xfree (a);
      a = tmp;
    }
}


void
recsel_dump (recsel_expr_t selector)
{
  recsel_expr_t se;

  log_debug ("--- Begin selectors ---\n");
  for (se = selector; se; se = se->next)
    {
      log_debug ("%s %s %s %s '%s'\n",
                 se==selector? "  ": (se->disjun? "||":"&&"),
                 se->xcase?  "-c":"  ",
                 se->name,
                 se->op == SELECT_SAME?    (se->not? "<>":"= "):
                 se->op == SELECT_SUB?     (se->not? "!~":"=~"):
                 se->op == SELECT_NONEMPTY?(se->not? "-z":"-n"):
                 se->op == SELECT_ISTRUE?  (se->not? "-f":"-t"):
                 se->op == SELECT_EQ?      (se->not? "!=":"=="):
                 se->op == SELECT_LT?      "< ":
                 se->op == SELECT_LE?      "<=":
                 se->op == SELECT_GT?      "> ":
                 se->op == SELECT_GE?      ">=":
                 se->op == SELECT_STRLT?   "-lt":
                 se->op == SELECT_STRLE?   "-le":
                 se->op == SELECT_STRGT?   "-gt":
                 se->op == SELECT_STRGE?   "-ge":
                 /**/                      "[oops]",
                 se->value);
    }
  log_debug ("--- End selectors ---\n");
}


/* Return true if the record RECORD has been selected.  The GETVAL
 * function is called with COOKIE and the NAME of a property used in
 * the expression.  */
int
recsel_select (recsel_expr_t selector,
               const char *(*getval)(void *cookie, const char *propname),
               void *cookie)
{
  recsel_expr_t se;
  const char *value;
  size_t selen, valuelen;
  long numvalue;
  int result = 1;

  se = selector;
  while (se)
    {
      value = getval? getval (cookie, se->name) : NULL;
      if (!value)
        value = "";

      if (!*value)
        {
          /* Field is empty.  */
          result = 0;
        }
      else /* Field has a value.  */
        {
          valuelen = strlen (value);
          numvalue = strtol (value, NULL, 0);
          selen = strlen (se->value);

          switch (se->op)
            {
            case SELECT_SAME:
              if (se->xcase)
                result = (valuelen==selen && !memcmp (value,se->value,selen));
              else
                result = (valuelen==selen && !memicmp (value,se->value,selen));
              break;
            case SELECT_SUB:
              if (se->xcase)
                result = !!my_memstr (value, valuelen, se->value);
              else
                result = !!memistr (value, valuelen, se->value);
              break;
            case SELECT_NONEMPTY:
              result = !!valuelen;
              break;
            case SELECT_ISTRUE:
              result = !!numvalue;
              break;
            case SELECT_EQ:
              result = (numvalue == se->numvalue);
              break;
            case SELECT_GT:
              result = (numvalue > se->numvalue);
              break;
            case SELECT_GE:
              result = (numvalue >= se->numvalue);
              break;
            case SELECT_LT:
              result = (numvalue < se->numvalue);
              break;
            case SELECT_LE:
              result = (numvalue <= se->numvalue);
              break;
            case SELECT_STRGT:
              if (se->xcase)
                result = strcmp (value, se->value) > 0;
              else
                result = strcasecmp (value, se->value) > 0;
              break;
            case SELECT_STRGE:
              if (se->xcase)
                result = strcmp (value, se->value) >= 0;
              else
                result = strcasecmp (value, se->value) >= 0;
              break;
            case SELECT_STRLT:
              if (se->xcase)
                result = strcmp (value, se->value) < 0;
              else
                result = strcasecmp (value, se->value) < 0;
              break;
            case SELECT_STRLE:
              if (se->xcase)
                result = strcmp (value, se->value) <= 0;
              else
                result = strcasecmp (value, se->value) <= 0;
              break;
            }
        }

      if (se->not)
        result = !result;

      if (result)
        {
          /* This expression evaluated to true.  See whether there are
             remaining expressions in this conjunction.  */
          if (!se->next || se->next->disjun)
            break; /* All expressions are true.  Return True.  */
          se = se->next;  /* Test the next.  */
        }
      else
        {
          /* This expression evaluated to false and thus the
           * conjunction evaluates to false.  We skip over the
           * remaining expressions of this conjunction and continue
           * with the next disjunction if any.  */
          do
            se = se->next;
          while (se && !se->disjun);
        }
    }

  return result;
}
