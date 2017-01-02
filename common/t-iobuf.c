#include <config.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "iobuf.h"
#include "stringhelp.h"

/* Return every other byte.  In particular, reads two bytes, returns
   the second one.  */
static int
every_other_filter (void *opaque, int control,
		    iobuf_t chain, byte *buf, size_t *len)
{
  (void) opaque;

  if (control == IOBUFCTRL_DESC)
    {
      mem2str (buf, "every_other_filter", *len);
    }
  if (control == IOBUFCTRL_UNDERFLOW)
    {
      int c = iobuf_readbyte (chain);
      int c2;
      if (c == -1)
	c2 = -1;
      else
	c2 = iobuf_readbyte (chain);

      /* printf ("Discarding %d (%c); return %d (%c)\n", c, c, c2, c2); */

      if (c2 == -1)
	{
	  *len = 0;
	  return -1;
	}

      *buf = c2;
      *len = 1;

      return 0;
    }

  return 0;
}

static int
double_filter (void *opaque, int control,
	       iobuf_t chain, byte *buf, size_t *len)
{
  (void) opaque;

  if (control == IOBUFCTRL_DESC)
    {
      mem2str (buf, "double_filter", *len);
    }
  if (control == IOBUFCTRL_FLUSH)
    {
      int i;

      for (i = 0; i < *len; i ++)
	{
	  int rc;

	  rc = iobuf_writebyte (chain, buf[i]);
	  if (rc)
	    return rc;
	  rc = iobuf_writebyte (chain, buf[i]);
	  if (rc)
	    return rc;
	}
    }

  return 0;
}

struct content_filter_state
{
  int pos;
  int len;
  const char *buffer;
};

static struct content_filter_state *
content_filter_new (const char *buffer)
{
  struct content_filter_state *state
    = malloc (sizeof (struct content_filter_state));

  state->pos = 0;
  state->len = strlen (buffer);
  state->buffer = buffer;

  return state;
}

static int
content_filter (void *opaque, int control,
		iobuf_t chain, byte *buf, size_t *len)
{
  struct content_filter_state *state = opaque;

  (void) chain;

  if (control == IOBUFCTRL_UNDERFLOW)
    {
      int remaining = state->len - state->pos;
      int toread = *len;
      assert (toread > 0);

      if (toread > remaining)
	toread = remaining;

      memcpy (buf, &state->buffer[state->pos], toread);

      state->pos += toread;

      *len = toread;

      if (toread == 0)
	return -1;
      return 0;
    }

  return 0;
}

int
main (int argc, char *argv[])
{
  (void) argc;
  (void) argv;

  /* A simple test to make sure filters work.  We use a static buffer
     and then add a filter in front of it that returns every other
     character.  */
  {
    char *content = "0123456789abcdefghijklm";
    iobuf_t iobuf;
    int c;
    int n;
    int rc;

    iobuf = iobuf_temp_with_content (content, strlen (content));
    rc = iobuf_push_filter (iobuf, every_other_filter, NULL);
    assert (rc == 0);

    n = 0;
    while ((c = iobuf_readbyte (iobuf)) != -1)
      {
	/* printf ("%d: %c\n", n + 1, (char) c); */
	assert (content[2 * n + 1] == c);
	n ++;
      }
    /* printf ("Got EOF after reading %d bytes (content: %d)\n", */
    /*         n, strlen (content)); */
    assert (n == strlen (content) / 2);

    iobuf_close (iobuf);
  }

  /* A simple test to check buffering.  Make sure that when we add a
     filter to a pipeline, any buffered data gets processed by the */
  {
    char *content = "0123456789abcdefghijklm";
    iobuf_t iobuf;
    int c;
    int n;
    int rc;
    int i;

    iobuf = iobuf_temp_with_content (content, strlen (content));

    n = 0;
    for (i = 0; i < 10; i ++)
      {
	c = iobuf_readbyte (iobuf);
	assert (content[i] == c);
	n ++;
      }

    rc = iobuf_push_filter (iobuf, every_other_filter, NULL);
    assert (rc == 0);

    while ((c = iobuf_readbyte (iobuf)) != -1)
      {
	/* printf ("%d: %c\n", n + 1, (char) c); */
	assert (content[2 * (n - 5) + 1] == c);
	n ++;
      }
    assert (n == 10 + (strlen (content) - 10) / 2);

    iobuf_close (iobuf);
  }


  /* A simple test to check that iobuf_read_line works.  */
  {
    /* - 3 characters plus new line
       - 4 characters plus new line
       - 5 characters plus new line
       - 5 characters, no new line
     */
    char *content = "abc\ndefg\nhijkl\nmnopq";
    iobuf_t iobuf;
    byte *buffer;
    unsigned size;
    unsigned max_len;
    int n;

    iobuf = iobuf_temp_with_content (content, strlen(content));

    /* We read a line with 3 characters plus a newline.  If we
       allocate a buffer that is 5 bytes long, then no reallocation
       should be required.  */
    size = 5;
    buffer = malloc (size);
    assert (buffer);
    max_len = 100;
    n = iobuf_read_line (iobuf, &buffer, &size, &max_len);
    assert (n == 4);
    assert (strcmp (buffer, "abc\n") == 0);
    assert (size == 5);
    assert (max_len == 100);
    free (buffer);

    /* We now read a line with 4 characters plus a newline.  This
       requires 6 bytes of storage.  We pass a buffer that is 5 bytes
       large and we allow the buffer to be grown.  */
    size = 5;
    buffer = malloc (size);
    max_len = 100;
    n = iobuf_read_line (iobuf, &buffer, &size, &max_len);
    assert (n == 5);
    assert (strcmp (buffer, "defg\n") == 0);
    assert (size >= 6);
    /* The string shouldn't have been truncated (max_len == 0).  */
    assert (max_len == 100);
    free (buffer);

    /* We now read a line with 5 characters plus a newline.  This
       requires 7 bytes of storage.  We pass a buffer that is 5 bytes
       large and we don't allow the buffer to be grown.  */
    size = 5;
    buffer = malloc (size);
    max_len = 5;
    n = iobuf_read_line (iobuf, &buffer, &size, &max_len);
    assert (n == 4);
    /* Note: the string should still have a trailing \n.  */
    assert (strcmp (buffer, "hij\n") == 0);
    assert (size == 5);
    /* The string should have been truncated (max_len == 0).  */
    assert (max_len == 0);
    free (buffer);

    /* We now read a line with 6 characters without a newline.  This
       requires 7 bytes of storage.  We pass a NULL buffer and we
       don't allow the buffer to be grown larger than 5 bytes.  */
    size = 5;
    buffer = NULL;
    max_len = 5;
    n = iobuf_read_line (iobuf, &buffer, &size, &max_len);
    assert (n == 4);
    /* Note: the string should still have a trailing \n.  */
    assert (strcmp (buffer, "mno\n") == 0);
    assert (size == 5);
    /* The string should have been truncated (max_len == 0).  */
    assert (max_len == 0);
    free (buffer);

    iobuf_close (iobuf);
  }

  {
    /* - 10 characters, EOF
       - 17 characters, EOF
     */
    char *content = "abcdefghijklmnopq";
    char *content2 = "0123456789";
    iobuf_t iobuf;
    int rc;
    int c;
    int n;
    int lastc = 0;
    struct content_filter_state *state;

    iobuf = iobuf_temp_with_content (content, strlen(content));
    rc = iobuf_push_filter (iobuf,
			    content_filter,
                            state=content_filter_new (content2));
    assert (rc == 0);

    n = 0;
    while (1)
      {
	c = iobuf_readbyte (iobuf);
	if (c == -1 && lastc == -1)
	  {
	    /* printf("Two EOFs in a row.  Done.\n");  */
	    assert (n == 27);
	    break;
	  }

	lastc = c;

	if (c == -1)
	  {
	    /* printf("After %d bytes, got EOF.\n", n); */
	    assert (n == 10 || n == 27);
	  }
	else
	  {
	    n ++;
	    /* printf ("%d: '%c' (%d)\n", n, c, c); */
	  }
      }

    iobuf_close (iobuf);
    free (state);
  }

  /* Write some data to a temporary filter.  Push a new filter.  The
     already written data should not be processed by the new
     filter.  */
  {
    iobuf_t iobuf;
    int rc;
    char *content = "0123456789";
    char *content2 = "abc";
    char buffer[4096];
    int n;

    iobuf = iobuf_temp ();
    assert (iobuf);

    rc = iobuf_write (iobuf, content, strlen (content));
    assert (rc == 0);

    rc = iobuf_push_filter (iobuf, double_filter, NULL);
    assert (rc == 0);

    /* Include a NUL.  */
    rc = iobuf_write (iobuf, content2, strlen (content2) + 1);
    assert (rc == 0);

    n = iobuf_temp_to_buffer (iobuf, buffer, sizeof (buffer));
#if 0
    printf ("Got %d bytes\n", n);
    printf ("buffer: `");
    fwrite (buffer, n, 1, stdout);
    fputc ('\'', stdout);
    fputc ('\n', stdout);
#endif

    assert (n == strlen (content) + 2 * (strlen (content2) + 1));
    assert (strcmp (buffer, "0123456789aabbcc") == 0);

    iobuf_close (iobuf);
  }

  {
    iobuf_t iobuf;
    int rc;
    char content[] = "0123456789";
    int n;
    int c;
    char buffer[10];

    assert (sizeof buffer == sizeof content - 1);

    iobuf = iobuf_temp_with_content (content, strlen (content));
    assert (iobuf);

    rc = iobuf_push_filter (iobuf, every_other_filter, NULL);
    assert (rc == 0);
    rc = iobuf_push_filter (iobuf, every_other_filter, NULL);
    assert (rc == 0);

    for (n = 0; (c = iobuf_get (iobuf)) != -1; n ++)
      {
	/* printf ("%d: `%c'\n", n, c);  */
	buffer[n] = c;
      }

    assert (n == 2);
    assert (buffer[0] == '3');
    assert (buffer[1] == '7');

    iobuf_close (iobuf);
  }

  return 0;
}
