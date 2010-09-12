/*
  Memleak: Detects memory leaks in C or C++ programs
  Copyright (C) 2010 Ravi Sankar Guntur <ravi.g@samsung.com>
  Copyright (C) 2010 Prateek Mathur <prateek.m@samsung.com>
  
  Memleak is free software: you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation, either version 3
  of the License, or any later version.
 
  Memleak is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with Memleak.  If not, see <http://www.gnu.org/licenses/>.

*/ 

#define _GNU_SOURCE
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <error.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <execinfo.h>
#include <sys/syscall.h>
#include <sys/inotify.h>

#ifndef __DEBUG_ON
#define printf(format,...)
#warning No debug support...
#endif

#define __VERSION "0.4"

#define powerof2(x)	((((x)-1)&(x))==0)
#ifdef _SLP
#define __INOTIFY_PATH "/opt/memleak"
#define __MEMLEAKLOGFILE "/opt/memleak/memleak.log"
#define __SCENARIO_FILE1 "/opt/memleak/scenario_begin"
#define __SCENARIO_FILE2 "/opt/memleak/scenario_end"
#else // CWD to avoid sudo
#define __INOTIFY_PATH "./"
#define __MEMLEAKLOGFILE "memleak.log"
#define __SCENARIO_FILE1 "scenario_begin"
#define __SCENARIO_FILE2 "scenario_end"
#endif
#define __RSIGNATURE1__ 0xdeadbeaf
#define __RSIGNATURE2__ 0xabcdefff
#define __BT_SIZE 30
#define __HEADER_LEN__ 4 + 4 + 4 + 4 + __BT_SIZE*4	// size, sig1, sig2, nframes, bt frames
#define __SCENARIO_START_FILENAME "scenario_begin"
#define __SCENARIO_END_FILENAME "scenario_end"

static int fd;
static FILE *fp = NULL;
static char *caltime = NULL;
static void *heap_start, *heap_end;
static __thread int recursion = -1;	// tls
static char logfile_name[100];
extern char *program_invocation_name;
static int i_fd;
pthread_t inotify_thread = 0;
static int wd;
static int scenario_start = 0;
static int scenario_based = 0;
static int init_done = 0;
static int header_written = 0;
/*	doug lea's routines	*/
extern void *dlcalloc (size_t, size_t);
extern void *dlmalloc (size_t);
extern void dlfree (void *);
extern void *dlrealloc (void *, size_t);
extern void *dlmemalign (size_t, size_t);
extern void *dlvalloc (size_t);

__attribute__ ((constructor))
     void
     init (void);

__attribute__ ((destructor))
     void
     deinit (void);

/*
 *	Public functions
 */
/*	crooked malloc fucntions 	*/
     void *
     calloc (size_t, size_t);
     void *
     malloc (size_t);
     void
     free (void *);
     void *
     realloc (void *, size_t);
     void *
     memalign (size_t, size_t);
     void *
     valloc (size_t);


/*	wrappers to doug les's malloc allocators 	*/
     void *
     malloc (size_t size)
{
  int *ptr, *sigptr1, *sigptr2, *sizeptr, *nframesptr, *btptr, *usrptr;
  size_t alt_size = size + __HEADER_LEN__;	// for size and sig
  int nptrs, btloop = 0;
  void *buffer[__BT_SIZE];
  ptr = dlmalloc (alt_size);
  if (ptr == NULL)
    return NULL;
  sizeptr = ptr;
  sigptr1 = sizeptr + 1;
  sigptr2 = sigptr1 + 1;
  nframesptr = sigptr2 + 1;
  btptr = nframesptr + 1;
  usrptr = btptr + __BT_SIZE;
  memset (ptr, '\0', alt_size);	// clear the data
  *sizeptr = size;		// insert size move
  if ((!scenario_based || (scenario_based && scenario_start)) && init_done)
    {
      *sigptr1 = __RSIGNATURE1__;	// insert sig1
      *sigptr2 = __RSIGNATURE2__;	// insert sig2
    }

  recursion++;
  if (recursion == 0)
    {
      nptrs = backtrace (buffer, __BT_SIZE);
//      nptrs--; // skip libc_start_main()
      printf ("malloc: addr %p and sixe %d, nframes %d bt  is..", usrptr,
	      size, nptrs);
      if (nptrs < 4)
	{
	  buffer[0] = __builtin_return_address (0);
	  nptrs = 1;
	}
      *nframesptr = nptrs;	// insert number of frames for bt
      while (btloop < (nptrs))
	{
	  *btptr++ = (int) buffer[btloop];
	  printf ("%p, ", buffer[btloop]);
	  btloop++;
	}
      printf ("\n");
    }
  else
    {
      printf ("recursion: for block %p size %d\n", usrptr, size);
    }
  recursion--;
  return usrptr;
}


/*	wrappers to doug les's malloc allocators 	*/
void
free (void *ptr)
{
  int *sigptr1, *sigptr2, *sizeptr, *allocptr, *btptr, *nframesptr;
  size_t size;
  if (ptr)
    {
      btptr = (int *) (ptr) - __BT_SIZE;
      nframesptr = btptr - 1;
      sigptr2 = nframesptr - 1;
      sigptr1 = sigptr2 - 1;
      sizeptr = sigptr1 - 1;
      allocptr = sizeptr;
      size = *sizeptr;
//      if ((*sigptr1 == (int) __RSIGNATURE1__)
//          && (*sigptr2 == (int) __RSIGNATURE2__)) {

      /*      clear the contents so that we dont get accidental sigs  */
      printf ("free: addr %p, size %d, nframes %d\n", ptr, size, *nframesptr);
      memset (sizeptr, '\0', __HEADER_LEN__);
      dlfree (sizeptr);
/*	}
#ifdef __DEBUG_ON
	else {
	    pid_t pid = getpid();
	    if (fp) {
		fprintf(fp,"free-error: sig mismatch at %p\n", ptr);
	    }

	    else
		printf("free-error: sig mismatch at %p\n", ptr);
	}

       */
    }
}


/*	wrappers to doug les's malloc allocators 	*/
void *
realloc (void *ptr, size_t size)
{
  int *sigptr1, *sigptr2, *sizeptr, *newptr, *usrptr, *nframesptr, *btptr;
  int nptrs, btloop = 0;
  void *buffer[__BT_SIZE];
  size_t alt_size = size + __HEADER_LEN__;	// for size and sig

  /*      as per the manpages. the same order of checks were performed    */
  if (ptr == NULL)
    {
      usrptr = malloc (size);
      nframesptr = usrptr - (__BT_SIZE + 1);	// BT size + 1 = NFrames Ptr
      nptrs = *nframesptr;
      if (nptrs < 4)
	{
	  *nframesptr = 1;
	  nframesptr++;		// will become btptr
	  *nframesptr = (int) __builtin_return_address (0);
	}
      return usrptr;

    }

  if (size == 0)
    {
      free (ptr);
      return ptr;
    }

  btptr = (int *) (ptr) - __BT_SIZE;
  nframesptr = btptr - 1;
  sigptr2 = nframesptr - 1;
  sigptr1 = sigptr2 - 1;
  sizeptr = sigptr1 - 1;

  newptr = dlrealloc (sizeptr, alt_size);
  if (newptr == NULL)
    return newptr;

  sizeptr = newptr;
  sigptr1 = sizeptr + 1;
  sigptr2 = sigptr1 + 1;
  nframesptr = sigptr2 + 1;
  btptr = nframesptr + 1;
  usrptr = btptr + __BT_SIZE;

  *sizeptr = size;		// insert size move
  if ((!scenario_based || (scenario_based && scenario_start)) && init_done)
    {
      *sigptr1 = __RSIGNATURE1__;	// insert sig
      *sigptr2 = __RSIGNATURE2__;	// insert sig
    }
  recursion++;
  if (recursion == 0)
    {
      nptrs = backtrace (buffer, __BT_SIZE);	// calls malloc() sometimes....
//      nptrs--; //skip libc_start_main()
      if (nptrs < 4)
	{
	  buffer[0] = __builtin_return_address (0);
	  nptrs = 1;
	}
      *nframesptr = nptrs;	// insert number of frames for bt
      while (btloop < nptrs)
	{
	  *btptr++ = (int) buffer[btloop];	// insert bt frames
	  printf ("%p, ", buffer[btloop]);
	  btloop++;
	}
      printf ("\n");
    }
  else
    {
      printf ("recursion: for block %p size %d\n", usrptr, size);
    }
  recursion--;
  return usrptr;
}


/*	wrappers to doug les's malloc allocators 	*/
void *
calloc (size_t nmemb, size_t size)
{
  int *usrptr, *nframesptr;
  int nptrs;

  usrptr = dlcalloc (nmemb, size);
  nframesptr = usrptr - (__BT_SIZE + 1);	// BT size + 1 = NFrames Ptr
  nptrs = *nframesptr;
  if (nptrs < 4)
    {
      *nframesptr = 1;
      nframesptr++;		// will become btptr
      *nframesptr = (int) __builtin_return_address (0);
    }
  return usrptr;
}

void *
memalign (size_t boundary, size_t size)
{

  int *ptr, *sigptr1, *sigptr2, *sizeptr, *nframesptr, *btptr, *usrptr;
  size_t alt_size = size + __HEADER_LEN__;	// for size and sig
  //int nptrs, btloop = 0;
  //void *buffer[__BT_SIZE];
  ptr = dlmemalign (boundary, alt_size);
  if (ptr == NULL)
    return NULL;
  sizeptr = ptr;
  sigptr1 = sizeptr + 1;
  sigptr2 = sigptr1 + 1;
  nframesptr = sigptr2 + 1;
  btptr = nframesptr + 1;
  usrptr = btptr + __BT_SIZE;
  memset (ptr, '\0', alt_size);
  *sizeptr = size;
  if ((!scenario_based || (scenario_based && scenario_start)) && init_done)
    {
      *sigptr1 = __RSIGNATURE1__;
      *sigptr2 = __RSIGNATURE2__;
    }
/* Check for stuff */
  return usrptr;
}

void *
valloc (size_t size)
{
  size_t boundary = sysconf (_SC_PAGESIZE);
  return memalign (boundary, size);
}

/* We need a wrapper function for one of the additions of POSIX.  */
int
posix_memalign (void **memptr, size_t alignment, size_t size)
{
  void *mem;
  /* Test whether the SIZE argument is valid.  It must be a power of
   *        two multiple of sizeof (void *).  */
  if (alignment % sizeof (void *) != 0
      || !powerof2 (alignment / sizeof (void *)) != 0 || alignment == 0)
    return EINVAL;

  mem = memalign (alignment, size);
  if (mem != NULL)
    {
      *memptr = mem;
      return 0;
    }
  return ENOMEM;
}


/*	load libc, get libc string funciton addresses	*/
int
__init (void)
{
  sprintf (logfile_name, "%s.%d", __MEMLEAKLOGFILE, getpid ());

  fp = fopen (logfile_name, "a");
  if (NULL == fp)
    {
      perror ("log file fopen error: ");
      abort ();
    }
  fd = open (logfile_name, O_RDWR | O_APPEND);
  if (fd == -1)
    {
      perror ("log file open error: ");
      abort ();
    }
  return 0;
}

void
__deinit (void)
{
  int *cur, *usrptr;
  int size, nframes, total = 0;
  void *buffer;
  char maps[1025] = { 0, };
  char file_name[100] = { 0, };
  int procfd;

  heap_end = sbrk (0);
  cur = heap_start;
  if (!header_written)
    {
      fprintf (fp,
	       "==========================================================================\n");
      fprintf (fp,
	       "Memleak utility version %s. \n",  __VERSION);
      fprintf (fp, "Debugged Program is %s. debug mode is %s, Time %s\n",
	       program_invocation_name, scenario_based?"scenario":"full", caltime);
      fprintf (fp, "Memleak: heap region is %p to %p. scanned %d bytes\n",
	       heap_start, heap_end, ((int) heap_end - (int) heap_start));
      fprintf (fp,
	       "==========================================================================\n");
      header_written = 1;
    }



  while ((void *) cur < (heap_end - 4))
    {
      size = *cur;
      cur++;			// go to sig1 or next [4 byte aligned] addr
      if (*cur == (int) __RSIGNATURE1__)
	{
	  cur++;		// go to sig2
	  if (*cur == (int) __RSIGNATURE2__)
	    {
	      cur++;		// go to nframes pointer
	      nframes = *cur;	// get the nframes in bt
	      cur++;		// go to bt ptr
	      usrptr = cur + __BT_SIZE;
	      total += size;	// accumulate total leaked bytes 
	      fprintf (fp, "\nblock of %d bytes was not freed. (id: %p)\n",
		       size, usrptr);
	      fflush (fp);
	      buffer = cur;
	      if (fd != -1 && nframes)
		backtrace_symbols_fd ((void *const *) buffer, nframes, fd);

	      cur = cur + __BT_SIZE;	// skip the bt frames
	      cur = cur + (size / 4);	// go to end of the block
	    }

	  else
	    {
	      printf ("strange: only sig1 matched\n");
	    }
	}
    }
  fprintf (fp,
	   "\n==========================================================================\n");
  fprintf (fp, "Memleak: Total %d bytes were not freed\n", total);
  fprintf (fp,
	   "==========================================================================\n");
  if(total)  {
	fprintf (fp, "Process maps table...\n");
	fflush (fp);

  /*  copy maps file to user log      */
  sprintf (file_name, "/proc/%d/maps", getpid ());
  procfd = open (file_name, O_RDONLY);

  while (read (procfd, maps, 1024))
    write (fd, maps, 1024);

  close (procfd);		// proc file 
}
}

void
inotify_reader_thread ()
{
  char buf[1024];
  int i = 0, len = 0;
  struct inotify_event *event;

  while (1)
    {
      //read 1024  bytes of events from fd into buf
      i = 0;
      len = read (i_fd, buf, 1024);
#ifdef __DEBUG_ON
      fprintf (fp, "running inotify loop len is %d\n", len);
#endif
      while (i < len)
	{
	  event = (struct inotify_event *) &buf[i];
	  if (event->len)
	    {
	      if (event->mask & IN_CREATE)
		{
		  if (event->mask & IN_ISDIR)
		    {
		      printf ("The directory %s was created.\n", event->name);
		    }
		  else
		    {
		      if (strcmp (event->name, __SCENARIO_START_FILENAME) ==
			  0)
			{
#ifdef __DEBUG_ON
			  fprintf (fp, "scenario start set to 1\n");
#endif
			  scenario_start = 1;
			}
		      else if (strcmp (event->name, __SCENARIO_END_FILENAME)
			       == 0)
			{
#ifdef __DEBUG_ON
			  fprintf (fp, "scenario start set to 0\n");
#endif
			  remove (__SCENARIO_FILE1);
			  remove (__SCENARIO_FILE2);

			  if (scenario_start)
			    {
			      scenario_start = 0;
			      if (scenario_based)
				__deinit ();
			    }
			}
		      else
			{
			  printf ("Unknown File created\n");
			}
		    }
		}
	    }

	  i += sizeof (struct inotify_event) + event->len;
#ifdef __DEBUG_ON
	  fprintf (fp, "i is now %d\n", i);
#endif
	}
    }
}


int
create_inotify_thread ()
{
  i_fd = inotify_init ();
  if (i_fd < 0)
    {
      fprintf (fp, "inotify init error\n");
      perror ("inotify_init");
      return i_fd;
    }
  /* watch directory for any activity and report it back to me */
  wd = inotify_add_watch (i_fd, __INOTIFY_PATH, IN_CREATE);
  //Create thread for reading inotify events.
  pthread_create (&inotify_thread, NULL, (void *) inotify_reader_thread,
		  NULL);
  init_done = 1;
  return 1;
}

__attribute__ ((constructor))
     void init (void)
{
  time_t result;
  char *value = NULL;
  heap_start = sbrk (0);
  __init ();
  result = time (NULL);
  caltime = ctime (&result);
  value = getenv ("SCENARIO");
  if (strcmp (value, "--scenario-mode") == 0)
    {
      scenario_based = 1;
      create_inotify_thread ();
    }
  else
    {
      scenario_based = 0;
      init_done = 1;
    }
}

__attribute__ ((destructor))
     void deinit (void)
{
  if (!scenario_based)
    {
      __deinit ();
    }
/*	scenario based: inotify thread is running	*/
  else
    {
      pthread_cancel (inotify_thread);
      if (scenario_start)
	__deinit ();
      inotify_rm_watch (i_fd, wd);
      close (i_fd);
    }

  if (fp)
    {				// log file
      fflush (fp);
      fclose (fp);
    }
  close (fd);			// log file     
}
