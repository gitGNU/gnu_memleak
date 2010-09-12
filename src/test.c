/*
  Memleak: Detects memory leaks in C or C++ programs
  Copyright (C) 2010 Ravi Sankar Guntur <ravisankar.g@gmail.com>
  
  Memleak is free software: you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation, either version 3
  of the License, or any later version.
 
  Memleak is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with Foobar.  If not, see <http://www.gnu.org/licenses/>.

  This file is part of the test package of Memleak
*/

#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <stdlib.h>

static inline int
leaks_exe (void)
{
  int *msome1, *msome2, *msome3;
  int *cptr1, *cptr2, *cptr3;
  char *rptr1, *rptr2, *rptr3;

  cptr1 = calloc (28, sizeof (char));
  cptr2 = calloc (4, sizeof (int));
  cptr3 = calloc (1, sizeof (short));

  msome1 = malloc (6);
  msome2 = malloc (150);
  msome3 = malloc (40);

  rptr1 = malloc (110);
  rptr2 = realloc (rptr1, 100);
  rptr3 = realloc (rptr2, 1000);

  printf ("test: calloc ptr at %p, size %d*char\n", cptr1, 28);
  printf ("test: calloc ptr at %p, size %d*int\n", cptr2, 4);
  printf ("test: calloc ptr at %p, size %d*short\n", cptr3, 1);
  printf ("test: malloc ptr at %p, size %d\n", msome1, 6);
  printf ("test: malloc ptr at %p, size %d\n", msome2, 150);
  printf ("test: malloc ptr at %p, size %d\n", msome3, 40);
  printf ("test: realloc ptr at %p, size %d\n", rptr3, 1000);

  free (cptr1);
  cptr2 = realloc (cptr2, 0);
//      free(cptr2);
  free (cptr3);
  free (msome1);
  msome2 = realloc (msome2, 0);
//      free(msome2);
  free (msome3);
  free (rptr3);

  printf("test: start\n");	
  sleep(10);
  msome1 = malloc(123);
  free(msome1);
  msome1 = malloc(321);
  printf("test: stop\n");	
  sleep(10);
  return 0;
}

int
leaks (void)
{
  return leaks_exe ();

}

int
foo (void)
{
  return leaks ();
}

int
main (void)
{
  foo ();
  exit (0);
}
