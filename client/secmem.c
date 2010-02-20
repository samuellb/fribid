/*

  Copyright (c) 2010 Linus Walleij <triad@df.lth.se>
 
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:
  
  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.
  
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.

*/

#define _BSD_SOURCE 1
#include <stdbool.h>
#include <string.h>
#include <unistd.h> // For sysconf()
#include <sys/mman.h> // For mmap()/mlock() etc

#include "misc.h"
#include "secmem.h"

/*
 * This is a rather straight-forward secure memory
 * implementation, i.e. a way to retrieve a pointer to
 * some memory that will certainly NOT be swapped out
 * to disk when memory gets crowded. Feel free to expand
 * this by layering and entire sec_[malloc,realloc,free]
 * interface with some granularity over this.
 */
#define SECPAGES 2
static int pageindex[SECPAGES];
static long pagesize = 0;
static char *pool = NULL;
static long poolsize = 0;

/**
 * Initialize the secure memory pool, map and lock
 * it down
 * @return false on success, true means "error"
 */
bool secmem_init_pool(void)
{
    int err;
    int i;

    // Make sure we weren't called before
    if (pool)
        return true;

    // Find out what the size of a page is on this system
#ifdef _SC_PAGESIZE
    pagesize = sysconf(_SC_PAGESIZE);
#else
    #warning "Cannot determine page size for secure memory"
    pagesize = 4096;
#endif
    if (pagesize < 512)
        return true;

    poolsize = pagesize * SECPAGES;

    // Allocate a secure memory pool, mmap call explained
    // inline. We map something anonymous, for reading and
    // writing.
    pool = mmap (0, poolsize,
             PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS,
             -1, 0);
    if (pool == MAP_FAILED)
        return true;

    // Lock this pool from any swapping!
    err = mlock(pool, poolsize);
    if (err) {
        munmap(pool, poolsize);
        pool = NULL;
        return true;
    }

    // Mark all pages as free
    for (i = 0; i < SECPAGES; i++)
        pageindex[i] = 0;

    return false;
}

/**
 * Get a page of secure memory
 * @page_size: a pointer to a variable that will hold
 * the size of the returned page on successful return
 * @return: a pointer to the secure page or NULL on failure
 */
char *secmem_get_page(long *page_size)
{
    int i;

    *page_size = 0;
    if (!pool)
        return NULL;

    // Locate a free page
    i = 0;
    while (i < SECPAGES && pageindex[i] != 0)
        i++;
    // All pages taken
    if (i == SECPAGES)
        return NULL;
    // Take this page
    pageindex[i] = 1;
    *page_size = pagesize;
    // Return a pointer to it
    return pool + (pagesize * i);
}

/**
 * Free a page of secure memory
 * @page: page to be free:d, illegal page pointers will be ignored
 */
void secmem_free_page(char *page)
{
    int i;

    // Bogus pointers will not match and are ignored
    for (i = 0; i < SECPAGES; i++) {
        if (pool + (pagesize * i) == page) {
            pageindex[i] = 0;
            guaranteed_memset(page, 0, pagesize);
            break;
        }
    }
    return;
}

/**
 * Destroy the secure memory pool
 */
void secmem_destroy_pool(void)
{
    int i;

    if (!pool)
        return;
    for (i = 0; i < SECPAGES; i++)
        pageindex[i] = 0;
    guaranteed_memset(pool, 0, poolsize);
    munmap(pool, poolsize);
    poolsize = 0;
    pool = NULL;
}
