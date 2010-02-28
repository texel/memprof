/* This is a public domain general purpose hash table package written by Peter Moore @ UCB. */

/* static	char	sccsid[] = "@(#) st.c 5.1 89/12/14 Crucible"; */

#include "config.h"
#include "defines.h"
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>
#include "memprof_st.h"

typedef struct mp_table_entry mp_table_entry;

struct mp_table_entry {
    unsigned int hash;
    mp_data_t key;
    mp_data_t record;
    mp_table_entry *next;
};

#define MP_DEFAULT_MAX_DENSITY 5
#define MP_DEFAULT_INIT_TABLE_SIZE 11

    /*
     * DEFAULT_MAX_DENSITY is the default for the largest we allow the
     * average number of items per bin before increasing the number of
     * bins
     *
     * DEFAULT_INIT_TABLE_SIZE is the default for the number of bins
     * allocated initially
     *
     */
static int numcmp(long, long);
static int numhash(long);
static struct mp_hash_type type_numhash = {
    numcmp,
    numhash,
};

/* extern int strcmp(const char *, const char *); */
static int strhash(const char *);
static struct mp_hash_type type_strhash = {
    strcmp,
    strhash,
};

static void rehash(mp_table *);

#define alloc(type) (type*)malloc((unsigned)sizeof(type))
#define Calloc(n,s) (char*)calloc((n),(s))

#define EQUAL(table,x,y) ((x)==(y) || (*table->type->compare)((x),(y)) == 0)

#define do_hash(key,table) (unsigned int)(*(table)->type->hash)((key))
#define do_hash_bin(key,table) (do_hash(key, table)%(table)->num_bins)

/*
 * MINSIZE is the minimum size of a dictionary.
 */

#define MINSIZE 8

/*
Table of prime numbers 2^n+a, 2<=n<=30.
*/
static long primes[] = {
	8 + 3,
	16 + 3,
	32 + 5,
	64 + 3,
	128 + 3,
	256 + 27,
	512 + 9,
	1024 + 9,
	2048 + 5,
	4096 + 3,
	8192 + 27,
	16384 + 43,
	32768 + 3,
	65536 + 45,
	131072 + 29,
	262144 + 3,
	524288 + 21,
	1048576 + 7,
	2097152 + 17,
	4194304 + 15,
	8388608 + 9,
	16777216 + 43,
	33554432 + 35,
	67108864 + 15,
	134217728 + 29,
	268435456 + 3,
	536870912 + 11,
	1073741824 + 85,
	0
};

static int
new_size(size)
    int size;
{
    int i;

#if 0
    for (i=3; i<31; i++) {
	if ((1<<i) > size) return 1<<i;
    }
    return -1;
#else
    int newsize;

    for (i = 0, newsize = MINSIZE;
	 i < sizeof(primes)/sizeof(primes[0]);
	 i++, newsize <<= 1)
    {
	if (newsize > size) return primes[i];
    }
    /* Ran out of polynomials */
    return -1;			/* should raise exception */
#endif
}

#ifdef HASH_LOG
static int collision = 0;
static int init_mp = 0;

static void
stat_col()
{
    FILE *f = fopen("/tmp/col", "w");
    fprintf(f, "collision: %d\n", collision);
    fclose(f);
}
#endif

#define MAX_FREELIST 10000

mp_table_entry*
get_new_entry(mp_table *table) {
  mp_table_entry *ret;

  if (table->freelist) {
    ret = table->freelist;
    table->freelist = table->freelist->next;
    table->freelist_entries--;
  } else {
    ret = alloc(mp_table_entry);
  }

  return ret;
}

void
free_entry(mp_table *table, mp_table_entry *entry) {
  if (table->freelist_entries >= MAX_FREELIST) {
    free(entry);
    return;
  }

  entry->next = table->freelist;
  table->freelist = entry;
  table->freelist_entries++;
}

mp_table*
mp_init_table_with_size(type, size)
    struct mp_hash_type *type;
    int size;
{
    mp_table *tbl;

#ifdef HASH_LOG
    if (init_mp == 0) {
	init_mp = 1;
	atexit(stat_col);
    }
#endif

    size = new_size(size);	/* round up to prime number */

    tbl = alloc(mp_table);
    tbl->type = type;
    tbl->num_entries = 0;
    tbl->num_bins = size;
    tbl->bins = (mp_table_entry **)Calloc(size, sizeof(mp_table_entry*));
    tbl->freelist = NULL;
    tbl->freelist_entries = 0;

    return tbl;
}

mp_table*
mp_init_table(type)
    struct mp_hash_type *type;
{
    return mp_init_table_with_size(type, 0);
}

mp_table*
mp_init_numtable(void)
{
    return mp_init_table(&type_numhash);
}

mp_table*
mp_init_numtable_with_size(size)
    int size;
{
    return mp_init_table_with_size(&type_numhash, size);
}

mp_table*
mp_init_strtable(void)
{
    return mp_init_table(&type_strhash);
}

mp_table*
mp_init_strtable_with_size(size)
    int size;
{
    return mp_init_table_with_size(&type_strhash, size);
}

void
mp_free_table(table)
    mp_table *table;
{
    register mp_table_entry *ptr, *next;
    int i;

    for(i = 0; i < table->num_bins; i++) {
	ptr = table->bins[i];
	while (ptr != 0) {
	    next = ptr->next;
	    free(ptr);
	    ptr = next;
	}
    }

    ptr = table->freelist;

    while (ptr != 0) {
	    next = ptr->next;
	    free(ptr);
	    ptr = next;
    }

    free(table->bins);
    free(table);
}

#define PTR_NOT_EQUAL(table, ptr, hash_val, key) \
((ptr) != 0 && (ptr->hash != (hash_val) || !EQUAL((table), (key), (ptr)->key)))

#ifdef HASH_LOG
#define COLLISION collision++
#else
#define COLLISION
#endif

#define FIND_ENTRY(table, ptr, hash_val, bin_pos) do {\
    bin_pos = hash_val%(table)->num_bins;\
    ptr = (table)->bins[bin_pos];\
    if (PTR_NOT_EQUAL(table, ptr, hash_val, key)) {\
	COLLISION;\
	while (PTR_NOT_EQUAL(table, ptr->next, hash_val, key)) {\
	    ptr = ptr->next;\
	}\
	ptr = ptr->next;\
    }\
} while (0)

int
mp_lookup(table, key, value)
    mp_table *table;
    register mp_data_t key;
    mp_data_t *value;
{
    unsigned int hash_val, bin_pos;
    register mp_table_entry *ptr;

    hash_val = do_hash(key, table);
    FIND_ENTRY(table, ptr, hash_val, bin_pos);

    if (ptr == 0) {
	return 0;
    }
    else {
	if (value != 0)  *value = ptr->record;
	return 1;
    }
}

#define ADD_DIRECT(table, key, value, hash_val, bin_pos)\
do {\
    mp_table_entry *entry;\
    if (table->num_entries/(table->num_bins) > MP_DEFAULT_MAX_DENSITY) {\
	rehash(table);\
        bin_pos = hash_val % table->num_bins;\
    }\
    \
    entry = get_new_entry(table);\
    \
    entry->hash = hash_val;\
    entry->key = key;\
    entry->record = value;\
    entry->next = table->bins[bin_pos];\
    table->bins[bin_pos] = entry;\
    table->num_entries++;\
} while (0)

int
mp_insert(table, key, value)
    register mp_table *table;
    register mp_data_t key;
    mp_data_t value;
{
    unsigned int hash_val, bin_pos;
    register mp_table_entry *ptr;

    hash_val = do_hash(key, table);
    FIND_ENTRY(table, ptr, hash_val, bin_pos);

    if (ptr == 0) {
	ADD_DIRECT(table, key, value, hash_val, bin_pos);
	return 0;
    }
    else {
	ptr->record = value;
	return 1;
    }
}

void
mp_add_direct(table, key, value)
    mp_table *table;
    mp_data_t key;
    mp_data_t value;
{
    unsigned int hash_val, bin_pos;

    hash_val = do_hash(key, table);
    bin_pos = hash_val % table->num_bins;
    ADD_DIRECT(table, key, value, hash_val, bin_pos);
}

static void
rehash(table)
    register mp_table *table;
{
    register mp_table_entry *ptr, *next, **new_bins;
    int i, old_num_bins = table->num_bins, new_num_bins;
    unsigned int hash_val;

    new_num_bins = new_size(old_num_bins+1);
    new_bins = (mp_table_entry**)Calloc(new_num_bins, sizeof(mp_table_entry*));

    for(i = 0; i < old_num_bins; i++) {
	ptr = table->bins[i];
	while (ptr != 0) {
	    next = ptr->next;
	    hash_val = ptr->hash % new_num_bins;
	    ptr->next = new_bins[hash_val];
	    new_bins[hash_val] = ptr;
	    ptr = next;
	}
    }
    free(table->bins);
    table->num_bins = new_num_bins;
    table->bins = new_bins;
}

mp_table*
mp_copy(old_table)
    mp_table *old_table;
{
    mp_table *new_table;
    mp_table_entry *ptr, *entry;
    int i, num_bins = old_table->num_bins;

    new_table = alloc(mp_table);
    if (new_table == 0) {
	return 0;
    }

    *new_table = *old_table;
    new_table->bins = (mp_table_entry**)
	Calloc((unsigned)num_bins, sizeof(mp_table_entry*));

    if (new_table->bins == 0) {
	free(new_table);
	return 0;
    }

    for(i = 0; i < num_bins; i++) {
	new_table->bins[i] = 0;
	ptr = old_table->bins[i];
	while (ptr != 0) {
	    entry = alloc(mp_table_entry);
	    if (entry == 0) {
		free(new_table->bins);
		free(new_table);
		return 0;
	    }
	    *entry = *ptr;
	    entry->next = new_table->bins[i];
	    new_table->bins[i] = entry;
	    ptr = ptr->next;
	}
    }
    return new_table;
}

int
mp_delete(table, key, value)
    register mp_table *table;
    register mp_data_t *key;
    mp_data_t *value;
{
    unsigned int hash_val;
    mp_table_entry *tmp;
    register mp_table_entry *ptr;

    hash_val = do_hash_bin(*key, table);
    ptr = table->bins[hash_val];

    if (ptr == 0) {
	if (value != 0) *value = 0;
	return 0;
    }

    if (EQUAL(table, *key, ptr->key)) {
	table->bins[hash_val] = ptr->next;
	table->num_entries--;
	if (value != 0) *value = ptr->record;
	*key = ptr->key;
	free_entry(table, ptr);
	return 1;
    }

    for(; ptr->next != 0; ptr = ptr->next) {
	if (EQUAL(table, ptr->next->key, *key)) {
	    tmp = ptr->next;
	    ptr->next = ptr->next->next;
	    table->num_entries--;
	    if (value != 0) *value = tmp->record;
	    *key = tmp->key;
	    free_entry(table, tmp);
	    return 1;
	}
    }

    return 0;
}

int
mp_delete_safe(table, key, value, never)
    register mp_table *table;
    register mp_data_t *key;
    mp_data_t *value;
    mp_data_t never;
{
    unsigned int hash_val;
    register mp_table_entry *ptr;

    hash_val = do_hash_bin(*key, table);
    ptr = table->bins[hash_val];

    if (ptr == 0) {
	if (value != 0) *value = 0;
	return 0;
    }

    for(; ptr != 0; ptr = ptr->next) {
	if ((ptr->key != never) && EQUAL(table, ptr->key, *key)) {
	    table->num_entries--;
	    *key = ptr->key;
	    if (value != 0) *value = ptr->record;
	    ptr->key = ptr->record = never;
	    return 1;
	}
    }

    return 0;
}

static int
delete_never(key, value, never)
    mp_data_t key, value, never;
{
    if (value == never) return MP_DELETE;
    return MP_CONTINUE;
}

void
mp_cleanup_safe(table, never)
    mp_table *table;
    mp_data_t never;
{
    int num_entries = table->num_entries;

    mp_foreach(table, delete_never, never);
    table->num_entries = num_entries;
}

int
mp_foreach(table, func, arg)
    mp_table *table;
    int (*func)();
    mp_data_t arg;
{
    mp_table_entry *ptr, *last, *tmp;
    enum mp_retval retval;
    int i;

    for(i = 0; i < table->num_bins; i++) {
	last = 0;
	for(ptr = table->bins[i]; ptr != 0;) {
	    retval = (*func)(ptr->key, ptr->record, arg);
	    switch (retval) {
	    case MP_CHECK:	/* check if hash is modified during iteration */
	        tmp = 0;
		if (i < table->num_bins) {
		    for (tmp = table->bins[i]; tmp; tmp=tmp->next) {
			if (tmp == ptr) break;
		    }
		}
		if (!tmp) {
		    /* call func with error notice */
		    return 1;
		}
		/* fall through */
	    case MP_CONTINUE:
		last = ptr;
		ptr = ptr->next;
		break;
	    case MP_STOP:
	        return 0;
	    case MP_DELETE:
		tmp = ptr;
		if (last == 0) {
		    table->bins[i] = ptr->next;
		}
		else {
		    last->next = ptr->next;
		}
		ptr = ptr->next;
		free_entry(table, tmp);
		table->num_entries--;
	    }
	}
    }
    return 0;
}

static int
strhash(string)
    register const char *string;
{
    register int c;

#ifdef HASH_ELFHASH
    register unsigned int h = 0, g;

    while ((c = *string++) != '\0') {
	h = ( h << 4 ) + c;
	if ( g = h & 0xF0000000 )
	    h ^= g >> 24;
	h &= ~g;
    }
    return h;
#elif defined(HASH_PERL)
    register int val = 0;

    while ((c = *string++) != '\0') {
	val += c;
	val += (val << 10);
	val ^= (val >> 6);
    }
    val += (val << 3);
    val ^= (val >> 11);

    return val + (val << 15);
#else
    register int val = 0;

    while ((c = *string++) != '\0') {
	val = val*997 + c;
    }

    return val + (val>>5);
#endif
}

static int
numcmp(x, y)
    long x, y;
{
    return x != y;
}

static int
numhash(n)
    long n;
{
    return n;
}
