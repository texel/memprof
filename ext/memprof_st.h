/* This is a public domain general purpose hash table package written by Peter Moore @ UCB. */

/* @(#) st.h 5.1 89/12/14 */

#ifndef MP_INCLUDED

#define MP_INCLUDED

#if SIZEOF_LONG == SIZEOF_VOIDP
typedef unsigned long mp_data_t;
#elif SIZEOF_LONG_LONG == SIZEOF_VOIDP
typedef unsigned LONG_LONG mp_data_t;
#else
# error ---->> st.c requires sizeof(void*) == sizeof(long) to be compiled. <<---
-
#endif
#define MP_DATA_T_DEFINED

typedef struct mp_table mp_table;

struct mp_hash_type {
    int (*compare)();
    int (*hash)();
};

struct mp_table {
    struct mp_hash_type *type;
    int num_bins;
    int num_entries;
    struct mp_table_entry **bins;
    struct mp_table_entry *freelist;
    int freelist_entries;
};

#define mp_is_member(table,key) mp_lookup(table,key,(mp_data_t *)0)

enum mp_retval {MP_CONTINUE, MP_STOP, MP_DELETE, MP_CHECK};

#ifndef _
# define _(args) args
#endif
#ifndef ANYARGS
# ifdef __cplusplus
#   define ANYARGS ...
# else
#   define ANYARGS
# endif
#endif

mp_table *mp_init_table _((struct mp_hash_type *));
mp_table *mp_init_table_with_size _((struct mp_hash_type *, int));
mp_table *mp_init_numtable _((void));
mp_table *mp_init_numtable_with_size _((int));
mp_table *mp_init_strtable _((void));
mp_table *mp_init_strtable_with_size _((int));
int mp_delete _((mp_table *, mp_data_t *, mp_data_t *));
int mp_delete_safe _((mp_table *, mp_data_t *, mp_data_t *, mp_data_t));
int mp_insert _((mp_table *, mp_data_t, mp_data_t));
int mp_lookup _((mp_table *, mp_data_t, mp_data_t *));
int mp_foreach _((mp_table *, int (*)(ANYARGS), mp_data_t));
void mp_add_direct _((mp_table *, mp_data_t, mp_data_t));
void mp_free_table _((mp_table *));
void mp_cleanup_safe _((mp_table *, mp_data_t));
mp_table *mp_copy _((mp_table *));

#define MP_NUMCMP	((int (*)()) 0)
#define MP_NUMHASH	((int (*)()) -2)

#define mp_numcmp MP_NUMCMP
#define mp_numhash  MP_NUMHASH

int mp_strhash();

#endif /* MP_INCLUDED */
