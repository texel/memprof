#define _GNU_SOURCE
#include <err.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sysexits.h>
#include <sys/mman.h>
#include <err.h>

#include <st.h>
#include <ruby.h>
#include <intern.h>
#include <node.h>

#include "bin_api.h"

size_t pagesize;
void *text_segment = NULL;
unsigned long text_segment_len = 0;

/*
   trampoline specific stuff
 */
struct tramp_tbl_entry *tramp_table = NULL;
size_t tramp_size = 0;

/*
   inline trampoline specific stuff
 */
size_t inline_tramp_size = 0;
struct inline_tramp_tbl_entry *inline_tramp_table = NULL;

/*
 * bleak_house stuff
 */
static int track_objs = 0;
static st_table *objs = NULL;

struct obj_track {
  VALUE obj;
  char *source;
  int line;
};

static void
error_tramp()
{
  printf("WARNING: NO TRAMPOLINE SET.\n");
  return;
}

static VALUE
newobj_tramp()
{
  VALUE ret = rb_newobj();
  struct obj_track *tracker = NULL;

  if (track_objs) {
    tracker = malloc(sizeof(*tracker));

    if (tracker) {
      if (ruby_current_node && ruby_current_node->nd_file && *ruby_current_node->nd_file) {
        tracker->source = strdup(ruby_current_node->nd_file);
        tracker->line = nd_line(ruby_current_node);
      } else if (ruby_sourcefile) {
        tracker->source = strdup(ruby_sourcefile);
        tracker->line = ruby_sourceline;
      } else {
        tracker->source = strdup("__null__");
        tracker->line = 0;
      }

      tracker->obj = ret;
      st_insert(objs, (st_data_t)ret, (st_data_t)tracker);
    } else {
      fprintf(stderr, "Warning, unable to allocate a tracker. You are running dangerously low on RAM!\n");
    }
  }

  return ret;
}

static void
freelist_tramp(unsigned long rval)
{
  struct obj_track *tracker = NULL;

  if (track_objs) {
    st_delete(objs, (st_data_t *) &rval, (st_data_t *) &tracker);
    if (tracker) {
      free(tracker->source);
      free(tracker);
    }
  }
}

static int
objs_free(st_data_t key, st_data_t record, st_data_t arg)
{
  struct obj_track *tracker = (struct obj_track *)record;
  free(tracker->source);
  free(tracker);
  return ST_DELETE;
}

static int
objs_tabulate(st_data_t key, st_data_t record, st_data_t arg)
{
  st_table *table = (st_table *)arg;
  struct obj_track *tracker = (struct obj_track *)record;
  char *source_key = NULL;
  unsigned long count = 0;
  char *type = NULL;

  switch (TYPE(tracker->obj)) {
    case T_NONE:
      type = "__none__"; break;
    case T_BLKTAG:
      type = "__blktag__"; break;
    case T_UNDEF:
      type = "__undef__"; break;
    case T_VARMAP:
      type = "__varmap__"; break;
    case T_SCOPE:
      type = "__scope__"; break;
    case T_NODE:
      type = "__node__"; break;
    default:
      if (RBASIC(tracker->obj)->klass) {
        type = (char*) rb_obj_classname(tracker->obj);
      } else {
        type = "__unknown__";
      }
  }

  asprintf(&source_key, "%s:%d:%s", tracker->source, tracker->line, type);
  st_lookup(table, (st_data_t)source_key, (st_data_t *)&count);
  if (st_insert(table, (st_data_t)source_key, ++count)) {
    free(source_key);
  }

  return ST_CONTINUE;
}

struct results {
  char **entries;
  unsigned long num_entries;
};

static int
objs_to_array(st_data_t key, st_data_t record, st_data_t arg)
{
  struct results *res = (struct results *)arg;
  unsigned long count = (unsigned long)record;
  char *source = (char *)key;
  
  asprintf(&(res->entries[res->num_entries++]), "%7d %s", count, source);

  free(source);
  return ST_DELETE;
}

static VALUE
memprof_start(VALUE self)
{
  if (track_objs == 1)
    return Qfalse;

  track_objs = 1;
  return Qtrue;
}

static VALUE
memprof_stop(VALUE self)
{
  if (track_objs == 0)
    return Qfalse;

  track_objs = 0;
  st_foreach(objs, objs_free, (st_data_t)0);
  return Qtrue;
}

static int
memprof_strcmp(const void *obj1, const void *obj2)
{
  char *str1 = *(char **)obj1;
  char *str2 = *(char **)obj2;
  return strcmp(str2, str1);
}

static VALUE
memprof_stats(int argc, VALUE *argv, VALUE self)
{
  st_table *tmp_table;
  struct results res;
  int i;
  VALUE str;
  FILE *out = NULL;

  if (!track_objs)
    rb_raise(rb_eRuntimeError, "object tracking disabled, call Memprof.start first");

  rb_scan_args(argc, argv, "01", &str);

  if (RTEST(str)) {
    out = fopen(StringValueCStr(str), "w");
    if (!out)
      rb_raise(rb_eArgError, "unable to open output file");
  }

  track_objs = 0;

  tmp_table = st_init_strtable();
  st_foreach(objs, objs_tabulate, (st_data_t)tmp_table);

  res.num_entries = 0;
  res.entries = malloc(sizeof(char*) * tmp_table->num_entries);

  st_foreach(tmp_table, objs_to_array, (st_data_t)&res);
  st_free_table(tmp_table);

  qsort(res.entries, res.num_entries, sizeof(char*), &memprof_strcmp);

  for (i=0; i < res.num_entries; i++) {
    fprintf(out ? out : stderr, "%s\n", res.entries[i]);
    free(res.entries[i]);
  }
  free(res.entries);

  track_objs = 1;
  return Qnil;
}

static VALUE
memprof_stats_bang(int argc, VALUE *argv, VALUE self)
{
  memprof_stats(argc, argv, self);
  st_foreach(objs, objs_free, (st_data_t)0);
  return Qnil;
}

static VALUE
memprof_track(int argc, VALUE *argv, VALUE self)
{
  if (!rb_block_given_p())
    rb_raise(rb_eArgError, "block required");

  memprof_start(self);
  rb_yield(Qnil);
  memprof_stats(argc, argv, self);
  memprof_stop(self);
  return Qnil;
}

static void
create_tramp_table()
{
  int i = 0;
  void *region = NULL;

  struct tramp_tbl_entry ent = {
    .ebx_save      = {'\x53'},                // push ebx
    .mov           = {'\xbb'},                 // mov addr into ebx
    .addr          = error_tramp,             // ^^^
    .calll         = {'\xff', '\xd3'},        // calll ebx
    .ebx_restore   = {'\x5b'},                // pop ebx
    .ret           = {'\xc3'},                // ret
  };

  struct inline_tramp_tbl_entry inline_ent = {
    .mov     = {'\x89'},
    .src_reg = {'\x05'},
    .mov_addr = 0,

    .frame = {
      .push_ebx = {'\x53'},
      .pushl = {'\xff', '\x35'},
      .freelist = 0,
      .mov_ebx = {'\xbb'},
      .fn_addr = 0,
      .calll = {'\xff', '\xd3'},
      .pop_ebx = {'\x5b'},
      .restore_ebx = {'\x5b'},
    },

    .jmp  = {'\xe9'},
    .jmp_addr = 0,
  };

  if ((region = bin_allocate_page()) == MAP_FAILED) {
    fprintf(stderr, "Failed to allocate memory for stage 1 trampolines.\n");
    return;
  }

  tramp_table = region;
  inline_tramp_table = region + pagesize/2;

  for (i = 0; i < (pagesize/2)/sizeof(struct tramp_tbl_entry); i++) {
    memcpy(tramp_table + i, &ent, sizeof(struct tramp_tbl_entry));
  }

  for (i = 0; i < (pagesize/2)/sizeof(struct inline_tramp_tbl_entry); i++) {
    memcpy(inline_tramp_table + i, &inline_ent, sizeof(struct inline_tramp_tbl_entry));
  }
}

void
update_callqs(int entry, void *trampee_addr)
{
  char *byte = text_segment;
  size_t count = 0;
  int fn_addr = 0;
  void *aligned_addr = NULL;

  for(; count < text_segment_len; count++) {
    if (*byte == '\xe8') {
      fn_addr = *(int *)(byte+1);
      if (((void *)trampee_addr - (void *)(byte+5)) == fn_addr) {
        aligned_addr = (void*)(((long)byte+1)&~(0xffff));
        mprotect(aligned_addr, (((void *)byte+1) - aligned_addr) + 10, PROT_READ|PROT_WRITE|PROT_EXEC);
        *(int  *)(byte+1) = (uint32_t)((void *)(tramp_table + entry) - (void *)(byte + 5));
        mprotect(aligned_addr, (((void *)byte+1) - aligned_addr) + 10, PROT_READ|PROT_EXEC);
      }
    }
    byte++;
  }
}


static void
hook_freelist(int entry)
{
  size_t sizes[] = { 0, 0, 0 };
  void *sym1 = bin_find_symbol("gc_sweep", &sizes[0]);

  if (sym1 == NULL) {
    /* this is MRI ... */
    sym1 = bin_find_symbol("garbage_collect", &sizes[0]);
  }

  void *sym2 = bin_find_symbol("finalize_list", &sizes[1]);
  void *sym3 = bin_find_symbol("rb_gc_force_recycle", &sizes[2]);
  void *freelist_callers[] = { sym1, sym2, sym3 };
  int max = 3;
  size_t i = 0;
  char *byte = freelist_callers[0];
  void *freelist = bin_find_symbol("freelist", NULL);
  void *mov_target =  0;
  void *aligned_addr = NULL;
  size_t count = 0;

  /* This is the stage 1 trampoline for hooking the inlined add_freelist
   * function .
   *
   * NOTE: We don't know (yet) how wide the instruction we'll overwrite is.
   * If its moving from %eax, it'll be 5 bytes. Any other register it will be
   * 6 bytes.
   *
   * Depending on what is getting overwritten the pad byte of this struct may
   * or may not actually get copied.
   */
  struct tramp_inline tramp = {
    .jmp           = {'\xe9'},
    .displacement  = 0,
    .pad           = {'\x90'},
  };

  struct inline_tramp_tbl_entry *inl_tramp_st2 = NULL;
  size_t pad_length = 0;

  for (;i < max;) {
    /* make sure it is a mov instruction */
    if (byte[0] == '\xa3' ||
        byte[0] == '\x89') {

      /* if the byte is 0xa3 then we're moving from %eax, so
       * the length is only 5, so we don't need the pad.
       *
       * otherwise, we're moving from something else, so the
       * length is going to be 6 and we need a NOP.
       */
      if (byte[0] == '\xa3')
        pad_length = 0;
      else
        pad_length = 1;

      /* Grab the target of the mov.
       *
       * REMEMBER: in this case the target is a 32bit displacment that gets
       * added to EIP (where EIP is the adress of the next instruction).
       */
      mov_target = (void *)(*(uint32_t *)(byte + 1 + pad_length));

      /* Sanity check. Ensure that the mov target is actually freelist. */
      if (freelist == mov_target) {

        /* grab the stage2 trampoline entry */
        inl_tramp_st2 = inline_tramp_table + entry;

        if (byte[0] == '\xa3') {
          /* if it's a mov from %eax, insert a NOP at the top.
           * REMEMBER: mov %eax is only 1 byte. other movs are 2.
           */
          inl_tramp_st2->mov[0] = '\x90';
          inl_tramp_st2->src_reg[0] = '\xa3';
        } else {
          /* If it's a mov from anything other than %eax, we need to copy
           * the *existing* mov bytes to correctly replicate the dest register.
           */
          inl_tramp_st2->mov[0] = byte[0];
          inl_tramp_st2->src_reg[0] = byte[1];
        }

        /* fill in all the absolute addresses needed for our stage 2 tramp */
        inl_tramp_st2->mov_addr = inl_tramp_st2->frame.freelist = freelist;
        inl_tramp_st2->frame.fn_addr = freelist_tramp;

        /* Setup the stage 1 trampoline. Calculate the displacement to
         * the stage 2 trampoline from the next instruction.
         *
         * REMEMBER: The address of the next instruction depends on whether
         * this mov was from %eax or somewhere else.
         */
        tramp.displacement = (uint32_t)((void *)(inl_tramp_st2) - (void *)(byte+5+pad_length));

        /* Figure out what page the stage 1 tramp is gonna be written to, mark
         * it WRITE, write the trampoline in, and then remove WRITE permission.
         */
        aligned_addr = (void*)(((long)byte)&~(0xffff));
        mprotect(aligned_addr, (((void *)byte) - aligned_addr) + 10, PROT_READ|PROT_WRITE|PROT_EXEC);
        memcpy(byte, &tramp, 5 + pad_length);
        mprotect(aligned_addr, (((void *)byte) - aligned_addr) + 10, PROT_READ|PROT_EXEC);

        /* jmp back to the instruction after stage 1 trampoline was inserted
         *
         * REMEMBER: Instruction length is variable, depends on where the mov
         * was from, %eax or elsewhere.
         */
        inl_tramp_st2->jmp_addr = (uint32_t)((void *)(byte + 5 + pad_length) -
                                             (void *)(inline_tramp_table + entry + 1));

        /* track the new entry and new trampoline size */
        entry++;
        inline_tramp_size++;
      }
    }

    if (count >= sizes[i]) {
        count = 0;
        i ++;
        byte = freelist_callers[i];
    }
    count++;
    byte++;
  }
}

static void
insert_tramp(char *trampee, void *tramp)
{
  void *trampee_addr = bin_find_symbol(trampee, NULL);
  int entry = tramp_size;
  int inline_ent = inline_tramp_size;

  if (trampee_addr == NULL) {
    if (strcmp("add_freelist", trampee) == 0) {
      /* XXX super hack */
      inline_tramp_table[inline_tramp_size].frame.fn_addr = tramp;
      inline_tramp_size++;
      hook_freelist(inline_ent);
    } else {
      return;
    }
  } else {
    tramp_table[tramp_size].addr = tramp;
    tramp_size++;
    bin_update_image(entry, trampee_addr);
  }
}

void
Init_memprof()
{
  VALUE memprof = rb_define_module("Memprof");
  rb_define_singleton_method(memprof, "start", memprof_start, 0);
  rb_define_singleton_method(memprof, "stop", memprof_stop, 0);
  rb_define_singleton_method(memprof, "stats", memprof_stats, -1);
  rb_define_singleton_method(memprof, "stats!", memprof_stats_bang, -1);
  rb_define_singleton_method(memprof, "track", memprof_track, -1);

  pagesize = getpagesize();
  objs = st_init_numtable();
  bin_init();
  create_tramp_table();

#if defined(HAVE_MACH)
  insert_tramp("_rb_newobj", newobj_tramp);
#elif defined(HAVE_ELF)
  insert_tramp("rb_newobj", newobj_tramp);
  insert_tramp("add_freelist", freelist_tramp);
#endif

  return;
}
