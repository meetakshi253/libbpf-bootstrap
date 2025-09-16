#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

typedef signed char __s8;

typedef unsigned char __u8;

typedef short int __s16;

typedef short unsigned int __u16;

typedef int __s32;

typedef unsigned int __u32;

typedef long long int __s64;

typedef long long unsigned int __u64;

typedef __s8 s8;

typedef __u8 u8;

typedef __s16 s16;

typedef __u16 u16;

typedef __s32 s32;

typedef __u32 u32;

typedef __s64 s64;

typedef __u64 u64;

enum {
	false = 0,
	true = 1,
};

typedef long int __kernel_long_t;

typedef long unsigned int __kernel_ulong_t;

typedef int __kernel_pid_t;

typedef unsigned int __kernel_uid32_t;

typedef unsigned int __kernel_gid32_t;

typedef __kernel_ulong_t __kernel_size_t;

typedef __kernel_long_t __kernel_ssize_t;

typedef long long int __kernel_loff_t;

typedef long long int __kernel_time64_t;

typedef __kernel_long_t __kernel_clock_t;

typedef int __kernel_timer_t;

typedef int __kernel_clockid_t;

typedef __u16 __be16;

typedef __u32 __be32;

typedef __u64 __be64;

typedef __u32 __wsum;

typedef unsigned int __poll_t;

typedef u32 __kernel_dev_t;

typedef __kernel_dev_t dev_t;

typedef __kernel_ulong_t ino_t;

typedef short unsigned int umode_t;

typedef __kernel_pid_t pid_t;

typedef __kernel_clockid_t clockid_t;

typedef _Bool bool;

typedef __kernel_uid32_t uid_t;

typedef __kernel_gid32_t gid_t;

typedef long unsigned int uintptr_t;

typedef __kernel_loff_t loff_t;

typedef __kernel_size_t size_t;

typedef __kernel_ssize_t ssize_t;

typedef s32 int32_t;

typedef u32 uint32_t;

typedef u64 uint64_t;

typedef s64 ktime_t;

typedef u64 sector_t;

typedef u64 blkcnt_t;

typedef u64 dma_addr_t;

typedef unsigned int gfp_t;

typedef unsigned int slab_flags_t;

typedef unsigned int fmode_t;

typedef u64 phys_addr_t;

typedef struct {
	int counter;
} atomic_t;

typedef struct {
	s64 counter;
} atomic64_t;

typedef struct {
	atomic_t refcnt;
} rcuref_t;

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

struct hlist_node;

struct hlist_head {
	struct hlist_node *first;
};

struct hlist_node {
	struct hlist_node *next;
	struct hlist_node **pprev;
};

struct callback_head {
	struct callback_head *next;
	void (*func)(struct callback_head *);
};

struct fs_parameter_spec;

struct lock_class_key {};

struct fs_context;

struct dentry;

struct super_block;

struct module;

struct file_system_type {
	const char *name;
	int fs_flags;
	int (*init_fs_context)(struct fs_context *);
	const struct fs_parameter_spec *parameters;
	struct dentry * (*mount)(struct file_system_type *, int, const char *, void *);
	void (*kill_sb)(struct super_block *);
	struct module *owner;
	struct file_system_type *next;
	struct hlist_head fs_supers;
	struct lock_class_key s_lock_key;
	struct lock_class_key s_umount_key;
	struct lock_class_key s_vfs_rename_key;
	struct lock_class_key s_writers_key[3];
	struct lock_class_key i_lock_key;
	struct lock_class_key i_mutex_key;
	struct lock_class_key invalidate_lock_key;
	struct lock_class_key i_mutex_dir_key;
};

enum module_state {
	MODULE_STATE_LIVE = 0,
	MODULE_STATE_COMING = 1,
	MODULE_STATE_GOING = 2,
	MODULE_STATE_UNFORMED = 3,
};

struct refcount_struct {
	atomic_t refs;
};

typedef struct refcount_struct refcount_t;

struct kref {
	refcount_t refcount;
};

struct kset;

struct kobj_type;

struct kernfs_node;

struct kobject {
	const char *name;
	struct list_head entry;
	struct kobject *parent;
	struct kset *kset;
	const struct kobj_type *ktype;
	struct kernfs_node *sd;
	struct kref kref;
	unsigned int state_initialized: 1;
	unsigned int state_in_sysfs: 1;
	unsigned int state_add_uevent_sent: 1;
	unsigned int state_remove_uevent_sent: 1;
	unsigned int uevent_suppress: 1;
};

struct module_param_attrs;

struct completion;

struct module_kobject {
	struct kobject kobj;
	struct module *mod;
	struct kobject *drivers_dir;
	struct module_param_attrs *mp;
	struct completion *kobj_completion;
};

struct kernel_symbol;

typedef atomic64_t atomic_long_t;

struct qspinlock {
	union {
		atomic_t val;
		struct {
			u8 locked;
			u8 pending;
		};
		struct {
			u16 locked_pending;
			u16 tail;
		};
	};
};

typedef struct qspinlock arch_spinlock_t;

struct raw_spinlock {
	arch_spinlock_t raw_lock;
};

typedef struct raw_spinlock raw_spinlock_t;

struct optimistic_spin_queue {
	atomic_t tail;
};

struct mutex {
	atomic_long_t owner;
	raw_spinlock_t wait_lock;
	struct optimistic_spin_queue osq;
	struct list_head wait_list;
};

struct rb_node {
	long unsigned int __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
};

struct latch_tree_node {
	struct rb_node node[2];
};

struct mod_tree_node {
	struct module *mod;
	struct latch_tree_node node;
};

struct module_memory {
	void *base;
	unsigned int size;
	struct mod_tree_node mtn;
};

struct mod_arch_specific {};

struct elf64_sym;

typedef struct elf64_sym Elf64_Sym;

struct mod_kallsyms {
	Elf64_Sym *symtab;
	unsigned int num_symtab;
	char *strtab;
	char *typetab;
};

struct module_sect_attrs;

struct module_notes_attrs;

typedef const int tracepoint_ptr_t;

struct _ddebug;

struct ddebug_class_map;

struct _ddebug_info {
	struct _ddebug *descs;
	struct ddebug_class_map *classes;
	unsigned int num_descs;
	unsigned int num_classes;
};

struct module_attribute;

struct kernel_param;

struct exception_table_entry;

struct bug_entry;

struct srcu_struct;

struct bpf_raw_event_map;

struct jump_entry;

struct trace_event_call;

struct trace_eval_map;

struct static_call_site;

struct error_injection_entry;

struct module {
	enum module_state state;
	struct list_head list;
	char name[56];
	struct module_kobject mkobj;
	struct module_attribute *modinfo_attrs;
	const char *version;
	const char *srcversion;
	struct kobject *holders_dir;
	const struct kernel_symbol *syms;
	const s32 *crcs;
	unsigned int num_syms;
	struct mutex param_lock;
	struct kernel_param *kp;
	unsigned int num_kp;
	unsigned int num_gpl_syms;
	const struct kernel_symbol *gpl_syms;
	const s32 *gpl_crcs;
	bool using_gplonly_symbols;
	bool sig_ok;
	bool async_probe_requested;
	unsigned int num_exentries;
	struct exception_table_entry *extable;
	int (*init)();
	struct module_memory mem[7];
	struct mod_arch_specific arch;
	long unsigned int taints;
	unsigned int num_bugs;
	struct list_head bug_list;
	struct bug_entry *bug_table;
	struct mod_kallsyms *kallsyms;
	struct mod_kallsyms core_kallsyms;
	struct module_sect_attrs *sect_attrs;
	struct module_notes_attrs *notes_attrs;
	char *args;
	void *percpu;
	unsigned int percpu_size;
	void *noinstr_text_start;
	unsigned int noinstr_text_size;
	unsigned int num_tracepoints;
	tracepoint_ptr_t *tracepoints_ptrs;
	unsigned int num_srcu_structs;
	struct srcu_struct **srcu_struct_ptrs;
	unsigned int num_bpf_raw_events;
	struct bpf_raw_event_map *bpf_raw_events;
	unsigned int btf_data_size;
	unsigned int btf_base_data_size;
	void *btf_data;
	void *btf_base_data;
	struct jump_entry *jump_entries;
	unsigned int num_jump_entries;
	unsigned int num_trace_bprintk_fmt;
	const char **trace_bprintk_fmt_start;
	struct trace_event_call **trace_events;
	unsigned int num_trace_events;
	struct trace_eval_map **trace_evals;
	unsigned int num_trace_evals;
	unsigned int num_ftrace_callsites;
	long unsigned int *ftrace_callsites;
	void *kprobes_text_start;
	unsigned int kprobes_text_size;
	long unsigned int *kprobe_blacklist;
	unsigned int num_kprobe_blacklist;
	int num_static_call_sites;
	struct static_call_site *static_call_sites;
	struct list_head source_list;
	struct list_head target_list;
	void (*exit)();
	atomic_t refcnt;
	int its_num_pages;
	void **its_page_array;
	struct error_injection_entry *ei_funcs;
	unsigned int num_ei_funcs;
	struct _ddebug_info dyndbg_info;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct qrwlock {
	union {
		atomic_t cnts;
		struct {
			u8 wlocked;
			u8 __lstate[3];
		};
	};
	arch_spinlock_t wait_lock;
};

typedef struct qrwlock arch_rwlock_t;

struct lockdep_map {};

struct ratelimit_state {
	raw_spinlock_t lock;
	int interval;
	int burst;
	int printed;
	int missed;
	unsigned int flags;
	long unsigned int begin;
};

struct static_key_mod;

struct jump_entry {
	s32 code;
	s32 target;
	long int key;
};

struct static_key {
	atomic_t enabled;
	union {
		long unsigned int type;
		struct jump_entry *entries;
		struct static_key_mod *next;
	};
};

struct static_key_true {
	struct static_key key;
};

struct static_key_false {
	struct static_key key;
};

struct _ddebug {
	const char *modname;
	const char *function;
	const char *filename;
	const char *format;
	unsigned int lineno: 18;
	unsigned int class_id: 6;
	unsigned int flags: 8;
	union {
		struct static_key_true dd_key_true;
		struct static_key_false dd_key_false;
	} key;
};

enum class_map_type {
	DD_CLASS_TYPE_DISJOINT_BITS = 0,
	DD_CLASS_TYPE_LEVEL_NUM = 1,
	DD_CLASS_TYPE_DISJOINT_NAMES = 2,
	DD_CLASS_TYPE_LEVEL_NAMES = 3,
};

struct ddebug_class_map {
	struct list_head link;
	struct module *mod;
	const char *mod_name;
	const char **class_names;
	const int length;
	const int base;
	enum class_map_type map_type;
};

struct kernel_param_ops {
	unsigned int flags;
	int (*set)(const char *, const struct kernel_param *);
	int (*get)(char *, const struct kernel_param *);
	void (*free)(void *);
};

typedef unsigned int fop_flags_t;

typedef void *fl_owner_t;

struct io_uring_cmd;

struct file;

struct kiocb;

struct iov_iter;

struct io_comp_batch;

struct dir_context;

struct poll_table_struct;

struct vm_area_struct;

struct inode;

struct file_lock;

struct pipe_inode_info;

struct file_lease;

struct seq_file;

struct file_operations {
	struct module *owner;
	fop_flags_t fop_flags;
	loff_t (*llseek)(struct file *, loff_t, int);
	ssize_t (*read)(struct file *, char *, size_t, loff_t *);
	ssize_t (*write)(struct file *, const char *, size_t, loff_t *);
	ssize_t (*read_iter)(struct kiocb *, struct iov_iter *);
	ssize_t (*write_iter)(struct kiocb *, struct iov_iter *);
	int (*iopoll)(struct kiocb *, struct io_comp_batch *, unsigned int);
	int (*iterate_shared)(struct file *, struct dir_context *);
	__poll_t (*poll)(struct file *, struct poll_table_struct *);
	long int (*unlocked_ioctl)(struct file *, unsigned int, long unsigned int);
	long int (*compat_ioctl)(struct file *, unsigned int, long unsigned int);
	int (*mmap)(struct file *, struct vm_area_struct *);
	int (*open)(struct inode *, struct file *);
	int (*flush)(struct file *, fl_owner_t);
	int (*release)(struct inode *, struct file *);
	int (*fsync)(struct file *, loff_t, loff_t, int);
	int (*fasync)(int, struct file *, int);
	int (*lock)(struct file *, int, struct file_lock *);
	long unsigned int (*get_unmapped_area)(struct file *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
	int (*check_flags)(int);
	int (*flock)(struct file *, int, struct file_lock *);
	ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
	ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	void (*splice_eof)(struct file *);
	int (*setlease)(struct file *, int, struct file_lease **, void **);
	long int (*fallocate)(struct file *, int, loff_t, loff_t);
	void (*show_fdinfo)(struct seq_file *, struct file *);
	ssize_t (*copy_file_range)(struct file *, loff_t, struct file *, loff_t, size_t, unsigned int);
	loff_t (*remap_file_range)(struct file *, loff_t, struct file *, loff_t, loff_t, unsigned int);
	int (*fadvise)(struct file *, loff_t, loff_t, int);
	int (*uring_cmd)(struct io_uring_cmd *, unsigned int);
	int (*uring_cmd_iopoll)(struct io_uring_cmd *, struct io_comp_batch *, unsigned int);
};

struct bug_entry {
	int bug_addr_disp;
	int file_disp;
	short unsigned int line;
	short unsigned int flags;
};

enum {
	___GFP_DMA_BIT = 0,
	___GFP_HIGHMEM_BIT = 1,
	___GFP_DMA32_BIT = 2,
	___GFP_MOVABLE_BIT = 3,
	___GFP_RECLAIMABLE_BIT = 4,
	___GFP_HIGH_BIT = 5,
	___GFP_IO_BIT = 6,
	___GFP_FS_BIT = 7,
	___GFP_ZERO_BIT = 8,
	___GFP_UNUSED_BIT = 9,
	___GFP_DIRECT_RECLAIM_BIT = 10,
	___GFP_KSWAPD_RECLAIM_BIT = 11,
	___GFP_WRITE_BIT = 12,
	___GFP_NOWARN_BIT = 13,
	___GFP_RETRY_MAYFAIL_BIT = 14,
	___GFP_NOFAIL_BIT = 15,
	___GFP_NORETRY_BIT = 16,
	___GFP_MEMALLOC_BIT = 17,
	___GFP_COMP_BIT = 18,
	___GFP_NOMEMALLOC_BIT = 19,
	___GFP_HARDWALL_BIT = 20,
	___GFP_THISNODE_BIT = 21,
	___GFP_ACCOUNT_BIT = 22,
	___GFP_ZEROTAGS_BIT = 23,
	___GFP_NO_OBJ_EXT_BIT = 24,
	___GFP_LAST_BIT = 25,
};

struct cacheline_padding {
	char x[0];
};

struct thread_info {
	long unsigned int flags;
	long unsigned int syscall_work;
	u32 status;
	u32 cpu;
};

struct llist_node {
	struct llist_node *next;
};

struct __call_single_node {
	struct llist_node llist;
	union {
		unsigned int u_flags;
		atomic_t a_flags;
	};
	u16 src;
	u16 dst;
};

struct load_weight {
	long unsigned int weight;
	u32 inv_weight;
};

struct cfs_rq;

struct sched_avg {
	u64 last_update_time;
	u64 load_sum;
	u64 runnable_sum;
	u32 util_sum;
	u32 period_contrib;
	long unsigned int load_avg;
	long unsigned int runnable_avg;
	long unsigned int util_avg;
	unsigned int util_est;
};

struct sched_entity {
	struct load_weight load;
	struct rb_node run_node;
	u64 deadline;
	u64 min_vruntime;
	u64 min_slice;
	struct list_head group_node;
	unsigned char on_rq;
	unsigned char sched_delayed;
	unsigned char rel_deadline;
	unsigned char custom_slice;
	u64 exec_start;
	u64 sum_exec_runtime;
	u64 prev_sum_exec_runtime;
	u64 vruntime;
	s64 vlag;
	u64 slice;
	u64 nr_migrations;
	int depth;
	struct sched_entity *parent;
	struct cfs_rq *cfs_rq;
	struct cfs_rq *my_q;
	long unsigned int runnable_weight;
	long: 64;
	struct sched_avg avg;
};

struct sched_rt_entity {
	struct list_head run_list;
	long unsigned int timeout;
	long unsigned int watchdog_stamp;
	unsigned int time_slice;
	short unsigned int on_rq;
	short unsigned int on_list;
	struct sched_rt_entity *back;
};

struct timerqueue_node {
	struct rb_node node;
	ktime_t expires;
};

enum hrtimer_restart {
	HRTIMER_NORESTART = 0,
	HRTIMER_RESTART = 1,
};

struct hrtimer_clock_base;

struct hrtimer {
	struct timerqueue_node node;
	ktime_t _softexpires;
	enum hrtimer_restart (*function)(struct hrtimer *);
	struct hrtimer_clock_base *base;
	u8 state;
	u8 is_rel;
	u8 is_soft;
	u8 is_hard;
};

struct rq;

struct sched_dl_entity;

typedef bool (*dl_server_has_tasks_f)(struct sched_dl_entity *);

struct task_struct;

typedef struct task_struct * (*dl_server_pick_f)(struct sched_dl_entity *);

struct sched_dl_entity {
	struct rb_node rb_node;
	u64 dl_runtime;
	u64 dl_deadline;
	u64 dl_period;
	u64 dl_bw;
	u64 dl_density;
	s64 runtime;
	u64 deadline;
	unsigned int flags;
	unsigned int dl_throttled: 1;
	unsigned int dl_yielded: 1;
	unsigned int dl_non_contending: 1;
	unsigned int dl_overrun: 1;
	unsigned int dl_server: 1;
	unsigned int dl_server_active: 1;
	unsigned int dl_defer: 1;
	unsigned int dl_defer_armed: 1;
	unsigned int dl_defer_running: 1;
	struct hrtimer dl_timer;
	struct hrtimer inactive_timer;
	struct rq *rq;
	dl_server_has_tasks_f server_has_tasks;
	dl_server_pick_f server_pick_task;
	struct sched_dl_entity *pi_se;
};

struct sched_class;

struct task_group;

struct uclamp_se {
	unsigned int value: 11;
	unsigned int bucket_id: 3;
	unsigned int active: 1;
	unsigned int user_defined: 1;
};

struct sched_statistics {};

struct cpumask {
	long unsigned int bits[1];
};

typedef struct cpumask cpumask_t;

union rcu_special {
	struct {
		u8 blocked;
		u8 need_qs;
		u8 exp_hint;
		u8 need_mb;
	} b;
	u32 s;
};

struct rcu_node;

struct sched_info {
	long unsigned int pcount;
	long long unsigned int run_delay;
	long long unsigned int last_arrival;
	long long unsigned int last_queued;
};

struct plist_node {
	int prio;
	struct list_head prio_list;
	struct list_head node_list;
};

enum timespec_type {
	TT_NONE = 0,
	TT_NATIVE = 1,
	TT_COMPAT = 2,
};

struct __kernel_timespec;

struct old_timespec32;

struct pollfd;

struct restart_block {
	long unsigned int arch_data;
	long int (*fn)(struct restart_block *);
	union {
		struct {
			u32 *uaddr;
			u32 val;
			u32 flags;
			u32 bitset;
			u64 time;
			u32 *uaddr2;
		} futex;
		struct {
			clockid_t clockid;
			enum timespec_type type;
			union {
				struct __kernel_timespec *rmtp;
				struct old_timespec32 *compat_rmtp;
			};
			u64 expires;
		} nanosleep;
		struct {
			struct pollfd *ufds;
			int nfds;
			int has_timeout;
			long unsigned int tv_sec;
			long unsigned int tv_nsec;
		} poll;
	};
};

struct prev_cputime {
	u64 utime;
	u64 stime;
	raw_spinlock_t lock;
};

struct rb_root {
	struct rb_node *rb_node;
};

struct rb_root_cached {
	struct rb_root rb_root;
	struct rb_node *rb_leftmost;
};

struct timerqueue_head {
	struct rb_root_cached rb_root;
};

struct posix_cputimer_base {
	u64 nextevt;
	struct timerqueue_head tqhead;
};

struct posix_cputimers {
	struct posix_cputimer_base bases[3];
	unsigned int timers_active;
	unsigned int expiry_active;
};

struct posix_cputimers_work {
	struct callback_head work;
	struct mutex mutex;
	unsigned int scheduled;
};

struct nameidata;

struct sem_undo_list;

struct sysv_sem {
	struct sem_undo_list *undo_list;
};

struct sysv_shm {
	struct list_head shm_clist;
};

struct fs_struct;

struct files_struct;

struct io_uring_task;

typedef struct {
	long unsigned int sig[1];
} sigset_t;

struct sigpending {
	struct list_head list;
	sigset_t signal;
};

struct audit_context;

typedef struct {
	uid_t val;
} kuid_t;

struct seccomp_filter;

struct seccomp {
	int mode;
	atomic_t filter_count;
	struct seccomp_filter *filter;
};

struct syscall_user_dispatch {
	char *selector;
	long unsigned int offset;
	long unsigned int len;
	bool on_dispatch;
};

struct spinlock {
	union {
		struct raw_spinlock rlock;
	};
};

typedef struct spinlock spinlock_t;

struct wake_q_node {
	struct wake_q_node *next;
};

struct rt_mutex_waiter;

struct capture_control;

struct task_io_accounting {
	u64 rchar;
	u64 wchar;
	u64 syscr;
	u64 syscw;
	u64 read_bytes;
	u64 write_bytes;
	u64 cancelled_write_bytes;
};

typedef struct {
	long unsigned int bits[1];
} nodemask_t;

struct seqcount {
	unsigned int sequence;
};

typedef struct seqcount seqcount_t;

struct seqcount_spinlock {
	seqcount_t seqcount;
};

typedef struct seqcount_spinlock seqcount_spinlock_t;

struct robust_list_head;

struct futex_pi_state;

struct mempolicy;

struct numa_group;

struct arch_tlbflush_unmap_batch {
	struct cpumask cpumask;
};

struct tlbflush_unmap_batch {
	struct arch_tlbflush_unmap_batch arch;
	bool flush_required;
	bool writable;
};

struct page;

struct page_frag {
	struct page *page;
	__u32 offset;
	__u32 size;
};

struct task_delay_info;

struct kmap_ctrl {};

struct timer_list {
	struct hlist_node entry;
	long unsigned int expires;
	void (*function)(struct timer_list *);
	u32 flags;
};

struct vm_struct;

struct bpf_local_storage;

struct bpf_net_context;

struct llist_head {
	struct llist_node *first;
};

struct desc_struct {
	u16 limit0;
	u16 base0;
	u16 base1: 8;
	u16 type: 4;
	u16 s: 1;
	u16 dpl: 2;
	u16 p: 1;
	u16 limit1: 4;
	u16 avl: 1;
	u16 l: 1;
	u16 d: 1;
	u16 g: 1;
	u16 base2: 8;
};

struct io_bitmap;

struct fpu_state_perm {
	u64 __state_perm;
	unsigned int __state_size;
	unsigned int __user_state_size;
};

struct fregs_state {
	u32 cwd;
	u32 swd;
	u32 twd;
	u32 fip;
	u32 fcs;
	u32 foo;
	u32 fos;
	u32 st_space[20];
	u32 status;
};

struct fxregs_state {
	u16 cwd;
	u16 swd;
	u16 twd;
	u16 fop;
	union {
		struct {
			u64 rip;
			u64 rdp;
		};
		struct {
			u32 fip;
			u32 fcs;
			u32 foo;
			u32 fos;
		};
	};
	u32 mxcsr;
	u32 mxcsr_mask;
	u32 st_space[32];
	u32 xmm_space[64];
	u32 padding[12];
	union {
		u32 padding1[12];
		u32 sw_reserved[12];
	};
};

struct math_emu_info;

struct swregs_state {
	u32 cwd;
	u32 swd;
	u32 twd;
	u32 fip;
	u32 fcs;
	u32 foo;
	u32 fos;
	u32 st_space[20];
	u8 ftop;
	u8 changed;
	u8 lookahead;
	u8 no_update;
	u8 rm;
	u8 alimit;
	struct math_emu_info *info;
	u32 entry_eip;
};

struct xstate_header {
	u64 xfeatures;
	u64 xcomp_bv;
	u64 reserved[6];
};

struct xregs_state {
	struct fxregs_state i387;
	struct xstate_header header;
	u8 extended_state_area[0];
};

union fpregs_state {
	struct fregs_state fsave;
	struct fxregs_state fxsave;
	struct swregs_state soft;
	struct xregs_state xsave;
	u8 __padding[4096];
};

struct fpstate {
	unsigned int size;
	unsigned int user_size;
	u64 xfeatures;
	u64 user_xfeatures;
	u64 xfd;
	unsigned int is_valloc: 1;
	unsigned int is_guest: 1;
	unsigned int is_confidential: 1;
	unsigned int in_use: 1;
	long: 64;
	long: 64;
	long: 64;
	union fpregs_state regs;
};

struct fpu {
	unsigned int last_cpu;
	long unsigned int avx512_timestamp;
	struct fpstate *fpstate;
	struct fpstate *__task_fpstate;
	struct fpu_state_perm perm;
	struct fpu_state_perm guest_perm;
	struct fpstate __fpstate;
};

struct perf_event;

struct thread_struct {
	struct desc_struct tls_array[3];
	long unsigned int sp;
	short unsigned int es;
	short unsigned int ds;
	short unsigned int fsindex;
	short unsigned int gsindex;
	long unsigned int fsbase;
	long unsigned int gsbase;
	struct perf_event *ptrace_bps[4];
	long unsigned int virtual_dr6;
	long unsigned int ptrace_dr7;
	long unsigned int cr2;
	long unsigned int trap_nr;
	long unsigned int error_code;
	struct io_bitmap *io_bitmap;
	long unsigned int iopl_emul;
	unsigned int iopl_warn: 1;
	u32 pkru;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct fpu fpu;
};

struct mm_struct;

struct address_space;

struct pid;

struct cred;

struct key;

struct nsproxy;

struct signal_struct;

struct sighand_struct;

struct bio_list;

struct blk_plug;

struct reclaim_state;

struct io_context;

struct kernel_siginfo;

typedef struct kernel_siginfo kernel_siginfo_t;

struct css_set;

struct compat_robust_list_head;

struct perf_event_context;

struct rseq;

struct mem_cgroup;

struct obj_cgroup;

struct gendisk;

struct uprobe_task;

struct bpf_run_ctx;

struct task_struct {
	struct thread_info thread_info;
	unsigned int __state;
	unsigned int saved_state;
	void *stack;
	refcount_t usage;
	unsigned int flags;
	unsigned int ptrace;
	int on_cpu;
	struct __call_single_node wake_entry;
	unsigned int wakee_flips;
	long unsigned int wakee_flip_decay_ts;
	struct task_struct *last_wakee;
	int recent_used_cpu;
	int wake_cpu;
	int on_rq;
	int prio;
	int static_prio;
	int normal_prio;
	unsigned int rt_priority;
	struct sched_entity se;
	struct sched_rt_entity rt;
	struct sched_dl_entity dl;
	struct sched_dl_entity *dl_server;
	const struct sched_class *sched_class;
	struct rb_node core_node;
	long unsigned int core_cookie;
	unsigned int core_occupation;
	struct task_group *sched_task_group;
	struct uclamp_se uclamp_req[2];
	struct uclamp_se uclamp[2];
	long: 64;
	struct sched_statistics stats;
	struct hlist_head preempt_notifiers;
	unsigned int btrace_seq;
	unsigned int policy;
	long unsigned int max_allowed_capacity;
	int nr_cpus_allowed;
	const cpumask_t *cpus_ptr;
	cpumask_t *user_cpus_ptr;
	cpumask_t cpus_mask;
	void *migration_pending;
	short unsigned int migration_disabled;
	short unsigned int migration_flags;
	int rcu_read_lock_nesting;
	union rcu_special rcu_read_unlock_special;
	struct list_head rcu_node_entry;
	struct rcu_node *rcu_blocked_node;
	long unsigned int rcu_tasks_nvcsw;
	u8 rcu_tasks_holdout;
	u8 rcu_tasks_idx;
	int rcu_tasks_idle_cpu;
	struct list_head rcu_tasks_holdout_list;
	int rcu_tasks_exit_cpu;
	struct list_head rcu_tasks_exit_list;
	int trc_reader_nesting;
	int trc_ipi_to_cpu;
	union rcu_special trc_reader_special;
	struct list_head trc_holdout_list;
	struct list_head trc_blkd_node;
	int trc_blkd_cpu;
	struct sched_info sched_info;
	struct list_head tasks;
	struct plist_node pushable_tasks;
	struct rb_node pushable_dl_tasks;
	struct mm_struct *mm;
	struct mm_struct *active_mm;
	struct address_space *faults_disabled_mapping;
	int exit_state;
	int exit_code;
	int exit_signal;
	int pdeath_signal;
	long unsigned int jobctl;
	unsigned int personality;
	unsigned int sched_reset_on_fork: 1;
	unsigned int sched_contributes_to_load: 1;
	unsigned int sched_migrated: 1;
	unsigned int sched_task_hot: 1;
	long: 28;
	unsigned int sched_remote_wakeup: 1;
	unsigned int sched_rt_mutex: 1;
	unsigned int in_execve: 1;
	unsigned int in_iowait: 1;
	unsigned int restore_sigmask: 1;
	unsigned int no_cgroup_migration: 1;
	unsigned int frozen: 1;
	unsigned int use_memdelay: 1;
	unsigned int in_memstall: 1;
	unsigned int in_eventfd: 1;
	unsigned int pasid_activated: 1;
	unsigned int reported_split_lock: 1;
	unsigned int in_thrashing: 1;
	long unsigned int atomic_flags;
	struct restart_block restart_block;
	pid_t pid;
	pid_t tgid;
	long unsigned int stack_canary;
	struct task_struct *real_parent;
	struct task_struct *parent;
	struct list_head children;
	struct list_head sibling;
	struct task_struct *group_leader;
	struct list_head ptraced;
	struct list_head ptrace_entry;
	struct pid *thread_pid;
	struct hlist_node pid_links[4];
	struct list_head thread_node;
	struct completion *vfork_done;
	int *set_child_tid;
	int *clear_child_tid;
	void *worker_private;
	u64 utime;
	u64 stime;
	u64 gtime;
	struct prev_cputime prev_cputime;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	u64 start_time;
	u64 start_boottime;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	struct posix_cputimers posix_cputimers;
	struct posix_cputimers_work posix_cputimers_work;
	const struct cred *ptracer_cred;
	const struct cred *real_cred;
	const struct cred *cred;
	struct key *cached_requested_key;
	char comm[16];
	struct nameidata *nameidata;
	struct sysv_sem sysvsem;
	struct sysv_shm sysvshm;
	struct fs_struct *fs;
	struct files_struct *files;
	struct io_uring_task *io_uring;
	struct nsproxy *nsproxy;
	struct signal_struct *signal;
	struct sighand_struct *sighand;
	sigset_t blocked;
	sigset_t real_blocked;
	sigset_t saved_sigmask;
	struct sigpending pending;
	long unsigned int sas_ss_sp;
	size_t sas_ss_size;
	unsigned int sas_ss_flags;
	struct callback_head *task_works;
	struct audit_context *audit_context;
	kuid_t loginuid;
	unsigned int sessionid;
	struct seccomp seccomp;
	struct syscall_user_dispatch syscall_dispatch;
	u64 parent_exec_id;
	u64 self_exec_id;
	spinlock_t alloc_lock;
	raw_spinlock_t pi_lock;
	struct wake_q_node wake_q;
	struct rb_root_cached pi_waiters;
	struct task_struct *pi_top_task;
	struct rt_mutex_waiter *pi_blocked_on;
	unsigned int in_ubsan;
	void *journal_info;
	struct bio_list *bio_list;
	struct blk_plug *plug;
	struct reclaim_state *reclaim_state;
	struct io_context *io_context;
	struct capture_control *capture_control;
	long unsigned int ptrace_message;
	kernel_siginfo_t *last_siginfo;
	struct task_io_accounting ioac;
	unsigned int psi_flags;
	u64 acct_rss_mem1;
	u64 acct_vm_mem1;
	u64 acct_timexpd;
	nodemask_t mems_allowed;
	seqcount_spinlock_t mems_allowed_seq;
	int cpuset_mem_spread_rotor;
	struct css_set *cgroups;
	struct list_head cg_list;
	u32 closid;
	u32 rmid;
	struct robust_list_head *robust_list;
	struct compat_robust_list_head *compat_robust_list;
	struct list_head pi_state_list;
	struct futex_pi_state *pi_state_cache;
	struct mutex futex_exit_mutex;
	unsigned int futex_state;
	u8 perf_recursion[4];
	struct perf_event_context *perf_event_ctxp;
	struct mutex perf_event_mutex;
	struct list_head perf_event_list;
	struct mempolicy *mempolicy;
	short int il_prev;
	u8 il_weight;
	short int pref_node_fork;
	int numa_scan_seq;
	unsigned int numa_scan_period;
	unsigned int numa_scan_period_max;
	int numa_preferred_nid;
	long unsigned int numa_migrate_retry;
	u64 node_stamp;
	u64 last_task_numa_placement;
	u64 last_sum_exec_runtime;
	struct callback_head numa_work;
	struct numa_group *numa_group;
	long unsigned int *numa_faults;
	long unsigned int total_numa_faults;
	long unsigned int numa_faults_locality[3];
	long unsigned int numa_pages_migrated;
	struct rseq *rseq;
	u32 rseq_len;
	u32 rseq_sig;
	long unsigned int rseq_event_mask;
	int mm_cid;
	int last_mm_cid;
	int migrate_from_cpu;
	int mm_cid_active;
	struct callback_head cid_work;
	struct tlbflush_unmap_batch tlb_ubc;
	struct pipe_inode_info *splice_pipe;
	struct page_frag task_frag;
	struct task_delay_info *delays;
	int nr_dirtied;
	int nr_dirtied_pause;
	long unsigned int dirty_paused_when;
	u64 timer_slack_ns;
	u64 default_timer_slack_ns;
	int curr_ret_stack;
	int curr_ret_depth;
	long unsigned int *ret_stack;
	long long unsigned int ftrace_timestamp;
	atomic_t trace_overrun;
	atomic_t tracing_graph_pause;
	long unsigned int trace_recursion;
	unsigned int memcg_nr_pages_over_high;
	struct mem_cgroup *active_memcg;
	struct obj_cgroup *objcg;
	struct gendisk *throttle_disk;
	struct uprobe_task *utask;
	unsigned int sequential_io;
	unsigned int sequential_io_avg;
	struct kmap_ctrl kmap_ctrl;
	struct callback_head rcu;
	refcount_t rcu_users;
	int pagefault_disabled;
	struct task_struct *oom_reaper_list;
	struct timer_list oom_reaper_timer;
	struct vm_struct *stack_vm_area;
	refcount_t stack_refcount;
	void *security;
	struct bpf_local_storage *bpf_storage;
	struct bpf_run_ctx *bpf_ctx;
	struct bpf_net_context *bpf_net_context;
	void *mce_vaddr;
	__u64 mce_kflags;
	u64 mce_addr;
	__u64 mce_ripv: 1;
	__u64 mce_whole_page: 1;
	__u64 __mce_reserved: 62;
	struct callback_head mce_kill_me;
	int mce_count;
	struct llist_head kretprobe_instances;
	struct llist_head rethooks;
	struct callback_head l1d_flush_kill;
	long: 64;
	long: 64;
	struct thread_struct thread;
};

struct pcpu_hot {
	union {
		struct {
			struct task_struct *current_task;
			int preempt_count;
			int cpu_number;
			u64 call_depth;
			long unsigned int top_of_stack;
			void *hardirq_stack_ptr;
			u16 softirq_pending;
			bool hardirq_stack_inuse;
		};
		u8 pad[64];
	};
};

struct static_call_site {
	s32 addr;
	s32 key;
};

struct static_call_mod {
	struct static_call_mod *next;
	struct module *mod;
	struct static_call_site *sites;
};

struct static_call_key {
	void *func;
	union {
		long unsigned int type;
		struct static_call_mod *mods;
		struct static_call_site *sites;
	};
};

typedef long unsigned int pteval_t;

typedef long unsigned int pmdval_t;

typedef long unsigned int pudval_t;

typedef long unsigned int pgdval_t;

typedef long unsigned int pgprotval_t;

typedef struct {
	pteval_t pte;
} pte_t;

typedef struct {
	pmdval_t pmd;
} pmd_t;

struct pgprot {
	pgprotval_t pgprot;
};

typedef struct pgprot pgprot_t;

typedef struct {
	pgdval_t pgd;
} pgd_t;

typedef struct {
	pudval_t pud;
} pud_t;

typedef struct page *pgtable_t;

struct page_pool;

struct dev_pagemap;

struct page {
	long unsigned int flags;
	union {
		struct {
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
				struct list_head buddy_list;
				struct list_head pcp_list;
			};
			struct address_space *mapping;
			union {
				long unsigned int index;
				long unsigned int share;
			};
			long unsigned int private;
		};
		struct {
			long unsigned int pp_magic;
			struct page_pool *pp;
			long unsigned int _pp_mapping_pad;
			long unsigned int dma_addr;
			atomic_long_t pp_ref_count;
		};
		struct {
			long unsigned int compound_head;
		};
		struct {
			struct dev_pagemap *pgmap;
			void *zone_device_data;
		};
		struct callback_head callback_head;
	};
	union {
		unsigned int page_type;
		atomic_t _mapcount;
	};
	atomic_t _refcount;
	long unsigned int memcg_data;
};

typedef struct {} lockdep_map_p;

struct maple_tree {
	union {
		spinlock_t ma_lock;
		lockdep_map_p ma_external_lock;
	};
	unsigned int ma_flags;
	void *ma_root;
};

struct rw_semaphore {
	atomic_long_t count;
	atomic_long_t owner;
	struct optimistic_spin_queue osq;
	raw_spinlock_t wait_lock;
	struct list_head wait_list;
};

struct percpu_counter {
	raw_spinlock_t lock;
	s64 count;
	struct list_head list;
	s32 *counters;
};

struct linux_binfmt;

struct ldt_struct;

struct vdso_image;

typedef struct {
	u64 ctx_id;
	atomic64_t tlb_gen;
	long unsigned int next_trim_cpumask;
	struct rw_semaphore ldt_usr_sem;
	struct ldt_struct *ldt;
	long unsigned int flags;
	struct mutex lock;
	void *vdso;
	const struct vdso_image *vdso_image;
	atomic_t perf_rdpmc_allowed;
	u16 pkey_allocation_map;
	s16 execute_only_pkey;
} mm_context_t;

struct kioctx_table;

struct mmu_notifier_subscriptions;

struct xol_area;

struct uprobes_state {
	struct xol_area *xol_area;
};

struct work_struct;

typedef void (*work_func_t)(struct work_struct *);

struct work_struct {
	atomic_long_t data;
	struct list_head entry;
	work_func_t func;
};

struct iommu_mm_data;

struct mm_cid;

struct user_namespace;

struct mm_struct {
	struct {
		struct {
			atomic_t mm_count;
			long: 64;
			long: 64;
			long: 64;
			long: 64;
			long: 64;
			long: 64;
			long: 64;
		};
		struct maple_tree mm_mt;
		long unsigned int mmap_base;
		long unsigned int mmap_legacy_base;
		long unsigned int mmap_compat_base;
		long unsigned int mmap_compat_legacy_base;
		long unsigned int task_size;
		pgd_t *pgd;
		atomic_t membarrier_state;
		atomic_t mm_users;
		struct mm_cid *pcpu_cid;
		long unsigned int mm_cid_next_scan;
		atomic_long_t pgtables_bytes;
		int map_count;
		spinlock_t page_table_lock;
		struct rw_semaphore mmap_lock;
		struct list_head mmlist;
		int mm_lock_seq;
		long unsigned int hiwater_rss;
		long unsigned int hiwater_vm;
		long unsigned int total_vm;
		long unsigned int locked_vm;
		atomic64_t pinned_vm;
		long unsigned int data_vm;
		long unsigned int exec_vm;
		long unsigned int stack_vm;
		long unsigned int def_flags;
		seqcount_t write_protect_seq;
		spinlock_t arg_lock;
		long unsigned int start_code;
		long unsigned int end_code;
		long unsigned int start_data;
		long unsigned int end_data;
		long unsigned int start_brk;
		long unsigned int brk;
		long unsigned int start_stack;
		long unsigned int arg_start;
		long unsigned int arg_end;
		long unsigned int env_start;
		long unsigned int env_end;
		long unsigned int saved_auxv[52];
		struct percpu_counter rss_stat[4];
		struct linux_binfmt *binfmt;
		mm_context_t context;
		long unsigned int flags;
		spinlock_t ioctx_lock;
		struct kioctx_table *ioctx_table;
		struct task_struct *owner;
		struct user_namespace *user_ns;
		struct file *exe_file;
		struct mmu_notifier_subscriptions *notifier_subscriptions;
		long unsigned int numa_next_scan;
		long unsigned int numa_scan_offset;
		int numa_scan_seq;
		atomic_t tlb_flush_pending;
		atomic_t tlb_flush_batched;
		struct uprobes_state uprobes_state;
		atomic_long_t hugetlb_usage;
		struct work_struct async_put_work;
		struct iommu_mm_data *iommu_mm;
		long unsigned int ksm_merging_pages;
		long unsigned int ksm_rmap_items;
		atomic_long_t ksm_zero_pages;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
	};
	long unsigned int cpu_bitmap[0];
};

typedef long unsigned int vm_flags_t;

struct anon_vma;

struct userfaultfd_ctx;

struct vm_userfaultfd_ctx {
	struct userfaultfd_ctx *ctx;
};

struct vma_lock;

struct vm_operations_struct;

struct vma_numab_state;

struct vm_area_struct {
	union {
		struct {
			long unsigned int vm_start;
			long unsigned int vm_end;
		};
		struct callback_head vm_rcu;
	};
	struct mm_struct *vm_mm;
	pgprot_t vm_page_prot;
	union {
		const vm_flags_t vm_flags;
		vm_flags_t __vm_flags;
	};
	bool detached;
	int vm_lock_seq;
	struct vma_lock *vm_lock;
	struct {
		struct rb_node rb;
		long unsigned int rb_subtree_last;
	} shared;
	struct list_head anon_vma_chain;
	struct anon_vma *anon_vma;
	const struct vm_operations_struct *vm_ops;
	long unsigned int vm_pgoff;
	struct file *vm_file;
	void *vm_private_data;
	atomic_long_t swap_readahead_info;
	struct mempolicy *vm_policy;
	struct vma_numab_state *numab_state;
	struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
};

enum fortify_func {
	FORTIFY_FUNC_strncpy = 0,
	FORTIFY_FUNC_strnlen = 1,
	FORTIFY_FUNC_strlen = 2,
	FORTIFY_FUNC_strscpy = 3,
	FORTIFY_FUNC_strlcat = 4,
	FORTIFY_FUNC_strcat = 5,
	FORTIFY_FUNC_strncat = 6,
	FORTIFY_FUNC_memset = 7,
	FORTIFY_FUNC_memcpy = 8,
	FORTIFY_FUNC_memmove = 9,
	FORTIFY_FUNC_memscan = 10,
	FORTIFY_FUNC_memcmp = 11,
	FORTIFY_FUNC_memchr = 12,
	FORTIFY_FUNC_memchr_inv = 13,
	FORTIFY_FUNC_kmemdup = 14,
	FORTIFY_FUNC_strcpy = 15,
	FORTIFY_FUNC_UNKNOWN = 16,
};

typedef struct {
	seqcount_spinlock_t seqcount;
	spinlock_t lock;
} seqlock_t;

struct free_area {
	struct list_head free_list[5];
	long unsigned int nr_free;
};

struct pglist_data;

struct per_cpu_pages;

struct per_cpu_zonestat;

struct zone {
	long unsigned int _watermark[4];
	long unsigned int watermark_boost;
	long unsigned int nr_reserved_highatomic;
	long unsigned int nr_free_highatomic;
	long int lowmem_reserve[5];
	int node;
	struct pglist_data *zone_pgdat;
	struct per_cpu_pages *per_cpu_pageset;
	struct per_cpu_zonestat *per_cpu_zonestats;
	int pageset_high_min;
	int pageset_high_max;
	int pageset_batch;
	long unsigned int zone_start_pfn;
	atomic_long_t managed_pages;
	long unsigned int spanned_pages;
	long unsigned int present_pages;
	long unsigned int present_early_pages;
	const char *name;
	long unsigned int nr_isolate_pageblock;
	seqlock_t span_seqlock;
	int initialized;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct free_area free_area[11];
	struct list_head unaccepted_pages;
	long unsigned int flags;
	spinlock_t lock;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	long unsigned int percpu_drift_mark;
	long unsigned int compact_cached_free_pfn;
	long unsigned int compact_cached_migrate_pfn[2];
	long unsigned int compact_init_migrate_pfn;
	long unsigned int compact_init_free_pfn;
	unsigned int compact_considered;
	unsigned int compact_defer_shift;
	int compact_order_failed;
	bool compact_blockskip_flush;
	bool contiguous;
	long: 0;
	struct cacheline_padding _pad3_;
	atomic_long_t vm_stat[12];
	atomic_long_t vm_numa_event[6];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct zoneref {
	struct zone *zone;
	int zone_idx;
};

struct zonelist {
	struct zoneref _zonerefs[321];
};

struct wait_queue_head {
	spinlock_t lock;
	struct list_head head;
};

typedef struct wait_queue_head wait_queue_head_t;

enum zone_type {
	ZONE_DMA = 0,
	ZONE_DMA32 = 1,
	ZONE_NORMAL = 2,
	ZONE_MOVABLE = 3,
	ZONE_DEVICE = 4,
	__MAX_NR_ZONES = 5,
};

struct deferred_split {
	spinlock_t split_queue_lock;
	struct list_head split_queue;
	long unsigned int split_queue_len;
};

struct zswap_lruvec_state {};

struct lruvec {
	struct list_head lists[5];
	spinlock_t lru_lock;
	long unsigned int anon_cost;
	long unsigned int file_cost;
	atomic_long_t nonresident_age;
	long unsigned int refaults[2];
	long unsigned int flags;
	struct pglist_data *pgdat;
	struct zswap_lruvec_state zswap_lruvec_state;
};

struct memory_tier;

struct memory_failure_stats {
	long unsigned int total;
	long unsigned int ignored;
	long unsigned int failed;
	long unsigned int delayed;
	long unsigned int recovered;
};

struct per_cpu_nodestat;

struct pglist_data {
	struct zone node_zones[5];
	struct zonelist node_zonelists[2];
	int nr_zones;
	spinlock_t node_size_lock;
	long unsigned int node_start_pfn;
	long unsigned int node_present_pages;
	long unsigned int node_spanned_pages;
	int node_id;
	wait_queue_head_t kswapd_wait;
	wait_queue_head_t pfmemalloc_wait;
	wait_queue_head_t reclaim_wait[4];
	atomic_t nr_writeback_throttled;
	long unsigned int nr_reclaim_start;
	struct mutex kswapd_lock;
	struct task_struct *kswapd;
	int kswapd_order;
	enum zone_type kswapd_highest_zoneidx;
	int kswapd_failures;
	int kcompactd_max_order;
	enum zone_type kcompactd_highest_zoneidx;
	wait_queue_head_t kcompactd_wait;
	struct task_struct *kcompactd;
	bool proactive_compact_trigger;
	long unsigned int totalreserve_pages;
	long unsigned int min_unmapped_pages;
	long unsigned int min_slab_pages;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct deferred_split deferred_split_queue;
	unsigned int nbp_rl_start;
	long unsigned int nbp_rl_nr_cand;
	unsigned int nbp_threshold;
	unsigned int nbp_th_start;
	long unsigned int nbp_th_nr_cand;
	struct lruvec __lruvec;
	long unsigned int flags;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	struct per_cpu_nodestat *per_cpu_nodestats;
	atomic_long_t vm_stat[47];
	struct memory_tier *memtier;
	struct memory_failure_stats mf_stats;
	long: 64;
	long: 64;
};

struct attribute;

struct bin_attribute;

struct attribute_group {
	const char *name;
	umode_t (*is_visible)(struct kobject *, struct attribute *, int);
	umode_t (*is_bin_visible)(struct kobject *, struct bin_attribute *, int);
	struct attribute **attrs;
	struct bin_attribute **bin_attrs;
};

struct __kernel_timespec {
	__kernel_time64_t tv_sec;
	long long int tv_nsec;
};

typedef s32 old_time32_t;

struct old_timespec32 {
	old_time32_t tv_sec;
	s32 tv_nsec;
};

struct pollfd {
	int fd;
	short int events;
	short int revents;
};

struct range {
	u64 start;
	u64 end;
};

struct fred_cs {
	u64 cs: 16;
	u64 sl: 2;
	u64 wfe: 1;
};

struct fred_ss {
	u64 ss: 16;
	u64 sti: 1;
	u64 swevent: 1;
	u64 nmi: 1;
	int: 13;
	u64 vector: 8;
	short: 8;
	u64 type: 4;
	char: 4;
	u64 enclave: 1;
	u64 lm: 1;
	u64 nested: 1;
	char: 1;
	u64 insnlen: 4;
};

struct pt_regs {
	long unsigned int r15;
	long unsigned int r14;
	long unsigned int r13;
	long unsigned int r12;
	long unsigned int bp;
	long unsigned int bx;
	long unsigned int r11;
	long unsigned int r10;
	long unsigned int r9;
	long unsigned int r8;
	long unsigned int ax;
	long unsigned int cx;
	long unsigned int dx;
	long unsigned int si;
	long unsigned int di;
	long unsigned int orig_ax;
	long unsigned int ip;
	union {
		u16 cs;
		u64 csx;
		struct fred_cs fred_cs;
	};
	long unsigned int flags;
	long unsigned int sp;
	union {
		u16 ss;
		u64 ssx;
		struct fred_ss fred_ss;
	};
};

struct math_emu_info {
	long int ___orig_eip;
	struct pt_regs *regs;
};

struct seq_operations {
	void * (*start)(struct seq_file *, loff_t *);
	void (*stop)(struct seq_file *, void *);
	void * (*next)(struct seq_file *, void *, loff_t *);
	int (*show)(struct seq_file *, void *);
};

typedef void (*smp_call_func_t)(void *);

struct __call_single_data {
	struct __call_single_node node;
	smp_call_func_t func;
	void *info;
};

typedef struct __call_single_data call_single_data_t;

typedef struct {
	arch_rwlock_t raw_lock;
} rwlock_t;

struct hlist_nulls_node {
	struct hlist_nulls_node *next;
	struct hlist_nulls_node **pprev;
};

struct wait_queue_entry;

typedef int (*wait_queue_func_t)(struct wait_queue_entry *, unsigned int, int, void *);

struct wait_queue_entry {
	unsigned int flags;
	void *private;
	wait_queue_func_t func;
	struct list_head entry;
};

typedef struct wait_queue_entry wait_queue_entry_t;

struct seqcount_raw_spinlock {
	seqcount_t seqcount;
};

typedef struct seqcount_raw_spinlock seqcount_raw_spinlock_t;

enum refcount_saturation_type {
	REFCOUNT_ADD_NOT_ZERO_OVF = 0,
	REFCOUNT_ADD_OVF = 1,
	REFCOUNT_ADD_UAF = 2,
	REFCOUNT_SUB_UAF = 3,
	REFCOUNT_DEC_LEAK = 4,
};

struct swait_queue_head {
	raw_spinlock_t lock;
	struct list_head task_list;
};

struct completion {
	unsigned int done;
	struct swait_queue_head wait;
};

typedef __s64 time64_t;

struct timespec64 {
	time64_t tv_sec;
	long int tv_nsec;
};

struct codetag {
	unsigned int flags;
	unsigned int lineno;
	const char *modname;
	const char *function;
	const char *filename;
};

struct alloc_tag_counters {
	u64 bytes;
	u64 calls;
};

struct alloc_tag {
	struct codetag ct;
	struct alloc_tag_counters *counters;
};

enum pid_type {
	PIDTYPE_PID = 0,
	PIDTYPE_TGID = 1,
	PIDTYPE_PGID = 2,
	PIDTYPE_SID = 3,
	PIDTYPE_MAX = 4,
};

struct hrtimer_cpu_base;

struct hrtimer_clock_base {
	struct hrtimer_cpu_base *cpu_base;
	unsigned int index;
	clockid_t clockid;
	seqcount_raw_spinlock_t seq;
	struct hrtimer *running;
	struct timerqueue_head active;
	ktime_t (*get_time)();
	ktime_t offset;
};

struct rlimit {
	__kernel_ulong_t rlim_cur;
	__kernel_ulong_t rlim_max;
};

struct task_cputime {
	u64 stime;
	u64 utime;
	long long unsigned int sum_exec_runtime;
};

typedef void __signalfn_t(int);

typedef __signalfn_t *__sighandler_t;

typedef void __restorefn_t();

typedef __restorefn_t *__sigrestore_t;

union sigval {
	int sival_int;
	void *sival_ptr;
};

typedef union sigval sigval_t;

union __sifields {
	struct {
		__kernel_pid_t _pid;
		__kernel_uid32_t _uid;
	} _kill;
	struct {
		__kernel_timer_t _tid;
		int _overrun;
		sigval_t _sigval;
		int _sys_private;
	} _timer;
	struct {
		__kernel_pid_t _pid;
		__kernel_uid32_t _uid;
		sigval_t _sigval;
	} _rt;
	struct {
		__kernel_pid_t _pid;
		__kernel_uid32_t _uid;
		int _status;
		__kernel_clock_t _utime;
		__kernel_clock_t _stime;
	} _sigchld;
	struct {
		void *_addr;
		union {
			int _trapno;
			short int _addr_lsb;
			struct {
				char _dummy_bnd[8];
				void *_lower;
				void *_upper;
			} _addr_bnd;
			struct {
				char _dummy_pkey[8];
				__u32 _pkey;
			} _addr_pkey;
			struct {
				long unsigned int _data;
				__u32 _type;
				__u32 _flags;
			} _perf;
		};
	} _sigfault;
	struct {
		long int _band;
		int _fd;
	} _sigpoll;
	struct {
		void *_call_addr;
		int _syscall;
		unsigned int _arch;
	} _sigsys;
};

struct kernel_siginfo {
	struct {
		int si_signo;
		int si_errno;
		int si_code;
		union __sifields _sifields;
	};
};

struct ucounts {
	struct hlist_node node;
	struct user_namespace *ns;
	kuid_t uid;
	atomic_t count;
	atomic_long_t ucount[12];
	atomic_long_t rlimit[4];
};

struct sigaction {
	__sighandler_t sa_handler;
	long unsigned int sa_flags;
	__sigrestore_t sa_restorer;
	sigset_t sa_mask;
};

struct k_sigaction {
	struct sigaction sa;
};

struct rseq {
	__u32 cpu_id_start;
	__u32 cpu_id;
	__u64 rseq_cs;
	__u32 flags;
	__u32 node_id;
	__u32 mm_cid;
	char end[0];
};

typedef struct {
	gid_t val;
} kgid_t;

struct xarray {
	spinlock_t xa_lock;
	gfp_t xa_flags;
	void *xa_head;
};

typedef u32 errseq_t;

struct address_space_operations;

struct address_space {
	struct inode *host;
	struct xarray i_pages;
	struct rw_semaphore invalidate_lock;
	gfp_t gfp_mask;
	atomic_t i_mmap_writable;
	struct rb_root_cached i_mmap;
	long unsigned int nrpages;
	long unsigned int writeback_index;
	const struct address_space_operations *a_ops;
	long unsigned int flags;
	errseq_t wb_err;
	spinlock_t i_private_lock;
	struct list_head i_private_list;
	struct rw_semaphore i_mmap_rwsem;
	void *i_private_data;
};

struct pid_namespace;

struct upid {
	int nr;
	struct pid_namespace *ns;
};

struct pid {
	refcount_t count;
	unsigned int level;
	spinlock_t lock;
	struct dentry *stashed;
	u64 ino;
	struct hlist_head tasks[4];
	struct hlist_head inodes;
	wait_queue_head_t wait_pidfd;
	struct callback_head rcu;
	struct upid numbers[0];
};

typedef struct {
	u64 val;
} kernel_cap_t;

struct user_struct;

struct group_info;

struct cred {
	atomic_long_t usage;
	kuid_t uid;
	kgid_t gid;
	kuid_t suid;
	kgid_t sgid;
	kuid_t euid;
	kgid_t egid;
	kuid_t fsuid;
	kgid_t fsgid;
	unsigned int securebits;
	kernel_cap_t cap_inheritable;
	kernel_cap_t cap_permitted;
	kernel_cap_t cap_effective;
	kernel_cap_t cap_bset;
	kernel_cap_t cap_ambient;
	unsigned char jit_keyring;
	struct key *session_keyring;
	struct key *process_keyring;
	struct key *thread_keyring;
	struct key *request_key_auth;
	void *security;
	struct user_struct *user;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct group_info *group_info;
	union {
		int non_rcu;
		struct callback_head rcu;
	};
};

typedef int32_t key_serial_t;

struct watch_list;

struct key_user;

typedef uint32_t key_perm_t;

struct key_type;

struct key_tag;

struct keyring_index_key {
	long unsigned int hash;
	union {
		struct {
			u16 desc_len;
			char desc[6];
		};
		long unsigned int x;
	};
	struct key_type *type;
	struct key_tag *domain_tag;
	const char *description;
};

union key_payload {
	void *rcu_data0;
	void *data[4];
};

struct assoc_array_ptr;

struct assoc_array {
	struct assoc_array_ptr *root;
	long unsigned int nr_leaves_on_tree;
};

struct key_restriction;

struct key {
	refcount_t usage;
	key_serial_t serial;
	union {
		struct list_head graveyard_link;
		struct rb_node serial_node;
	};
	struct watch_list *watchers;
	struct rw_semaphore sem;
	struct key_user *user;
	void *security;
	union {
		time64_t expiry;
		time64_t revoked_at;
	};
	time64_t last_used_at;
	kuid_t uid;
	kgid_t gid;
	key_perm_t perm;
	short unsigned int quotalen;
	short unsigned int datalen;
	short int state;
	long unsigned int flags;
	union {
		struct keyring_index_key index_key;
		struct {
			long unsigned int hash;
			long unsigned int len_desc;
			struct key_type *type;
			struct key_tag *domain_tag;
			char *description;
		};
	};
	union {
		union key_payload payload;
		struct {
			struct list_head name_link;
			struct assoc_array keys;
		};
	};
	struct key_restriction *restrict_link;
};

struct ipc_namespace;

struct mnt_namespace;

struct time_namespace;

struct uts_namespace;

struct net;

struct cgroup_namespace;

struct nsproxy {
	refcount_t count;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct mnt_namespace *mnt_ns;
	struct pid_namespace *pid_ns_for_children;
	struct net *net_ns;
	struct time_namespace *time_ns;
	struct time_namespace *time_ns_for_children;
	struct cgroup_namespace *cgroup_ns;
};

struct cpu_itimer {
	u64 expires;
	u64 incr;
};

struct task_cputime_atomic {
	atomic64_t utime;
	atomic64_t stime;
	atomic64_t sum_exec_runtime;
};

struct thread_group_cputimer {
	struct task_cputime_atomic cputime_atomic;
};

struct tty_struct;

struct autogroup;

struct pacct_struct {
	int ac_flag;
	long int ac_exitcode;
	long unsigned int ac_mem;
	u64 ac_utime;
	u64 ac_stime;
	long unsigned int ac_minflt;
	long unsigned int ac_majflt;
};

struct tty_audit_buf;

struct core_state;

struct taskstats;

struct signal_struct {
	refcount_t sigcnt;
	atomic_t live;
	int nr_threads;
	int quick_threads;
	struct list_head thread_head;
	wait_queue_head_t wait_chldexit;
	struct task_struct *curr_target;
	struct sigpending shared_pending;
	struct hlist_head multiprocess;
	int group_exit_code;
	int notify_count;
	struct task_struct *group_exec_task;
	int group_stop_count;
	unsigned int flags;
	struct core_state *core_state;
	unsigned int is_child_subreaper: 1;
	unsigned int has_child_subreaper: 1;
	unsigned int next_posix_timer_id;
	struct hlist_head posix_timers;
	struct hrtimer real_timer;
	ktime_t it_real_incr;
	struct cpu_itimer it[2];
	struct thread_group_cputimer cputimer;
	struct posix_cputimers posix_cputimers;
	struct pid *pids[4];
	struct pid *tty_old_pgrp;
	int leader;
	struct tty_struct *tty;
	struct autogroup *autogroup;
	seqlock_t stats_lock;
	u64 utime;
	u64 stime;
	u64 cutime;
	u64 cstime;
	u64 gtime;
	u64 cgtime;
	struct prev_cputime prev_cputime;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	long unsigned int cnvcsw;
	long unsigned int cnivcsw;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	long unsigned int cmin_flt;
	long unsigned int cmaj_flt;
	long unsigned int inblock;
	long unsigned int oublock;
	long unsigned int cinblock;
	long unsigned int coublock;
	long unsigned int maxrss;
	long unsigned int cmaxrss;
	struct task_io_accounting ioac;
	long long unsigned int sum_sched_runtime;
	struct rlimit rlim[16];
	struct pacct_struct pacct;
	struct taskstats *stats;
	unsigned int audit_tty;
	struct tty_audit_buf *tty_audit_buf;
	bool oom_flag_origin;
	short int oom_score_adj;
	short int oom_score_adj_min;
	struct mm_struct *oom_mm;
	struct mutex cred_guard_mutex;
	struct rw_semaphore exec_update_lock;
};

struct sighand_struct {
	spinlock_t siglock;
	refcount_t count;
	wait_queue_head_t signalfd_wqh;
	struct k_sigaction action[64];
};

struct bio;

struct bio_list {
	struct bio *head;
	struct bio *tail;
};

struct reclaim_state {
	long unsigned int reclaimed;
};

struct io_cq;

struct io_context {
	atomic_long_t refcount;
	atomic_t active_ref;
	short unsigned int ioprio;
	spinlock_t lock;
	struct xarray icq_tree;
	struct io_cq *icq_hint;
	struct hlist_head icq_list;
	struct work_struct release_work;
};

struct cgroup_subsys_state;

struct cgroup;

struct css_set {
	struct cgroup_subsys_state *subsys[14];
	refcount_t refcount;
	struct css_set *dom_cset;
	struct cgroup *dfl_cgrp;
	int nr_tasks;
	struct list_head tasks;
	struct list_head mg_tasks;
	struct list_head dying_tasks;
	struct list_head task_iters;
	struct list_head e_cset_node[14];
	struct list_head threaded_csets;
	struct list_head threaded_csets_node;
	struct hlist_node hlist;
	struct list_head cgrp_links;
	struct list_head mg_src_preload_node;
	struct list_head mg_dst_preload_node;
	struct list_head mg_node;
	struct cgroup *mg_src_cgrp;
	struct cgroup *mg_dst_cgrp;
	struct css_set *mg_dst_cset;
	bool dead;
	struct callback_head callback_head;
};

typedef u32 compat_uptr_t;

struct compat_robust_list {
	compat_uptr_t next;
};

typedef s32 compat_long_t;

struct compat_robust_list_head {
	struct compat_robust_list list;
	compat_long_t futex_offset;
	compat_uptr_t list_op_pending;
};

struct percpu_ref_data;

struct percpu_ref {
	long unsigned int percpu_count_ptr;
	struct percpu_ref_data *data;
};

struct workqueue_struct;

struct rcu_work {
	struct work_struct work;
	struct callback_head rcu;
	struct workqueue_struct *wq;
};

struct cgroup_subsys;

struct cgroup_subsys_state {
	struct cgroup *cgroup;
	struct cgroup_subsys *ss;
	struct percpu_ref refcnt;
	struct list_head sibling;
	struct list_head children;
	struct list_head rstat_css_node;
	int id;
	unsigned int flags;
	u64 serial_nr;
	atomic_t online_cnt;
	struct work_struct destroy_work;
	struct rcu_work destroy_rwork;
	struct cgroup_subsys_state *parent;
	int nr_descendants;
};

struct mem_cgroup_id {
	int id;
	refcount_t ref;
};

struct page_counter {
	atomic_long_t usage;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	long unsigned int emin;
	atomic_long_t min_usage;
	atomic_long_t children_min_usage;
	long unsigned int elow;
	atomic_long_t low_usage;
	atomic_long_t children_low_usage;
	long unsigned int watermark;
	long unsigned int local_watermark;
	long unsigned int failcnt;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	bool protection_support;
	long unsigned int min;
	long unsigned int low;
	long unsigned int high;
	long unsigned int max;
	struct page_counter *parent;
	long: 64;
	long: 64;
};

struct vmpressure {
	long unsigned int scanned;
	long unsigned int reclaimed;
	long unsigned int tree_scanned;
	long unsigned int tree_reclaimed;
	spinlock_t sr_lock;
	struct list_head events;
	struct mutex events_lock;
	struct work_struct work;
};

struct cgroup_file {
	struct kernfs_node *kn;
	long unsigned int notified_at;
	struct timer_list notify_timer;
};

struct memcg_vmstats;

struct memcg_vmstats_percpu;

struct fprop_global {
	struct percpu_counter events;
	unsigned int period;
	seqcount_t sequence;
};

struct wb_domain {
	spinlock_t lock;
	struct fprop_global completions;
	struct timer_list period_timer;
	long unsigned int period_time;
	long unsigned int dirty_limit_tstamp;
	long unsigned int dirty_limit;
};

struct wb_completion {
	atomic_t cnt;
	wait_queue_head_t *waitq;
};

struct memcg_cgwb_frn {
	u64 bdi_id;
	int memcg_id;
	u64 at;
	struct wb_completion done;
};

struct mem_cgroup_per_node;

struct mem_cgroup {
	struct cgroup_subsys_state css;
	struct mem_cgroup_id id;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct page_counter memory;
	union {
		struct page_counter swap;
		struct page_counter memsw;
	};
	struct list_head memory_peaks;
	struct list_head swap_peaks;
	spinlock_t peaks_lock;
	struct work_struct high_work;
	struct vmpressure vmpressure;
	bool oom_group;
	int swappiness;
	struct cgroup_file events_file;
	struct cgroup_file events_local_file;
	struct cgroup_file swap_events_file;
	struct memcg_vmstats *vmstats;
	atomic_long_t memory_events[9];
	atomic_long_t memory_events_local[9];
	long unsigned int socket_pressure;
	int kmemcg_id;
	struct obj_cgroup *objcg;
	struct obj_cgroup *orig_objcg;
	struct list_head objcg_list;
	struct memcg_vmstats_percpu *vmstats_percpu;
	struct list_head cgwb_list;
	struct wb_domain cgwb_domain;
	struct memcg_cgwb_frn cgwb_frn[4];
	struct deferred_split deferred_split_queue;
	struct mem_cgroup_per_node *nodeinfo[0];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct obj_cgroup {
	struct percpu_ref refcnt;
	struct mem_cgroup *memcg;
	atomic_t nr_charged_bytes;
	union {
		struct list_head list;
		struct callback_head rcu;
	};
};

enum uprobe_task_state {
	UTASK_RUNNING = 0,
	UTASK_SSTEP = 1,
	UTASK_SSTEP_ACK = 2,
	UTASK_SSTEP_TRAPPED = 3,
};

struct arch_uprobe_task {
	long unsigned int saved_scratch_register;
	unsigned int saved_trap_nr;
	unsigned int saved_tf;
};

struct uprobe;

struct arch_uprobe;

struct return_instance;

struct uprobe_task {
	enum uprobe_task_state state;
	union {
		struct {
			struct arch_uprobe_task autask;
			long unsigned int vaddr;
		};
		struct {
			struct callback_head dup_xol_work;
			long unsigned int dup_xol_addr;
		};
	};
	struct uprobe *active_uprobe;
	long unsigned int xol_vaddr;
	struct arch_uprobe *auprobe;
	struct return_instance *return_instances;
	unsigned int depth;
};

struct bpf_run_ctx {};

struct tracepoint_func {
	void *func;
	void *data;
	int prio;
};

struct tracepoint {
	const char *name;
	struct static_key key;
	struct static_call_key *static_call_key;
	void *static_call_tramp;
	void *iterator;
	void *probestub;
	int (*regfunc)();
	void (*unregfunc)();
	struct tracepoint_func *funcs;
};

struct bpf_raw_event_map {
	struct tracepoint *tp;
	void *bpf_func;
	u32 num_args;
	u32 writable_size;
	long: 64;
};

struct delayed_work {
	struct work_struct work;
	struct timer_list timer;
	struct workqueue_struct *wq;
	int cpu;
};

struct rcu_segcblist {
	struct callback_head *head;
	struct callback_head **tails[4];
	long unsigned int gp_seq[4];
	long int len;
	long int seglen[4];
	u8 flags;
};

struct srcu_node;

struct srcu_data {
	atomic_long_t srcu_lock_count[2];
	atomic_long_t srcu_unlock_count[2];
	int srcu_nmi_safety;
	long: 64;
	long: 64;
	long: 64;
	spinlock_t lock;
	struct rcu_segcblist srcu_cblist;
	long unsigned int srcu_gp_seq_needed;
	long unsigned int srcu_gp_seq_needed_exp;
	bool srcu_cblist_invoking;
	struct timer_list delay_work;
	struct work_struct work;
	struct callback_head srcu_barrier_head;
	struct srcu_node *mynode;
	long unsigned int grpmask;
	int cpu;
	struct srcu_struct *ssp;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct srcu_node {
	spinlock_t lock;
	long unsigned int srcu_have_cbs[4];
	long unsigned int srcu_data_have_cbs[4];
	long unsigned int srcu_gp_seq_needed_exp;
	struct srcu_node *srcu_parent;
	int grplo;
	int grphi;
};

struct srcu_usage;

struct srcu_struct {
	unsigned int srcu_idx;
	struct srcu_data *sda;
	struct lockdep_map dep_map;
	struct srcu_usage *srcu_sup;
};

struct srcu_usage {
	struct srcu_node *node;
	struct srcu_node *level[3];
	int srcu_size_state;
	struct mutex srcu_cb_mutex;
	spinlock_t lock;
	struct mutex srcu_gp_mutex;
	long unsigned int srcu_gp_seq;
	long unsigned int srcu_gp_seq_needed;
	long unsigned int srcu_gp_seq_needed_exp;
	long unsigned int srcu_gp_start;
	long unsigned int srcu_last_gp_end;
	long unsigned int srcu_size_jiffies;
	long unsigned int srcu_n_lock_retries;
	long unsigned int srcu_n_exp_nodelay;
	bool sda_is_static;
	long unsigned int srcu_barrier_seq;
	struct mutex srcu_barrier_mutex;
	struct completion srcu_barrier_completion;
	atomic_t srcu_barrier_cpu_cnt;
	long unsigned int reschedule_jiffies;
	long unsigned int reschedule_count;
	struct delayed_work work;
	struct srcu_struct *srcu_ssp;
};

struct notifier_block;

typedef int (*notifier_fn_t)(struct notifier_block *, long unsigned int, void *);

struct notifier_block {
	notifier_fn_t notifier_call;
	struct notifier_block *next;
	int priority;
};

struct blocking_notifier_head {
	struct rw_semaphore rwsem;
	struct notifier_block *head;
};

struct raw_notifier_head {
	struct notifier_block *head;
};

struct uprobe_xol_ops;

struct arch_uprobe {
	union {
		u8 insn[16];
		u8 ixol[16];
	};
	const struct uprobe_xol_ops *ops;
	union {
		struct {
			s32 offs;
			u8 ilen;
			u8 opc1;
		} branch;
		struct {
			u8 fixups;
			u8 ilen;
		} defparam;
		struct {
			u8 reg_offset;
			u8 ilen;
		} push;
	};
};

struct return_instance {
	struct uprobe *uprobe;
	long unsigned int func;
	long unsigned int stack;
	long unsigned int orig_ret_vaddr;
	bool chained;
	struct return_instance *next;
};

struct vdso_image {
	void *data;
	long unsigned int size;
	long unsigned int alt;
	long unsigned int alt_len;
	long unsigned int extable_base;
	long unsigned int extable_len;
	const void *extable;
	long int sym_vvar_start;
	long int sym_vvar_page;
	long int sym_pvclock_page;
	long int sym_hvclock_page;
	long int sym_timens_page;
	long int sym_VDSO32_NOTE_MASK;
	long int sym___kernel_sigreturn;
	long int sym___kernel_rt_sigreturn;
	long int sym___kernel_vsyscall;
	long int sym_int80_landing_pad;
	long int sym_vdso32_sigreturn_landing_pad;
	long int sym_vdso32_rt_sigreturn_landing_pad;
};

struct vmem_altmap {
	long unsigned int base_pfn;
	const long unsigned int end_pfn;
	const long unsigned int reserve;
	long unsigned int free;
	long unsigned int align;
	long unsigned int alloc;
	bool inaccessible;
};

enum memory_type {
	MEMORY_DEVICE_PRIVATE = 1,
	MEMORY_DEVICE_COHERENT = 2,
	MEMORY_DEVICE_FS_DAX = 3,
	MEMORY_DEVICE_GENERIC = 4,
	MEMORY_DEVICE_PCI_P2PDMA = 5,
};

struct dev_pagemap_ops;

struct dev_pagemap {
	struct vmem_altmap altmap;
	struct percpu_ref ref;
	struct completion done;
	enum memory_type type;
	unsigned int flags;
	long unsigned int vmemmap_shift;
	const struct dev_pagemap_ops *ops;
	void *owner;
	int nr_range;
	union {
		struct range range;
		struct {
			struct {} __empty_ranges;
			struct range ranges[0];
		};
	};
};

typedef struct {
	long unsigned int val;
} swp_entry_t;

struct folio {
	union {
		struct {
			long unsigned int flags;
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
			};
			struct address_space *mapping;
			long unsigned int index;
			union {
				void *private;
				swp_entry_t swap;
			};
			atomic_t _mapcount;
			atomic_t _refcount;
			long unsigned int memcg_data;
		};
		struct page page;
	};
	union {
		struct {
			long unsigned int _flags_1;
			long unsigned int _head_1;
			atomic_t _large_mapcount;
			atomic_t _entire_mapcount;
			atomic_t _nr_pages_mapped;
			atomic_t _pincount;
			unsigned int _folio_nr_pages;
		};
		struct page __page_1;
	};
	union {
		struct {
			long unsigned int _flags_2;
			long unsigned int _head_2;
			void *_hugetlb_subpool;
			void *_hugetlb_cgroup;
			void *_hugetlb_cgroup_rsvd;
			void *_hugetlb_hwpoison;
		};
		struct {
			long unsigned int _flags_2a;
			long unsigned int _head_2a;
			struct list_head _deferred_list;
		};
		struct page __page_2;
	};
};

struct vfsmount;

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

struct file_ra_state {
	long unsigned int start;
	unsigned int size;
	unsigned int async_size;
	unsigned int ra_pages;
	unsigned int mmap_miss;
	loff_t prev_pos;
};

typedef struct {
	long unsigned int v;
} freeptr_t;

struct fown_struct;

struct file {
	atomic_long_t f_count;
	spinlock_t f_lock;
	fmode_t f_mode;
	const struct file_operations *f_op;
	struct address_space *f_mapping;
	void *private_data;
	struct inode *f_inode;
	unsigned int f_flags;
	unsigned int f_iocb_flags;
	const struct cred *f_cred;
	struct path f_path;
	union {
		struct mutex f_pos_lock;
		u64 f_pipe;
	};
	loff_t f_pos;
	void *f_security;
	struct fown_struct *f_owner;
	errseq_t f_wb_err;
	errseq_t f_sb_err;
	struct hlist_head *f_ep;
	union {
		struct callback_head f_task_work;
		struct llist_node f_llist;
		struct file_ra_state f_ra;
		freeptr_t f_freeptr;
	};
};

struct vma_lock {
	struct rw_semaphore lock;
};

struct vma_numab_state {
	long unsigned int next_scan;
	long unsigned int pids_active_reset;
	long unsigned int pids_active[2];
	int start_scan_seq;
	int prev_scan_seq;
};

typedef unsigned int vm_fault_t;

struct vm_fault;

struct vm_operations_struct {
	void (*open)(struct vm_area_struct *);
	void (*close)(struct vm_area_struct *);
	int (*may_split)(struct vm_area_struct *, long unsigned int);
	int (*mremap)(struct vm_area_struct *);
	int (*mprotect)(struct vm_area_struct *, long unsigned int, long unsigned int, long unsigned int);
	vm_fault_t (*fault)(struct vm_fault *);
	vm_fault_t (*huge_fault)(struct vm_fault *, unsigned int);
	vm_fault_t (*map_pages)(struct vm_fault *, long unsigned int, long unsigned int);
	long unsigned int (*pagesize)(struct vm_area_struct *);
	vm_fault_t (*page_mkwrite)(struct vm_fault *);
	vm_fault_t (*pfn_mkwrite)(struct vm_fault *);
	int (*access)(struct vm_area_struct *, long unsigned int, void *, int, int);
	const char * (*name)(struct vm_area_struct *);
	int (*set_policy)(struct vm_area_struct *, struct mempolicy *);
	struct mempolicy * (*get_policy)(struct vm_area_struct *, long unsigned int, long unsigned int *);
	struct page * (*find_special_page)(struct vm_area_struct *, long unsigned int);
};

struct mm_cid {
	u64 time;
	int cid;
};

struct uid_gid_extent {
	u32 first;
	u32 lower_first;
	u32 count;
};

struct uid_gid_map {
	union {
		struct {
			struct uid_gid_extent extent[5];
			u32 nr_extents;
		};
		struct {
			struct uid_gid_extent *forward;
			struct uid_gid_extent *reverse;
		};
	};
};

struct proc_ns_operations;

struct ns_common {
	struct dentry *stashed;
	const struct proc_ns_operations *ops;
	unsigned int inum;
	refcount_t count;
};

struct ctl_table;

struct ctl_table_root;

struct ctl_table_set;

struct ctl_dir;

struct ctl_node;

struct ctl_table_header {
	union {
		struct {
			struct ctl_table *ctl_table;
			int ctl_table_size;
			int used;
			int count;
			int nreg;
		};
		struct callback_head rcu;
	};
	struct completion *unregistering;
	const struct ctl_table *ctl_table_arg;
	struct ctl_table_root *root;
	struct ctl_table_set *set;
	struct ctl_dir *parent;
	struct ctl_node *node;
	struct hlist_head inodes;
	enum {
		SYSCTL_TABLE_TYPE_DEFAULT = 0,
		SYSCTL_TABLE_TYPE_PERMANENTLY_EMPTY = 1,
	} type;
};

struct ctl_dir {
	struct ctl_table_header header;
	struct rb_root root;
};

struct ctl_table_set {
	int (*is_seen)(struct ctl_table_set *);
	struct ctl_dir dir;
};

struct binfmt_misc;

struct user_namespace {
	struct uid_gid_map uid_map;
	struct uid_gid_map gid_map;
	struct uid_gid_map projid_map;
	struct user_namespace *parent;
	int level;
	kuid_t owner;
	kgid_t group;
	struct ns_common ns;
	long unsigned int flags;
	bool parent_could_setfcap;
	struct list_head keyring_name_list;
	struct key *user_keyring_register;
	struct rw_semaphore keyring_sem;
	struct key *persistent_keyring_register;
	struct work_struct work;
	struct ctl_table_set set;
	struct ctl_table_header *sysctls;
	struct ucounts *ucounts;
	long int ucount_max[12];
	long int rlimit_max[4];
	struct binfmt_misc *binfmt_misc;
};

enum fault_flag {
	FAULT_FLAG_WRITE = 1,
	FAULT_FLAG_MKWRITE = 2,
	FAULT_FLAG_ALLOW_RETRY = 4,
	FAULT_FLAG_RETRY_NOWAIT = 8,
	FAULT_FLAG_KILLABLE = 16,
	FAULT_FLAG_TRIED = 32,
	FAULT_FLAG_USER = 64,
	FAULT_FLAG_REMOTE = 128,
	FAULT_FLAG_INSTRUCTION = 256,
	FAULT_FLAG_INTERRUPTIBLE = 512,
	FAULT_FLAG_UNSHARE = 1024,
	FAULT_FLAG_ORIG_PTE_VALID = 2048,
	FAULT_FLAG_VMA_LOCK = 4096,
};

struct vm_fault {
	const struct {
		struct vm_area_struct *vma;
		gfp_t gfp_mask;
		long unsigned int pgoff;
		long unsigned int address;
		long unsigned int real_address;
	};
	enum fault_flag flags;
	pmd_t *pmd;
	pud_t *pud;
	union {
		pte_t orig_pte;
		pmd_t orig_pmd;
	};
	struct page *cow_page;
	struct page *page;
	pte_t *pte;
	spinlock_t *ptl;
	pgtable_t prealloc_pte;
};

enum pageflags {
	PG_locked = 0,
	PG_writeback = 1,
	PG_referenced = 2,
	PG_uptodate = 3,
	PG_dirty = 4,
	PG_lru = 5,
	PG_head = 6,
	PG_waiters = 7,
	PG_active = 8,
	PG_workingset = 9,
	PG_owner_priv_1 = 10,
	PG_owner_2 = 11,
	PG_arch_1 = 12,
	PG_reserved = 13,
	PG_private = 14,
	PG_private_2 = 15,
	PG_reclaim = 16,
	PG_swapbacked = 17,
	PG_unevictable = 18,
	PG_mlocked = 19,
	PG_hwpoison = 20,
	PG_young = 21,
	PG_idle = 22,
	PG_arch_2 = 23,
	__NR_PAGEFLAGS = 24,
	PG_readahead = 16,
	PG_swapcache = 10,
	PG_checked = 10,
	PG_anon_exclusive = 11,
	PG_mappedtodisk = 11,
	PG_fscache = 15,
	PG_pinned = 10,
	PG_savepinned = 4,
	PG_foreign = 10,
	PG_xen_remapped = 10,
	PG_isolated = 16,
	PG_reported = 3,
	PG_vmemmap_self_hosted = 10,
	PG_has_hwpoisoned = 8,
	PG_large_rmappable = 9,
	PG_partially_mapped = 16,
};

struct per_cpu_pages {
	spinlock_t lock;
	int count;
	int high;
	int high_min;
	int high_max;
	int batch;
	u8 flags;
	u8 alloc_factor;
	u8 expire;
	short int free_count;
	struct list_head lists[14];
};

struct per_cpu_zonestat {
	s8 vm_stat_diff[12];
	s8 stat_threshold;
	long unsigned int vm_numa_event[6];
};

struct per_cpu_nodestat {
	s8 stat_threshold;
	s8 vm_node_stat_diff[47];
};

struct irq_domain;

typedef void percpu_ref_func_t(struct percpu_ref *);

struct percpu_ref_data {
	atomic_long_t count;
	percpu_ref_func_t *release;
	percpu_ref_func_t *confirm_switch;
	bool force_atomic: 1;
	bool allow_reinit: 1;
	struct callback_head rcu;
	struct percpu_ref *ref;
};

struct shrinker_info_unit {
	atomic_long_t nr_deferred[64];
	long unsigned int map[1];
};

struct shrinker_info {
	struct callback_head rcu;
	int map_nr_max;
	struct shrinker_info_unit *unit[0];
};

struct shrink_control {
	gfp_t gfp_mask;
	int nid;
	long unsigned int nr_to_scan;
	long unsigned int nr_scanned;
	struct mem_cgroup *memcg;
};

struct shrinker {
	long unsigned int (*count_objects)(struct shrinker *, struct shrink_control *);
	long unsigned int (*scan_objects)(struct shrinker *, struct shrink_control *);
	long int batch;
	int seeks;
	unsigned int flags;
	refcount_t refcount;
	struct completion done;
	struct callback_head rcu;
	void *private_data;
	struct list_head list;
	int id;
	atomic_long_t *nr_deferred;
};

struct dev_pagemap_ops {
	void (*page_free)(struct page *);
	vm_fault_t (*migrate_to_ram)(struct vm_fault *);
	int (*memory_failure)(struct dev_pagemap *, long unsigned int, long unsigned int, int);
};

enum kmalloc_cache_type {
	KMALLOC_NORMAL = 0,
	KMALLOC_RANDOM_START = 0,
	KMALLOC_RANDOM_END = 0,
	KMALLOC_RECLAIM = 1,
	KMALLOC_DMA = 2,
	KMALLOC_CGROUP = 3,
	NR_KMALLOC_TYPES = 4,
};

struct kmem_cache;

struct hlist_bl_node;

struct hlist_bl_head {
	struct hlist_bl_node *first;
};

struct hlist_bl_node {
	struct hlist_bl_node *next;
	struct hlist_bl_node **pprev;
};

struct lockref {
	union {
		__u64 lock_count;
		struct {
			spinlock_t lock;
			int count;
		};
	};
};

struct qstr {
	union {
		struct {
			u32 hash;
			u32 len;
		};
		u64 hash_len;
	};
	const unsigned char *name;
};

struct dentry_operations;

struct dentry {
	unsigned int d_flags;
	seqcount_spinlock_t d_seq;
	struct hlist_bl_node d_hash;
	struct dentry *d_parent;
	struct qstr d_name;
	struct inode *d_inode;
	unsigned char d_iname[40];
	const struct dentry_operations *d_op;
	struct super_block *d_sb;
	long unsigned int d_time;
	void *d_fsdata;
	struct lockref d_lockref;
	union {
		struct list_head d_lru;
		wait_queue_head_t *d_wait;
	};
	struct hlist_node d_sib;
	struct hlist_head d_children;
	union {
		struct hlist_node d_alias;
		struct hlist_bl_node d_in_lookup_hash;
		struct callback_head d_rcu;
	} d_u;
};

enum rw_hint {
	WRITE_LIFE_NOT_SET = 0,
	WRITE_LIFE_NONE = 1,
	WRITE_LIFE_SHORT = 2,
	WRITE_LIFE_MEDIUM = 3,
	WRITE_LIFE_LONG = 4,
	WRITE_LIFE_EXTREME = 5,
} __attribute__((mode(byte)));

struct cdev;

struct fsnotify_mark_connector;

struct fscrypt_inode_info;

struct fsverity_info;

struct posix_acl;

struct inode_operations;

struct bdi_writeback;

struct file_lock_context;

struct inode {
	umode_t i_mode;
	short unsigned int i_opflags;
	kuid_t i_uid;
	kgid_t i_gid;
	unsigned int i_flags;
	struct posix_acl *i_acl;
	struct posix_acl *i_default_acl;
	const struct inode_operations *i_op;
	struct super_block *i_sb;
	struct address_space *i_mapping;
	void *i_security;
	long unsigned int i_ino;
	union {
		const unsigned int i_nlink;
		unsigned int __i_nlink;
	};
	dev_t i_rdev;
	loff_t i_size;
	time64_t i_atime_sec;
	time64_t i_mtime_sec;
	time64_t i_ctime_sec;
	u32 i_atime_nsec;
	u32 i_mtime_nsec;
	u32 i_ctime_nsec;
	u32 i_generation;
	spinlock_t i_lock;
	short unsigned int i_bytes;
	u8 i_blkbits;
	enum rw_hint i_write_hint;
	blkcnt_t i_blocks;
	u32 i_state;
	struct rw_semaphore i_rwsem;
	long unsigned int dirtied_when;
	long unsigned int dirtied_time_when;
	struct hlist_node i_hash;
	struct list_head i_io_list;
	struct bdi_writeback *i_wb;
	int i_wb_frn_winner;
	u16 i_wb_frn_avg_time;
	u16 i_wb_frn_history;
	struct list_head i_lru;
	struct list_head i_sb_list;
	struct list_head i_wb_list;
	union {
		struct hlist_head i_dentry;
		struct callback_head i_rcu;
	};
	atomic64_t i_version;
	atomic64_t i_sequence;
	atomic_t i_count;
	atomic_t i_dio_count;
	atomic_t i_writecount;
	atomic_t i_readcount;
	union {
		const struct file_operations *i_fop;
		void (*free_inode)(struct inode *);
	};
	struct file_lock_context *i_flctx;
	struct address_space i_data;
	struct list_head i_devices;
	union {
		struct pipe_inode_info *i_pipe;
		struct cdev *i_cdev;
		char *i_link;
		unsigned int i_dir_seq;
	};
	__u32 i_fsnotify_mask;
	struct fsnotify_mark_connector *i_fsnotify_marks;
	struct fscrypt_inode_info *i_crypt_info;
	struct fsverity_info *i_verity_info;
	void *i_private;
};

enum d_real_type {
	D_REAL_DATA = 0,
	D_REAL_METADATA = 1,
};

struct dentry_operations {
	int (*d_revalidate)(struct dentry *, unsigned int);
	int (*d_weak_revalidate)(struct dentry *, unsigned int);
	int (*d_hash)(const struct dentry *, struct qstr *);
	int (*d_compare)(const struct dentry *, unsigned int, const char *, const struct qstr *);
	int (*d_delete)(const struct dentry *);
	int (*d_init)(struct dentry *);
	void (*d_release)(struct dentry *);
	void (*d_prune)(struct dentry *);
	void (*d_iput)(struct dentry *, struct inode *);
	char * (*d_dname)(struct dentry *, char *, int);
	struct vfsmount * (*d_automount)(struct path *);
	int (*d_manage)(const struct path *, bool);
	struct dentry * (*d_real)(struct dentry *, enum d_real_type);
	long: 64;
	long: 64;
	long: 64;
};

struct export_operations;

struct fscrypt_operations;

struct fscrypt_keyring;

struct fsverity_operations;

struct unicode_map;

struct mtd_info;

typedef long long int qsize_t;

struct quota_format_type;

struct mem_dqinfo {
	struct quota_format_type *dqi_format;
	int dqi_fmt_id;
	struct list_head dqi_dirty_list;
	long unsigned int dqi_flags;
	unsigned int dqi_bgrace;
	unsigned int dqi_igrace;
	qsize_t dqi_max_spc_limit;
	qsize_t dqi_max_ino_limit;
	void *dqi_priv;
};

struct quota_format_ops;

struct quota_info {
	unsigned int flags;
	struct rw_semaphore dqio_sem;
	struct inode *files[3];
	struct mem_dqinfo info[3];
	const struct quota_format_ops *ops[3];
};

struct rcu_sync {
	int gp_state;
	int gp_count;
	wait_queue_head_t gp_wait;
	struct callback_head cb_head;
};

struct rcuwait {
	struct task_struct *task;
};

struct percpu_rw_semaphore {
	struct rcu_sync rss;
	unsigned int *read_count;
	struct rcuwait writer;
	wait_queue_head_t waiters;
	atomic_t block;
};

struct sb_writers {
	short unsigned int frozen;
	int freeze_kcount;
	int freeze_ucount;
	struct percpu_rw_semaphore rw_sem[3];
};

struct fsnotify_sb_info;

typedef struct {
	__u8 b[16];
} uuid_t;

struct list_lru_node;

struct list_lru {
	struct list_lru_node *node;
	struct list_head list;
	int shrinker_id;
	bool memcg_aware;
	struct xarray xa;
};

struct super_operations;

struct dquot_operations;

struct quotactl_ops;

struct xattr_handler;

struct block_device;

struct backing_dev_info;

struct super_block {
	struct list_head s_list;
	dev_t s_dev;
	unsigned char s_blocksize_bits;
	long unsigned int s_blocksize;
	loff_t s_maxbytes;
	struct file_system_type *s_type;
	const struct super_operations *s_op;
	const struct dquot_operations *dq_op;
	const struct quotactl_ops *s_qcop;
	const struct export_operations *s_export_op;
	long unsigned int s_flags;
	long unsigned int s_iflags;
	long unsigned int s_magic;
	struct dentry *s_root;
	struct rw_semaphore s_umount;
	int s_count;
	atomic_t s_active;
	void *s_security;
	const struct xattr_handler * const *s_xattr;
	const struct fscrypt_operations *s_cop;
	struct fscrypt_keyring *s_master_keys;
	const struct fsverity_operations *s_vop;
	struct unicode_map *s_encoding;
	__u16 s_encoding_flags;
	struct hlist_bl_head s_roots;
	struct list_head s_mounts;
	struct block_device *s_bdev;
	struct file *s_bdev_file;
	struct backing_dev_info *s_bdi;
	struct mtd_info *s_mtd;
	struct hlist_node s_instances;
	unsigned int s_quota_types;
	struct quota_info s_dquot;
	struct sb_writers s_writers;
	void *s_fs_info;
	u32 s_time_gran;
	time64_t s_time_min;
	time64_t s_time_max;
	u32 s_fsnotify_mask;
	struct fsnotify_sb_info *s_fsnotify_info;
	char s_id[32];
	uuid_t s_uuid;
	u8 s_uuid_len;
	char s_sysfs_name[37];
	unsigned int s_max_links;
	struct mutex s_vfs_rename_mutex;
	const char *s_subtype;
	const struct dentry_operations *s_d_op;
	struct shrinker *s_shrink;
	atomic_long_t s_remove_count;
	int s_readonly_remount;
	errseq_t s_wb_err;
	struct workqueue_struct *s_dio_done_wq;
	struct hlist_head s_pins;
	struct user_namespace *s_user_ns;
	struct list_lru s_dentry_lru;
	struct list_lru s_inode_lru;
	struct callback_head rcu;
	struct work_struct destroy_work;
	struct mutex s_sync_lock;
	int s_stack_depth;
	long: 64;
	spinlock_t s_inode_list_lock;
	struct list_head s_inodes;
	spinlock_t s_inode_wblist_lock;
	struct list_head s_inodes_wb;
	long: 64;
	long: 64;
};

struct mnt_idmap;

struct vfsmount {
	struct dentry *mnt_root;
	struct super_block *mnt_sb;
	int mnt_flags;
	struct mnt_idmap *mnt_idmap;
};

struct kstat {
	u32 result_mask;
	umode_t mode;
	unsigned int nlink;
	uint32_t blksize;
	u64 attributes;
	u64 attributes_mask;
	u64 ino;
	dev_t dev;
	dev_t rdev;
	kuid_t uid;
	kgid_t gid;
	loff_t size;
	struct timespec64 atime;
	struct timespec64 mtime;
	struct timespec64 ctime;
	struct timespec64 btime;
	u64 blocks;
	u64 mnt_id;
	u32 dio_mem_align;
	u32 dio_offset_align;
	u64 change_cookie;
	u64 subvol;
	u32 atomic_write_unit_min;
	u32 atomic_write_unit_max;
	u32 atomic_write_segments_max;
};

struct list_lru_one {
	struct list_head list;
	long int nr_items;
};

struct list_lru_node {
	spinlock_t lock;
	struct list_lru_one lru;
	long int nr_items;
	long: 64;
	long: 64;
	long: 64;
};

enum migrate_mode {
	MIGRATE_ASYNC = 0,
	MIGRATE_SYNC_LIGHT = 1,
	MIGRATE_SYNC = 2,
};

struct exception_table_entry {
	int insn;
	int fixup;
	int data;
};

struct cgroup_base_stat {
	struct task_cputime cputime;
	u64 forceidle_sum;
	u64 ntime;
};

struct bpf_prog_array;

struct cgroup_bpf {
	struct bpf_prog_array *effective[38];
	struct hlist_head progs[38];
	u8 flags[38];
	struct list_head storages;
	struct bpf_prog_array *inactive;
	struct percpu_ref refcnt;
	struct work_struct release_work;
};

struct cgroup_freezer_state {
	bool freeze;
	int e_freeze;
	int nr_frozen_descendants;
	int nr_frozen_tasks;
};

struct cgroup_root;

struct cgroup_rstat_cpu;

struct psi_group;

struct cgroup {
	struct cgroup_subsys_state self;
	long unsigned int flags;
	int level;
	int max_depth;
	int nr_descendants;
	int nr_dying_descendants;
	int max_descendants;
	int nr_populated_csets;
	int nr_populated_domain_children;
	int nr_populated_threaded_children;
	int nr_threaded_children;
	unsigned int kill_seq;
	struct kernfs_node *kn;
	struct cgroup_file procs_file;
	struct cgroup_file events_file;
	struct cgroup_file psi_files[3];
	u16 subtree_control;
	u16 subtree_ss_mask;
	u16 old_subtree_control;
	u16 old_subtree_ss_mask;
	struct cgroup_subsys_state *subsys[14];
	int nr_dying_subsys[14];
	struct cgroup_root *root;
	struct list_head cset_links;
	struct list_head e_csets[14];
	struct cgroup *dom_cgrp;
	struct cgroup *old_dom_cgrp;
	struct cgroup_rstat_cpu *rstat_cpu;
	struct list_head rstat_css_list;
	long: 64;
	long: 64;
	struct cacheline_padding _pad_;
	struct cgroup *rstat_flush_next;
	struct cgroup_base_stat last_bstat;
	struct cgroup_base_stat bstat;
	struct prev_cputime prev_cputime;
	struct list_head pidlists;
	struct mutex pidlist_mutex;
	wait_queue_head_t offline_waitq;
	struct work_struct release_agent_work;
	struct psi_group *psi;
	struct cgroup_bpf bpf;
	struct cgroup_freezer_state freezer;
	struct bpf_local_storage *bpf_cgrp_storage;
	struct cgroup *ancestors[0];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

typedef int proc_handler(const struct ctl_table *, int, void *, size_t *, loff_t *);

struct ctl_table_poll;

struct ctl_table {
	const char *procname;
	void *data;
	int maxlen;
	umode_t mode;
	proc_handler *proc_handler;
	struct ctl_table_poll *poll;
	void *extra1;
	void *extra2;
};

struct ctl_table_poll {
	atomic_t event;
	wait_queue_head_t wait;
};

struct ctl_node {
	struct rb_node node;
	struct ctl_table_header *header;
};

struct ctl_table_root {
	struct ctl_table_set default_set;
	struct ctl_table_set * (*lookup)(struct ctl_table_root *);
	void (*set_ownership)(struct ctl_table_header *, kuid_t *, kgid_t *);
	int (*permissions)(struct ctl_table_header *, const struct ctl_table *);
};

struct key_tag {
	struct callback_head rcu;
	refcount_t usage;
	bool removed;
};

typedef int (*request_key_actor_t)(struct key *, void *);

struct key_preparsed_payload;

struct key_match_data;

struct kernel_pkey_params;

struct kernel_pkey_query;

struct key_type {
	const char *name;
	size_t def_datalen;
	unsigned int flags;
	int (*vet_description)(const char *);
	int (*preparse)(struct key_preparsed_payload *);
	void (*free_preparse)(struct key_preparsed_payload *);
	int (*instantiate)(struct key *, struct key_preparsed_payload *);
	int (*update)(struct key *, struct key_preparsed_payload *);
	int (*match_preparse)(struct key_match_data *);
	void (*match_free)(struct key_match_data *);
	void (*revoke)(struct key *);
	void (*destroy)(struct key *);
	void (*describe)(const struct key *, struct seq_file *);
	long int (*read)(const struct key *, char *, size_t);
	request_key_actor_t request_key;
	struct key_restriction * (*lookup_restriction)(const char *);
	int (*asym_query)(const struct kernel_pkey_params *, struct kernel_pkey_query *);
	int (*asym_eds_op)(struct kernel_pkey_params *, const void *, void *);
	int (*asym_verify_signature)(struct kernel_pkey_params *, const void *, const void *);
	struct list_head link;
	struct lock_class_key lock_class;
};

typedef int (*key_restrict_link_func_t)(struct key *, const struct key_type *, const union key_payload *, struct key *);

struct key_restriction {
	key_restrict_link_func_t check;
	struct key *key;
	struct key_type *keytype;
};

struct user_struct {
	refcount_t __count;
	struct percpu_counter epoll_watches;
	long unsigned int unix_inflight;
	atomic_long_t pipe_bufs;
	struct hlist_node uidhash_node;
	kuid_t uid;
	atomic_long_t locked_vm;
	atomic_t nr_watches;
	struct ratelimit_state ratelimit;
};

struct group_info {
	refcount_t usage;
	int ngroups;
	kgid_t gid[0];
};

struct hrtimer_cpu_base {
	raw_spinlock_t lock;
	unsigned int cpu;
	unsigned int active_bases;
	unsigned int clock_was_set_seq;
	unsigned int hres_active: 1;
	unsigned int in_hrtirq: 1;
	unsigned int hang_detected: 1;
	unsigned int softirq_activated: 1;
	unsigned int online: 1;
	unsigned int nr_events;
	short unsigned int nr_retries;
	short unsigned int nr_hangs;
	unsigned int max_hang_time;
	ktime_t expires_next;
	struct hrtimer *next_timer;
	ktime_t softirq_expires_next;
	struct hrtimer *softirq_next_timer;
	struct hrtimer_clock_base clock_base[8];
	call_single_data_t csd;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct core_thread {
	struct task_struct *task;
	struct core_thread *next;
};

struct core_state {
	atomic_t nr_threads;
	struct core_thread dumper;
	struct completion startup;
};

struct taskstats {
	__u16 version;
	__u32 ac_exitcode;
	__u8 ac_flag;
	__u8 ac_nice;
	__u64 cpu_count;
	__u64 cpu_delay_total;
	__u64 blkio_count;
	__u64 blkio_delay_total;
	__u64 swapin_count;
	__u64 swapin_delay_total;
	__u64 cpu_run_real_total;
	__u64 cpu_run_virtual_total;
	char ac_comm[32];
	__u8 ac_sched;
	__u8 ac_pad[3];
	long: 0;
	__u32 ac_uid;
	__u32 ac_gid;
	__u32 ac_pid;
	__u32 ac_ppid;
	__u32 ac_btime;
	__u64 ac_etime;
	__u64 ac_utime;
	__u64 ac_stime;
	__u64 ac_minflt;
	__u64 ac_majflt;
	__u64 coremem;
	__u64 virtmem;
	__u64 hiwater_rss;
	__u64 hiwater_vm;
	__u64 read_char;
	__u64 write_char;
	__u64 read_syscalls;
	__u64 write_syscalls;
	__u64 read_bytes;
	__u64 write_bytes;
	__u64 cancelled_write_bytes;
	__u64 nvcsw;
	__u64 nivcsw;
	__u64 ac_utimescaled;
	__u64 ac_stimescaled;
	__u64 cpu_scaled_run_real_total;
	__u64 freepages_count;
	__u64 freepages_delay_total;
	__u64 thrashing_count;
	__u64 thrashing_delay_total;
	__u64 ac_btime64;
	__u64 compact_count;
	__u64 compact_delay_total;
	__u32 ac_tgid;
	__u64 ac_tgetime;
	__u64 ac_exe_dev;
	__u64 ac_exe_inode;
	__u64 wpcopy_count;
	__u64 wpcopy_delay_total;
	__u64 irq_count;
	__u64 irq_delay_total;
};

struct delayed_call {
	void (*fn)(void *);
	void *arg;
};

struct request_queue;

struct io_cq {
	struct request_queue *q;
	struct io_context *ioc;
	union {
		struct list_head q_node;
		struct kmem_cache *__rcu_icq_cache;
	};
	union {
		struct hlist_node ioc_node;
		struct callback_head __rcu_head;
	};
	unsigned int flags;
};

typedef struct {
	uid_t val;
} vfsuid_t;

typedef struct {
	gid_t val;
} vfsgid_t;

struct wait_page_queue;

struct kiocb {
	struct file *ki_filp;
	loff_t ki_pos;
	void (*ki_complete)(struct kiocb *, long int);
	void *private;
	int ki_flags;
	u16 ki_ioprio;
	union {
		struct wait_page_queue *ki_waitq;
		ssize_t (*dio_complete)(void *);
	};
};

struct iattr {
	unsigned int ia_valid;
	umode_t ia_mode;
	union {
		kuid_t ia_uid;
		vfsuid_t ia_vfsuid;
	};
	union {
		kgid_t ia_gid;
		vfsgid_t ia_vfsgid;
	};
	loff_t ia_size;
	struct timespec64 ia_atime;
	struct timespec64 ia_mtime;
	struct timespec64 ia_ctime;
	struct file *ia_file;
};

typedef __kernel_uid32_t projid_t;

typedef struct {
	projid_t val;
} kprojid_t;

enum quota_type {
	USRQUOTA = 0,
	GRPQUOTA = 1,
	PRJQUOTA = 2,
};

struct kqid {
	union {
		kuid_t uid;
		kgid_t gid;
		kprojid_t projid;
	};
	enum quota_type type;
};

struct mem_dqblk {
	qsize_t dqb_bhardlimit;
	qsize_t dqb_bsoftlimit;
	qsize_t dqb_curspace;
	qsize_t dqb_rsvspace;
	qsize_t dqb_ihardlimit;
	qsize_t dqb_isoftlimit;
	qsize_t dqb_curinodes;
	time64_t dqb_btime;
	time64_t dqb_itime;
};

struct dquot {
	struct hlist_node dq_hash;
	struct list_head dq_inuse;
	struct list_head dq_free;
	struct list_head dq_dirty;
	struct mutex dq_lock;
	spinlock_t dq_dqb_lock;
	atomic_t dq_count;
	struct super_block *dq_sb;
	struct kqid dq_id;
	loff_t dq_off;
	long unsigned int dq_flags;
	struct mem_dqblk dq_dqb;
};

struct quota_format_type {
	int qf_fmt_id;
	const struct quota_format_ops *qf_ops;
	struct module *qf_owner;
	struct quota_format_type *qf_next;
};

struct quota_format_ops {
	int (*check_quota_file)(struct super_block *, int);
	int (*read_file_info)(struct super_block *, int);
	int (*write_file_info)(struct super_block *, int);
	int (*free_file_info)(struct super_block *, int);
	int (*read_dqblk)(struct dquot *);
	int (*commit_dqblk)(struct dquot *);
	int (*release_dqblk)(struct dquot *);
	int (*get_next_id)(struct super_block *, struct kqid *);
};

struct dquot_operations {
	int (*write_dquot)(struct dquot *);
	struct dquot * (*alloc_dquot)(struct super_block *, int);
	void (*destroy_dquot)(struct dquot *);
	int (*acquire_dquot)(struct dquot *);
	int (*release_dquot)(struct dquot *);
	int (*mark_dirty)(struct dquot *);
	int (*write_info)(struct super_block *, int);
	qsize_t * (*get_reserved_space)(struct inode *);
	int (*get_projid)(struct inode *, kprojid_t *);
	int (*get_inode_usage)(struct inode *, qsize_t *);
	int (*get_next_id)(struct super_block *, struct kqid *);
};

struct qc_dqblk {
	int d_fieldmask;
	u64 d_spc_hardlimit;
	u64 d_spc_softlimit;
	u64 d_ino_hardlimit;
	u64 d_ino_softlimit;
	u64 d_space;
	u64 d_ino_count;
	s64 d_ino_timer;
	s64 d_spc_timer;
	int d_ino_warns;
	int d_spc_warns;
	u64 d_rt_spc_hardlimit;
	u64 d_rt_spc_softlimit;
	u64 d_rt_space;
	s64 d_rt_spc_timer;
	int d_rt_spc_warns;
};

struct qc_type_state {
	unsigned int flags;
	unsigned int spc_timelimit;
	unsigned int ino_timelimit;
	unsigned int rt_spc_timelimit;
	unsigned int spc_warnlimit;
	unsigned int ino_warnlimit;
	unsigned int rt_spc_warnlimit;
	long long unsigned int ino;
	blkcnt_t blocks;
	blkcnt_t nextents;
};

struct qc_state {
	unsigned int s_incoredqs;
	struct qc_type_state s_state[3];
};

struct qc_info {
	int i_fieldmask;
	unsigned int i_flags;
	unsigned int i_spc_timelimit;
	unsigned int i_ino_timelimit;
	unsigned int i_rt_spc_timelimit;
	unsigned int i_spc_warnlimit;
	unsigned int i_ino_warnlimit;
	unsigned int i_rt_spc_warnlimit;
};

struct quotactl_ops {
	int (*quota_on)(struct super_block *, int, int, const struct path *);
	int (*quota_off)(struct super_block *, int);
	int (*quota_enable)(struct super_block *, unsigned int);
	int (*quota_disable)(struct super_block *, unsigned int);
	int (*quota_sync)(struct super_block *, int);
	int (*set_info)(struct super_block *, int, struct qc_info *);
	int (*get_dqblk)(struct super_block *, struct kqid, struct qc_dqblk *);
	int (*get_nextdqblk)(struct super_block *, struct kqid *, struct qc_dqblk *);
	int (*set_dqblk)(struct super_block *, struct kqid, struct qc_dqblk *);
	int (*get_state)(struct super_block *, struct qc_state *);
	int (*rm_xquota)(struct super_block *, unsigned int);
};

struct wait_page_queue {
	struct folio *folio;
	int bit_nr;
	wait_queue_entry_t wait;
};

struct writeback_control;

struct readahead_control;

struct swap_info_struct;

struct address_space_operations {
	int (*writepage)(struct page *, struct writeback_control *);
	int (*read_folio)(struct file *, struct folio *);
	int (*writepages)(struct address_space *, struct writeback_control *);
	bool (*dirty_folio)(struct address_space *, struct folio *);
	void (*readahead)(struct readahead_control *);
	int (*write_begin)(struct file *, struct address_space *, loff_t, unsigned int, struct folio **, void **);
	int (*write_end)(struct file *, struct address_space *, loff_t, unsigned int, unsigned int, struct folio *, void *);
	sector_t (*bmap)(struct address_space *, sector_t);
	void (*invalidate_folio)(struct folio *, size_t, size_t);
	bool (*release_folio)(struct folio *, gfp_t);
	void (*free_folio)(struct folio *);
	ssize_t (*direct_IO)(struct kiocb *, struct iov_iter *);
	int (*migrate_folio)(struct address_space *, struct folio *, struct folio *, enum migrate_mode);
	int (*launder_folio)(struct folio *);
	bool (*is_partially_uptodate)(struct folio *, size_t, size_t);
	void (*is_dirty_writeback)(struct folio *, bool *, bool *);
	int (*error_remove_folio)(struct address_space *, struct folio *);
	int (*swap_activate)(struct swap_info_struct *, struct file *, sector_t *);
	void (*swap_deactivate)(struct file *);
	int (*swap_rw)(struct kiocb *, struct iov_iter *);
};

enum writeback_sync_modes {
	WB_SYNC_NONE = 0,
	WB_SYNC_ALL = 1,
};

struct swap_iocb;

struct folio_batch {
	unsigned char nr;
	unsigned char i;
	bool percpu_pvec_drained;
	struct folio *folios[31];
};

struct writeback_control {
	long int nr_to_write;
	long int pages_skipped;
	loff_t range_start;
	loff_t range_end;
	enum writeback_sync_modes sync_mode;
	unsigned int for_kupdate: 1;
	unsigned int for_background: 1;
	unsigned int tagged_writepages: 1;
	unsigned int for_reclaim: 1;
	unsigned int range_cyclic: 1;
	unsigned int for_sync: 1;
	unsigned int unpinned_netfs_wb: 1;
	unsigned int no_cgroup_owner: 1;
	struct swap_iocb **swap_plug;
	struct list_head *list;
	struct folio_batch fbatch;
	long unsigned int index;
	int saved_err;
	struct bdi_writeback *wb;
	struct inode *inode;
	int wb_id;
	int wb_lcand_id;
	int wb_tcand_id;
	size_t wb_bytes;
	size_t wb_lcand_bytes;
	size_t wb_tcand_bytes;
};

struct readahead_control {
	struct file *file;
	struct address_space *mapping;
	struct file_ra_state *ra;
	long unsigned int _index;
	unsigned int _nr_pages;
	unsigned int _batch_count;
	bool _workingset;
	long unsigned int _pflags;
};

struct iovec {
	void *iov_base;
	__kernel_size_t iov_len;
};

struct folio_queue;

struct kvec;

struct bio_vec;

struct iov_iter {
	u8 iter_type;
	bool nofault;
	bool data_source;
	size_t iov_offset;
	union {
		struct iovec __ubuf_iovec;
		struct {
			union {
				const struct iovec *__iov;
				const struct kvec *kvec;
				const struct bio_vec *bvec;
				const struct folio_queue *folioq;
				struct xarray *xarray;
				void *ubuf;
			};
			size_t count;
		};
	};
	union {
		long unsigned int nr_segs;
		u8 folioq_slot;
		loff_t xarray_start;
	};
};

struct swap_cluster_info;

struct percpu_cluster;

struct swap_info_struct {
	struct percpu_ref users;
	long unsigned int flags;
	short int prio;
	struct plist_node list;
	signed char type;
	unsigned int max;
	unsigned char *swap_map;
	long unsigned int *zeromap;
	struct swap_cluster_info *cluster_info;
	struct list_head free_clusters;
	struct list_head full_clusters;
	struct list_head nonfull_clusters[10];
	struct list_head frag_clusters[10];
	unsigned int frag_cluster_nr[10];
	unsigned int lowest_bit;
	unsigned int highest_bit;
	unsigned int pages;
	unsigned int inuse_pages;
	unsigned int cluster_next;
	unsigned int cluster_nr;
	unsigned int *cluster_next_cpu;
	struct percpu_cluster *percpu_cluster;
	struct rb_root swap_extent_root;
	struct block_device *bdev;
	struct file *swap_file;
	struct completion comp;
	spinlock_t lock;
	spinlock_t cont_lock;
	struct work_struct discard_work;
	struct work_struct reclaim_work;
	struct list_head discard_clusters;
	struct plist_node avail_lists[0];
};

struct posix_acl_entry {
	short int e_tag;
	short unsigned int e_perm;
	union {
		kuid_t e_uid;
		kgid_t e_gid;
	};
};

struct posix_acl {
	refcount_t a_refcount;
	struct callback_head a_rcu;
	unsigned int a_count;
	struct posix_acl_entry a_entries[0];
};

struct fiemap_extent_info;

struct fileattr;

struct offset_ctx;

struct inode_operations {
	struct dentry * (*lookup)(struct inode *, struct dentry *, unsigned int);
	const char * (*get_link)(struct dentry *, struct inode *, struct delayed_call *);
	int (*permission)(struct mnt_idmap *, struct inode *, int);
	struct posix_acl * (*get_inode_acl)(struct inode *, int, bool);
	int (*readlink)(struct dentry *, char *, int);
	int (*create)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t, bool);
	int (*link)(struct dentry *, struct inode *, struct dentry *);
	int (*unlink)(struct inode *, struct dentry *);
	int (*symlink)(struct mnt_idmap *, struct inode *, struct dentry *, const char *);
	int (*mkdir)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t);
	int (*rmdir)(struct inode *, struct dentry *);
	int (*mknod)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t, dev_t);
	int (*rename)(struct mnt_idmap *, struct inode *, struct dentry *, struct inode *, struct dentry *, unsigned int);
	int (*setattr)(struct mnt_idmap *, struct dentry *, struct iattr *);
	int (*getattr)(struct mnt_idmap *, const struct path *, struct kstat *, u32, unsigned int);
	ssize_t (*listxattr)(struct dentry *, char *, size_t);
	int (*fiemap)(struct inode *, struct fiemap_extent_info *, u64, u64);
	int (*update_time)(struct inode *, int);
	int (*atomic_open)(struct inode *, struct dentry *, struct file *, unsigned int, umode_t);
	int (*tmpfile)(struct mnt_idmap *, struct inode *, struct file *, umode_t);
	struct posix_acl * (*get_acl)(struct mnt_idmap *, struct dentry *, int);
	int (*set_acl)(struct mnt_idmap *, struct dentry *, struct posix_acl *, int);
	int (*fileattr_set)(struct mnt_idmap *, struct dentry *, struct fileattr *);
	int (*fileattr_get)(struct dentry *, struct fileattr *);
	struct offset_ctx * (*get_offset_ctx)(struct inode *);
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct fprop_local_percpu {
	struct percpu_counter events;
	unsigned int period;
	raw_spinlock_t lock;
};

enum wb_reason {
	WB_REASON_BACKGROUND = 0,
	WB_REASON_VMSCAN = 1,
	WB_REASON_SYNC = 2,
	WB_REASON_PERIODIC = 3,
	WB_REASON_LAPTOP_TIMER = 4,
	WB_REASON_FS_FREE_SPACE = 5,
	WB_REASON_FORKER_THREAD = 6,
	WB_REASON_FOREIGN_FLUSH = 7,
	WB_REASON_MAX = 8,
};

struct bdi_writeback {
	struct backing_dev_info *bdi;
	long unsigned int state;
	long unsigned int last_old_flush;
	struct list_head b_dirty;
	struct list_head b_io;
	struct list_head b_more_io;
	struct list_head b_dirty_time;
	spinlock_t list_lock;
	atomic_t writeback_inodes;
	struct percpu_counter stat[4];
	long unsigned int bw_time_stamp;
	long unsigned int dirtied_stamp;
	long unsigned int written_stamp;
	long unsigned int write_bandwidth;
	long unsigned int avg_write_bandwidth;
	long unsigned int dirty_ratelimit;
	long unsigned int balanced_dirty_ratelimit;
	struct fprop_local_percpu completions;
	int dirty_exceeded;
	enum wb_reason start_all_reason;
	spinlock_t work_lock;
	struct list_head work_list;
	struct delayed_work dwork;
	struct delayed_work bw_dwork;
	struct list_head bdi_node;
	struct percpu_ref refcnt;
	struct fprop_local_percpu memcg_completions;
	struct cgroup_subsys_state *memcg_css;
	struct cgroup_subsys_state *blkcg_css;
	struct list_head memcg_node;
	struct list_head blkcg_node;
	struct list_head b_attached;
	struct list_head offline_node;
	union {
		struct work_struct release_work;
		struct callback_head rcu;
	};
};

struct file_lock_context {
	spinlock_t flc_lock;
	struct list_head flc_flock;
	struct list_head flc_posix;
	struct list_head flc_lease;
};

struct fown_struct {
	struct file *file;
	rwlock_t lock;
	struct pid *pid;
	enum pid_type pid_type;
	kuid_t uid;
	kuid_t euid;
	int signum;
};

struct fasync_struct {
	rwlock_t fa_lock;
	int magic;
	int fa_fd;
	struct fasync_struct *fa_next;
	struct file *fa_file;
	struct callback_head fa_rcu;
};

enum freeze_holder {
	FREEZE_HOLDER_KERNEL = 1,
	FREEZE_HOLDER_USERSPACE = 2,
	FREEZE_MAY_NEST = 4,
};

struct kstatfs;

struct super_operations {
	struct inode * (*alloc_inode)(struct super_block *);
	void (*destroy_inode)(struct inode *);
	void (*free_inode)(struct inode *);
	void (*dirty_inode)(struct inode *, int);
	int (*write_inode)(struct inode *, struct writeback_control *);
	int (*drop_inode)(struct inode *);
	void (*evict_inode)(struct inode *);
	void (*put_super)(struct super_block *);
	int (*sync_fs)(struct super_block *, int);
	int (*freeze_super)(struct super_block *, enum freeze_holder);
	int (*freeze_fs)(struct super_block *);
	int (*thaw_super)(struct super_block *, enum freeze_holder);
	int (*unfreeze_fs)(struct super_block *);
	int (*statfs)(struct dentry *, struct kstatfs *);
	int (*remount_fs)(struct super_block *, int *, char *);
	void (*umount_begin)(struct super_block *);
	int (*show_options)(struct seq_file *, struct dentry *);
	int (*show_devname)(struct seq_file *, struct dentry *);
	int (*show_path)(struct seq_file *, struct dentry *);
	int (*show_stats)(struct seq_file *, struct dentry *);
	ssize_t (*quota_read)(struct super_block *, int, char *, size_t, loff_t);
	ssize_t (*quota_write)(struct super_block *, int, const char *, size_t, loff_t);
	struct dquot ** (*get_dquots)(struct inode *);
	long int (*nr_cached_objects)(struct super_block *, struct shrink_control *);
	long int (*free_cached_objects)(struct super_block *, struct shrink_control *);
	void (*shutdown)(struct super_block *);
};

struct xattr_handler {
	const char *name;
	const char *prefix;
	int flags;
	bool (*list)(struct dentry *);
	int (*get)(const struct xattr_handler *, struct dentry *, struct inode *, const char *, void *, size_t);
	int (*set)(const struct xattr_handler *, struct mnt_idmap *, struct dentry *, struct inode *, const char *, const void *, size_t, int);
};

struct disk_stats;

struct device_private;

enum dl_dev_state {
	DL_DEV_NO_DRIVER = 0,
	DL_DEV_PROBING = 1,
	DL_DEV_DRIVER_BOUND = 2,
	DL_DEV_UNBINDING = 3,
};

struct dev_links_info {
	struct list_head suppliers;
	struct list_head consumers;
	struct list_head defer_sync;
	enum dl_dev_state status;
};

struct pm_message {
	int event;
};

typedef struct pm_message pm_message_t;

struct wake_irq;

enum rpm_request {
	RPM_REQ_NONE = 0,
	RPM_REQ_IDLE = 1,
	RPM_REQ_SUSPEND = 2,
	RPM_REQ_AUTOSUSPEND = 3,
	RPM_REQ_RESUME = 4,
};

enum rpm_status {
	RPM_INVALID = -1,
	RPM_ACTIVE = 0,
	RPM_RESUMING = 1,
	RPM_SUSPENDED = 2,
	RPM_SUSPENDING = 3,
};

struct dev_pm_qos;

struct wakeup_source;

struct pm_subsys_data;

struct device;

struct dev_pm_info {
	pm_message_t power_state;
	bool can_wakeup: 1;
	bool async_suspend: 1;
	bool in_dpm_list: 1;
	bool is_prepared: 1;
	bool is_suspended: 1;
	bool is_noirq_suspended: 1;
	bool is_late_suspended: 1;
	bool no_pm: 1;
	bool early_init: 1;
	bool direct_complete: 1;
	u32 driver_flags;
	spinlock_t lock;
	struct list_head entry;
	struct completion completion;
	struct wakeup_source *wakeup;
	bool wakeup_path: 1;
	bool syscore: 1;
	bool no_pm_callbacks: 1;
	bool async_in_progress: 1;
	bool must_resume: 1;
	bool may_skip_resume: 1;
	struct hrtimer suspend_timer;
	u64 timer_expires;
	struct work_struct work;
	wait_queue_head_t wait_queue;
	struct wake_irq *wakeirq;
	atomic_t usage_count;
	atomic_t child_count;
	unsigned int disable_depth: 3;
	bool idle_notification: 1;
	bool request_pending: 1;
	bool deferred_resume: 1;
	bool needs_force_resume: 1;
	bool runtime_auto: 1;
	bool ignore_children: 1;
	bool no_callbacks: 1;
	bool irq_safe: 1;
	bool use_autosuspend: 1;
	bool timer_autosuspends: 1;
	bool memalloc_noio: 1;
	unsigned int links_count;
	enum rpm_request request;
	enum rpm_status runtime_status;
	enum rpm_status last_status;
	int runtime_error;
	int autosuspend_delay;
	u64 last_busy;
	u64 active_time;
	u64 suspended_time;
	u64 accounting_timestamp;
	struct pm_subsys_data *subsys_data;
	void (*set_latency_tolerance)(struct device *, s32);
	struct dev_pm_qos *qos;
};

struct dev_pin_info;

struct msi_device_data;

struct dev_msi_info {
	struct irq_domain *domain;
	struct msi_device_data *data;
};

struct dma_map_ops;

struct bus_dma_region;

struct io_tlb_mem;

struct dev_archdata {};

struct device_node;

struct iommu_group;

struct dev_iommu;

enum device_removable {
	DEVICE_REMOVABLE_NOT_SUPPORTED = 0,
	DEVICE_REMOVABLE_UNKNOWN = 1,
	DEVICE_FIXED = 2,
	DEVICE_REMOVABLE = 3,
};

struct device_type;

struct bus_type;

struct device_driver;

struct dev_pm_domain;

struct em_perf_domain;

struct device_dma_parameters;

struct fwnode_handle;

struct class;

struct device_physical_location;

struct device {
	struct kobject kobj;
	struct device *parent;
	struct device_private *p;
	const char *init_name;
	const struct device_type *type;
	const struct bus_type *bus;
	struct device_driver *driver;
	void *platform_data;
	void *driver_data;
	struct mutex mutex;
	struct dev_links_info links;
	struct dev_pm_info power;
	struct dev_pm_domain *pm_domain;
	struct em_perf_domain *em_pd;
	struct dev_pin_info *pins;
	struct dev_msi_info msi;
	const struct dma_map_ops *dma_ops;
	u64 *dma_mask;
	u64 coherent_dma_mask;
	u64 bus_dma_limit;
	const struct bus_dma_region *dma_range_map;
	struct device_dma_parameters *dma_parms;
	struct list_head dma_pools;
	struct io_tlb_mem *dma_io_tlb_mem;
	struct dev_archdata archdata;
	struct device_node *of_node;
	struct fwnode_handle *fwnode;
	int numa_node;
	dev_t devt;
	u32 id;
	spinlock_t devres_lock;
	struct list_head devres_head;
	const struct class *class;
	const struct attribute_group **groups;
	void (*release)(struct device *);
	struct iommu_group *iommu_group;
	struct dev_iommu *iommu;
	struct device_physical_location *physical_location;
	enum device_removable removable;
	bool offline_disabled: 1;
	bool offline: 1;
	bool of_node_reused: 1;
	bool state_synced: 1;
	bool can_match: 1;
	bool dma_skip_sync: 1;
	bool dma_iommu: 1;
};

struct blk_holder_ops;

struct partition_meta_info;

struct block_device {
	sector_t bd_start_sect;
	sector_t bd_nr_sectors;
	struct gendisk *bd_disk;
	struct request_queue *bd_queue;
	struct disk_stats *bd_stats;
	long unsigned int bd_stamp;
	atomic_t __bd_flags;
	dev_t bd_dev;
	struct address_space *bd_mapping;
	atomic_t bd_openers;
	spinlock_t bd_size_lock;
	void *bd_claiming;
	void *bd_holder;
	const struct blk_holder_ops *bd_holder_ops;
	struct mutex bd_holder_lock;
	int bd_holders;
	struct kobject *bd_holder_dir;
	atomic_t bd_fsfreeze_count;
	struct mutex bd_fsfreeze_mutex;
	struct partition_meta_info *bd_meta_info;
	int bd_writers;
	void *bd_security;
	struct device bd_device;
};

struct backing_dev_info {
	u64 id;
	struct rb_node rb_node;
	struct list_head bdi_list;
	long unsigned int ra_pages;
	long unsigned int io_pages;
	struct kref refcnt;
	unsigned int capabilities;
	unsigned int min_ratio;
	unsigned int max_ratio;
	unsigned int max_prop_frac;
	atomic_long_t tot_write_bandwidth;
	long unsigned int last_bdp_sleep;
	struct bdi_writeback wb;
	struct list_head wb_list;
	struct xarray cgwb_tree;
	struct mutex cgwb_release_mutex;
	struct rw_semaphore wb_switch_rwsem;
	wait_queue_head_t wb_waitq;
	struct device *dev;
	char dev_name[64];
	struct device *owner;
	struct timer_list laptop_mode_wb_timer;
	struct dentry *debug_dir;
};

typedef bool (*filldir_t)(struct dir_context *, const char *, int, loff_t, u64, unsigned int);

struct dir_context {
	filldir_t actor;
	loff_t pos;
};

typedef void (*poll_queue_proc)(struct file *, wait_queue_head_t *, struct poll_table_struct *);

struct poll_table_struct {
	poll_queue_proc _qproc;
	__poll_t _key;
};

struct file_lock_core {
	struct file_lock_core *flc_blocker;
	struct list_head flc_list;
	struct hlist_node flc_link;
	struct list_head flc_blocked_requests;
	struct list_head flc_blocked_member;
	fl_owner_t flc_owner;
	unsigned int flc_flags;
	unsigned char flc_type;
	pid_t flc_pid;
	int flc_link_cpu;
	wait_queue_head_t flc_wait;
	struct file *flc_file;
};

struct nlm_lockowner;

struct nfs_lock_info {
	u32 state;
	struct nlm_lockowner *owner;
	struct list_head list;
};

struct nfs4_lock_state;

struct nfs4_lock_info {
	struct nfs4_lock_state *owner;
};

struct file_lock_operations;

struct lock_manager_operations;

struct file_lock {
	struct file_lock_core c;
	loff_t fl_start;
	loff_t fl_end;
	const struct file_lock_operations *fl_ops;
	const struct lock_manager_operations *fl_lmops;
	union {
		struct nfs_lock_info nfs_fl;
		struct nfs4_lock_info nfs4_fl;
		struct {
			struct list_head link;
			int state;
			unsigned int debug_id;
		} afs;
		struct {
			struct inode *inode;
		} ceph;
	} fl_u;
};

struct lease_manager_operations;

struct file_lease {
	struct file_lock_core c;
	struct fasync_struct *fl_fasync;
	long unsigned int fl_break_time;
	long unsigned int fl_downgrade_time;
	const struct lease_manager_operations *fl_lmops;
};

struct seq_file {
	char *buf;
	size_t size;
	size_t from;
	size_t count;
	size_t pad_until;
	loff_t index;
	loff_t read_pos;
	struct mutex lock;
	const struct seq_operations *op;
	int poll_event;
	const struct file *file;
	void *private;
};

struct offset_ctx {
	struct maple_tree mt;
	long unsigned int next_offset;
};

struct fc_log;

struct p_log {
	const char *prefix;
	struct fc_log *log;
};

enum fs_context_purpose {
	FS_CONTEXT_FOR_MOUNT = 0,
	FS_CONTEXT_FOR_SUBMOUNT = 1,
	FS_CONTEXT_FOR_RECONFIGURE = 2,
};

enum fs_context_phase {
	FS_CONTEXT_CREATE_PARAMS = 0,
	FS_CONTEXT_CREATING = 1,
	FS_CONTEXT_AWAITING_MOUNT = 2,
	FS_CONTEXT_AWAITING_RECONF = 3,
	FS_CONTEXT_RECONF_PARAMS = 4,
	FS_CONTEXT_RECONFIGURING = 5,
	FS_CONTEXT_FAILED = 6,
};

struct fs_context_operations;

struct fs_context {
	const struct fs_context_operations *ops;
	struct mutex uapi_mutex;
	struct file_system_type *fs_type;
	void *fs_private;
	void *sget_key;
	struct dentry *root;
	struct user_namespace *user_ns;
	struct net *net_ns;
	const struct cred *cred;
	struct p_log log;
	const char *source;
	void *security;
	void *s_fs_info;
	unsigned int sb_flags;
	unsigned int sb_flags_mask;
	unsigned int s_iflags;
	enum fs_context_purpose purpose: 8;
	enum fs_context_phase phase: 8;
	bool need_free: 1;
	bool global: 1;
	bool oldapi: 1;
	bool exclusive: 1;
};

struct audit_names;

struct filename {
	const char *name;
	const char *uptr;
	atomic_t refcnt;
	struct audit_names *aname;
	const char iname[0];
};

typedef __u32 blk_opf_t;

typedef u8 blk_status_t;

struct bvec_iter {
	sector_t bi_sector;
	unsigned int bi_size;
	unsigned int bi_idx;
	unsigned int bi_bvec_done;
} __attribute__((packed));

typedef unsigned int blk_qc_t;

typedef void bio_end_io_t(struct bio *);

struct blkcg_gq;

struct bio_issue {
	u64 value;
};

struct bio_crypt_ctx;

struct bio_integrity_payload;

struct bio_vec {
	struct page *bv_page;
	unsigned int bv_len;
	unsigned int bv_offset;
};

struct bio_set;

struct bio {
	struct bio *bi_next;
	struct block_device *bi_bdev;
	blk_opf_t bi_opf;
	short unsigned int bi_flags;
	short unsigned int bi_ioprio;
	enum rw_hint bi_write_hint;
	blk_status_t bi_status;
	atomic_t __bi_remaining;
	struct bvec_iter bi_iter;
	union {
		blk_qc_t bi_cookie;
		unsigned int __bi_nr_segments;
	};
	bio_end_io_t *bi_end_io;
	void *bi_private;
	struct blkcg_gq *bi_blkg;
	struct bio_issue bi_issue;
	u64 bi_iocost_cost;
	struct bio_crypt_ctx *bi_crypt_context;
	struct bio_integrity_payload *bi_integrity;
	short unsigned int bi_vcnt;
	short unsigned int bi_max_vecs;
	atomic_t __bi_cnt;
	struct bio_vec *bi_io_vec;
	struct bio_set *bi_pool;
	struct bio_vec bi_inline_vecs[0];
};

struct idr {
	struct xarray idr_rt;
	unsigned int idr_base;
	unsigned int idr_next;
};

struct kernfs_root;

struct kernfs_elem_dir {
	long unsigned int subdirs;
	struct rb_root children;
	struct kernfs_root *root;
	long unsigned int rev;
};

struct kernfs_elem_symlink {
	struct kernfs_node *target_kn;
};

struct kernfs_open_node;

struct kernfs_ops;

struct kernfs_elem_attr {
	const struct kernfs_ops *ops;
	struct kernfs_open_node *open;
	loff_t size;
	struct kernfs_node *notify_next;
};

struct kernfs_iattrs;

struct kernfs_node {
	atomic_t count;
	atomic_t active;
	struct kernfs_node *parent;
	const char *name;
	struct rb_node rb;
	const void *ns;
	unsigned int hash;
	short unsigned int flags;
	umode_t mode;
	union {
		struct kernfs_elem_dir dir;
		struct kernfs_elem_symlink symlink;
		struct kernfs_elem_attr attr;
	};
	u64 id;
	void *priv;
	struct kernfs_iattrs *iattr;
	struct callback_head rcu;
};

struct kernfs_open_file;

struct kernfs_ops {
	int (*open)(struct kernfs_open_file *);
	void (*release)(struct kernfs_open_file *);
	int (*seq_show)(struct seq_file *, void *);
	void * (*seq_start)(struct seq_file *, loff_t *);
	void * (*seq_next)(struct seq_file *, void *, loff_t *);
	void (*seq_stop)(struct seq_file *, void *);
	ssize_t (*read)(struct kernfs_open_file *, char *, size_t, loff_t);
	size_t atomic_write_len;
	bool prealloc;
	ssize_t (*write)(struct kernfs_open_file *, char *, size_t, loff_t);
	__poll_t (*poll)(struct kernfs_open_file *, struct poll_table_struct *);
	int (*mmap)(struct kernfs_open_file *, struct vm_area_struct *);
	loff_t (*llseek)(struct kernfs_open_file *, loff_t, int);
};

struct kernfs_open_file {
	struct kernfs_node *kn;
	struct file *file;
	struct seq_file *seq_file;
	void *priv;
	struct mutex mutex;
	struct mutex prealloc_mutex;
	int event;
	struct list_head list;
	char *prealloc_buf;
	size_t atomic_write_len;
	bool mmapped: 1;
	bool released: 1;
	const struct vm_operations_struct *vm_ops;
};

enum kobj_ns_type {
	KOBJ_NS_TYPE_NONE = 0,
	KOBJ_NS_TYPE_NET = 1,
	KOBJ_NS_TYPES = 2,
};

struct sock;

struct kobj_ns_type_operations {
	enum kobj_ns_type type;
	bool (*current_may_mount)();
	void * (*grab_current_ns)();
	const void * (*netlink_ns)(struct sock *);
	const void * (*initial_ns)();
	void (*drop_ns)(void *);
};

typedef __u64 __addrpair;

typedef __u32 __portpair;

typedef struct {
	struct net *net;
} possible_net_t;

struct proto;

struct inet_timewait_death_row;

struct sock_common {
	union {
		__addrpair skc_addrpair;
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		unsigned int skc_hash;
		__u16 skc_u16hashes[2];
	};
	union {
		__portpair skc_portpair;
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	short unsigned int skc_family;
	volatile unsigned char skc_state;
	unsigned char skc_reuse: 4;
	unsigned char skc_reuseport: 1;
	unsigned char skc_ipv6only: 1;
	unsigned char skc_net_refcnt: 1;
	int skc_bound_dev_if;
	union {
		struct hlist_node skc_bind_node;
		struct hlist_node skc_portaddr_node;
	};
	struct proto *skc_prot;
	possible_net_t skc_net;
	atomic64_t skc_cookie;
	union {
		long unsigned int skc_flags;
		struct sock *skc_listener;
		struct inet_timewait_death_row *skc_tw_dr;
	};
	int skc_dontcopy_begin[0];
	union {
		struct hlist_node skc_node;
		struct hlist_nulls_node skc_nulls_node;
	};
	short unsigned int skc_tx_queue_mapping;
	short unsigned int skc_rx_queue_mapping;
	union {
		int skc_incoming_cpu;
		u32 skc_rcv_wnd;
		u32 skc_tw_rcv_nxt;
	};
	refcount_t skc_refcnt;
	int skc_dontcopy_end[0];
	union {
		u32 skc_rxhash;
		u32 skc_window_clamp;
		u32 skc_tw_snd_nxt;
	};
};

struct sk_buff;

struct sk_buff_list {
	struct sk_buff *next;
	struct sk_buff *prev;
};

struct sk_buff_head {
	union {
		struct {
			struct sk_buff *next;
			struct sk_buff *prev;
		};
		struct sk_buff_list list;
	};
	__u32 qlen;
	spinlock_t lock;
};

struct sk_filter;

struct xfrm_policy;

typedef struct {
	spinlock_t slock;
	int owned;
	wait_queue_head_t wq;
} socket_lock_t;

typedef u64 netdev_features_t;

struct sock_cgroup_data {
	struct cgroup *cgroup;
	u32 classid;
	u16 prioidx;
};

struct sock_reuseport;

typedef struct {} netns_tracker;

struct dst_entry;

struct socket_wq;

struct socket;

struct net_device;

struct sock {
	struct sock_common __sk_common;
	__u8 __cacheline_group_begin__sock_write_rx[0];
	atomic_t sk_drops;
	__s32 sk_peek_off;
	struct sk_buff_head sk_error_queue;
	struct sk_buff_head sk_receive_queue;
	struct {
		atomic_t rmem_alloc;
		int len;
		struct sk_buff *head;
		struct sk_buff *tail;
	} sk_backlog;
	__u8 __cacheline_group_end__sock_write_rx[0];
	__u8 __cacheline_group_begin__sock_read_rx[0];
	struct dst_entry *sk_rx_dst;
	int sk_rx_dst_ifindex;
	u32 sk_rx_dst_cookie;
	unsigned int sk_ll_usec;
	unsigned int sk_napi_id;
	u16 sk_busy_poll_budget;
	u8 sk_prefer_busy_poll;
	u8 sk_userlocks;
	int sk_rcvbuf;
	struct sk_filter *sk_filter;
	union {
		struct socket_wq *sk_wq;
		struct socket_wq *sk_wq_raw;
	};
	void (*sk_data_ready)(struct sock *);
	long int sk_rcvtimeo;
	int sk_rcvlowat;
	__u8 __cacheline_group_end__sock_read_rx[0];
	__u8 __cacheline_group_begin__sock_read_rxtx[0];
	int sk_err;
	struct socket *sk_socket;
	struct mem_cgroup *sk_memcg;
	struct xfrm_policy *sk_policy[2];
	__u8 __cacheline_group_end__sock_read_rxtx[0];
	__u8 __cacheline_group_begin__sock_write_rxtx[0];
	socket_lock_t sk_lock;
	u32 sk_reserved_mem;
	int sk_forward_alloc;
	u32 sk_tsflags;
	__u8 __cacheline_group_end__sock_write_rxtx[0];
	__u8 __cacheline_group_begin__sock_write_tx[0];
	int sk_write_pending;
	atomic_t sk_omem_alloc;
	int sk_sndbuf;
	int sk_wmem_queued;
	refcount_t sk_wmem_alloc;
	long unsigned int sk_tsq_flags;
	union {
		struct sk_buff *sk_send_head;
		struct rb_root tcp_rtx_queue;
	};
	struct sk_buff_head sk_write_queue;
	u32 sk_dst_pending_confirm;
	u32 sk_pacing_status;
	struct page_frag sk_frag;
	struct timer_list sk_timer;
	long unsigned int sk_pacing_rate;
	atomic_t sk_zckey;
	atomic_t sk_tskey;
	__u8 __cacheline_group_end__sock_write_tx[0];
	__u8 __cacheline_group_begin__sock_read_tx[0];
	long unsigned int sk_max_pacing_rate;
	long int sk_sndtimeo;
	u32 sk_priority;
	u32 sk_mark;
	struct dst_entry *sk_dst_cache;
	netdev_features_t sk_route_caps;
	struct sk_buff * (*sk_validate_xmit_skb)(struct sock *, struct net_device *, struct sk_buff *);
	u16 sk_gso_type;
	u16 sk_gso_max_segs;
	unsigned int sk_gso_max_size;
	gfp_t sk_allocation;
	u32 sk_txhash;
	u8 sk_pacing_shift;
	bool sk_use_task_frag;
	__u8 __cacheline_group_end__sock_read_tx[0];
	u8 sk_gso_disabled: 1;
	u8 sk_kern_sock: 1;
	u8 sk_no_check_tx: 1;
	u8 sk_no_check_rx: 1;
	u8 sk_shutdown;
	u16 sk_type;
	u16 sk_protocol;
	long unsigned int sk_lingertime;
	struct proto *sk_prot_creator;
	rwlock_t sk_callback_lock;
	int sk_err_soft;
	u32 sk_ack_backlog;
	u32 sk_max_ack_backlog;
	kuid_t sk_uid;
	spinlock_t sk_peer_lock;
	int sk_bind_phc;
	struct pid *sk_peer_pid;
	const struct cred *sk_peer_cred;
	ktime_t sk_stamp;
	int sk_disconnects;
	u8 sk_txrehash;
	u8 sk_clockid;
	u8 sk_txtime_deadline_mode: 1;
	u8 sk_txtime_report_errors: 1;
	u8 sk_txtime_unused: 6;
	void *sk_user_data;
	void *sk_security;
	struct sock_cgroup_data sk_cgrp_data;
	void (*sk_state_change)(struct sock *);
	void (*sk_write_space)(struct sock *);
	void (*sk_error_report)(struct sock *);
	int (*sk_backlog_rcv)(struct sock *, struct sk_buff *);
	void (*sk_destruct)(struct sock *);
	struct sock_reuseport *sk_reuseport_cb;
	struct bpf_local_storage *sk_bpf_storage;
	struct callback_head sk_rcu;
	netns_tracker ns_tracker;
	struct xarray sk_user_frags;
};

struct attribute {
	const char *name;
	umode_t mode;
};

struct bin_attribute {
	struct attribute attr;
	size_t size;
	void *private;
	struct address_space * (*f_mapping)();
	ssize_t (*read)(struct file *, struct kobject *, struct bin_attribute *, char *, loff_t, size_t);
	ssize_t (*write)(struct file *, struct kobject *, struct bin_attribute *, char *, loff_t, size_t);
	loff_t (*llseek)(struct file *, struct kobject *, struct bin_attribute *, loff_t, int);
	int (*mmap)(struct file *, struct kobject *, struct bin_attribute *, struct vm_area_struct *);
};

struct sysfs_ops {
	ssize_t (*show)(struct kobject *, struct attribute *, char *);
	ssize_t (*store)(struct kobject *, struct attribute *, const char *, size_t);
};

struct kset_uevent_ops;

struct kset {
	struct list_head list;
	spinlock_t list_lock;
	struct kobject kobj;
	const struct kset_uevent_ops *uevent_ops;
};

struct kobj_type {
	void (*release)(struct kobject *);
	const struct sysfs_ops *sysfs_ops;
	const struct attribute_group **default_groups;
	const struct kobj_ns_type_operations * (*child_ns_type)(const struct kobject *);
	const void * (*namespace)(const struct kobject *);
	void (*get_ownership)(const struct kobject *, kuid_t *, kgid_t *);
};

struct kobj_uevent_env {
	char *argv[3];
	char *envp[64];
	int envp_idx;
	char buf[2048];
	int buflen;
};

struct kset_uevent_ops {
	int (* const filter)(const struct kobject *);
	const char * (* const name)(const struct kobject *);
	int (* const uevent)(const struct kobject *, struct kobj_uevent_env *);
};

struct kvec {
	void *iov_base;
	size_t iov_len;
};

typedef short unsigned int __kernel_sa_family_t;

struct __kernel_sockaddr_storage {
	union {
		struct {
			__kernel_sa_family_t ss_family;
			char __data[126];
		};
		void *__align;
	};
};

typedef __kernel_sa_family_t sa_family_t;

struct sockaddr {
	sa_family_t sa_family;
	union {
		char sa_data_min[14];
		struct {
			struct {} __empty_sa_data;
			char sa_data[0];
		};
	};
};

struct ubuf_info;

struct msghdr {
	void *msg_name;
	int msg_namelen;
	int msg_inq;
	struct iov_iter msg_iter;
	union {
		void *msg_control;
		void *msg_control_user;
	};
	bool msg_control_is_user: 1;
	bool msg_get_inq: 1;
	unsigned int msg_flags;
	__kernel_size_t msg_controllen;
	struct kiocb *msg_iocb;
	struct ubuf_info *msg_ubuf;
	int (*sg_from_iter)(struct sk_buff *, struct iov_iter *, size_t);
};

struct ubuf_info_ops;

struct ubuf_info {
	const struct ubuf_info_ops *ops;
	refcount_t refcnt;
	u8 flags;
};

typedef unsigned int sk_buff_data_t;

struct skb_ext;

struct sk_buff {
	union {
		struct {
			struct sk_buff *next;
			struct sk_buff *prev;
			union {
				struct net_device *dev;
				long unsigned int dev_scratch;
			};
		};
		struct rb_node rbnode;
		struct list_head list;
		struct llist_node ll_node;
	};
	struct sock *sk;
	union {
		ktime_t tstamp;
		u64 skb_mstamp_ns;
	};
	char cb[48];
	union {
		struct {
			long unsigned int _skb_refdst;
			void (*destructor)(struct sk_buff *);
		};
		struct list_head tcp_tsorted_anchor;
		long unsigned int _sk_redir;
	};
	long unsigned int _nfct;
	unsigned int len;
	unsigned int data_len;
	__u16 mac_len;
	__u16 hdr_len;
	__u16 queue_mapping;
	__u8 __cloned_offset[0];
	__u8 cloned: 1;
	__u8 nohdr: 1;
	__u8 fclone: 2;
	__u8 peeked: 1;
	__u8 head_frag: 1;
	__u8 pfmemalloc: 1;
	__u8 pp_recycle: 1;
	__u8 active_extensions;
	union {
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 dst_pending_confirm: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 __mono_tc_offset[0];
			__u8 tstamp_type: 2;
			__u8 tc_at_ingress: 1;
			__u8 tc_skip_classify: 1;
			__u8 remcsum_offload: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 inner_protocol_type: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 ipvs_property: 1;
			__u8 nf_trace: 1;
			__u8 offload_fwd_mark: 1;
			__u8 offload_l3_fwd_mark: 1;
			__u8 redirected: 1;
			__u8 from_ingress: 1;
			__u8 nf_skip_egress: 1;
			__u8 decrypted: 1;
			__u8 slow_gro: 1;
			__u8 csum_not_inet: 1;
			__u8 unreadable: 1;
			__u16 tc_index;
			u16 alloc_cpu;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			union {
				u32 vlan_all;
				struct {
					__be16 vlan_proto;
					__u16 vlan_tci;
				};
			};
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			__u32 secmark;
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		};
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 dst_pending_confirm: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 __mono_tc_offset[0];
			__u8 tstamp_type: 2;
			__u8 tc_at_ingress: 1;
			__u8 tc_skip_classify: 1;
			__u8 remcsum_offload: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 inner_protocol_type: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 ipvs_property: 1;
			__u8 nf_trace: 1;
			__u8 offload_fwd_mark: 1;
			__u8 offload_l3_fwd_mark: 1;
			__u8 redirected: 1;
			__u8 from_ingress: 1;
			__u8 nf_skip_egress: 1;
			__u8 decrypted: 1;
			__u8 slow_gro: 1;
			__u8 csum_not_inet: 1;
			__u8 unreadable: 1;
			__u16 tc_index;
			u16 alloc_cpu;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			union {
				u32 vlan_all;
				struct {
					__be16 vlan_proto;
					__u16 vlan_tci;
				};
			};
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			__u32 secmark;
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		} headers;
	};
	sk_buff_data_t tail;
	sk_buff_data_t end;
	unsigned char *head;
	unsigned char *data;
	unsigned int truesize;
	refcount_t users;
	struct skb_ext *extensions;
};

struct in6_addr {
	union {
		__u8 u6_addr8[16];
		__be16 u6_addr16[8];
		__be32 u6_addr32[4];
	} in6_u;
};

typedef u32 rpc_authflavor_t;

enum rpc_auth_flavors {
	RPC_AUTH_NULL = 0,
	RPC_AUTH_UNIX = 1,
	RPC_AUTH_SHORT = 2,
	RPC_AUTH_DES = 3,
	RPC_AUTH_KRB = 4,
	RPC_AUTH_GSS = 6,
	RPC_AUTH_TLS = 7,
	RPC_AUTH_MAXFLAVOR = 8,
	RPC_AUTH_GSS_KRB5 = 390003,
	RPC_AUTH_GSS_KRB5I = 390004,
	RPC_AUTH_GSS_KRB5P = 390005,
	RPC_AUTH_GSS_LKEY = 390006,
	RPC_AUTH_GSS_LKEYI = 390007,
	RPC_AUTH_GSS_LKEYP = 390008,
	RPC_AUTH_GSS_SPKM = 390009,
	RPC_AUTH_GSS_SPKMI = 390010,
	RPC_AUTH_GSS_SPKMP = 390011,
};

struct flowi_tunnel {
	__be64 tun_id;
};

struct flowi_common {
	int flowic_oif;
	int flowic_iif;
	int flowic_l3mdev;
	__u32 flowic_mark;
	__u8 flowic_tos;
	__u8 flowic_scope;
	__u8 flowic_proto;
	__u8 flowic_flags;
	__u32 flowic_secid;
	kuid_t flowic_uid;
	__u32 flowic_multipath_hash;
	struct flowi_tunnel flowic_tun_key;
};

union flowi_uli {
	struct {
		__be16 dport;
		__be16 sport;
	} ports;
	struct {
		__u8 type;
		__u8 code;
	} icmpt;
	__be32 gre_key;
	struct {
		__u8 type;
	} mht;
};

struct flowi4 {
	struct flowi_common __fl_common;
	__be32 saddr;
	__be32 daddr;
	union flowi_uli uli;
};

struct flowi6 {
	struct flowi_common __fl_common;
	struct in6_addr daddr;
	struct in6_addr saddr;
	__be32 flowlabel;
	union flowi_uli uli;
	__u32 mp_hash;
};

struct flowi {
	union {
		struct flowi_common __fl_common;
		struct flowi4 ip4;
		struct flowi6 ip6;
	} u;
};

struct prot_inuse;

struct netns_core {
	struct ctl_table_header *sysctl_hdr;
	int sysctl_somaxconn;
	int sysctl_optmem_max;
	u8 sysctl_txrehash;
	struct prot_inuse *prot_inuse;
	struct cpumask *rps_default_mask;
};

struct prot_inuse {
	int all;
	int val[64];
};

struct u64_stats_sync {};

typedef struct {
	atomic_long_t a;
} local_t;

typedef struct {
	local_t a;
} local64_t;

typedef struct {
	local64_t v;
} u64_stats_t;

struct ipstats_mib {
	u64 mibs[38];
	struct u64_stats_sync syncp;
};

struct icmp_mib {
	long unsigned int mibs[30];
};

struct icmpmsg_mib {
	atomic_long_t mibs[512];
};

struct icmpv6_mib_device {
	atomic_long_t mibs[7];
};

struct icmpv6msg_mib_device {
	atomic_long_t mibs[512];
};

struct tcp_mib {
	long unsigned int mibs[16];
};

struct udp_mib {
	long unsigned int mibs[10];
};

struct linux_mib {
	long unsigned int mibs[132];
};

struct linux_xfrm_mib {
	long unsigned int mibs[31];
};

struct linux_tls_mib {
	long unsigned int mibs[13];
};

struct mptcp_mib;

struct netns_mib {
	struct ipstats_mib *ip_statistics;
	struct tcp_mib *tcp_statistics;
	struct linux_mib *net_statistics;
	struct udp_mib *udp_statistics;
	struct linux_xfrm_mib *xfrm_statistics;
	struct linux_tls_mib *tls_statistics;
	struct mptcp_mib *mptcp_statistics;
	struct udp_mib *udplite_statistics;
	struct icmp_mib *icmp_statistics;
	struct icmpmsg_mib *icmpmsg_statistics;
};

struct unix_table {
	spinlock_t *locks;
	struct hlist_head *buckets;
};

struct netns_unix {
	struct unix_table table;
	int sysctl_max_dgram_qlen;
	struct ctl_table_header *ctl;
};

struct netns_packet {
	struct mutex sklist_lock;
	struct hlist_head sklist;
};

struct rhash_head {
	struct rhash_head *next;
};

struct rhashtable;

struct rhashtable_compare_arg {
	struct rhashtable *ht;
	const void *key;
};

struct bucket_table;

typedef u32 (*rht_hashfn_t)(const void *, u32, u32);

typedef u32 (*rht_obj_hashfn_t)(const void *, u32, u32);

typedef int (*rht_obj_cmpfn_t)(struct rhashtable_compare_arg *, const void *);

struct rhashtable_params {
	u16 nelem_hint;
	u16 key_len;
	u16 key_offset;
	u16 head_offset;
	unsigned int max_size;
	u16 min_size;
	bool automatic_shrinking;
	rht_hashfn_t hashfn;
	rht_obj_hashfn_t obj_hashfn;
	rht_obj_cmpfn_t obj_cmpfn;
};

struct rhashtable {
	struct bucket_table *tbl;
	unsigned int key_len;
	unsigned int max_elems;
	struct rhashtable_params p;
	bool rhlist;
	struct work_struct run_work;
	struct mutex mutex;
	spinlock_t lock;
	atomic_t nelems;
};

struct inet_frags;

struct fqdir {
	long int high_thresh;
	long int low_thresh;
	int timeout;
	int max_dist;
	struct inet_frags *f;
	struct net *net;
	bool dead;
	long: 64;
	long: 64;
	struct rhashtable rhashtable;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	atomic_long_t mem;
	struct work_struct destroy_work;
	struct llist_node free_list;
	long: 64;
	long: 64;
};

struct inet_frag_queue;

struct inet_frags {
	unsigned int qsize;
	void (*constructor)(struct inet_frag_queue *, const void *);
	void (*destructor)(struct inet_frag_queue *);
	void (*frag_expire)(struct timer_list *);
	struct kmem_cache *frags_cachep;
	const char *frags_cache_name;
	struct rhashtable_params rhash_params;
	refcount_t refcnt;
	struct completion completion;
};

struct ref_tracker_dir {};

struct proc_dir_entry;

struct uevent_sock;

struct netns_nexthop {
	struct rb_root rb_root;
	struct hlist_head *devhash;
	unsigned int seq;
	u32 last_id_allocated;
	struct blocking_notifier_head notifier_chain;
};

struct inet_hashinfo;

struct inet_timewait_death_row {
	refcount_t tw_refcount;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct inet_hashinfo *hashinfo;
	int sysctl_max_tw_buckets;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct udp_table;

struct ipv4_devconf;

struct ip_ra_chain;

struct fib_table;

struct inet_peer_base;

struct local_ports {
	u32 range;
	bool warned;
};

struct tcp_congestion_ops;

struct tcp_fastopen_context;

struct ping_group_range {
	seqlock_t lock;
	kgid_t range[2];
};

struct sysctl_fib_multipath_hash_seed {
	u32 user_seed;
	u32 mp_seed;
};

typedef struct {
	u64 key[2];
} siphash_key_t;

struct fib_rules_ops;

struct fib_notifier_ops;

struct netns_ipv4 {
	__u8 __cacheline_group_begin__netns_ipv4_read_tx[0];
	u8 sysctl_tcp_early_retrans;
	u8 sysctl_tcp_tso_win_divisor;
	u8 sysctl_tcp_tso_rtt_log;
	u8 sysctl_tcp_autocorking;
	int sysctl_tcp_min_snd_mss;
	unsigned int sysctl_tcp_notsent_lowat;
	int sysctl_tcp_limit_output_bytes;
	int sysctl_tcp_min_rtt_wlen;
	int sysctl_tcp_wmem[3];
	u8 sysctl_ip_fwd_use_pmtu;
	__u8 __cacheline_group_end__netns_ipv4_read_tx[0];
	__u8 __cacheline_group_begin__netns_ipv4_read_txrx[0];
	u8 sysctl_tcp_moderate_rcvbuf;
	__u8 __cacheline_group_end__netns_ipv4_read_txrx[0];
	__u8 __cacheline_group_begin__netns_ipv4_read_rx[0];
	u8 sysctl_ip_early_demux;
	u8 sysctl_tcp_early_demux;
	int sysctl_tcp_reordering;
	int sysctl_tcp_rmem[3];
	__u8 __cacheline_group_end__netns_ipv4_read_rx[0];
	long: 64;
	struct inet_timewait_death_row tcp_death_row;
	struct udp_table *udp_table;
	struct ctl_table_header *forw_hdr;
	struct ctl_table_header *frags_hdr;
	struct ctl_table_header *ipv4_hdr;
	struct ctl_table_header *route_hdr;
	struct ctl_table_header *xfrm4_hdr;
	struct ipv4_devconf *devconf_all;
	struct ipv4_devconf *devconf_dflt;
	struct ip_ra_chain *ra_chain;
	struct mutex ra_mutex;
	struct fib_rules_ops *rules_ops;
	struct fib_table *fib_main;
	struct fib_table *fib_default;
	unsigned int fib_rules_require_fldissect;
	bool fib_has_custom_rules;
	bool fib_has_custom_local_routes;
	bool fib_offload_disabled;
	u8 sysctl_tcp_shrink_window;
	atomic_t fib_num_tclassid_users;
	struct hlist_head *fib_table_hash;
	struct sock *fibnl;
	struct sock *mc_autojoin_sk;
	struct inet_peer_base *peers;
	struct fqdir *fqdir;
	u8 sysctl_icmp_echo_ignore_all;
	u8 sysctl_icmp_echo_enable_probe;
	u8 sysctl_icmp_echo_ignore_broadcasts;
	u8 sysctl_icmp_ignore_bogus_error_responses;
	u8 sysctl_icmp_errors_use_inbound_ifaddr;
	int sysctl_icmp_ratelimit;
	int sysctl_icmp_ratemask;
	int sysctl_icmp_msgs_per_sec;
	int sysctl_icmp_msgs_burst;
	atomic_t icmp_global_credit;
	u32 icmp_global_stamp;
	u32 ip_rt_min_pmtu;
	int ip_rt_mtu_expires;
	int ip_rt_min_advmss;
	struct local_ports ip_local_ports;
	u8 sysctl_tcp_ecn;
	u8 sysctl_tcp_ecn_fallback;
	u8 sysctl_ip_default_ttl;
	u8 sysctl_ip_no_pmtu_disc;
	u8 sysctl_ip_fwd_update_priority;
	u8 sysctl_ip_nonlocal_bind;
	u8 sysctl_ip_autobind_reuse;
	u8 sysctl_ip_dynaddr;
	u8 sysctl_raw_l3mdev_accept;
	u8 sysctl_udp_early_demux;
	u8 sysctl_nexthop_compat_mode;
	u8 sysctl_fwmark_reflect;
	u8 sysctl_tcp_fwmark_accept;
	u8 sysctl_tcp_l3mdev_accept;
	u8 sysctl_tcp_mtu_probing;
	int sysctl_tcp_mtu_probe_floor;
	int sysctl_tcp_base_mss;
	int sysctl_tcp_probe_threshold;
	u32 sysctl_tcp_probe_interval;
	int sysctl_tcp_keepalive_time;
	int sysctl_tcp_keepalive_intvl;
	u8 sysctl_tcp_keepalive_probes;
	u8 sysctl_tcp_syn_retries;
	u8 sysctl_tcp_synack_retries;
	u8 sysctl_tcp_syncookies;
	u8 sysctl_tcp_migrate_req;
	u8 sysctl_tcp_comp_sack_nr;
	u8 sysctl_tcp_backlog_ack_defer;
	u8 sysctl_tcp_pingpong_thresh;
	u8 sysctl_tcp_retries1;
	u8 sysctl_tcp_retries2;
	u8 sysctl_tcp_orphan_retries;
	u8 sysctl_tcp_tw_reuse;
	int sysctl_tcp_fin_timeout;
	u8 sysctl_tcp_sack;
	u8 sysctl_tcp_window_scaling;
	u8 sysctl_tcp_timestamps;
	int sysctl_tcp_rto_min_us;
	u8 sysctl_tcp_recovery;
	u8 sysctl_tcp_thin_linear_timeouts;
	u8 sysctl_tcp_slow_start_after_idle;
	u8 sysctl_tcp_retrans_collapse;
	u8 sysctl_tcp_stdurg;
	u8 sysctl_tcp_rfc1337;
	u8 sysctl_tcp_abort_on_overflow;
	u8 sysctl_tcp_fack;
	int sysctl_tcp_max_reordering;
	int sysctl_tcp_adv_win_scale;
	u8 sysctl_tcp_dsack;
	u8 sysctl_tcp_app_win;
	u8 sysctl_tcp_frto;
	u8 sysctl_tcp_nometrics_save;
	u8 sysctl_tcp_no_ssthresh_metrics_save;
	u8 sysctl_tcp_workaround_signed_windows;
	int sysctl_tcp_challenge_ack_limit;
	u8 sysctl_tcp_min_tso_segs;
	u8 sysctl_tcp_reflect_tos;
	int sysctl_tcp_invalid_ratelimit;
	int sysctl_tcp_pacing_ss_ratio;
	int sysctl_tcp_pacing_ca_ratio;
	unsigned int sysctl_tcp_child_ehash_entries;
	long unsigned int sysctl_tcp_comp_sack_delay_ns;
	long unsigned int sysctl_tcp_comp_sack_slack_ns;
	int sysctl_max_syn_backlog;
	int sysctl_tcp_fastopen;
	const struct tcp_congestion_ops *tcp_congestion_control;
	struct tcp_fastopen_context *tcp_fastopen_ctx;
	unsigned int sysctl_tcp_fastopen_blackhole_timeout;
	atomic_t tfo_active_disable_times;
	long unsigned int tfo_active_disable_stamp;
	u32 tcp_challenge_timestamp;
	u32 tcp_challenge_count;
	u8 sysctl_tcp_plb_enabled;
	u8 sysctl_tcp_plb_idle_rehash_rounds;
	u8 sysctl_tcp_plb_rehash_rounds;
	u8 sysctl_tcp_plb_suspend_rto_sec;
	int sysctl_tcp_plb_cong_thresh;
	int sysctl_udp_wmem_min;
	int sysctl_udp_rmem_min;
	u8 sysctl_fib_notify_on_flag_change;
	u8 sysctl_tcp_syn_linear_timeouts;
	u8 sysctl_udp_l3mdev_accept;
	u8 sysctl_igmp_llm_reports;
	int sysctl_igmp_max_memberships;
	int sysctl_igmp_max_msf;
	int sysctl_igmp_qrv;
	struct ping_group_range ping_group_range;
	atomic_t dev_addr_genid;
	unsigned int sysctl_udp_child_hash_entries;
	long unsigned int *sysctl_local_reserved_ports;
	int sysctl_ip_prot_sock;
	struct list_head mr_tables;
	struct fib_rules_ops *mr_rules_ops;
	struct sysctl_fib_multipath_hash_seed sysctl_fib_multipath_hash_seed;
	u32 sysctl_fib_multipath_hash_fields;
	u8 sysctl_fib_multipath_use_neigh;
	u8 sysctl_fib_multipath_hash_policy;
	struct fib_notifier_ops *notifier_ops;
	unsigned int fib_seq;
	struct fib_notifier_ops *ipmr_notifier_ops;
	unsigned int ipmr_seq;
	atomic_t rt_genid;
	siphash_key_t ip_id_key;
};

struct sctp_mib;

struct netns_sctp {
	struct sctp_mib *sctp_statistics;
	struct proc_dir_entry *proc_net_sctp;
	struct ctl_table_header *sysctl_header;
	struct sock *ctl_sock;
	struct sock *udp4_sock;
	struct sock *udp6_sock;
	int udp_port;
	int encap_port;
	struct list_head local_addr_list;
	struct list_head addr_waitq;
	struct timer_list addr_wq_timer;
	struct list_head auto_asconf_splist;
	spinlock_t addr_wq_lock;
	spinlock_t local_addr_lock;
	unsigned int rto_initial;
	unsigned int rto_min;
	unsigned int rto_max;
	int rto_alpha;
	int rto_beta;
	int max_burst;
	int cookie_preserve_enable;
	char *sctp_hmac_alg;
	unsigned int valid_cookie_life;
	unsigned int sack_timeout;
	unsigned int hb_interval;
	unsigned int probe_interval;
	int max_retrans_association;
	int max_retrans_path;
	int max_retrans_init;
	int pf_retrans;
	int ps_retrans;
	int pf_enable;
	int pf_expose;
	int sndbuf_policy;
	int rcvbuf_policy;
	int default_auto_asconf;
	int addip_enable;
	int addip_noauth;
	int prsctp_enable;
	int reconf_enable;
	int auth_enable;
	int intl_enable;
	int ecn_enable;
	int scope_policy;
	int rwnd_upd_shift;
	long unsigned int max_autoclose;
	int l3mdev_accept;
};

struct nf_logger;

struct nf_hook_entries;

struct netns_nf {
	struct proc_dir_entry *proc_netfilter;
	const struct nf_logger *nf_loggers[11];
	struct ctl_table_header *nf_log_dir_header;
	struct ctl_table_header *nf_lwtnl_dir_header;
	struct nf_hook_entries *hooks_ipv4[5];
	struct nf_hook_entries *hooks_ipv6[5];
	struct nf_hook_entries *hooks_arp[3];
	struct nf_hook_entries *hooks_bridge[5];
	unsigned int defrag_ipv4_users;
};

struct nf_ct_event_notifier;

struct nf_generic_net {
	unsigned int timeout;
};

struct nf_tcp_net {
	unsigned int timeouts[14];
	u8 tcp_loose;
	u8 tcp_be_liberal;
	u8 tcp_max_retrans;
	u8 tcp_ignore_invalid_rst;
	unsigned int offload_timeout;
};

struct nf_udp_net {
	unsigned int timeouts[2];
	unsigned int offload_timeout;
};

struct nf_icmp_net {
	unsigned int timeout;
};

struct nf_dccp_net {
	u8 dccp_loose;
	unsigned int dccp_timeout[10];
};

struct nf_sctp_net {
	unsigned int timeouts[10];
};

struct nf_gre_net {
	struct list_head keymap_list;
	unsigned int timeouts[2];
};

struct nf_ip_net {
	struct nf_generic_net generic;
	struct nf_tcp_net tcp;
	struct nf_udp_net udp;
	struct nf_icmp_net icmp;
	struct nf_icmp_net icmpv6;
	struct nf_dccp_net dccp;
	struct nf_sctp_net sctp;
	struct nf_gre_net gre;
};

struct ip_conntrack_stat;

struct netns_ct {
	bool ecache_dwork_pending;
	u8 sysctl_log_invalid;
	u8 sysctl_events;
	u8 sysctl_acct;
	u8 sysctl_tstamp;
	u8 sysctl_checksum;
	struct ip_conntrack_stat *stat;
	struct nf_ct_event_notifier *nf_conntrack_event_cb;
	struct nf_ip_net nf_ct_proto;
	atomic_t labels_used;
};

struct netns_nftables {
	u8 gencursor;
};

struct nf_flow_table_stat;

struct netns_ft {
	struct nf_flow_table_stat *stat;
};

struct bpf_prog;

struct netns_bpf {
	struct bpf_prog_array *run_array[2];
	struct bpf_prog *progs[2];
	struct list_head links[2];
};

struct xfrm_policy_hash {
	struct hlist_head *table;
	unsigned int hmask;
	u8 dbits4;
	u8 sbits4;
	u8 dbits6;
	u8 sbits6;
};

struct xfrm_policy_hthresh {
	struct work_struct work;
	seqlock_t lock;
	u8 lbits4;
	u8 rbits4;
	u8 lbits6;
	u8 rbits6;
};

struct neighbour;

struct dst_ops {
	short unsigned int family;
	unsigned int gc_thresh;
	void (*gc)(struct dst_ops *);
	struct dst_entry * (*check)(struct dst_entry *, __u32);
	unsigned int (*default_advmss)(const struct dst_entry *);
	unsigned int (*mtu)(const struct dst_entry *);
	u32 * (*cow_metrics)(struct dst_entry *, long unsigned int);
	void (*destroy)(struct dst_entry *);
	void (*ifdown)(struct dst_entry *, struct net_device *);
	void (*negative_advice)(struct sock *, struct dst_entry *);
	void (*link_failure)(struct sk_buff *);
	void (*update_pmtu)(struct dst_entry *, struct sock *, struct sk_buff *, u32, bool);
	void (*redirect)(struct dst_entry *, struct sock *, struct sk_buff *);
	int (*local_out)(struct net *, struct sock *, struct sk_buff *);
	struct neighbour * (*neigh_lookup)(const struct dst_entry *, struct sk_buff *, const void *);
	void (*confirm_neigh)(const struct dst_entry *, const void *);
	struct kmem_cache *kmem_cachep;
	struct percpu_counter pcpuc_entries;
	long: 64;
	long: 64;
	long: 64;
};

struct netns_xfrm {
	struct list_head state_all;
	struct hlist_head *state_bydst;
	struct hlist_head *state_bysrc;
	struct hlist_head *state_byspi;
	struct hlist_head *state_byseq;
	struct hlist_head *state_cache_input;
	unsigned int state_hmask;
	unsigned int state_num;
	struct work_struct state_hash_work;
	struct list_head policy_all;
	struct hlist_head *policy_byidx;
	unsigned int policy_idx_hmask;
	unsigned int idx_generator;
	struct xfrm_policy_hash policy_bydst[3];
	unsigned int policy_count[6];
	struct work_struct policy_hash_work;
	struct xfrm_policy_hthresh policy_hthresh;
	struct list_head inexact_bins;
	struct sock *nlsk;
	struct sock *nlsk_stash;
	u32 sysctl_aevent_etime;
	u32 sysctl_aevent_rseqth;
	int sysctl_larval_drop;
	u32 sysctl_acq_expires;
	u8 policy_default[3];
	struct ctl_table_header *sysctl_hdr;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct dst_ops xfrm4_dst_ops;
	spinlock_t xfrm_state_lock;
	seqcount_spinlock_t xfrm_state_hash_generation;
	seqcount_spinlock_t xfrm_policy_hash_generation;
	spinlock_t xfrm_policy_lock;
	struct mutex xfrm_cfg_mutex;
	struct delayed_work nat_keepalive_work;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct netns_ipvs;

struct mpls_route;

struct netns_mpls {
	int ip_ttl_propagate;
	int default_ttl;
	size_t platform_labels;
	struct mpls_route **platform_label;
	struct ctl_table_header *ctl;
};

struct can_dev_rcv_lists;

struct can_pkg_stats;

struct can_rcv_lists_stats;

struct netns_can {
	struct proc_dir_entry *proc_dir;
	struct proc_dir_entry *pde_stats;
	struct proc_dir_entry *pde_reset_stats;
	struct proc_dir_entry *pde_rcvlist_all;
	struct proc_dir_entry *pde_rcvlist_fil;
	struct proc_dir_entry *pde_rcvlist_inv;
	struct proc_dir_entry *pde_rcvlist_sff;
	struct proc_dir_entry *pde_rcvlist_eff;
	struct proc_dir_entry *pde_rcvlist_err;
	struct proc_dir_entry *bcmproc_dir;
	struct can_dev_rcv_lists *rx_alldev_list;
	spinlock_t rcvlists_lock;
	struct timer_list stattimer;
	struct can_pkg_stats *pkg_stats;
	struct can_rcv_lists_stats *rcv_lists_stats;
	struct hlist_head cgw_list;
};

struct netns_xdp {
	struct mutex lock;
	struct hlist_head list;
};

struct netns_mctp {
	struct list_head routes;
	struct mutex bind_lock;
	struct hlist_head binds;
	spinlock_t keys_lock;
	struct hlist_head keys;
	unsigned int default_net;
	struct mutex neigh_lock;
	struct list_head neighbours;
};

struct smc_stats;

struct smc_stats_rsn;

struct netns_smc {
	struct smc_stats *smc_stats;
	struct mutex mutex_fback_rsn;
	struct smc_stats_rsn *fback_rsn;
	bool limit_smc_hs;
	struct ctl_table_header *smc_hdr;
	unsigned int sysctl_autocorking_size;
	unsigned int sysctl_smcr_buf_type;
	int sysctl_smcr_testlink_time;
	int sysctl_wmem;
	int sysctl_rmem;
	int sysctl_max_links_per_lgr;
	int sysctl_max_conns_per_lgr;
};

struct net_generic;

struct net {
	refcount_t passive;
	spinlock_t rules_mod_lock;
	unsigned int dev_base_seq;
	u32 ifindex;
	spinlock_t nsid_lock;
	atomic_t fnhe_genid;
	struct list_head list;
	struct list_head exit_list;
	struct llist_node defer_free_list;
	struct llist_node cleanup_list;
	struct key_tag *key_domain;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct idr netns_ids;
	struct ns_common ns;
	struct ref_tracker_dir refcnt_tracker;
	struct ref_tracker_dir notrefcnt_tracker;
	struct list_head dev_base_head;
	struct proc_dir_entry *proc_net;
	struct proc_dir_entry *proc_net_stat;
	struct ctl_table_set sysctls;
	struct sock *rtnl;
	struct sock *genl_sock;
	struct uevent_sock *uevent_sock;
	struct hlist_head *dev_name_head;
	struct hlist_head *dev_index_head;
	struct xarray dev_by_index;
	struct raw_notifier_head netdev_chain;
	u32 hash_mix;
	struct net_device *loopback_dev;
	struct list_head rules_ops;
	struct netns_core core;
	struct netns_mib mib;
	struct netns_packet packet;
	struct netns_unix unx;
	struct netns_nexthop nexthop;
	struct netns_ipv4 ipv4;
	struct netns_sctp sctp;
	struct netns_nf nf;
	struct netns_ct ct;
	struct netns_nftables nft;
	struct netns_ft ft;
	struct sk_buff_head wext_nlevents;
	struct net_generic *gen;
	struct netns_bpf bpf;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netns_xfrm xfrm;
	u64 net_cookie;
	struct netns_ipvs *ipvs;
	struct netns_mpls mpls;
	struct netns_can can;
	struct netns_xdp xdp;
	struct netns_mctp mctp;
	struct sock *crypto_nlsk;
	struct sock *diag_nlsk;
	struct netns_smc smc;
	long: 64;
	long: 64;
	long: 64;
};

struct frag_v4_compare_key {
	__be32 saddr;
	__be32 daddr;
	u32 user;
	u32 vif;
	__be16 id;
	u16 protocol;
};

struct frag_v6_compare_key {
	struct in6_addr saddr;
	struct in6_addr daddr;
	u32 user;
	__be32 id;
	u32 iif;
};

struct inet_frag_queue {
	struct rhash_head node;
	union {
		struct frag_v4_compare_key v4;
		struct frag_v6_compare_key v6;
	} key;
	struct timer_list timer;
	spinlock_t lock;
	refcount_t refcnt;
	struct rb_root rb_fragments;
	struct sk_buff *fragments_tail;
	struct sk_buff *last_run_head;
	ktime_t stamp;
	int len;
	int meat;
	u8 tstamp_type;
	__u8 flags;
	u16 max_size;
	struct fqdir *fqdir;
	struct callback_head rcu;
};

struct fib_rule;

struct fib_lookup_arg;

struct fib_rule_hdr;

struct nlattr;

struct netlink_ext_ack;

struct fib_rules_ops {
	int family;
	struct list_head list;
	int rule_size;
	int addr_size;
	int unresolved_rules;
	int nr_goto_rules;
	unsigned int fib_rules_seq;
	int (*action)(struct fib_rule *, struct flowi *, int, struct fib_lookup_arg *);
	bool (*suppress)(struct fib_rule *, int, struct fib_lookup_arg *);
	int (*match)(struct fib_rule *, struct flowi *, int);
	int (*configure)(struct fib_rule *, struct sk_buff *, struct fib_rule_hdr *, struct nlattr **, struct netlink_ext_ack *);
	int (*delete)(struct fib_rule *);
	int (*compare)(struct fib_rule *, struct fib_rule_hdr *, struct nlattr **);
	int (*fill)(struct fib_rule *, struct sk_buff *, struct fib_rule_hdr *);
	size_t (*nlmsg_payload)(struct fib_rule *);
	void (*flush_cache)(struct fib_rules_ops *);
	int nlgroup;
	struct list_head rules_list;
	struct module *owner;
	struct net *fro_net;
	struct callback_head rcu;
};

struct fib_notifier_ops {
	int family;
	struct list_head list;
	unsigned int (*fib_seq_read)(struct net *);
	int (*fib_dump)(struct net *, struct notifier_block *, struct netlink_ext_ack *);
	struct module *owner;
	struct callback_head rcu;
};

struct xfrm_state;

typedef struct {} netdevice_tracker;

struct uncached_list;

struct lwtunnel_state;

struct dst_entry {
	struct net_device *dev;
	struct dst_ops *ops;
	long unsigned int _metrics;
	long unsigned int expires;
	struct xfrm_state *xfrm;
	int (*input)(struct sk_buff *);
	int (*output)(struct net *, struct sock *, struct sk_buff *);
	short unsigned int flags;
	short int obsolete;
	short unsigned int header_len;
	short unsigned int trailer_len;
	rcuref_t __rcuref;
	int __use;
	long unsigned int lastuse;
	struct callback_head callback_head;
	short int error;
	short int __pad;
	__u32 tclassid;
	netdevice_tracker dev_tracker;
	struct list_head rt_uncached;
	struct uncached_list *rt_uncached_list;
	struct lwtunnel_state *lwtstate;
};

struct netdev_tc_txq {
	u16 count;
	u16 offset;
};

struct bpf_mprog_entry;

struct netdev_rx_queue;

enum rx_handler_result {
	RX_HANDLER_CONSUMED = 0,
	RX_HANDLER_ANOTHER = 1,
	RX_HANDLER_EXACT = 2,
	RX_HANDLER_PASS = 3,
};

typedef enum rx_handler_result rx_handler_result_t;

typedef rx_handler_result_t rx_handler_func_t(struct sk_buff **);

struct netpoll_info;

struct netdev_name_node;

typedef u32 xdp_features_t;

struct xdp_metadata_ops;

struct xsk_tx_metadata_ops;

struct net_device_stats {
	union {
		long unsigned int rx_packets;
		atomic_long_t __rx_packets;
	};
	union {
		long unsigned int tx_packets;
		atomic_long_t __tx_packets;
	};
	union {
		long unsigned int rx_bytes;
		atomic_long_t __rx_bytes;
	};
	union {
		long unsigned int tx_bytes;
		atomic_long_t __tx_bytes;
	};
	union {
		long unsigned int rx_errors;
		atomic_long_t __rx_errors;
	};
	union {
		long unsigned int tx_errors;
		atomic_long_t __tx_errors;
	};
	union {
		long unsigned int rx_dropped;
		atomic_long_t __rx_dropped;
	};
	union {
		long unsigned int tx_dropped;
		atomic_long_t __tx_dropped;
	};
	union {
		long unsigned int multicast;
		atomic_long_t __multicast;
	};
	union {
		long unsigned int collisions;
		atomic_long_t __collisions;
	};
	union {
		long unsigned int rx_length_errors;
		atomic_long_t __rx_length_errors;
	};
	union {
		long unsigned int rx_over_errors;
		atomic_long_t __rx_over_errors;
	};
	union {
		long unsigned int rx_crc_errors;
		atomic_long_t __rx_crc_errors;
	};
	union {
		long unsigned int rx_frame_errors;
		atomic_long_t __rx_frame_errors;
	};
	union {
		long unsigned int rx_fifo_errors;
		atomic_long_t __rx_fifo_errors;
	};
	union {
		long unsigned int rx_missed_errors;
		atomic_long_t __rx_missed_errors;
	};
	union {
		long unsigned int tx_aborted_errors;
		atomic_long_t __tx_aborted_errors;
	};
	union {
		long unsigned int tx_carrier_errors;
		atomic_long_t __tx_carrier_errors;
	};
	union {
		long unsigned int tx_fifo_errors;
		atomic_long_t __tx_fifo_errors;
	};
	union {
		long unsigned int tx_heartbeat_errors;
		atomic_long_t __tx_heartbeat_errors;
	};
	union {
		long unsigned int tx_window_errors;
		atomic_long_t __tx_window_errors;
	};
	union {
		long unsigned int rx_compressed;
		atomic_long_t __rx_compressed;
	};
	union {
		long unsigned int tx_compressed;
		atomic_long_t __tx_compressed;
	};
};

struct iw_handler_def;

struct iw_public_data;

struct ethtool_ops;

struct tlsdev_ops;

struct netdev_hw_addr_list {
	struct list_head list;
	int count;
	struct rb_root tree;
};

struct in_device;

struct vlan_info;

struct dsa_port;

struct tipc_bearer;

struct ax25_dev;

struct wireless_dev;

struct wpan_dev;

struct mpls_dev;

struct mctp_dev;

struct cpu_rmap;

struct Qdisc;

struct xdp_dev_bulk_queue;

enum netdev_ml_priv_type {
	ML_PRIV_NONE = 0,
	ML_PRIV_CAN = 1,
};

enum netdev_stat_type {
	NETDEV_PCPU_STAT_NONE = 0,
	NETDEV_PCPU_STAT_LSTATS = 1,
	NETDEV_PCPU_STAT_TSTATS = 2,
	NETDEV_PCPU_STAT_DSTATS = 3,
};

struct garp_port;

struct mrp_port;

struct dm_hw_stat_delta;

struct netdev_stat_ops;

struct netdev_queue_mgmt_ops;

struct phy_link_topology;

struct phy_device;

struct sfp_bus;

struct macsec_ops;

struct udp_tunnel_nic_info;

struct udp_tunnel_nic;

struct ethtool_netdev_state;

struct bpf_xdp_link;

struct bpf_xdp_entity {
	struct bpf_prog *prog;
	struct bpf_xdp_link *link;
};

struct devlink_port;

struct dpll_pin;

struct dim_irq_moder;

struct net_device_ops;

struct header_ops;

struct netdev_queue;

struct xps_dev_maps;

struct pcpu_lstats;

struct pcpu_sw_netstats;

struct pcpu_dstats;

struct inet6_dev;

struct dev_ifalias;

struct net_device_core_stats;

struct l3mdev_ops;

struct xfrmdev_ops;

struct rtnl_link_ops;

struct dcbnl_rtnl_ops;

struct netprio_map;

struct rtnl_hw_stats64;

struct net_device {
	__u8 __cacheline_group_begin__net_device_read_tx[0];
	union {
		struct {
			long unsigned int priv_flags: 32;
			long unsigned int lltx: 1;
		};
		struct {
			long unsigned int priv_flags: 32;
			long unsigned int lltx: 1;
		} priv_flags_fast;
	};
	const struct net_device_ops *netdev_ops;
	const struct header_ops *header_ops;
	struct netdev_queue *_tx;
	netdev_features_t gso_partial_features;
	unsigned int real_num_tx_queues;
	unsigned int gso_max_size;
	unsigned int gso_ipv4_max_size;
	u16 gso_max_segs;
	s16 num_tc;
	unsigned int mtu;
	short unsigned int needed_headroom;
	struct netdev_tc_txq tc_to_txq[16];
	struct xps_dev_maps *xps_maps[2];
	struct nf_hook_entries *nf_hooks_egress;
	struct bpf_mprog_entry *tcx_egress;
	__u8 __cacheline_group_end__net_device_read_tx[0];
	__u8 __cacheline_group_begin__net_device_read_txrx[0];
	union {
		struct pcpu_lstats *lstats;
		struct pcpu_sw_netstats *tstats;
		struct pcpu_dstats *dstats;
	};
	long unsigned int state;
	unsigned int flags;
	short unsigned int hard_header_len;
	netdev_features_t features;
	struct inet6_dev *ip6_ptr;
	__u8 __cacheline_group_end__net_device_read_txrx[0];
	__u8 __cacheline_group_begin__net_device_read_rx[0];
	struct bpf_prog *xdp_prog;
	struct list_head ptype_specific;
	int ifindex;
	unsigned int real_num_rx_queues;
	struct netdev_rx_queue *_rx;
	long unsigned int gro_flush_timeout;
	u32 napi_defer_hard_irqs;
	unsigned int gro_max_size;
	unsigned int gro_ipv4_max_size;
	rx_handler_func_t *rx_handler;
	void *rx_handler_data;
	possible_net_t nd_net;
	struct netpoll_info *npinfo;
	struct bpf_mprog_entry *tcx_ingress;
	__u8 __cacheline_group_end__net_device_read_rx[0];
	char name[16];
	struct netdev_name_node *name_node;
	struct dev_ifalias *ifalias;
	long unsigned int mem_end;
	long unsigned int mem_start;
	long unsigned int base_addr;
	struct list_head dev_list;
	struct list_head napi_list;
	struct list_head unreg_list;
	struct list_head close_list;
	struct list_head ptype_all;
	struct {
		struct list_head upper;
		struct list_head lower;
	} adj_list;
	xdp_features_t xdp_features;
	const struct xdp_metadata_ops *xdp_metadata_ops;
	const struct xsk_tx_metadata_ops *xsk_tx_metadata_ops;
	short unsigned int gflags;
	short unsigned int needed_tailroom;
	netdev_features_t hw_features;
	netdev_features_t wanted_features;
	netdev_features_t vlan_features;
	netdev_features_t hw_enc_features;
	netdev_features_t mpls_features;
	unsigned int min_mtu;
	unsigned int max_mtu;
	short unsigned int type;
	unsigned char min_header_len;
	unsigned char name_assign_type;
	int group;
	struct net_device_stats stats;
	struct net_device_core_stats *core_stats;
	atomic_t carrier_up_count;
	atomic_t carrier_down_count;
	const struct iw_handler_def *wireless_handlers;
	struct iw_public_data *wireless_data;
	const struct ethtool_ops *ethtool_ops;
	const struct l3mdev_ops *l3mdev_ops;
	const struct xfrmdev_ops *xfrmdev_ops;
	const struct tlsdev_ops *tlsdev_ops;
	unsigned int operstate;
	unsigned char link_mode;
	unsigned char if_port;
	unsigned char dma;
	unsigned char perm_addr[32];
	unsigned char addr_assign_type;
	unsigned char addr_len;
	unsigned char upper_level;
	unsigned char lower_level;
	short unsigned int neigh_priv_len;
	short unsigned int dev_id;
	short unsigned int dev_port;
	int irq;
	u32 priv_len;
	spinlock_t addr_list_lock;
	struct netdev_hw_addr_list uc;
	struct netdev_hw_addr_list mc;
	struct netdev_hw_addr_list dev_addrs;
	struct kset *queues_kset;
	unsigned int promiscuity;
	unsigned int allmulti;
	bool uc_promisc;
	struct in_device *ip_ptr;
	struct vlan_info *vlan_info;
	struct dsa_port *dsa_ptr;
	struct tipc_bearer *tipc_ptr;
	void *atalk_ptr;
	struct ax25_dev *ax25_ptr;
	struct wireless_dev *ieee80211_ptr;
	struct wpan_dev *ieee802154_ptr;
	struct mpls_dev *mpls_ptr;
	struct mctp_dev *mctp_ptr;
	const unsigned char *dev_addr;
	unsigned int num_rx_queues;
	unsigned int xdp_zc_max_segs;
	struct netdev_queue *ingress_queue;
	struct nf_hook_entries *nf_hooks_ingress;
	unsigned char broadcast[32];
	struct cpu_rmap *rx_cpu_rmap;
	struct hlist_node index_hlist;
	unsigned int num_tx_queues;
	struct Qdisc *qdisc;
	unsigned int tx_queue_len;
	spinlock_t tx_global_lock;
	struct xdp_dev_bulk_queue *xdp_bulkq;
	struct hlist_head qdisc_hash[16];
	struct timer_list watchdog_timer;
	int watchdog_timeo;
	u32 proto_down_reason;
	struct list_head todo_list;
	int *pcpu_refcnt;
	struct ref_tracker_dir refcnt_tracker;
	struct list_head link_watch_list;
	u8 reg_state;
	bool dismantle;
	enum {
		RTNL_LINK_INITIALIZED = 0,
		RTNL_LINK_INITIALIZING = 1,
	} rtnl_link_state: 16;
	bool needs_free_netdev;
	void (*priv_destructor)(struct net_device *);
	void *ml_priv;
	enum netdev_ml_priv_type ml_priv_type;
	enum netdev_stat_type pcpu_stat_type: 8;
	struct garp_port *garp_port;
	struct mrp_port *mrp_port;
	struct dm_hw_stat_delta *dm_private;
	struct device dev;
	const struct attribute_group *sysfs_groups[4];
	const struct attribute_group *sysfs_rx_queue_group;
	const struct rtnl_link_ops *rtnl_link_ops;
	const struct netdev_stat_ops *stat_ops;
	const struct netdev_queue_mgmt_ops *queue_mgmt_ops;
	unsigned int tso_max_size;
	u16 tso_max_segs;
	const struct dcbnl_rtnl_ops *dcbnl_ops;
	u8 prio_tc_map[16];
	unsigned int fcoe_ddp_xid;
	struct netprio_map *priomap;
	struct phy_link_topology *link_topo;
	struct phy_device *phydev;
	struct sfp_bus *sfp_bus;
	struct lock_class_key *qdisc_tx_busylock;
	bool proto_down;
	bool threaded;
	long unsigned int see_all_hwtstamp_requests: 1;
	long unsigned int change_proto_down: 1;
	long unsigned int netns_local: 1;
	long unsigned int fcoe_mtu: 1;
	struct list_head net_notifier_list;
	const struct macsec_ops *macsec_ops;
	const struct udp_tunnel_nic_info *udp_tunnel_nic_info;
	struct udp_tunnel_nic *udp_tunnel_nic;
	struct ethtool_netdev_state *ethtool;
	struct bpf_xdp_entity xdp_state[3];
	u8 dev_addr_shadow[32];
	netdevice_tracker linkwatch_dev_tracker;
	netdevice_tracker watchdog_dev_tracker;
	netdevice_tracker dev_registered_tracker;
	struct rtnl_hw_stats64 *offload_xstats_l3;
	struct devlink_port *devlink_port;
	struct dpll_pin *dpll_pin;
	struct hlist_head page_pools;
	struct dim_irq_moder *irq_moder;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	u8 priv[0];
};

struct hh_cache {
	unsigned int hh_len;
	seqlock_t hh_lock;
	long unsigned int hh_data[16];
};

struct neigh_table;

struct neigh_parms;

struct neigh_ops;

struct neighbour {
	struct neighbour *next;
	struct neigh_table *tbl;
	struct neigh_parms *parms;
	long unsigned int confirmed;
	long unsigned int updated;
	rwlock_t lock;
	refcount_t refcnt;
	unsigned int arp_queue_len_bytes;
	struct sk_buff_head arp_queue;
	struct timer_list timer;
	long unsigned int used;
	atomic_t probes;
	u8 nud_state;
	u8 type;
	u8 dead;
	u8 protocol;
	u32 flags;
	seqlock_t ha_lock;
	long: 0;
	unsigned char ha[32];
	struct hh_cache hh;
	int (*output)(struct neighbour *, struct sk_buff *);
	const struct neigh_ops *ops;
	struct list_head gc_list;
	struct list_head managed_list;
	struct callback_head rcu;
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	u8 primary_key[0];
};

struct ipv6_stable_secret {
	bool initialized;
	struct in6_addr secret;
};

struct ipv6_devconf {
	__u8 __cacheline_group_begin__ipv6_devconf_read_txrx[0];
	__s32 disable_ipv6;
	__s32 hop_limit;
	__s32 mtu6;
	__s32 forwarding;
	__s32 disable_policy;
	__s32 proxy_ndp;
	__u8 __cacheline_group_end__ipv6_devconf_read_txrx[0];
	__s32 accept_ra;
	__s32 accept_redirects;
	__s32 autoconf;
	__s32 dad_transmits;
	__s32 rtr_solicits;
	__s32 rtr_solicit_interval;
	__s32 rtr_solicit_max_interval;
	__s32 rtr_solicit_delay;
	__s32 force_mld_version;
	__s32 mldv1_unsolicited_report_interval;
	__s32 mldv2_unsolicited_report_interval;
	__s32 use_tempaddr;
	__s32 temp_valid_lft;
	__s32 temp_prefered_lft;
	__s32 regen_min_advance;
	__s32 regen_max_retry;
	__s32 max_desync_factor;
	__s32 max_addresses;
	__s32 accept_ra_defrtr;
	__u32 ra_defrtr_metric;
	__s32 accept_ra_min_hop_limit;
	__s32 accept_ra_min_lft;
	__s32 accept_ra_pinfo;
	__s32 ignore_routes_with_linkdown;
	__s32 accept_source_route;
	__s32 accept_ra_from_local;
	__s32 drop_unicast_in_l2_multicast;
	__s32 accept_dad;
	__s32 force_tllao;
	__s32 ndisc_notify;
	__s32 suppress_frag_ndisc;
	__s32 accept_ra_mtu;
	__s32 drop_unsolicited_na;
	__s32 accept_untracked_na;
	struct ipv6_stable_secret stable_secret;
	__s32 use_oif_addrs_only;
	__s32 keep_addr_on_down;
	__s32 seg6_enabled;
	__u32 enhanced_dad;
	__u32 addr_gen_mode;
	__s32 ndisc_tclass;
	__s32 rpl_seg_enabled;
	__u32 ioam6_id;
	__u32 ioam6_id_wide;
	__u8 ioam6_enabled;
	__u8 ndisc_evict_nocarrier;
	__u8 ra_honor_pio_life;
	__u8 ra_honor_pio_pflag;
	struct ctl_table_header *sysctl_header;
};

struct fib6_info;

struct ip_conntrack_stat {
	unsigned int found;
	unsigned int invalid;
	unsigned int insert;
	unsigned int insert_failed;
	unsigned int clash_resolve;
	unsigned int drop;
	unsigned int early_drop;
	unsigned int error;
	unsigned int expect_new;
	unsigned int expect_create;
	unsigned int expect_delete;
	unsigned int search_restart;
	unsigned int chaintoolong;
};

struct nf_flow_table_stat {
	unsigned int count_wq_add;
	unsigned int count_wq_del;
	unsigned int count_wq_stats;
};

struct bpf_cgroup_storage;

struct bpf_prog_array_item {
	struct bpf_prog *prog;
	union {
		struct bpf_cgroup_storage *cgroup_storage[2];
		u64 bpf_cookie;
	};
};

struct bpf_prog_array {
	struct callback_head rcu;
	struct bpf_prog_array_item items[0];
};

enum bpf_prog_type {
	BPF_PROG_TYPE_UNSPEC = 0,
	BPF_PROG_TYPE_SOCKET_FILTER = 1,
	BPF_PROG_TYPE_KPROBE = 2,
	BPF_PROG_TYPE_SCHED_CLS = 3,
	BPF_PROG_TYPE_SCHED_ACT = 4,
	BPF_PROG_TYPE_TRACEPOINT = 5,
	BPF_PROG_TYPE_XDP = 6,
	BPF_PROG_TYPE_PERF_EVENT = 7,
	BPF_PROG_TYPE_CGROUP_SKB = 8,
	BPF_PROG_TYPE_CGROUP_SOCK = 9,
	BPF_PROG_TYPE_LWT_IN = 10,
	BPF_PROG_TYPE_LWT_OUT = 11,
	BPF_PROG_TYPE_LWT_XMIT = 12,
	BPF_PROG_TYPE_SOCK_OPS = 13,
	BPF_PROG_TYPE_SK_SKB = 14,
	BPF_PROG_TYPE_CGROUP_DEVICE = 15,
	BPF_PROG_TYPE_SK_MSG = 16,
	BPF_PROG_TYPE_RAW_TRACEPOINT = 17,
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR = 18,
	BPF_PROG_TYPE_LWT_SEG6LOCAL = 19,
	BPF_PROG_TYPE_LIRC_MODE2 = 20,
	BPF_PROG_TYPE_SK_REUSEPORT = 21,
	BPF_PROG_TYPE_FLOW_DISSECTOR = 22,
	BPF_PROG_TYPE_CGROUP_SYSCTL = 23,
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE = 24,
	BPF_PROG_TYPE_CGROUP_SOCKOPT = 25,
	BPF_PROG_TYPE_TRACING = 26,
	BPF_PROG_TYPE_STRUCT_OPS = 27,
	BPF_PROG_TYPE_EXT = 28,
	BPF_PROG_TYPE_LSM = 29,
	BPF_PROG_TYPE_SK_LOOKUP = 30,
	BPF_PROG_TYPE_SYSCALL = 31,
	BPF_PROG_TYPE_NETFILTER = 32,
	__MAX_BPF_PROG_TYPE = 33,
};

enum bpf_attach_type {
	BPF_CGROUP_INET_INGRESS = 0,
	BPF_CGROUP_INET_EGRESS = 1,
	BPF_CGROUP_INET_SOCK_CREATE = 2,
	BPF_CGROUP_SOCK_OPS = 3,
	BPF_SK_SKB_STREAM_PARSER = 4,
	BPF_SK_SKB_STREAM_VERDICT = 5,
	BPF_CGROUP_DEVICE = 6,
	BPF_SK_MSG_VERDICT = 7,
	BPF_CGROUP_INET4_BIND = 8,
	BPF_CGROUP_INET6_BIND = 9,
	BPF_CGROUP_INET4_CONNECT = 10,
	BPF_CGROUP_INET6_CONNECT = 11,
	BPF_CGROUP_INET4_POST_BIND = 12,
	BPF_CGROUP_INET6_POST_BIND = 13,
	BPF_CGROUP_UDP4_SENDMSG = 14,
	BPF_CGROUP_UDP6_SENDMSG = 15,
	BPF_LIRC_MODE2 = 16,
	BPF_FLOW_DISSECTOR = 17,
	BPF_CGROUP_SYSCTL = 18,
	BPF_CGROUP_UDP4_RECVMSG = 19,
	BPF_CGROUP_UDP6_RECVMSG = 20,
	BPF_CGROUP_GETSOCKOPT = 21,
	BPF_CGROUP_SETSOCKOPT = 22,
	BPF_TRACE_RAW_TP = 23,
	BPF_TRACE_FENTRY = 24,
	BPF_TRACE_FEXIT = 25,
	BPF_MODIFY_RETURN = 26,
	BPF_LSM_MAC = 27,
	BPF_TRACE_ITER = 28,
	BPF_CGROUP_INET4_GETPEERNAME = 29,
	BPF_CGROUP_INET6_GETPEERNAME = 30,
	BPF_CGROUP_INET4_GETSOCKNAME = 31,
	BPF_CGROUP_INET6_GETSOCKNAME = 32,
	BPF_XDP_DEVMAP = 33,
	BPF_CGROUP_INET_SOCK_RELEASE = 34,
	BPF_XDP_CPUMAP = 35,
	BPF_SK_LOOKUP = 36,
	BPF_XDP = 37,
	BPF_SK_SKB_VERDICT = 38,
	BPF_SK_REUSEPORT_SELECT = 39,
	BPF_SK_REUSEPORT_SELECT_OR_MIGRATE = 40,
	BPF_PERF_EVENT = 41,
	BPF_TRACE_KPROBE_MULTI = 42,
	BPF_LSM_CGROUP = 43,
	BPF_STRUCT_OPS = 44,
	BPF_NETFILTER = 45,
	BPF_TCX_INGRESS = 46,
	BPF_TCX_EGRESS = 47,
	BPF_TRACE_UPROBE_MULTI = 48,
	BPF_CGROUP_UNIX_CONNECT = 49,
	BPF_CGROUP_UNIX_SENDMSG = 50,
	BPF_CGROUP_UNIX_RECVMSG = 51,
	BPF_CGROUP_UNIX_GETPEERNAME = 52,
	BPF_CGROUP_UNIX_GETSOCKNAME = 53,
	BPF_NETKIT_PRIMARY = 54,
	BPF_NETKIT_PEER = 55,
	BPF_TRACE_KPROBE_SESSION = 56,
	__MAX_BPF_ATTACH_TYPE = 57,
};

struct bpf_prog_stats;

struct sock_fprog_kern;

struct sock_filter {
	__u16 code;
	__u8 jt;
	__u8 jf;
	__u32 k;
};

struct bpf_insn {
	__u8 code;
	__u8 dst_reg: 4;
	__u8 src_reg: 4;
	__s16 off;
	__s32 imm;
};

struct bpf_prog_aux;

struct bpf_prog {
	u16 pages;
	u16 jited: 1;
	u16 jit_requested: 1;
	u16 gpl_compatible: 1;
	u16 cb_access: 1;
	u16 dst_needed: 1;
	u16 blinding_requested: 1;
	u16 blinded: 1;
	u16 is_func: 1;
	u16 kprobe_override: 1;
	u16 has_callchain_buf: 1;
	u16 enforce_expected_attach_type: 1;
	u16 call_get_stack: 1;
	u16 call_get_func_ip: 1;
	u16 tstamp_type_access: 1;
	u16 sleepable: 1;
	enum bpf_prog_type type;
	enum bpf_attach_type expected_attach_type;
	u32 len;
	u32 jited_len;
	u8 tag[8];
	struct bpf_prog_stats *stats;
	int *active;
	unsigned int (*bpf_func)(const void *, const struct bpf_insn *);
	struct bpf_prog_aux *aux;
	struct sock_fprog_kern *orig_prog;
	union {
		struct {
			struct {} __empty_insns;
			struct sock_filter insns[0];
		};
		struct {
			struct {} __empty_insnsi;
			struct bpf_insn insnsi[0];
		};
	};
};

struct em_perf_state {
	long unsigned int performance;
	long unsigned int frequency;
	long unsigned int power;
	long unsigned int cost;
	long unsigned int flags;
};

struct em_perf_table {
	struct callback_head rcu;
	struct kref kref;
	struct em_perf_state state[0];
};

struct em_perf_domain {
	struct em_perf_table *em_table;
	int nr_perf_states;
	long unsigned int flags;
	long unsigned int cpus[0];
};

struct dev_pm_ops {
	int (*prepare)(struct device *);
	void (*complete)(struct device *);
	int (*suspend)(struct device *);
	int (*resume)(struct device *);
	int (*freeze)(struct device *);
	int (*thaw)(struct device *);
	int (*poweroff)(struct device *);
	int (*restore)(struct device *);
	int (*suspend_late)(struct device *);
	int (*resume_early)(struct device *);
	int (*freeze_late)(struct device *);
	int (*thaw_early)(struct device *);
	int (*poweroff_late)(struct device *);
	int (*restore_early)(struct device *);
	int (*suspend_noirq)(struct device *);
	int (*resume_noirq)(struct device *);
	int (*freeze_noirq)(struct device *);
	int (*thaw_noirq)(struct device *);
	int (*poweroff_noirq)(struct device *);
	int (*restore_noirq)(struct device *);
	int (*runtime_suspend)(struct device *);
	int (*runtime_resume)(struct device *);
	int (*runtime_idle)(struct device *);
};

struct pm_subsys_data {
	spinlock_t lock;
	unsigned int refcount;
	unsigned int clock_op_might_sleep;
	struct mutex clock_mutex;
	struct list_head clock_list;
};

struct wakeup_source {
	const char *name;
	int id;
	struct list_head entry;
	spinlock_t lock;
	struct wake_irq *wakeirq;
	struct timer_list timer;
	long unsigned int timer_expires;
	ktime_t total_time;
	ktime_t max_time;
	ktime_t last_time;
	ktime_t start_prevent_time;
	ktime_t prevent_sleep_time;
	long unsigned int event_count;
	long unsigned int active_count;
	long unsigned int relax_count;
	long unsigned int expire_count;
	long unsigned int wakeup_count;
	struct device *dev;
	bool active: 1;
	bool autosleep_enabled: 1;
};

struct dev_pm_domain {
	struct dev_pm_ops ops;
	int (*start)(struct device *);
	void (*detach)(struct device *, bool);
	int (*activate)(struct device *);
	void (*sync)(struct device *);
	void (*dismiss)(struct device *);
	int (*set_performance_state)(struct device *, unsigned int);
};

struct bus_type {
	const char *name;
	const char *dev_name;
	const struct attribute_group **bus_groups;
	const struct attribute_group **dev_groups;
	const struct attribute_group **drv_groups;
	int (*match)(struct device *, const struct device_driver *);
	int (*uevent)(const struct device *, struct kobj_uevent_env *);
	int (*probe)(struct device *);
	void (*sync_state)(struct device *);
	void (*remove)(struct device *);
	void (*shutdown)(struct device *);
	const struct cpumask * (*irq_get_affinity)(struct device *, unsigned int);
	int (*online)(struct device *);
	int (*offline)(struct device *);
	int (*suspend)(struct device *, pm_message_t);
	int (*resume)(struct device *);
	int (*num_vf)(struct device *);
	int (*dma_configure)(struct device *);
	void (*dma_cleanup)(struct device *);
	const struct dev_pm_ops *pm;
	bool need_parent_lock;
};

enum probe_type {
	PROBE_DEFAULT_STRATEGY = 0,
	PROBE_PREFER_ASYNCHRONOUS = 1,
	PROBE_FORCE_SYNCHRONOUS = 2,
};

struct of_device_id;

struct acpi_device_id;

struct driver_private;

struct device_driver {
	const char *name;
	const struct bus_type *bus;
	struct module *owner;
	const char *mod_name;
	bool suppress_bind_attrs;
	enum probe_type probe_type;
	const struct of_device_id *of_match_table;
	const struct acpi_device_id *acpi_match_table;
	int (*probe)(struct device *);
	void (*sync_state)(struct device *);
	int (*remove)(struct device *);
	void (*shutdown)(struct device *);
	int (*suspend)(struct device *, pm_message_t);
	int (*resume)(struct device *);
	const struct attribute_group **groups;
	const struct attribute_group **dev_groups;
	const struct dev_pm_ops *pm;
	void (*coredump)(struct device *);
	struct driver_private *p;
};

struct class {
	const char *name;
	const struct attribute_group **class_groups;
	const struct attribute_group **dev_groups;
	int (*dev_uevent)(const struct device *, struct kobj_uevent_env *);
	char * (*devnode)(const struct device *, umode_t *);
	void (*class_release)(const struct class *);
	void (*dev_release)(struct device *);
	int (*shutdown_pre)(struct device *);
	const struct kobj_ns_type_operations *ns_type;
	const void * (*namespace)(const struct device *);
	void (*get_ownership)(const struct device *, kuid_t *, kgid_t *);
	const struct dev_pm_ops *pm;
};

struct device_type {
	const char *name;
	const struct attribute_group **groups;
	int (*uevent)(const struct device *, struct kobj_uevent_env *);
	char * (*devnode)(const struct device *, umode_t *, kuid_t *, kgid_t *);
	void (*release)(struct device *);
	const struct dev_pm_ops *pm;
};

typedef struct {
	unsigned int clock_rate;
	unsigned int clock_type;
	short unsigned int loopback;
} sync_serial_settings;

typedef struct {
	unsigned int clock_rate;
	unsigned int clock_type;
	short unsigned int loopback;
	unsigned int slot_map;
} te1_settings;

typedef struct {
	short unsigned int encoding;
	short unsigned int parity;
} raw_hdlc_proto;

typedef struct {
	unsigned int t391;
	unsigned int t392;
	unsigned int n391;
	unsigned int n392;
	unsigned int n393;
	short unsigned int lmi;
	short unsigned int dce;
} fr_proto;

typedef struct {
	unsigned int dlci;
} fr_proto_pvc;

typedef struct {
	unsigned int dlci;
	char master[16];
} fr_proto_pvc_info;

typedef struct {
	unsigned int interval;
	unsigned int timeout;
} cisco_proto;

typedef struct {
	short unsigned int dce;
	unsigned int modulo;
	unsigned int window;
	unsigned int t1;
	unsigned int t2;
	unsigned int n2;
} x25_hdlc_proto;

struct ifmap {
	long unsigned int mem_start;
	long unsigned int mem_end;
	short unsigned int base_addr;
	unsigned char irq;
	unsigned char dma;
	unsigned char port;
};

struct if_settings {
	unsigned int type;
	unsigned int size;
	union {
		raw_hdlc_proto *raw_hdlc;
		cisco_proto *cisco;
		fr_proto *fr;
		fr_proto_pvc *fr_pvc;
		fr_proto_pvc_info *fr_pvc_info;
		x25_hdlc_proto *x25;
		sync_serial_settings *sync;
		te1_settings *te1;
	} ifs_ifsu;
};

struct ifreq {
	union {
		char ifrn_name[16];
	} ifr_ifrn;
	union {
		struct sockaddr ifru_addr;
		struct sockaddr ifru_dstaddr;
		struct sockaddr ifru_broadaddr;
		struct sockaddr ifru_netmask;
		struct sockaddr ifru_hwaddr;
		short int ifru_flags;
		int ifru_ivalue;
		int ifru_mtu;
		struct ifmap ifru_map;
		char ifru_slave[16];
		char ifru_newname[16];
		void *ifru_data;
		struct if_settings ifru_settings;
	} ifr_ifru;
};

typedef __u64 Elf64_Addr;

typedef __u16 Elf64_Half;

typedef __u32 Elf64_Word;

typedef __u64 Elf64_Xword;

struct elf64_sym {
	Elf64_Word st_name;
	unsigned char st_info;
	unsigned char st_other;
	Elf64_Half st_shndx;
	Elf64_Addr st_value;
	Elf64_Xword st_size;
};

struct kparam_string;

struct kparam_array;

struct kernel_param {
	const char *name;
	struct module *mod;
	const struct kernel_param_ops *ops;
	const u16 perm;
	s8 level;
	u8 flags;
	union {
		void *arg;
		const struct kparam_string *str;
		const struct kparam_array *arr;
	};
};

struct kparam_string {
	unsigned int maxlen;
	char *string;
};

struct kparam_array {
	unsigned int max;
	unsigned int elemsize;
	unsigned int *num;
	const struct kernel_param_ops *ops;
	void *elem;
};

struct error_injection_entry {
	long unsigned int addr;
	int etype;
};

struct module_attribute {
	struct attribute attr;
	ssize_t (*show)(struct module_attribute *, struct module_kobject *, char *);
	ssize_t (*store)(struct module_attribute *, struct module_kobject *, const char *, size_t);
	void (*setup)(struct module *, const char *);
	int (*test)(struct module *);
	void (*free)(struct module *);
};

struct trace_eval_map {
	const char *system;
	const char *eval_string;
	long unsigned int eval_value;
};

struct device_dma_parameters {
	unsigned int max_segment_size;
	unsigned int min_align_mask;
	long unsigned int segment_boundary_mask;
};

enum device_physical_location_panel {
	DEVICE_PANEL_TOP = 0,
	DEVICE_PANEL_BOTTOM = 1,
	DEVICE_PANEL_LEFT = 2,
	DEVICE_PANEL_RIGHT = 3,
	DEVICE_PANEL_FRONT = 4,
	DEVICE_PANEL_BACK = 5,
	DEVICE_PANEL_UNKNOWN = 6,
};

enum device_physical_location_vertical_position {
	DEVICE_VERT_POS_UPPER = 0,
	DEVICE_VERT_POS_CENTER = 1,
	DEVICE_VERT_POS_LOWER = 2,
};

enum device_physical_location_horizontal_position {
	DEVICE_HORI_POS_LEFT = 0,
	DEVICE_HORI_POS_CENTER = 1,
	DEVICE_HORI_POS_RIGHT = 2,
};

struct device_physical_location {
	enum device_physical_location_panel panel;
	enum device_physical_location_vertical_position vertical_position;
	enum device_physical_location_horizontal_position horizontal_position;
	bool dock;
	bool lid;
};

struct fwnode_operations;

struct fwnode_handle {
	struct fwnode_handle *secondary;
	const struct fwnode_operations *ops;
	struct device *dev;
	struct list_head suppliers;
	struct list_head consumers;
	u8 flags;
};

enum dev_dma_attr {
	DEV_DMA_NOT_SUPPORTED = 0,
	DEV_DMA_NON_COHERENT = 1,
	DEV_DMA_COHERENT = 2,
};

struct fwnode_reference_args;

struct fwnode_endpoint;

struct fwnode_operations {
	struct fwnode_handle * (*get)(struct fwnode_handle *);
	void (*put)(struct fwnode_handle *);
	bool (*device_is_available)(const struct fwnode_handle *);
	const void * (*device_get_match_data)(const struct fwnode_handle *, const struct device *);
	bool (*device_dma_supported)(const struct fwnode_handle *);
	enum dev_dma_attr (*device_get_dma_attr)(const struct fwnode_handle *);
	bool (*property_present)(const struct fwnode_handle *, const char *);
	int (*property_read_int_array)(const struct fwnode_handle *, const char *, unsigned int, void *, size_t);
	int (*property_read_string_array)(const struct fwnode_handle *, const char *, const char **, size_t);
	const char * (*get_name)(const struct fwnode_handle *);
	const char * (*get_name_prefix)(const struct fwnode_handle *);
	struct fwnode_handle * (*get_parent)(const struct fwnode_handle *);
	struct fwnode_handle * (*get_next_child_node)(const struct fwnode_handle *, struct fwnode_handle *);
	struct fwnode_handle * (*get_named_child_node)(const struct fwnode_handle *, const char *);
	int (*get_reference_args)(const struct fwnode_handle *, const char *, const char *, unsigned int, unsigned int, struct fwnode_reference_args *);
	struct fwnode_handle * (*graph_get_next_endpoint)(const struct fwnode_handle *, struct fwnode_handle *);
	struct fwnode_handle * (*graph_get_remote_endpoint)(const struct fwnode_handle *);
	struct fwnode_handle * (*graph_get_port_parent)(struct fwnode_handle *);
	int (*graph_parse_endpoint)(const struct fwnode_handle *, struct fwnode_endpoint *);
	void * (*iomap)(struct fwnode_handle *, int);
	int (*irq_get)(const struct fwnode_handle *, unsigned int);
	int (*add_links)(struct fwnode_handle *);
};

struct fwnode_endpoint {
	unsigned int port;
	unsigned int id;
	const struct fwnode_handle *local_fwnode;
};

struct fwnode_reference_args {
	struct fwnode_handle *fwnode;
	unsigned int nargs;
	u64 args[16];
};

struct scatterlist {
	long unsigned int page_link;
	unsigned int offset;
	unsigned int length;
	dma_addr_t dma_address;
	unsigned int dma_length;
	unsigned int dma_flags;
};

struct skb_shared_hwtstamps {
	union {
		ktime_t hwtstamp;
		void *netdev_data;
	};
};

struct ubuf_info_ops {
	void (*complete)(struct sk_buff *, struct ubuf_info *, bool);
	int (*link_skb)(struct sk_buff *, struct ubuf_info *);
};

struct skb_ext {
	refcount_t refcnt;
	u8 offset[4];
	u8 chunks;
	long: 0;
	char data[0];
};

struct net_generic {
	union {
		struct {
			unsigned int len;
			struct callback_head rcu;
		} s;
		struct {
			struct {} __empty_ptr;
			void *ptr[0];
		};
	};
};

struct xdr_netobj {
	unsigned int len;
	u8 *data;
};

struct xdr_buf {
	struct kvec head[1];
	struct kvec tail[1];
	struct bio_vec *bvec;
	struct page **pages;
	unsigned int page_base;
	unsigned int page_len;
	unsigned int flags;
	unsigned int buflen;
	unsigned int len;
};

struct rpc_rqst;

struct xdr_stream {
	__be32 *p;
	struct xdr_buf *buf;
	__be32 *end;
	struct kvec *iov;
	struct kvec scratch;
	struct page **page_ptr;
	void *page_kaddr;
	unsigned int nwords;
	struct rpc_rqst *rqst;
};

struct lwq_node {
	struct llist_node node;
};

struct rpc_xprt;

struct rpc_task;

struct rpc_cred;

struct rpc_rqst {
	struct rpc_xprt *rq_xprt;
	struct xdr_buf rq_snd_buf;
	struct xdr_buf rq_rcv_buf;
	struct rpc_task *rq_task;
	struct rpc_cred *rq_cred;
	__be32 rq_xid;
	int rq_cong;
	u32 rq_seqno;
	int rq_enc_pages_num;
	struct page **rq_enc_pages;
	void (*rq_release_snd_buf)(struct rpc_rqst *);
	union {
		struct list_head rq_list;
		struct rb_node rq_recv;
	};
	struct list_head rq_xmit;
	struct list_head rq_xmit2;
	void *rq_buffer;
	size_t rq_callsize;
	void *rq_rbuffer;
	size_t rq_rcvsize;
	size_t rq_xmit_bytes_sent;
	size_t rq_reply_bytes_recvd;
	struct xdr_buf rq_private_buf;
	long unsigned int rq_majortimeo;
	long unsigned int rq_minortimeo;
	long unsigned int rq_timeout;
	ktime_t rq_rtt;
	unsigned int rq_retries;
	unsigned int rq_connect_cookie;
	atomic_t rq_pin;
	u32 rq_bytes_sent;
	ktime_t rq_xtime;
	int rq_ntrans;
	struct lwq_node rq_bc_list;
	long unsigned int rq_bc_pa_state;
	struct list_head rq_bc_pa_list;
};

typedef void (*kxdreproc_t)(struct rpc_rqst *, struct xdr_stream *, const void *);

typedef int (*kxdrdproc_t)(struct rpc_rqst *, struct xdr_stream *, void *);

struct rpc_procinfo;

struct rpc_message {
	const struct rpc_procinfo *rpc_proc;
	void *rpc_argp;
	void *rpc_resp;
	const struct cred *rpc_cred;
};

struct rpc_procinfo {
	u32 p_proc;
	kxdreproc_t p_encode;
	kxdrdproc_t p_decode;
	unsigned int p_arglen;
	unsigned int p_replen;
	unsigned int p_timer;
	u32 p_statidx;
	const char *p_name;
};

struct rpc_wait {
	struct list_head list;
	struct list_head links;
	struct list_head timer_list;
};

struct rpc_timeout {
	long unsigned int to_initval;
	long unsigned int to_maxval;
	long unsigned int to_increment;
	unsigned int to_retries;
	unsigned char to_exponential;
};

struct rpc_wait_queue;

struct rpc_call_ops;

struct rpc_clnt;

struct rpc_task {
	atomic_t tk_count;
	int tk_status;
	struct list_head tk_task;
	void (*tk_callback)(struct rpc_task *);
	void (*tk_action)(struct rpc_task *);
	long unsigned int tk_timeout;
	long unsigned int tk_runstate;
	struct rpc_wait_queue *tk_waitqueue;
	union {
		struct work_struct tk_work;
		struct rpc_wait tk_wait;
	} u;
	struct rpc_message tk_msg;
	void *tk_calldata;
	const struct rpc_call_ops *tk_ops;
	struct rpc_clnt *tk_client;
	struct rpc_xprt *tk_xprt;
	struct rpc_cred *tk_op_cred;
	struct rpc_rqst *tk_rqstp;
	struct workqueue_struct *tk_workqueue;
	ktime_t tk_start;
	pid_t tk_owner;
	int tk_rpc_status;
	short unsigned int tk_flags;
	short unsigned int tk_timeouts;
	short unsigned int tk_pid;
	unsigned char tk_priority: 2;
	unsigned char tk_garb_retry: 2;
	unsigned char tk_cred_retry: 2;
};

struct rpc_timer {
	struct list_head list;
	long unsigned int expires;
	struct delayed_work dwork;
};

struct rpc_wait_queue {
	spinlock_t lock;
	struct list_head tasks[4];
	unsigned char maxpriority;
	unsigned char priority;
	unsigned char nr;
	unsigned int qlen;
	struct rpc_timer timer_list;
	const char *name;
};

struct rpc_call_ops {
	void (*rpc_call_prepare)(struct rpc_task *, void *);
	void (*rpc_call_done)(struct rpc_task *, void *);
	void (*rpc_count_stats)(struct rpc_task *, void *);
	void (*rpc_release)(void *);
};

struct rpc_iostats;

enum xprtsec_policies {
	RPC_XPRTSEC_NONE = 0,
	RPC_XPRTSEC_TLS_ANON = 1,
	RPC_XPRTSEC_TLS_X509 = 2,
};

struct xprtsec_parms {
	enum xprtsec_policies policy;
	key_serial_t cert_serial;
	key_serial_t privkey_serial;
};

struct rpc_pipe_dir_head {
	struct list_head pdh_entries;
	struct dentry *pdh_dentry;
};

struct rpc_rtt {
	long unsigned int timeo;
	long unsigned int srtt[5];
	long unsigned int sdrtt[5];
	int ntimeouts[5];
};

struct rpc_xprt_switch;

struct rpc_xprt_iter_ops;

struct rpc_xprt_iter {
	struct rpc_xprt_switch *xpi_xpswitch;
	struct rpc_xprt *xpi_cursor;
	const struct rpc_xprt_iter_ops *xpi_ops;
};

struct rpc_auth;

struct rpc_stat;

struct rpc_program;

struct rpc_sysfs_client;

struct rpc_clnt {
	refcount_t cl_count;
	unsigned int cl_clid;
	struct list_head cl_clients;
	struct list_head cl_tasks;
	atomic_t cl_pid;
	spinlock_t cl_lock;
	struct rpc_xprt *cl_xprt;
	const struct rpc_procinfo *cl_procinfo;
	u32 cl_prog;
	u32 cl_vers;
	u32 cl_maxproc;
	struct rpc_auth *cl_auth;
	struct rpc_stat *cl_stats;
	struct rpc_iostats *cl_metrics;
	unsigned int cl_softrtry: 1;
	unsigned int cl_softerr: 1;
	unsigned int cl_discrtry: 1;
	unsigned int cl_noretranstimeo: 1;
	unsigned int cl_autobind: 1;
	unsigned int cl_chatty: 1;
	unsigned int cl_shutdown: 1;
	struct xprtsec_parms cl_xprtsec;
	struct rpc_rtt *cl_rtt;
	const struct rpc_timeout *cl_timeout;
	atomic_t cl_swapper;
	int cl_nodelen;
	char cl_nodename[65];
	struct rpc_pipe_dir_head cl_pipedir_objects;
	struct rpc_clnt *cl_parent;
	struct rpc_rtt cl_rtt_default;
	struct rpc_timeout cl_timeout_default;
	const struct rpc_program *cl_program;
	const char *cl_principal;
	struct dentry *cl_debugfs;
	struct rpc_sysfs_client *cl_sysfs;
	union {
		struct rpc_xprt_iter cl_xpi;
		struct work_struct cl_work;
	};
	const struct cred *cl_cred;
	unsigned int cl_max_connect;
	struct super_block *pipefs_sb;
};

struct rpc_sysfs_xprt;

struct rpc_xprt_ops;

struct svc_xprt;

struct svc_serv;

struct xprt_class;

struct rpc_xprt {
	struct kref kref;
	const struct rpc_xprt_ops *ops;
	unsigned int id;
	const struct rpc_timeout *timeout;
	struct __kernel_sockaddr_storage addr;
	size_t addrlen;
	int prot;
	long unsigned int cong;
	long unsigned int cwnd;
	size_t max_payload;
	struct rpc_wait_queue binding;
	struct rpc_wait_queue sending;
	struct rpc_wait_queue pending;
	struct rpc_wait_queue backlog;
	struct list_head free;
	unsigned int max_reqs;
	unsigned int min_reqs;
	unsigned int num_reqs;
	long unsigned int state;
	unsigned char resvport: 1;
	unsigned char reuseport: 1;
	atomic_t swapper;
	unsigned int bind_index;
	struct list_head xprt_switch;
	long unsigned int bind_timeout;
	long unsigned int reestablish_timeout;
	struct xprtsec_parms xprtsec;
	unsigned int connect_cookie;
	struct work_struct task_cleanup;
	struct timer_list timer;
	long unsigned int last_used;
	long unsigned int idle_timeout;
	long unsigned int connect_timeout;
	long unsigned int max_reconnect_timeout;
	atomic_long_t queuelen;
	spinlock_t transport_lock;
	spinlock_t reserve_lock;
	spinlock_t queue_lock;
	u32 xid;
	struct rpc_task *snd_task;
	struct list_head xmit_queue;
	atomic_long_t xmit_queuelen;
	struct svc_xprt *bc_xprt;
	struct svc_serv *bc_serv;
	unsigned int bc_alloc_max;
	unsigned int bc_alloc_count;
	atomic_t bc_slot_count;
	spinlock_t bc_pa_lock;
	struct list_head bc_pa_list;
	struct rb_root recv_queue;
	struct {
		long unsigned int bind_count;
		long unsigned int connect_count;
		long unsigned int connect_start;
		long unsigned int connect_time;
		long unsigned int sends;
		long unsigned int recvs;
		long unsigned int bad_xids;
		long unsigned int max_slots;
		long long unsigned int req_u;
		long long unsigned int bklog_u;
		long long unsigned int sending_u;
		long long unsigned int pending_u;
	} stat;
	struct net *xprt_net;
	netns_tracker ns_tracker;
	const char *servername;
	const char *address_strings[6];
	struct dentry *debugfs;
	struct callback_head rcu;
	const struct xprt_class *xprt_class;
	struct rpc_sysfs_xprt *xprt_sysfs;
	bool main;
};

struct rpc_credops;

struct rpc_cred {
	struct hlist_node cr_hash;
	struct list_head cr_lru;
	struct callback_head cr_rcu;
	struct rpc_auth *cr_auth;
	const struct rpc_credops *cr_ops;
	long unsigned int cr_expire;
	long unsigned int cr_flags;
	refcount_t cr_count;
	const struct cred *cr_cred;
};

typedef void (*rpc_action)(struct rpc_task *);

struct rpc_task_setup {
	struct rpc_task *task;
	struct rpc_clnt *rpc_client;
	struct rpc_xprt *rpc_xprt;
	struct rpc_cred *rpc_op_cred;
	const struct rpc_message *rpc_message;
	const struct rpc_call_ops *callback_ops;
	void *callback_data;
	struct workqueue_struct *workqueue;
	short unsigned int flags;
	signed char priority;
};

enum rpc_display_format_t {
	RPC_DISPLAY_ADDR = 0,
	RPC_DISPLAY_PORT = 1,
	RPC_DISPLAY_PROTO = 2,
	RPC_DISPLAY_HEX_ADDR = 3,
	RPC_DISPLAY_HEX_PORT = 4,
	RPC_DISPLAY_NETID = 5,
	RPC_DISPLAY_MAX = 6,
};

struct lwq {
	spinlock_t lock;
	struct llist_node *ready;
	struct llist_head new;
};

struct rpc_xprt_ops {
	void (*set_buffer_size)(struct rpc_xprt *, size_t, size_t);
	int (*reserve_xprt)(struct rpc_xprt *, struct rpc_task *);
	void (*release_xprt)(struct rpc_xprt *, struct rpc_task *);
	void (*alloc_slot)(struct rpc_xprt *, struct rpc_task *);
	void (*free_slot)(struct rpc_xprt *, struct rpc_rqst *);
	void (*rpcbind)(struct rpc_task *);
	void (*set_port)(struct rpc_xprt *, short unsigned int);
	void (*connect)(struct rpc_xprt *, struct rpc_task *);
	int (*get_srcaddr)(struct rpc_xprt *, char *, size_t);
	short unsigned int (*get_srcport)(struct rpc_xprt *);
	int (*buf_alloc)(struct rpc_task *);
	void (*buf_free)(struct rpc_task *);
	int (*prepare_request)(struct rpc_rqst *, struct xdr_buf *);
	int (*send_request)(struct rpc_rqst *);
	void (*abort_send_request)(struct rpc_rqst *);
	void (*wait_for_reply_request)(struct rpc_task *);
	void (*timer)(struct rpc_xprt *, struct rpc_task *);
	void (*release_request)(struct rpc_task *);
	void (*close)(struct rpc_xprt *);
	void (*destroy)(struct rpc_xprt *);
	void (*set_connect_timeout)(struct rpc_xprt *, long unsigned int, long unsigned int);
	void (*print_stats)(struct rpc_xprt *, struct seq_file *);
	int (*enable_swap)(struct rpc_xprt *);
	void (*disable_swap)(struct rpc_xprt *);
	void (*inject_disconnect)(struct rpc_xprt *);
	int (*bc_setup)(struct rpc_xprt *, unsigned int);
	size_t (*bc_maxpayload)(struct rpc_xprt *);
	unsigned int (*bc_num_slots)(struct rpc_xprt *);
	void (*bc_free_rqst)(struct rpc_rqst *);
	void (*bc_destroy)(struct rpc_xprt *, unsigned int);
};

struct svc_program;

struct svc_stat;

struct svc_pool;

struct svc_serv {
	struct svc_program *sv_programs;
	struct svc_stat *sv_stats;
	spinlock_t sv_lock;
	unsigned int sv_nprogs;
	unsigned int sv_nrthreads;
	unsigned int sv_maxconn;
	unsigned int sv_max_payload;
	unsigned int sv_max_mesg;
	unsigned int sv_xdrsize;
	struct list_head sv_permsocks;
	struct list_head sv_tempsocks;
	int sv_tmpcnt;
	struct timer_list sv_temptimer;
	char *sv_name;
	unsigned int sv_nrpools;
	bool sv_is_pooled;
	struct svc_pool *sv_pools;
	int (*sv_threadfn)(void *);
	struct lwq sv_cb_list;
	bool sv_bc_enabled;
};

struct xprt_create;

struct xprt_class {
	struct list_head list;
	int ident;
	struct rpc_xprt * (*setup)(struct xprt_create *);
	struct module *owner;
	char name[32];
	const char *netid[0];
};

struct xprt_create {
	int ident;
	struct net *net;
	struct sockaddr *srcaddr;
	struct sockaddr *dstaddr;
	size_t addrlen;
	const char *servername;
	struct svc_xprt *bc_xprt;
	struct rpc_xprt_switch *bc_xps;
	unsigned int flags;
	struct xprtsec_parms xprtsec;
	long unsigned int connect_timeout;
	long unsigned int reconnect_timeout;
};

struct rpc_sysfs_xprt_switch;

struct rpc_xprt_switch {
	spinlock_t xps_lock;
	struct kref xps_kref;
	unsigned int xps_id;
	unsigned int xps_nxprts;
	unsigned int xps_nactive;
	unsigned int xps_nunique_destaddr_xprts;
	atomic_long_t xps_queuelen;
	struct list_head xps_xprt_list;
	struct net *xps_net;
	const struct rpc_xprt_iter_ops *xps_iter_ops;
	struct rpc_sysfs_xprt_switch *xps_sysfs;
	struct callback_head xps_rcu;
};

struct new_utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
	char domainname[65];
};

struct uts_namespace {
	struct new_utsname name;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct ns_common ns;
};

struct cgroup_namespace {
	struct ns_common ns;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct css_set *root_cset;
};

struct auth_cred {
	const struct cred *cred;
	const char *principal;
};

struct rpc_cred_cache;

struct rpc_authops;

struct rpc_auth {
	unsigned int au_cslack;
	unsigned int au_rslack;
	unsigned int au_verfsize;
	unsigned int au_ralign;
	long unsigned int au_flags;
	const struct rpc_authops *au_ops;
	rpc_authflavor_t au_flavor;
	refcount_t au_count;
	struct rpc_cred_cache *au_credcache;
};

struct rpc_credops {
	const char *cr_name;
	int (*cr_init)(struct rpc_auth *, struct rpc_cred *);
	void (*crdestroy)(struct rpc_cred *);
	int (*crmatch)(struct auth_cred *, struct rpc_cred *, int);
	int (*crmarshal)(struct rpc_task *, struct xdr_stream *);
	int (*crrefresh)(struct rpc_task *);
	int (*crvalidate)(struct rpc_task *, struct xdr_stream *);
	int (*crwrap_req)(struct rpc_task *, struct xdr_stream *);
	int (*crunwrap_resp)(struct rpc_task *, struct xdr_stream *);
	int (*crkey_timeout)(struct rpc_cred *);
	char * (*crstringify_acceptor)(struct rpc_cred *);
	bool (*crneed_reencode)(struct rpc_task *);
};

struct rpc_auth_create_args;

struct rpcsec_gss_info;

struct rpc_authops {
	struct module *owner;
	rpc_authflavor_t au_flavor;
	char *au_name;
	struct rpc_auth * (*create)(const struct rpc_auth_create_args *, struct rpc_clnt *);
	void (*destroy)(struct rpc_auth *);
	int (*hash_cred)(struct auth_cred *, unsigned int);
	struct rpc_cred * (*lookup_cred)(struct rpc_auth *, struct auth_cred *, int);
	struct rpc_cred * (*crcreate)(struct rpc_auth *, struct auth_cred *, int, gfp_t);
	rpc_authflavor_t (*info2flavor)(struct rpcsec_gss_info *);
	int (*flavor2info)(rpc_authflavor_t, struct rpcsec_gss_info *);
	int (*key_timeout)(struct rpc_auth *, struct rpc_cred *);
	int (*ping)(struct rpc_clnt *);
};

struct rpc_auth_create_args {
	rpc_authflavor_t pseudoflavor;
	const char *target_name;
};

struct rpcsec_gss_oid {
	unsigned int len;
	u8 data[32];
};

struct rpcsec_gss_info {
	struct rpcsec_gss_oid oid;
	u32 qop;
	u32 service;
};

struct rpc_stat {
	const struct rpc_program *program;
	unsigned int netcnt;
	unsigned int netudpcnt;
	unsigned int nettcpcnt;
	unsigned int nettcpconn;
	unsigned int netreconn;
	unsigned int rpccnt;
	unsigned int rpcretrans;
	unsigned int rpcauthrefresh;
	unsigned int rpcgarbage;
};

struct rpc_version;

struct rpc_program {
	const char *name;
	u32 number;
	unsigned int nrvers;
	const struct rpc_version **version;
	struct rpc_stat *stats;
	const char *pipe_dir_name;
};

struct svc_stat {
	struct svc_program *program;
	unsigned int netcnt;
	unsigned int netudpcnt;
	unsigned int nettcpcnt;
	unsigned int nettcpconn;
	unsigned int rpccnt;
	unsigned int rpcbadfmt;
	unsigned int rpcbadauth;
	unsigned int rpcbadclnt;
};

enum svc_auth_status {
	SVC_GARBAGE = 1,
	SVC_SYSERR = 2,
	SVC_VALID = 3,
	SVC_NEGATIVE = 4,
	SVC_OK = 5,
	SVC_DROP = 6,
	SVC_CLOSE = 7,
	SVC_DENIED = 8,
	SVC_PENDING = 9,
	SVC_COMPLETE = 10,
};

struct svc_version;

struct svc_rqst;

struct svc_process_info;

struct svc_program {
	u32 pg_prog;
	unsigned int pg_lovers;
	unsigned int pg_hivers;
	unsigned int pg_nvers;
	const struct svc_version **pg_vers;
	char *pg_name;
	char *pg_class;
	enum svc_auth_status (*pg_authenticate)(struct svc_rqst *);
	__be32 (*pg_init_request)(struct svc_rqst *, const struct svc_program *, struct svc_process_info *);
	int (*pg_rpcbind_set)(struct net *, const struct svc_program *, u32, int, short unsigned int, short unsigned int);
};

struct rpc_pipe_msg {
	struct list_head list;
	void *data;
	size_t len;
	size_t copied;
	int errno;
};

struct rpc_pipe_ops {
	ssize_t (*upcall)(struct file *, struct rpc_pipe_msg *, char *, size_t);
	ssize_t (*downcall)(struct file *, const char *, size_t);
	void (*release_pipe)(struct inode *);
	int (*open_pipe)(struct inode *);
	void (*destroy_msg)(struct rpc_pipe_msg *);
};

struct rpc_pipe {
	struct list_head pipe;
	struct list_head in_upcall;
	struct list_head in_downcall;
	int pipelen;
	int nreaders;
	int nwriters;
	int flags;
	struct delayed_work queue_timeout;
	const struct rpc_pipe_ops *ops;
	spinlock_t lock;
	struct dentry *dentry;
};

struct dql {
	unsigned int num_queued;
	unsigned int adj_limit;
	unsigned int last_obj_cnt;
	short unsigned int stall_thrs;
	long unsigned int history_head;
	long unsigned int history[4];
	long: 64;
	unsigned int limit;
	unsigned int num_completed;
	unsigned int prev_ovlimit;
	unsigned int prev_num_queued;
	unsigned int prev_last_obj_cnt;
	unsigned int lowest_slack;
	long unsigned int slack_start_time;
	unsigned int max_limit;
	unsigned int min_limit;
	unsigned int slack_hold_time;
	short unsigned int stall_max;
	long unsigned int last_reap;
	long unsigned int stall_cnt;
};

struct ieee_ets {
	__u8 willing;
	__u8 ets_cap;
	__u8 cbs;
	__u8 tc_tx_bw[8];
	__u8 tc_rx_bw[8];
	__u8 tc_tsa[8];
	__u8 prio_tc[8];
	__u8 tc_reco_bw[8];
	__u8 tc_reco_tsa[8];
	__u8 reco_prio_tc[8];
};

struct ieee_maxrate {
	__u64 tc_maxrate[8];
};

struct ieee_qcn {
	__u8 rpg_enable[8];
	__u32 rppp_max_rps[8];
	__u32 rpg_time_reset[8];
	__u32 rpg_byte_reset[8];
	__u32 rpg_threshold[8];
	__u32 rpg_max_rate[8];
	__u32 rpg_ai_rate[8];
	__u32 rpg_hai_rate[8];
	__u32 rpg_gd[8];
	__u32 rpg_min_dec_fac[8];
	__u32 rpg_min_rate[8];
	__u32 cndd_state_machine[8];
};

struct ieee_qcn_stats {
	__u64 rppp_rp_centiseconds[8];
	__u32 rppp_created_rps[8];
};

struct ieee_pfc {
	__u8 pfc_cap;
	__u8 pfc_en;
	__u8 mbc;
	__u16 delay;
	__u64 requests[8];
	__u64 indications[8];
};

struct dcbnl_buffer {
	__u8 prio2buffer[8];
	__u32 buffer_size[8];
	__u32 total_size;
};

struct cee_pg {
	__u8 willing;
	__u8 error;
	__u8 pg_en;
	__u8 tcs_supported;
	__u8 pg_bw[8];
	__u8 prio_pg[8];
};

struct cee_pfc {
	__u8 willing;
	__u8 error;
	__u8 pfc_en;
	__u8 tcs_supported;
};

struct dcb_app {
	__u8 selector;
	__u8 priority;
	__u16 protocol;
};

struct dcb_peer_app_info {
	__u8 willing;
	__u8 error;
};

struct dcbnl_rtnl_ops {
	int (*ieee_getets)(struct net_device *, struct ieee_ets *);
	int (*ieee_setets)(struct net_device *, struct ieee_ets *);
	int (*ieee_getmaxrate)(struct net_device *, struct ieee_maxrate *);
	int (*ieee_setmaxrate)(struct net_device *, struct ieee_maxrate *);
	int (*ieee_getqcn)(struct net_device *, struct ieee_qcn *);
	int (*ieee_setqcn)(struct net_device *, struct ieee_qcn *);
	int (*ieee_getqcnstats)(struct net_device *, struct ieee_qcn_stats *);
	int (*ieee_getpfc)(struct net_device *, struct ieee_pfc *);
	int (*ieee_setpfc)(struct net_device *, struct ieee_pfc *);
	int (*ieee_getapp)(struct net_device *, struct dcb_app *);
	int (*ieee_setapp)(struct net_device *, struct dcb_app *);
	int (*ieee_delapp)(struct net_device *, struct dcb_app *);
	int (*ieee_peer_getets)(struct net_device *, struct ieee_ets *);
	int (*ieee_peer_getpfc)(struct net_device *, struct ieee_pfc *);
	u8 (*getstate)(struct net_device *);
	u8 (*setstate)(struct net_device *, u8);
	void (*getpermhwaddr)(struct net_device *, u8 *);
	void (*setpgtccfgtx)(struct net_device *, int, u8, u8, u8, u8);
	void (*setpgbwgcfgtx)(struct net_device *, int, u8);
	void (*setpgtccfgrx)(struct net_device *, int, u8, u8, u8, u8);
	void (*setpgbwgcfgrx)(struct net_device *, int, u8);
	void (*getpgtccfgtx)(struct net_device *, int, u8 *, u8 *, u8 *, u8 *);
	void (*getpgbwgcfgtx)(struct net_device *, int, u8 *);
	void (*getpgtccfgrx)(struct net_device *, int, u8 *, u8 *, u8 *, u8 *);
	void (*getpgbwgcfgrx)(struct net_device *, int, u8 *);
	void (*setpfccfg)(struct net_device *, int, u8);
	void (*getpfccfg)(struct net_device *, int, u8 *);
	u8 (*setall)(struct net_device *);
	u8 (*getcap)(struct net_device *, int, u8 *);
	int (*getnumtcs)(struct net_device *, int, u8 *);
	int (*setnumtcs)(struct net_device *, int, u8);
	u8 (*getpfcstate)(struct net_device *);
	void (*setpfcstate)(struct net_device *, u8);
	void (*getbcncfg)(struct net_device *, int, u32 *);
	void (*setbcncfg)(struct net_device *, int, u32);
	void (*getbcnrp)(struct net_device *, int, u8 *);
	void (*setbcnrp)(struct net_device *, int, u8);
	int (*setapp)(struct net_device *, u8, u16, u8);
	int (*getapp)(struct net_device *, u8, u16);
	u8 (*getfeatcfg)(struct net_device *, int, u8 *);
	u8 (*setfeatcfg)(struct net_device *, int, u8);
	u8 (*getdcbx)(struct net_device *);
	u8 (*setdcbx)(struct net_device *, u8);
	int (*peer_getappinfo)(struct net_device *, struct dcb_peer_app_info *, u16 *);
	int (*peer_getapptable)(struct net_device *, struct dcb_app *);
	int (*cee_peer_getpg)(struct net_device *, struct cee_pg *);
	int (*cee_peer_getpfc)(struct net_device *, struct cee_pfc *);
	int (*dcbnl_getbuffer)(struct net_device *, struct dcbnl_buffer *);
	int (*dcbnl_setbuffer)(struct net_device *, struct dcbnl_buffer *);
	int (*dcbnl_setapptrust)(struct net_device *, u8 *, int);
	int (*dcbnl_getapptrust)(struct net_device *, u8 *, int *);
	int (*dcbnl_setrewr)(struct net_device *, struct dcb_app *);
	int (*dcbnl_delrewr)(struct net_device *, struct dcb_app *);
};

struct psi_group_cpu {
	unsigned int tasks[4];
	u32 state_mask;
	u32 times[7];
	u64 state_start;
	long: 64;
	u32 times_prev[14];
	long: 64;
};

struct psi_group {
	struct psi_group *parent;
	bool enabled;
	struct mutex avgs_lock;
	struct psi_group_cpu *pcpu;
	u64 avg_total[6];
	u64 avg_last_update;
	u64 avg_next_update;
	struct delayed_work avgs_work;
	struct list_head avg_triggers;
	u32 avg_nr_triggers[6];
	u64 total[12];
	long unsigned int avg[18];
	struct task_struct *rtpoll_task;
	struct timer_list rtpoll_timer;
	wait_queue_head_t rtpoll_wait;
	atomic_t rtpoll_wakeup;
	atomic_t rtpoll_scheduled;
	struct mutex rtpoll_trigger_lock;
	struct list_head rtpoll_triggers;
	u32 rtpoll_nr_triggers[6];
	u32 rtpoll_states;
	u64 rtpoll_min_period;
	u64 rtpoll_total[6];
	u64 rtpoll_next_update;
	u64 rtpoll_until;
};

struct cgroup_taskset;

struct cftype;

struct cgroup_subsys {
	struct cgroup_subsys_state * (*css_alloc)(struct cgroup_subsys_state *);
	int (*css_online)(struct cgroup_subsys_state *);
	void (*css_offline)(struct cgroup_subsys_state *);
	void (*css_released)(struct cgroup_subsys_state *);
	void (*css_free)(struct cgroup_subsys_state *);
	void (*css_reset)(struct cgroup_subsys_state *);
	void (*css_killed)(struct cgroup_subsys_state *);
	void (*css_rstat_flush)(struct cgroup_subsys_state *, int);
	int (*css_extra_stat_show)(struct seq_file *, struct cgroup_subsys_state *);
	int (*css_local_stat_show)(struct seq_file *, struct cgroup_subsys_state *);
	int (*can_attach)(struct cgroup_taskset *);
	void (*cancel_attach)(struct cgroup_taskset *);
	void (*attach)(struct cgroup_taskset *);
	void (*post_attach)();
	int (*can_fork)(struct task_struct *, struct css_set *);
	void (*cancel_fork)(struct task_struct *, struct css_set *);
	void (*fork)(struct task_struct *);
	void (*exit)(struct task_struct *);
	void (*release)(struct task_struct *);
	void (*bind)(struct cgroup_subsys_state *);
	bool early_init: 1;
	bool implicit_on_dfl: 1;
	bool threaded: 1;
	int id;
	const char *name;
	const char *legacy_name;
	struct cgroup_root *root;
	struct idr css_idr;
	struct list_head cfts;
	struct cftype *dfl_cftypes;
	struct cftype *legacy_cftypes;
	unsigned int depends_on;
};

struct cgroup_rstat_cpu {
	struct u64_stats_sync bsync;
	struct cgroup_base_stat bstat;
	struct cgroup_base_stat last_bstat;
	struct cgroup_base_stat subtree_bstat;
	struct cgroup_base_stat last_subtree_bstat;
	struct cgroup *updated_children;
	struct cgroup *updated_next;
};

struct cgroup_root {
	struct kernfs_root *kf_root;
	unsigned int subsys_mask;
	int hierarchy_id;
	struct list_head root_list;
	struct callback_head rcu;
	long: 64;
	long: 64;
	struct cgroup cgrp;
	struct cgroup *cgrp_ancestor_storage;
	atomic_t nr_cgrps;
	unsigned int flags;
	char release_agent_path[4096];
	char name[64];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct cftype {
	char name[64];
	long unsigned int private;
	size_t max_write_len;
	unsigned int flags;
	unsigned int file_offset;
	struct cgroup_subsys *ss;
	struct list_head node;
	struct kernfs_ops *kf_ops;
	int (*open)(struct kernfs_open_file *);
	void (*release)(struct kernfs_open_file *);
	u64 (*read_u64)(struct cgroup_subsys_state *, struct cftype *);
	s64 (*read_s64)(struct cgroup_subsys_state *, struct cftype *);
	int (*seq_show)(struct seq_file *, void *);
	void * (*seq_start)(struct seq_file *, loff_t *);
	void * (*seq_next)(struct seq_file *, void *, loff_t *);
	void (*seq_stop)(struct seq_file *, void *);
	int (*write_u64)(struct cgroup_subsys_state *, struct cftype *, u64);
	int (*write_s64)(struct cgroup_subsys_state *, struct cftype *, s64);
	ssize_t (*write)(struct kernfs_open_file *, char *, size_t, loff_t);
	__poll_t (*poll)(struct kernfs_open_file *, struct poll_table_struct *);
	struct lock_class_key lockdep_key;
};

struct netprio_map {
	struct callback_head rcu;
	u32 priomap_len;
	u32 priomap[0];
};

typedef struct {
	union {
		void *kernel;
		void *user;
	};
	bool is_kernel: 1;
} sockptr_t;

typedef enum {
	SS_FREE = 0,
	SS_UNCONNECTED = 1,
	SS_CONNECTING = 2,
	SS_CONNECTED = 3,
	SS_DISCONNECTING = 4,
} socket_state;

struct socket_wq {
	wait_queue_head_t wait;
	struct fasync_struct *fasync_list;
	long unsigned int flags;
	struct callback_head rcu;
	long: 64;
};

struct proto_ops;

struct socket {
	socket_state state;
	short int type;
	long unsigned int flags;
	struct file *file;
	struct sock *sk;
	const struct proto_ops *ops;
	long: 64;
	long: 64;
	long: 64;
	struct socket_wq wq;
};

typedef struct {
	size_t written;
	size_t count;
	union {
		char *buf;
		void *data;
	} arg;
	int error;
} read_descriptor_t;

typedef int (*sk_read_actor_t)(read_descriptor_t *, struct sk_buff *, unsigned int, size_t);

typedef int (*skb_read_actor_t)(struct sock *, struct sk_buff *);

struct proto_accept_arg;

struct proto_ops {
	int family;
	struct module *owner;
	int (*release)(struct socket *);
	int (*bind)(struct socket *, struct sockaddr *, int);
	int (*connect)(struct socket *, struct sockaddr *, int, int);
	int (*socketpair)(struct socket *, struct socket *);
	int (*accept)(struct socket *, struct socket *, struct proto_accept_arg *);
	int (*getname)(struct socket *, struct sockaddr *, int);
	__poll_t (*poll)(struct file *, struct socket *, struct poll_table_struct *);
	int (*ioctl)(struct socket *, unsigned int, long unsigned int);
	int (*compat_ioctl)(struct socket *, unsigned int, long unsigned int);
	int (*gettstamp)(struct socket *, void *, bool, bool);
	int (*listen)(struct socket *, int);
	int (*shutdown)(struct socket *, int);
	int (*setsockopt)(struct socket *, int, int, sockptr_t, unsigned int);
	int (*getsockopt)(struct socket *, int, int, char *, int *);
	void (*show_fdinfo)(struct seq_file *, struct socket *);
	int (*sendmsg)(struct socket *, struct msghdr *, size_t);
	int (*recvmsg)(struct socket *, struct msghdr *, size_t, int);
	int (*mmap)(struct file *, struct socket *, struct vm_area_struct *);
	ssize_t (*splice_read)(struct socket *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	void (*splice_eof)(struct socket *);
	int (*set_peek_off)(struct sock *, int);
	int (*peek_len)(struct socket *);
	int (*read_sock)(struct sock *, read_descriptor_t *, sk_read_actor_t);
	int (*read_skb)(struct sock *, skb_read_actor_t);
	int (*sendmsg_locked)(struct sock *, struct msghdr *, size_t);
	int (*set_rcvlowat)(struct sock *, int);
};

struct proto_accept_arg {
	int flags;
	int err;
	int is_empty;
	bool kern;
};

enum bpf_cgroup_iter_order {
	BPF_CGROUP_ITER_ORDER_UNSPEC = 0,
	BPF_CGROUP_ITER_SELF_ONLY = 1,
	BPF_CGROUP_ITER_DESCENDANTS_PRE = 2,
	BPF_CGROUP_ITER_DESCENDANTS_POST = 3,
	BPF_CGROUP_ITER_ANCESTORS_UP = 4,
};

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PROG_ARRAY = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_STACK_TRACE = 7,
	BPF_MAP_TYPE_CGROUP_ARRAY = 8,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
	BPF_MAP_TYPE_LPM_TRIE = 11,
	BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
	BPF_MAP_TYPE_HASH_OF_MAPS = 13,
	BPF_MAP_TYPE_DEVMAP = 14,
	BPF_MAP_TYPE_SOCKMAP = 15,
	BPF_MAP_TYPE_CPUMAP = 16,
	BPF_MAP_TYPE_XSKMAP = 17,
	BPF_MAP_TYPE_SOCKHASH = 18,
	BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED = 19,
	BPF_MAP_TYPE_CGROUP_STORAGE = 19,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED = 21,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
	BPF_MAP_TYPE_QUEUE = 22,
	BPF_MAP_TYPE_STACK = 23,
	BPF_MAP_TYPE_SK_STORAGE = 24,
	BPF_MAP_TYPE_DEVMAP_HASH = 25,
	BPF_MAP_TYPE_STRUCT_OPS = 26,
	BPF_MAP_TYPE_RINGBUF = 27,
	BPF_MAP_TYPE_INODE_STORAGE = 28,
	BPF_MAP_TYPE_TASK_STORAGE = 29,
	BPF_MAP_TYPE_BLOOM_FILTER = 30,
	BPF_MAP_TYPE_USER_RINGBUF = 31,
	BPF_MAP_TYPE_CGRP_STORAGE = 32,
	BPF_MAP_TYPE_ARENA = 33,
	__MAX_BPF_MAP_TYPE = 34,
};

union bpf_attr {
	struct {
		__u32 map_type;
		__u32 key_size;
		__u32 value_size;
		__u32 max_entries;
		__u32 map_flags;
		__u32 inner_map_fd;
		__u32 numa_node;
		char map_name[16];
		__u32 map_ifindex;
		__u32 btf_fd;
		__u32 btf_key_type_id;
		__u32 btf_value_type_id;
		__u32 btf_vmlinux_value_type_id;
		__u64 map_extra;
		__s32 value_type_btf_obj_fd;
		__s32 map_token_fd;
	};
	struct {
		__u32 map_fd;
		__u64 key;
		union {
			__u64 value;
			__u64 next_key;
		};
		__u64 flags;
	};
	struct {
		__u64 in_batch;
		__u64 out_batch;
		__u64 keys;
		__u64 values;
		__u32 count;
		__u32 map_fd;
		__u64 elem_flags;
		__u64 flags;
	} batch;
	struct {
		__u32 prog_type;
		__u32 insn_cnt;
		__u64 insns;
		__u64 license;
		__u32 log_level;
		__u32 log_size;
		__u64 log_buf;
		__u32 kern_version;
		__u32 prog_flags;
		char prog_name[16];
		__u32 prog_ifindex;
		__u32 expected_attach_type;
		__u32 prog_btf_fd;
		__u32 func_info_rec_size;
		__u64 func_info;
		__u32 func_info_cnt;
		__u32 line_info_rec_size;
		__u64 line_info;
		__u32 line_info_cnt;
		__u32 attach_btf_id;
		union {
			__u32 attach_prog_fd;
			__u32 attach_btf_obj_fd;
		};
		__u32 core_relo_cnt;
		__u64 fd_array;
		__u64 core_relos;
		__u32 core_relo_rec_size;
		__u32 log_true_size;
		__s32 prog_token_fd;
	};
	struct {
		__u64 pathname;
		__u32 bpf_fd;
		__u32 file_flags;
		__s32 path_fd;
	};
	struct {
		union {
			__u32 target_fd;
			__u32 target_ifindex;
		};
		__u32 attach_bpf_fd;
		__u32 attach_type;
		__u32 attach_flags;
		__u32 replace_bpf_fd;
		union {
			__u32 relative_fd;
			__u32 relative_id;
		};
		__u64 expected_revision;
	};
	struct {
		__u32 prog_fd;
		__u32 retval;
		__u32 data_size_in;
		__u32 data_size_out;
		__u64 data_in;
		__u64 data_out;
		__u32 repeat;
		__u32 duration;
		__u32 ctx_size_in;
		__u32 ctx_size_out;
		__u64 ctx_in;
		__u64 ctx_out;
		__u32 flags;
		__u32 cpu;
		__u32 batch_size;
	} test;
	struct {
		union {
			__u32 start_id;
			__u32 prog_id;
			__u32 map_id;
			__u32 btf_id;
			__u32 link_id;
		};
		__u32 next_id;
		__u32 open_flags;
	};
	struct {
		__u32 bpf_fd;
		__u32 info_len;
		__u64 info;
	} info;
	struct {
		union {
			__u32 target_fd;
			__u32 target_ifindex;
		};
		__u32 attach_type;
		__u32 query_flags;
		__u32 attach_flags;
		__u64 prog_ids;
		union {
			__u32 prog_cnt;
			__u32 count;
		};
		__u64 prog_attach_flags;
		__u64 link_ids;
		__u64 link_attach_flags;
		__u64 revision;
	} query;
	struct {
		__u64 name;
		__u32 prog_fd;
		__u64 cookie;
	} raw_tracepoint;
	struct {
		__u64 btf;
		__u64 btf_log_buf;
		__u32 btf_size;
		__u32 btf_log_size;
		__u32 btf_log_level;
		__u32 btf_log_true_size;
		__u32 btf_flags;
		__s32 btf_token_fd;
	};
	struct {
		__u32 pid;
		__u32 fd;
		__u32 flags;
		__u32 buf_len;
		__u64 buf;
		__u32 prog_id;
		__u32 fd_type;
		__u64 probe_offset;
		__u64 probe_addr;
	} task_fd_query;
	struct {
		union {
			__u32 prog_fd;
			__u32 map_fd;
		};
		union {
			__u32 target_fd;
			__u32 target_ifindex;
		};
		__u32 attach_type;
		__u32 flags;
		union {
			__u32 target_btf_id;
			struct {
				__u64 iter_info;
				__u32 iter_info_len;
			};
			struct {
				__u64 bpf_cookie;
			} perf_event;
			struct {
				__u32 flags;
				__u32 cnt;
				__u64 syms;
				__u64 addrs;
				__u64 cookies;
			} kprobe_multi;
			struct {
				__u32 target_btf_id;
				__u64 cookie;
			} tracing;
			struct {
				__u32 pf;
				__u32 hooknum;
				__s32 priority;
				__u32 flags;
			} netfilter;
			struct {
				union {
					__u32 relative_fd;
					__u32 relative_id;
				};
				__u64 expected_revision;
			} tcx;
			struct {
				__u64 path;
				__u64 offsets;
				__u64 ref_ctr_offsets;
				__u64 cookies;
				__u32 cnt;
				__u32 flags;
				__u32 pid;
			} uprobe_multi;
			struct {
				union {
					__u32 relative_fd;
					__u32 relative_id;
				};
				__u64 expected_revision;
			} netkit;
		};
	} link_create;
	struct {
		__u32 link_fd;
		union {
			__u32 new_prog_fd;
			__u32 new_map_fd;
		};
		__u32 flags;
		union {
			__u32 old_prog_fd;
			__u32 old_map_fd;
		};
	} link_update;
	struct {
		__u32 link_fd;
	} link_detach;
	struct {
		__u32 type;
	} enable_stats;
	struct {
		__u32 link_fd;
		__u32 flags;
	} iter_create;
	struct {
		__u32 prog_fd;
		__u32 map_fd;
		__u32 flags;
	} prog_bind_map;
	struct {
		__u32 flags;
		__u32 bpffs_fd;
	} token_create;
};

struct bpf_func_info {
	__u32 insn_off;
	__u32 type_id;
};

struct bpf_line_info {
	__u32 insn_off;
	__u32 file_name_off;
	__u32 line_off;
	__u32 line_col;
};

struct btf_type {
	__u32 name_off;
	__u32 info;
	union {
		__u32 size;
		__u32 type;
	};
};

enum btf_field_type {
	BPF_SPIN_LOCK = 1,
	BPF_TIMER = 2,
	BPF_KPTR_UNREF = 4,
	BPF_KPTR_REF = 8,
	BPF_KPTR_PERCPU = 16,
	BPF_KPTR = 28,
	BPF_LIST_HEAD = 32,
	BPF_LIST_NODE = 64,
	BPF_RB_ROOT = 128,
	BPF_RB_NODE = 256,
	BPF_GRAPH_NODE = 320,
	BPF_GRAPH_ROOT = 160,
	BPF_REFCOUNT = 512,
	BPF_WORKQUEUE = 1024,
};

struct btf;

typedef void (*btf_dtor_kfunc_t)(void *);

struct btf_field_kptr {
	struct btf *btf;
	struct module *module;
	btf_dtor_kfunc_t dtor;
	u32 btf_id;
};

struct btf_record;

struct btf_field_graph_root {
	struct btf *btf;
	u32 value_btf_id;
	u32 node_offset;
	struct btf_record *value_rec;
};

struct btf_field {
	u32 offset;
	u32 size;
	enum btf_field_type type;
	union {
		struct btf_field_kptr kptr;
		struct btf_field_graph_root graph_root;
	};
};

struct btf_record {
	u32 cnt;
	u32 field_mask;
	int spin_lock_off;
	int timer_off;
	int wq_off;
	int refcount_off;
	struct btf_field fields[0];
};

struct blk_holder_ops {
	void (*mark_dead)(struct block_device *, bool);
	void (*sync)(struct block_device *);
	int (*freeze)(struct block_device *);
	int (*thaw)(struct block_device *);
};

struct bio_alloc_cache;

typedef void *mempool_alloc_t(gfp_t, void *);

typedef void mempool_free_t(void *, void *);

struct mempool_s {
	spinlock_t lock;
	int min_nr;
	int curr_nr;
	void **elements;
	void *pool_data;
	mempool_alloc_t *alloc;
	mempool_free_t *free;
	wait_queue_head_t wait;
};

typedef struct mempool_s mempool_t;

struct bio_set {
	struct kmem_cache *bio_slab;
	unsigned int front_pad;
	struct bio_alloc_cache *cache;
	mempool_t bio_pool;
	mempool_t bvec_pool;
	mempool_t bio_integrity_pool;
	mempool_t bvec_integrity_pool;
	unsigned int back_pad;
	spinlock_t rescue_lock;
	struct bio_list rescue_list;
	struct work_struct rescue_work;
	struct workqueue_struct *rescue_workqueue;
	struct hlist_node cpuhp_dead;
};

struct mem_cgroup_reclaim_iter {
	struct mem_cgroup *position;
	atomic_t generation;
};

struct lruvec_stats_percpu;

struct lruvec_stats;

struct mem_cgroup_per_node {
	struct mem_cgroup *memcg;
	struct lruvec_stats_percpu *lruvec_stats_percpu;
	struct lruvec_stats *lruvec_stats;
	struct shrinker_info *shrinker_info;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct lruvec lruvec;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	long unsigned int lru_zone_size[25];
	struct mem_cgroup_reclaim_iter iter;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

typedef u64 (*bpf_callback_t)(u64, u64, u64, u64, u64);

struct bpf_iter_aux_info;

typedef int (*bpf_iter_init_seq_priv_t)(void *, struct bpf_iter_aux_info *);

enum bpf_iter_task_type {
	BPF_TASK_ITER_ALL = 0,
	BPF_TASK_ITER_TID = 1,
	BPF_TASK_ITER_TGID = 2,
};

struct bpf_map;

struct bpf_iter_aux_info {
	struct bpf_map *map;
	struct {
		struct cgroup *start;
		enum bpf_cgroup_iter_order order;
	} cgroup;
	struct {
		enum bpf_iter_task_type type;
		u32 pid;
	} task;
};

typedef void (*bpf_iter_fini_seq_priv_t)(void *);

struct bpf_iter_seq_info {
	const struct seq_operations *seq_ops;
	bpf_iter_init_seq_priv_t init_seq_private;
	bpf_iter_fini_seq_priv_t fini_seq_private;
	u32 seq_priv_size;
};

struct bpf_local_storage_map;

struct bpf_verifier_env;

struct bpf_func_state;

struct bpf_map_ops {
	int (*map_alloc_check)(union bpf_attr *);
	struct bpf_map * (*map_alloc)(union bpf_attr *);
	void (*map_release)(struct bpf_map *, struct file *);
	void (*map_free)(struct bpf_map *);
	int (*map_get_next_key)(struct bpf_map *, void *, void *);
	void (*map_release_uref)(struct bpf_map *);
	void * (*map_lookup_elem_sys_only)(struct bpf_map *, void *);
	int (*map_lookup_batch)(struct bpf_map *, const union bpf_attr *, union bpf_attr *);
	int (*map_lookup_and_delete_elem)(struct bpf_map *, void *, void *, u64);
	int (*map_lookup_and_delete_batch)(struct bpf_map *, const union bpf_attr *, union bpf_attr *);
	int (*map_update_batch)(struct bpf_map *, struct file *, const union bpf_attr *, union bpf_attr *);
	int (*map_delete_batch)(struct bpf_map *, const union bpf_attr *, union bpf_attr *);
	void * (*map_lookup_elem)(struct bpf_map *, void *);
	long int (*map_update_elem)(struct bpf_map *, void *, void *, u64);
	long int (*map_delete_elem)(struct bpf_map *, void *);
	long int (*map_push_elem)(struct bpf_map *, void *, u64);
	long int (*map_pop_elem)(struct bpf_map *, void *);
	long int (*map_peek_elem)(struct bpf_map *, void *);
	void * (*map_lookup_percpu_elem)(struct bpf_map *, void *, u32);
	void * (*map_fd_get_ptr)(struct bpf_map *, struct file *, int);
	void (*map_fd_put_ptr)(struct bpf_map *, void *, bool);
	int (*map_gen_lookup)(struct bpf_map *, struct bpf_insn *);
	u32 (*map_fd_sys_lookup_elem)(void *);
	void (*map_seq_show_elem)(struct bpf_map *, void *, struct seq_file *);
	int (*map_check_btf)(const struct bpf_map *, const struct btf *, const struct btf_type *, const struct btf_type *);
	int (*map_poke_track)(struct bpf_map *, struct bpf_prog_aux *);
	void (*map_poke_untrack)(struct bpf_map *, struct bpf_prog_aux *);
	void (*map_poke_run)(struct bpf_map *, u32, struct bpf_prog *, struct bpf_prog *);
	int (*map_direct_value_addr)(const struct bpf_map *, u64 *, u32);
	int (*map_direct_value_meta)(const struct bpf_map *, u64, u32 *);
	int (*map_mmap)(struct bpf_map *, struct vm_area_struct *);
	__poll_t (*map_poll)(struct bpf_map *, struct file *, struct poll_table_struct *);
	long unsigned int (*map_get_unmapped_area)(struct file *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
	int (*map_local_storage_charge)(struct bpf_local_storage_map *, void *, u32);
	void (*map_local_storage_uncharge)(struct bpf_local_storage_map *, void *, u32);
	struct bpf_local_storage ** (*map_owner_storage_ptr)(void *);
	long int (*map_redirect)(struct bpf_map *, u64, u64);
	bool (*map_meta_equal)(const struct bpf_map *, const struct bpf_map *);
	int (*map_set_for_each_callback_args)(struct bpf_verifier_env *, struct bpf_func_state *, struct bpf_func_state *);
	long int (*map_for_each_callback)(struct bpf_map *, bpf_callback_t, void *, u64);
	u64 (*map_mem_usage)(const struct bpf_map *);
	int *map_btf_id;
	const struct bpf_iter_seq_info *iter_seq_info;
};

struct bpf_map {
	const struct bpf_map_ops *ops;
	struct bpf_map *inner_map_meta;
	void *security;
	enum bpf_map_type map_type;
	u32 key_size;
	u32 value_size;
	u32 max_entries;
	u64 map_extra;
	u32 map_flags;
	u32 id;
	struct btf_record *record;
	int numa_node;
	u32 btf_key_type_id;
	u32 btf_value_type_id;
	u32 btf_vmlinux_value_type_id;
	struct btf *btf;
	struct obj_cgroup *objcg;
	char name[16];
	struct mutex freeze_mutex;
	atomic64_t refcnt;
	atomic64_t usercnt;
	union {
		struct work_struct work;
		struct callback_head rcu;
	};
	atomic64_t writecnt;
	struct {
		const struct btf_type *attach_func_proto;
		spinlock_t lock;
		enum bpf_prog_type type;
		bool jited;
		bool xdp_has_frags;
	} owner;
	bool bypass_spec_v1;
	bool frozen;
	bool free_after_mult_rcu_gp;
	bool free_after_rcu_gp;
	atomic64_t sleepable_refcnt;
	s64 *elem_count;
};

struct bpf_arena;

struct bpf_kfunc_desc_tab;

struct bpf_kfunc_btf_tab;

struct bpf_ksym {
	long unsigned int start;
	long unsigned int end;
	char name[512];
	struct list_head lnode;
	struct latch_tree_node tnode;
	bool prog;
};

struct bpf_ctx_arg_aux;

struct bpf_trampoline;

struct bpf_jit_poke_descriptor;

struct bpf_prog_ops;

struct btf_mod_pair;

struct bpf_token;

struct bpf_prog_offload;

struct bpf_func_info_aux;

struct bpf_prog_aux {
	atomic64_t refcnt;
	u32 used_map_cnt;
	u32 used_btf_cnt;
	u32 max_ctx_offset;
	u32 max_pkt_offset;
	u32 max_tp_access;
	u32 stack_depth;
	u32 id;
	u32 func_cnt;
	u32 real_func_cnt;
	u32 func_idx;
	u32 attach_btf_id;
	u32 ctx_arg_info_size;
	u32 max_rdonly_access;
	u32 max_rdwr_access;
	struct btf *attach_btf;
	const struct bpf_ctx_arg_aux *ctx_arg_info;
	struct mutex dst_mutex;
	struct bpf_prog *dst_prog;
	struct bpf_trampoline *dst_trampoline;
	enum bpf_prog_type saved_dst_prog_type;
	enum bpf_attach_type saved_dst_attach_type;
	bool verifier_zext;
	bool dev_bound;
	bool offload_requested;
	bool attach_btf_trace;
	bool attach_tracing_prog;
	bool func_proto_unreliable;
	bool tail_call_reachable;
	bool xdp_has_frags;
	bool exception_cb;
	bool exception_boundary;
	bool is_extended;
	bool changes_pkt_data;
	u64 prog_array_member_cnt;
	struct mutex ext_mutex;
	struct bpf_arena *arena;
	const struct btf_type *attach_func_proto;
	const char *attach_func_name;
	struct bpf_prog **func;
	void *jit_data;
	struct bpf_jit_poke_descriptor *poke_tab;
	struct bpf_kfunc_desc_tab *kfunc_tab;
	struct bpf_kfunc_btf_tab *kfunc_btf_tab;
	u32 size_poke_tab;
	struct bpf_ksym ksym;
	const struct bpf_prog_ops *ops;
	struct bpf_map **used_maps;
	struct mutex used_maps_mutex;
	struct btf_mod_pair *used_btfs;
	struct bpf_prog *prog;
	struct user_struct *user;
	u64 load_time;
	u32 verified_insns;
	int cgroup_atype;
	struct bpf_map *cgroup_storage[2];
	char name[16];
	u64 (*bpf_exception_cb)(u64, u64, u64, u64, u64);
	void *security;
	struct bpf_token *token;
	struct bpf_prog_offload *offload;
	struct btf *btf;
	struct bpf_func_info *func_info;
	struct bpf_func_info_aux *func_info_aux;
	struct bpf_line_info *linfo;
	void **jited_linfo;
	u32 func_info_cnt;
	u32 nr_linfo;
	u32 linfo_idx;
	struct module *mod;
	u32 num_exentries;
	struct exception_table_entry *extable;
	union {
		struct work_struct work;
		struct callback_head rcu;
	};
};

struct bpf_offloaded_map;

struct bpf_map_dev_ops {
	int (*map_get_next_key)(struct bpf_offloaded_map *, void *, void *);
	int (*map_lookup_elem)(struct bpf_offloaded_map *, void *, void *);
	int (*map_update_elem)(struct bpf_offloaded_map *, void *, void *, u64);
	int (*map_delete_elem)(struct bpf_offloaded_map *, void *);
};

struct bpf_offloaded_map {
	struct bpf_map map;
	struct net_device *netdev;
	const struct bpf_map_dev_ops *dev_ops;
	void *dev_priv;
	struct list_head offloads;
};

enum bpf_reg_type {
	NOT_INIT = 0,
	SCALAR_VALUE = 1,
	PTR_TO_CTX = 2,
	CONST_PTR_TO_MAP = 3,
	PTR_TO_MAP_VALUE = 4,
	PTR_TO_MAP_KEY = 5,
	PTR_TO_STACK = 6,
	PTR_TO_PACKET_META = 7,
	PTR_TO_PACKET = 8,
	PTR_TO_PACKET_END = 9,
	PTR_TO_FLOW_KEYS = 10,
	PTR_TO_SOCKET = 11,
	PTR_TO_SOCK_COMMON = 12,
	PTR_TO_TCP_SOCK = 13,
	PTR_TO_TP_BUFFER = 14,
	PTR_TO_XDP_SOCK = 15,
	PTR_TO_BTF_ID = 16,
	PTR_TO_MEM = 17,
	PTR_TO_ARENA = 18,
	PTR_TO_BUF = 19,
	PTR_TO_FUNC = 20,
	CONST_PTR_TO_DYNPTR = 21,
	__BPF_REG_TYPE_MAX = 22,
	PTR_TO_MAP_VALUE_OR_NULL = 260,
	PTR_TO_SOCKET_OR_NULL = 267,
	PTR_TO_SOCK_COMMON_OR_NULL = 268,
	PTR_TO_TCP_SOCK_OR_NULL = 269,
	PTR_TO_BTF_ID_OR_NULL = 272,
	__BPF_REG_TYPE_LIMIT = 134217727,
};

struct bpf_prog_ops {
	int (*test_run)(struct bpf_prog *, const union bpf_attr *, union bpf_attr *);
};

struct bpf_offload_dev;

struct bpf_prog_offload {
	struct bpf_prog *prog;
	struct net_device *netdev;
	struct bpf_offload_dev *offdev;
	void *dev_priv;
	struct list_head offloads;
	bool dev_state;
	bool opt_failed;
	void *jited_image;
	u32 jited_len;
};

struct btf_func_model {
	u8 ret_size;
	u8 ret_flags;
	u8 nr_args;
	u8 arg_size[12];
	u8 arg_flags[12];
};

struct bpf_tramp_image {
	void *image;
	int size;
	struct bpf_ksym ksym;
	struct percpu_ref pcref;
	void *ip_after_call;
	void *ip_epilogue;
	union {
		struct callback_head rcu;
		struct work_struct work;
	};
};

struct ftrace_ops;

struct bpf_trampoline {
	struct hlist_node hlist;
	struct ftrace_ops *fops;
	struct mutex mutex;
	refcount_t refcnt;
	u32 flags;
	u64 key;
	struct {
		struct btf_func_model model;
		void *addr;
		bool ftrace_managed;
	} func;
	struct bpf_prog *extension_prog;
	struct hlist_head progs_hlist[3];
	int progs_cnt[3];
	struct bpf_tramp_image *cur_image;
};

struct bpf_func_info_aux {
	u16 linkage;
	bool unreliable;
	bool called: 1;
	bool verified: 1;
};

struct bpf_jit_poke_descriptor {
	void *tailcall_target;
	void *tailcall_bypass;
	void *bypass_addr;
	void *aux;
	union {
		struct {
			struct bpf_map *map;
			u32 key;
		} tail_call;
	};
	bool tailcall_target_stable;
	u8 adj_off;
	u16 reason;
	u32 insn_idx;
};

struct bpf_ctx_arg_aux {
	u32 offset;
	enum bpf_reg_type reg_type;
	struct btf *btf;
	u32 btf_id;
};

struct btf_mod_pair {
	struct btf *btf;
	struct module *module;
};

struct bpf_token {
	struct work_struct work;
	atomic64_t refcnt;
	struct user_namespace *userns;
	u64 allowed_cmds;
	u64 allowed_maps;
	u64 allowed_progs;
	u64 allowed_attachs;
	void *security;
};

struct nlmsghdr {
	__u32 nlmsg_len;
	__u16 nlmsg_type;
	__u16 nlmsg_flags;
	__u32 nlmsg_seq;
	__u32 nlmsg_pid;
};

struct nlattr {
	__u16 nla_len;
	__u16 nla_type;
};

struct nla_policy;

struct netlink_ext_ack {
	const char *_msg;
	const struct nlattr *bad_attr;
	const struct nla_policy *policy;
	const struct nlattr *miss_nest;
	u16 miss_type;
	u8 cookie[20];
	u8 cookie_len;
	char _msg_buf[80];
};

struct netlink_range_validation;

struct netlink_range_validation_signed;

struct nla_policy {
	u8 type;
	u8 validation_type;
	u16 len;
	union {
		u16 strict_start_type;
		const u32 bitfield32_valid;
		const u32 mask;
		const char *reject_message;
		const struct nla_policy *nested_policy;
		const struct netlink_range_validation *range;
		const struct netlink_range_validation_signed *range_signed;
		struct {
			s16 min;
			s16 max;
		};
		int (*validate)(const struct nlattr *, struct netlink_ext_ack *);
	};
};

struct netlink_callback {
	struct sk_buff *skb;
	const struct nlmsghdr *nlh;
	int (*dump)(struct sk_buff *, struct netlink_callback *);
	int (*done)(struct netlink_callback *);
	void *data;
	struct module *module;
	struct netlink_ext_ack *extack;
	u16 family;
	u16 answer_flags;
	u32 min_dump_alloc;
	unsigned int prev_seq;
	unsigned int seq;
	int flags;
	bool strict_check;
	union {
		u8 ctx[48];
		long int args[6];
	};
};

struct ndmsg {
	__u8 ndm_family;
	__u8 ndm_pad1;
	__u16 ndm_pad2;
	__s32 ndm_ifindex;
	__u16 ndm_state;
	__u8 ndm_flags;
	__u8 ndm_type;
};

struct rtnl_link_stats64 {
	__u64 rx_packets;
	__u64 tx_packets;
	__u64 rx_bytes;
	__u64 tx_bytes;
	__u64 rx_errors;
	__u64 tx_errors;
	__u64 rx_dropped;
	__u64 tx_dropped;
	__u64 multicast;
	__u64 collisions;
	__u64 rx_length_errors;
	__u64 rx_over_errors;
	__u64 rx_crc_errors;
	__u64 rx_frame_errors;
	__u64 rx_fifo_errors;
	__u64 rx_missed_errors;
	__u64 tx_aborted_errors;
	__u64 tx_carrier_errors;
	__u64 tx_fifo_errors;
	__u64 tx_heartbeat_errors;
	__u64 tx_window_errors;
	__u64 rx_compressed;
	__u64 tx_compressed;
	__u64 rx_nohandler;
	__u64 rx_otherhost_dropped;
};

struct rtnl_hw_stats64 {
	__u64 rx_packets;
	__u64 tx_packets;
	__u64 rx_bytes;
	__u64 tx_bytes;
	__u64 rx_errors;
	__u64 tx_errors;
	__u64 rx_dropped;
	__u64 tx_dropped;
	__u64 multicast;
};

struct ifla_vf_guid {
	__u32 vf;
	__u64 guid;
};

struct ifla_vf_stats {
	__u64 rx_packets;
	__u64 tx_packets;
	__u64 rx_bytes;
	__u64 tx_bytes;
	__u64 broadcast;
	__u64 multicast;
	__u64 rx_dropped;
	__u64 tx_dropped;
};

struct ifla_vf_info {
	__u32 vf;
	__u8 mac[32];
	__u32 vlan;
	__u32 qos;
	__u32 spoofchk;
	__u32 linkstate;
	__u32 min_tx_rate;
	__u32 max_tx_rate;
	__u32 rss_query_en;
	__u32 trusted;
	__be16 vlan_proto;
};

enum netdev_tx {
	__NETDEV_TX_MIN = -2147483648,
	NETDEV_TX_OK = 0,
	NETDEV_TX_BUSY = 16,
};

typedef enum netdev_tx netdev_tx_t;

struct net_device_core_stats {
	long unsigned int rx_dropped;
	long unsigned int tx_dropped;
	long unsigned int rx_nohandler;
	long unsigned int rx_otherhost_dropped;
};

struct header_ops {
	int (*create)(struct sk_buff *, struct net_device *, short unsigned int, const void *, const void *, unsigned int);
	int (*parse)(const struct sk_buff *, unsigned char *);
	int (*cache)(const struct neighbour *, struct hh_cache *, __be16);
	void (*cache_update)(struct hh_cache *, const struct net_device *, const unsigned char *);
	bool (*validate)(const char *, unsigned int);
	__be16 (*parse_protocol)(const struct sk_buff *);
};

struct gro_list {
	struct list_head list;
	int count;
};

struct napi_struct {
	struct list_head poll_list;
	long unsigned int state;
	int weight;
	u32 defer_hard_irqs_count;
	long unsigned int gro_bitmask;
	int (*poll)(struct napi_struct *, int);
	int poll_owner;
	int list_owner;
	struct net_device *dev;
	struct gro_list gro_hash[8];
	struct sk_buff *skb;
	struct list_head rx_list;
	int rx_count;
	unsigned int napi_id;
	struct hrtimer timer;
	struct task_struct *thread;
	struct list_head dev_list;
	struct hlist_node napi_hash_node;
	int irq;
};

struct xsk_buff_pool;

struct netdev_queue {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct Qdisc *qdisc;
	struct Qdisc *qdisc_sleeping;
	struct kobject kobj;
	long unsigned int tx_maxrate;
	atomic_long_t trans_timeout;
	struct net_device *sb_dev;
	struct xsk_buff_pool *pool;
	long: 64;
	struct dql dql;
	spinlock_t _xmit_lock;
	int xmit_lock_owner;
	long unsigned int trans_start;
	long unsigned int state;
	struct napi_struct *napi;
	int numa_node;
	long: 64;
	long: 64;
	long: 64;
};

struct xps_map {
	unsigned int len;
	unsigned int alloc_len;
	struct callback_head rcu;
	u16 queues[0];
};

struct xps_dev_maps {
	struct callback_head rcu;
	unsigned int nr_ids;
	s16 num_tc;
	struct xps_map *attr_map[0];
};

struct netdev_fcoe_hbainfo {
	char manufacturer[64];
	char serial_number[64];
	char hardware_version[64];
	char driver_version[64];
	char optionrom_version[64];
	char firmware_version[64];
	char model[256];
	char model_description[256];
};

struct netdev_phys_item_id {
	unsigned char id[32];
	unsigned char id_len;
};

enum net_device_path_type {
	DEV_PATH_ETHERNET = 0,
	DEV_PATH_VLAN = 1,
	DEV_PATH_BRIDGE = 2,
	DEV_PATH_PPPOE = 3,
	DEV_PATH_DSA = 4,
	DEV_PATH_MTK_WDMA = 5,
};

struct net_device_path {
	enum net_device_path_type type;
	const struct net_device *dev;
	union {
		struct {
			u16 id;
			__be16 proto;
			u8 h_dest[6];
		} encap;
		struct {
			enum {
				DEV_PATH_BR_VLAN_KEEP = 0,
				DEV_PATH_BR_VLAN_TAG = 1,
				DEV_PATH_BR_VLAN_UNTAG = 2,
				DEV_PATH_BR_VLAN_UNTAG_HW = 3,
			} vlan_mode;
			u16 vlan_id;
			__be16 vlan_proto;
		} bridge;
		struct {
			int port;
			u16 proto;
		} dsa;
		struct {
			u8 wdma_idx;
			u8 queue;
			u16 wcid;
			u8 bss;
			u8 amsdu;
		} mtk_wdma;
	};
};

struct net_device_path_ctx {
	const struct net_device *dev;
	u8 daddr[6];
	int num_vlans;
	struct {
		u16 id;
		__be16 proto;
	} vlan[2];
};

enum tc_setup_type {
	TC_QUERY_CAPS = 0,
	TC_SETUP_QDISC_MQPRIO = 1,
	TC_SETUP_CLSU32 = 2,
	TC_SETUP_CLSFLOWER = 3,
	TC_SETUP_CLSMATCHALL = 4,
	TC_SETUP_CLSBPF = 5,
	TC_SETUP_BLOCK = 6,
	TC_SETUP_QDISC_CBS = 7,
	TC_SETUP_QDISC_RED = 8,
	TC_SETUP_QDISC_PRIO = 9,
	TC_SETUP_QDISC_MQ = 10,
	TC_SETUP_QDISC_ETF = 11,
	TC_SETUP_ROOT_QDISC = 12,
	TC_SETUP_QDISC_GRED = 13,
	TC_SETUP_QDISC_TAPRIO = 14,
	TC_SETUP_FT = 15,
	TC_SETUP_QDISC_ETS = 16,
	TC_SETUP_QDISC_TBF = 17,
	TC_SETUP_QDISC_FIFO = 18,
	TC_SETUP_QDISC_HTB = 19,
	TC_SETUP_ACT = 20,
};

enum bpf_netdev_command {
	XDP_SETUP_PROG = 0,
	XDP_SETUP_PROG_HW = 1,
	BPF_OFFLOAD_MAP_ALLOC = 2,
	BPF_OFFLOAD_MAP_FREE = 3,
	XDP_SETUP_XSK_POOL = 4,
};

struct netdev_bpf {
	enum bpf_netdev_command command;
	union {
		struct {
			u32 flags;
			struct bpf_prog *prog;
			struct netlink_ext_ack *extack;
		};
		struct {
			struct bpf_offloaded_map *offmap;
		};
		struct {
			struct xsk_buff_pool *pool;
			u16 queue_id;
		} xsk;
	};
};

struct xfrmdev_ops {
	int (*xdo_dev_state_add)(struct xfrm_state *, struct netlink_ext_ack *);
	void (*xdo_dev_state_delete)(struct xfrm_state *);
	void (*xdo_dev_state_free)(struct xfrm_state *);
	bool (*xdo_dev_offload_ok)(struct sk_buff *, struct xfrm_state *);
	void (*xdo_dev_state_advance_esn)(struct xfrm_state *);
	void (*xdo_dev_state_update_stats)(struct xfrm_state *);
	int (*xdo_dev_policy_add)(struct xfrm_policy *, struct netlink_ext_ack *);
	void (*xdo_dev_policy_delete)(struct xfrm_policy *);
	void (*xdo_dev_policy_free)(struct xfrm_policy *);
};

struct dev_ifalias {
	struct callback_head rcuhead;
	char ifalias[0];
};

struct xdp_frame;

struct xdp_buff;

struct ip_tunnel_parm_kern;

struct kernel_hwtstamp_config;

struct net_device_ops {
	int (*ndo_init)(struct net_device *);
	void (*ndo_uninit)(struct net_device *);
	int (*ndo_open)(struct net_device *);
	int (*ndo_stop)(struct net_device *);
	netdev_tx_t (*ndo_start_xmit)(struct sk_buff *, struct net_device *);
	netdev_features_t (*ndo_features_check)(struct sk_buff *, struct net_device *, netdev_features_t);
	u16 (*ndo_select_queue)(struct net_device *, struct sk_buff *, struct net_device *);
	void (*ndo_change_rx_flags)(struct net_device *, int);
	void (*ndo_set_rx_mode)(struct net_device *);
	int (*ndo_set_mac_address)(struct net_device *, void *);
	int (*ndo_validate_addr)(struct net_device *);
	int (*ndo_do_ioctl)(struct net_device *, struct ifreq *, int);
	int (*ndo_eth_ioctl)(struct net_device *, struct ifreq *, int);
	int (*ndo_siocbond)(struct net_device *, struct ifreq *, int);
	int (*ndo_siocwandev)(struct net_device *, struct if_settings *);
	int (*ndo_siocdevprivate)(struct net_device *, struct ifreq *, void *, int);
	int (*ndo_set_config)(struct net_device *, struct ifmap *);
	int (*ndo_change_mtu)(struct net_device *, int);
	int (*ndo_neigh_setup)(struct net_device *, struct neigh_parms *);
	void (*ndo_tx_timeout)(struct net_device *, unsigned int);
	void (*ndo_get_stats64)(struct net_device *, struct rtnl_link_stats64 *);
	bool (*ndo_has_offload_stats)(const struct net_device *, int);
	int (*ndo_get_offload_stats)(int, const struct net_device *, void *);
	struct net_device_stats * (*ndo_get_stats)(struct net_device *);
	int (*ndo_vlan_rx_add_vid)(struct net_device *, __be16, u16);
	int (*ndo_vlan_rx_kill_vid)(struct net_device *, __be16, u16);
	void (*ndo_poll_controller)(struct net_device *);
	int (*ndo_netpoll_setup)(struct net_device *, struct netpoll_info *);
	void (*ndo_netpoll_cleanup)(struct net_device *);
	int (*ndo_set_vf_mac)(struct net_device *, int, u8 *);
	int (*ndo_set_vf_vlan)(struct net_device *, int, u16, u8, __be16);
	int (*ndo_set_vf_rate)(struct net_device *, int, int, int);
	int (*ndo_set_vf_spoofchk)(struct net_device *, int, bool);
	int (*ndo_set_vf_trust)(struct net_device *, int, bool);
	int (*ndo_get_vf_config)(struct net_device *, int, struct ifla_vf_info *);
	int (*ndo_set_vf_link_state)(struct net_device *, int, int);
	int (*ndo_get_vf_stats)(struct net_device *, int, struct ifla_vf_stats *);
	int (*ndo_set_vf_port)(struct net_device *, int, struct nlattr **);
	int (*ndo_get_vf_port)(struct net_device *, int, struct sk_buff *);
	int (*ndo_get_vf_guid)(struct net_device *, int, struct ifla_vf_guid *, struct ifla_vf_guid *);
	int (*ndo_set_vf_guid)(struct net_device *, int, u64, int);
	int (*ndo_set_vf_rss_query_en)(struct net_device *, int, bool);
	int (*ndo_setup_tc)(struct net_device *, enum tc_setup_type, void *);
	int (*ndo_fcoe_enable)(struct net_device *);
	int (*ndo_fcoe_disable)(struct net_device *);
	int (*ndo_fcoe_ddp_setup)(struct net_device *, u16, struct scatterlist *, unsigned int);
	int (*ndo_fcoe_ddp_done)(struct net_device *, u16);
	int (*ndo_fcoe_ddp_target)(struct net_device *, u16, struct scatterlist *, unsigned int);
	int (*ndo_fcoe_get_hbainfo)(struct net_device *, struct netdev_fcoe_hbainfo *);
	int (*ndo_fcoe_get_wwn)(struct net_device *, u64 *, int);
	int (*ndo_rx_flow_steer)(struct net_device *, const struct sk_buff *, u16, u32);
	int (*ndo_add_slave)(struct net_device *, struct net_device *, struct netlink_ext_ack *);
	int (*ndo_del_slave)(struct net_device *, struct net_device *);
	struct net_device * (*ndo_get_xmit_slave)(struct net_device *, struct sk_buff *, bool);
	struct net_device * (*ndo_sk_get_lower_dev)(struct net_device *, struct sock *);
	netdev_features_t (*ndo_fix_features)(struct net_device *, netdev_features_t);
	int (*ndo_set_features)(struct net_device *, netdev_features_t);
	int (*ndo_neigh_construct)(struct net_device *, struct neighbour *);
	void (*ndo_neigh_destroy)(struct net_device *, struct neighbour *);
	int (*ndo_fdb_add)(struct ndmsg *, struct nlattr **, struct net_device *, const unsigned char *, u16, u16, struct netlink_ext_ack *);
	int (*ndo_fdb_del)(struct ndmsg *, struct nlattr **, struct net_device *, const unsigned char *, u16, struct netlink_ext_ack *);
	int (*ndo_fdb_del_bulk)(struct nlmsghdr *, struct net_device *, struct netlink_ext_ack *);
	int (*ndo_fdb_dump)(struct sk_buff *, struct netlink_callback *, struct net_device *, struct net_device *, int *);
	int (*ndo_fdb_get)(struct sk_buff *, struct nlattr **, struct net_device *, const unsigned char *, u16, u32, u32, struct netlink_ext_ack *);
	int (*ndo_mdb_add)(struct net_device *, struct nlattr **, u16, struct netlink_ext_ack *);
	int (*ndo_mdb_del)(struct net_device *, struct nlattr **, struct netlink_ext_ack *);
	int (*ndo_mdb_del_bulk)(struct net_device *, struct nlattr **, struct netlink_ext_ack *);
	int (*ndo_mdb_dump)(struct net_device *, struct sk_buff *, struct netlink_callback *);
	int (*ndo_mdb_get)(struct net_device *, struct nlattr **, u32, u32, struct netlink_ext_ack *);
	int (*ndo_bridge_setlink)(struct net_device *, struct nlmsghdr *, u16, struct netlink_ext_ack *);
	int (*ndo_bridge_getlink)(struct sk_buff *, u32, u32, struct net_device *, u32, int);
	int (*ndo_bridge_dellink)(struct net_device *, struct nlmsghdr *, u16);
	int (*ndo_change_carrier)(struct net_device *, bool);
	int (*ndo_get_phys_port_id)(struct net_device *, struct netdev_phys_item_id *);
	int (*ndo_get_port_parent_id)(struct net_device *, struct netdev_phys_item_id *);
	int (*ndo_get_phys_port_name)(struct net_device *, char *, size_t);
	void * (*ndo_dfwd_add_station)(struct net_device *, struct net_device *);
	void (*ndo_dfwd_del_station)(struct net_device *, void *);
	int (*ndo_set_tx_maxrate)(struct net_device *, int, u32);
	int (*ndo_get_iflink)(const struct net_device *);
	int (*ndo_fill_metadata_dst)(struct net_device *, struct sk_buff *);
	void (*ndo_set_rx_headroom)(struct net_device *, int);
	int (*ndo_bpf)(struct net_device *, struct netdev_bpf *);
	int (*ndo_xdp_xmit)(struct net_device *, int, struct xdp_frame **, u32);
	struct net_device * (*ndo_xdp_get_xmit_slave)(struct net_device *, struct xdp_buff *);
	int (*ndo_xsk_wakeup)(struct net_device *, u32, u32);
	int (*ndo_tunnel_ctl)(struct net_device *, struct ip_tunnel_parm_kern *, int);
	struct net_device * (*ndo_get_peer_dev)(struct net_device *);
	int (*ndo_fill_forward_path)(struct net_device_path_ctx *, struct net_device_path *);
	ktime_t (*ndo_get_tstamp)(struct net_device *, const struct skb_shared_hwtstamps *, bool);
	int (*ndo_hwtstamp_get)(struct net_device *, struct kernel_hwtstamp_config *);
	int (*ndo_hwtstamp_set)(struct net_device *, struct kernel_hwtstamp_config *, struct netlink_ext_ack *);
};

struct neigh_parms {
	possible_net_t net;
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct list_head list;
	int (*neigh_setup)(struct neighbour *);
	struct neigh_table *tbl;
	void *sysctl_table;
	int dead;
	refcount_t refcnt;
	struct callback_head callback_head;
	int reachable_time;
	u32 qlen;
	int data[14];
	long unsigned int data_state[1];
};

enum hwtstamp_source {
	HWTSTAMP_SOURCE_UNSPEC = 0,
	HWTSTAMP_SOURCE_NETDEV = 1,
	HWTSTAMP_SOURCE_PHYLIB = 2,
};

struct kernel_hwtstamp_config {
	int flags;
	int tx_type;
	int rx_filter;
	struct ifreq *ifr;
	bool copied_to_user;
	enum hwtstamp_source source;
};

struct pcpu_lstats {
	u64_stats_t packets;
	u64_stats_t bytes;
	struct u64_stats_sync syncp;
};

struct pcpu_sw_netstats {
	u64_stats_t rx_packets;
	u64_stats_t rx_bytes;
	u64_stats_t tx_packets;
	u64_stats_t tx_bytes;
	struct u64_stats_sync syncp;
};

struct pcpu_dstats {
	u64_stats_t rx_packets;
	u64_stats_t rx_bytes;
	u64_stats_t rx_drops;
	u64_stats_t tx_packets;
	u64_stats_t tx_bytes;
	u64_stats_t tx_drops;
	struct u64_stats_sync syncp;
	long: 64;
	long: 64;
};

struct ipv6_devstat {
	struct proc_dir_entry *proc_dir_entry;
	struct ipstats_mib *ipv6;
	struct icmpv6_mib_device *icmpv6dev;
	struct icmpv6msg_mib_device *icmpv6msgdev;
};

struct ifmcaddr6;

struct ifacaddr6;

struct inet6_dev {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct list_head addr_list;
	struct ifmcaddr6 *mc_list;
	struct ifmcaddr6 *mc_tomb;
	unsigned char mc_qrv;
	unsigned char mc_gq_running;
	unsigned char mc_ifc_count;
	unsigned char mc_dad_count;
	long unsigned int mc_v1_seen;
	long unsigned int mc_qi;
	long unsigned int mc_qri;
	long unsigned int mc_maxdelay;
	struct delayed_work mc_gq_work;
	struct delayed_work mc_ifc_work;
	struct delayed_work mc_dad_work;
	struct delayed_work mc_query_work;
	struct delayed_work mc_report_work;
	struct sk_buff_head mc_query_queue;
	struct sk_buff_head mc_report_queue;
	spinlock_t mc_query_lock;
	spinlock_t mc_report_lock;
	struct mutex mc_lock;
	struct ifacaddr6 *ac_list;
	rwlock_t lock;
	refcount_t refcnt;
	__u32 if_flags;
	int dead;
	u32 desync_factor;
	struct list_head tempaddr_list;
	struct in6_addr token;
	struct neigh_parms *nd_parms;
	struct ipv6_devconf cnf;
	struct ipv6_devstat stats;
	struct timer_list rs_timer;
	__s32 rs_interval;
	__u8 rs_probes;
	long unsigned int tstamp;
	struct callback_head rcu;
	unsigned int ra_mtu;
};

struct l3mdev_ops {
	u32 (*l3mdev_fib_table)(const struct net_device *);
	struct sk_buff * (*l3mdev_l3_rcv)(struct net_device *, struct sk_buff *, u16);
	struct sk_buff * (*l3mdev_l3_out)(struct net_device *, struct sock *, struct sk_buff *, u16);
	struct dst_entry * (*l3mdev_link_scope_lookup)(const struct net_device *, struct flowi6 *);
};

struct rtnl_link_ops {
	struct list_head list;
	const char *kind;
	size_t priv_size;
	struct net_device * (*alloc)(struct nlattr **, const char *, unsigned char, unsigned int, unsigned int);
	void (*setup)(struct net_device *);
	bool netns_refund;
	unsigned int maxtype;
	const struct nla_policy *policy;
	int (*validate)(struct nlattr **, struct nlattr **, struct netlink_ext_ack *);
	int (*newlink)(struct net *, struct net_device *, struct nlattr **, struct nlattr **, struct netlink_ext_ack *);
	int (*changelink)(struct net_device *, struct nlattr **, struct nlattr **, struct netlink_ext_ack *);
	void (*dellink)(struct net_device *, struct list_head *);
	size_t (*get_size)(const struct net_device *);
	int (*fill_info)(struct sk_buff *, const struct net_device *);
	size_t (*get_xstats_size)(const struct net_device *);
	int (*fill_xstats)(struct sk_buff *, const struct net_device *);
	unsigned int (*get_num_tx_queues)();
	unsigned int (*get_num_rx_queues)();
	unsigned int slave_maxtype;
	const struct nla_policy *slave_policy;
	int (*slave_changelink)(struct net_device *, struct net_device *, struct nlattr **, struct nlattr **, struct netlink_ext_ack *);
	size_t (*get_slave_size)(const struct net_device *, const struct net_device *);
	int (*fill_slave_info)(struct sk_buff *, const struct net_device *, const struct net_device *);
	struct net * (*get_link_net)(const struct net_device *);
	size_t (*get_linkxstats_size)(const struct net_device *, int);
	int (*fill_linkxstats)(struct sk_buff *, const struct net_device *, int *, int);
};

enum {
	RTAX_UNSPEC = 0,
	RTAX_LOCK = 1,
	RTAX_MTU = 2,
	RTAX_WINDOW = 3,
	RTAX_RTT = 4,
	RTAX_RTTVAR = 5,
	RTAX_SSTHRESH = 6,
	RTAX_CWND = 7,
	RTAX_ADVMSS = 8,
	RTAX_REORDERING = 9,
	RTAX_HOPLIMIT = 10,
	RTAX_INITCWND = 11,
	RTAX_FEATURES = 12,
	RTAX_RTO_MIN = 13,
	RTAX_INITRWND = 14,
	RTAX_QUICKACK = 15,
	RTAX_CC_ALGO = 16,
	RTAX_FASTOPEN_NO_COOKIE = 17,
	__RTAX_MAX = 18,
};

struct netlink_range_validation {
	u64 min;
	u64 max;
};

struct netlink_range_validation_signed {
	s64 min;
	s64 max;
};

enum {
	NEIGH_VAR_MCAST_PROBES = 0,
	NEIGH_VAR_UCAST_PROBES = 1,
	NEIGH_VAR_APP_PROBES = 2,
	NEIGH_VAR_MCAST_REPROBES = 3,
	NEIGH_VAR_RETRANS_TIME = 4,
	NEIGH_VAR_BASE_REACHABLE_TIME = 5,
	NEIGH_VAR_DELAY_PROBE_TIME = 6,
	NEIGH_VAR_INTERVAL_PROBE_TIME_MS = 7,
	NEIGH_VAR_GC_STALETIME = 8,
	NEIGH_VAR_QUEUE_LEN_BYTES = 9,
	NEIGH_VAR_PROXY_QLEN = 10,
	NEIGH_VAR_ANYCAST_DELAY = 11,
	NEIGH_VAR_PROXY_DELAY = 12,
	NEIGH_VAR_LOCKTIME = 13,
	NEIGH_VAR_QUEUE_LEN = 14,
	NEIGH_VAR_RETRANS_TIME_MS = 15,
	NEIGH_VAR_BASE_REACHABLE_TIME_MS = 16,
	NEIGH_VAR_GC_INTERVAL = 17,
	NEIGH_VAR_GC_THRESH1 = 18,
	NEIGH_VAR_GC_THRESH2 = 19,
	NEIGH_VAR_GC_THRESH3 = 20,
	NEIGH_VAR_MAX = 21,
};

struct pneigh_entry;

struct neigh_statistics;

struct neigh_hash_table;

struct neigh_table {
	int family;
	unsigned int entry_size;
	unsigned int key_len;
	__be16 protocol;
	__u32 (*hash)(const void *, const struct net_device *, __u32 *);
	bool (*key_eq)(const struct neighbour *, const void *);
	int (*constructor)(struct neighbour *);
	int (*pconstructor)(struct pneigh_entry *);
	void (*pdestructor)(struct pneigh_entry *);
	void (*proxy_redo)(struct sk_buff *);
	int (*is_multicast)(const void *);
	bool (*allow_add)(const struct net_device *, struct netlink_ext_ack *);
	char *id;
	struct neigh_parms parms;
	struct list_head parms_list;
	int gc_interval;
	int gc_thresh1;
	int gc_thresh2;
	int gc_thresh3;
	long unsigned int last_flush;
	struct delayed_work gc_work;
	struct delayed_work managed_work;
	struct timer_list proxy_timer;
	struct sk_buff_head proxy_queue;
	atomic_t entries;
	atomic_t gc_entries;
	struct list_head gc_list;
	struct list_head managed_list;
	rwlock_t lock;
	long unsigned int last_rand;
	struct neigh_statistics *stats;
	struct neigh_hash_table *nht;
	struct pneigh_entry **phash_buckets;
};

struct neigh_statistics {
	long unsigned int allocs;
	long unsigned int destroys;
	long unsigned int hash_grows;
	long unsigned int res_failed;
	long unsigned int lookups;
	long unsigned int hits;
	long unsigned int rcv_probes_mcast;
	long unsigned int rcv_probes_ucast;
	long unsigned int periodic_gc_runs;
	long unsigned int forced_gc_runs;
	long unsigned int unres_discards;
	long unsigned int table_fulls;
};

struct neigh_ops {
	int family;
	void (*solicit)(struct neighbour *, struct sk_buff *);
	void (*error_report)(struct neighbour *, struct sk_buff *);
	int (*output)(struct neighbour *, struct sk_buff *);
	int (*connected_output)(struct neighbour *, struct sk_buff *);
};

struct pneigh_entry {
	struct pneigh_entry *next;
	possible_net_t net;
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	u32 flags;
	u8 protocol;
	bool permanent;
	u32 key[0];
};

struct neigh_hash_table {
	struct neighbour **hash_buckets;
	unsigned int hash_shift;
	__u32 hash_rnd[4];
	struct callback_head rcu;
};

enum {
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT = 2,
	TCP_SYN_RECV = 3,
	TCP_FIN_WAIT1 = 4,
	TCP_FIN_WAIT2 = 5,
	TCP_TIME_WAIT = 6,
	TCP_CLOSE = 7,
	TCP_CLOSE_WAIT = 8,
	TCP_LAST_ACK = 9,
	TCP_LISTEN = 10,
	TCP_CLOSING = 11,
	TCP_NEW_SYN_RECV = 12,
	TCP_BOUND_INACTIVE = 13,
	TCP_MAX_STATES = 14,
};

struct fib_rule_hdr {
	__u8 family;
	__u8 dst_len;
	__u8 src_len;
	__u8 tos;
	__u8 table;
	__u8 res1;
	__u8 res2;
	__u8 action;
	__u32 flags;
};

struct fib_rule_port_range {
	__u16 start;
	__u16 end;
};

struct fib_kuid_range {
	kuid_t start;
	kuid_t end;
};

struct fib_rule {
	struct list_head list;
	int iifindex;
	int oifindex;
	u32 mark;
	u32 mark_mask;
	u32 flags;
	u32 table;
	u8 action;
	u8 l3mdev;
	u8 proto;
	u8 ip_proto;
	u32 target;
	__be64 tun_id;
	struct fib_rule *ctarget;
	struct net *fr_net;
	refcount_t refcnt;
	u32 pref;
	int suppress_ifgroup;
	int suppress_prefixlen;
	char iifname[16];
	char oifname[16];
	struct fib_kuid_range uid_range;
	struct fib_rule_port_range sport_range;
	struct fib_rule_port_range dport_range;
	struct callback_head rcu;
};

struct fib_lookup_arg {
	void *lookup_ptr;
	const void *lookup_data;
	void *result;
	struct fib_rule *rule;
	u32 table;
	int flags;
};

struct sk_psock;

struct raw_hashinfo;

struct smc_hashinfo;

struct request_sock_ops;

struct timewait_sock_ops;

struct proto {
	void (*close)(struct sock *, long int);
	int (*pre_connect)(struct sock *, struct sockaddr *, int);
	int (*connect)(struct sock *, struct sockaddr *, int);
	int (*disconnect)(struct sock *, int);
	struct sock * (*accept)(struct sock *, struct proto_accept_arg *);
	int (*ioctl)(struct sock *, int, int *);
	int (*init)(struct sock *);
	void (*destroy)(struct sock *);
	void (*shutdown)(struct sock *, int);
	int (*setsockopt)(struct sock *, int, int, sockptr_t, unsigned int);
	int (*getsockopt)(struct sock *, int, int, char *, int *);
	void (*keepalive)(struct sock *, int);
	int (*compat_ioctl)(struct sock *, unsigned int, long unsigned int);
	int (*sendmsg)(struct sock *, struct msghdr *, size_t);
	int (*recvmsg)(struct sock *, struct msghdr *, size_t, int, int *);
	void (*splice_eof)(struct socket *);
	int (*bind)(struct sock *, struct sockaddr *, int);
	int (*bind_add)(struct sock *, struct sockaddr *, int);
	int (*backlog_rcv)(struct sock *, struct sk_buff *);
	bool (*bpf_bypass_getsockopt)(int, int);
	void (*release_cb)(struct sock *);
	int (*hash)(struct sock *);
	void (*unhash)(struct sock *);
	void (*rehash)(struct sock *);
	int (*get_port)(struct sock *, short unsigned int);
	void (*put_port)(struct sock *);
	int (*psock_update_sk_prot)(struct sock *, struct sk_psock *, bool);
	unsigned int inuse_idx;
	int (*forward_alloc_get)(const struct sock *);
	bool (*stream_memory_free)(const struct sock *, int);
	bool (*sock_is_readable)(struct sock *);
	void (*enter_memory_pressure)(struct sock *);
	void (*leave_memory_pressure)(struct sock *);
	atomic_long_t *memory_allocated;
	int *per_cpu_fw_alloc;
	struct percpu_counter *sockets_allocated;
	long unsigned int *memory_pressure;
	long int *sysctl_mem;
	int *sysctl_wmem;
	int *sysctl_rmem;
	u32 sysctl_wmem_offset;
	u32 sysctl_rmem_offset;
	int max_header;
	bool no_autobind;
	struct kmem_cache *slab;
	unsigned int obj_size;
	unsigned int ipv6_pinfo_offset;
	slab_flags_t slab_flags;
	unsigned int useroffset;
	unsigned int usersize;
	unsigned int *orphan_count;
	struct request_sock_ops *rsk_prot;
	struct timewait_sock_ops *twsk_prot;
	union {
		struct inet_hashinfo *hashinfo;
		struct udp_table *udp_table;
		struct raw_hashinfo *raw_hash;
		struct smc_hashinfo *smc_hash;
	} h;
	struct module *owner;
	char name[32];
	struct list_head node;
	int (*diag_destroy)(struct sock *, int);
};

enum sk_rst_reason {
	SK_RST_REASON_NOT_SPECIFIED = 0,
	SK_RST_REASON_NO_SOCKET = 1,
	SK_RST_REASON_TCP_INVALID_ACK_SEQUENCE = 2,
	SK_RST_REASON_TCP_RFC7323_PAWS = 3,
	SK_RST_REASON_TCP_TOO_OLD_ACK = 4,
	SK_RST_REASON_TCP_ACK_UNSENT_DATA = 5,
	SK_RST_REASON_TCP_FLAGS = 6,
	SK_RST_REASON_TCP_OLD_ACK = 7,
	SK_RST_REASON_TCP_ABORT_ON_DATA = 8,
	SK_RST_REASON_TCP_TIMEWAIT_SOCKET = 9,
	SK_RST_REASON_INVALID_SYN = 10,
	SK_RST_REASON_TCP_ABORT_ON_CLOSE = 11,
	SK_RST_REASON_TCP_ABORT_ON_LINGER = 12,
	SK_RST_REASON_TCP_ABORT_ON_MEMORY = 13,
	SK_RST_REASON_TCP_STATE = 14,
	SK_RST_REASON_TCP_KEEPALIVE_TIMEOUT = 15,
	SK_RST_REASON_TCP_DISCONNECT_WITH_DATA = 16,
	SK_RST_REASON_MPTCP_RST_EUNSPEC = 17,
	SK_RST_REASON_MPTCP_RST_EMPTCP = 18,
	SK_RST_REASON_MPTCP_RST_ERESOURCE = 19,
	SK_RST_REASON_MPTCP_RST_EPROHIBIT = 20,
	SK_RST_REASON_MPTCP_RST_EWQ2BIG = 21,
	SK_RST_REASON_MPTCP_RST_EBADPERF = 22,
	SK_RST_REASON_MPTCP_RST_EMIDDLEBOX = 23,
	SK_RST_REASON_ERROR = 24,
	SK_RST_REASON_MAX = 25,
};

struct request_sock;

struct request_sock_ops {
	int family;
	unsigned int obj_size;
	struct kmem_cache *slab;
	char *slab_name;
	int (*rtx_syn_ack)(const struct sock *, struct request_sock *);
	void (*send_ack)(const struct sock *, struct sk_buff *, struct request_sock *);
	void (*send_reset)(const struct sock *, struct sk_buff *, enum sk_rst_reason);
	void (*destructor)(struct request_sock *);
	void (*syn_ack_timeout)(const struct request_sock *);
};

struct timewait_sock_ops {
	struct kmem_cache *twsk_slab;
	char *twsk_slab_name;
	unsigned int twsk_obj_size;
	void (*twsk_destructor)(struct sock *);
};

struct saved_syn;

struct request_sock {
	struct sock_common __req_common;
	struct request_sock *dl_next;
	u16 mss;
	u8 num_retrans;
	u8 syncookie: 1;
	u8 num_timeout: 7;
	u32 ts_recent;
	struct timer_list rsk_timer;
	const struct request_sock_ops *rsk_ops;
	struct sock *sk;
	struct saved_syn *saved_syn;
	u32 secid;
	u32 peer_secid;
	u32 timeout;
};

struct saved_syn {
	u32 mac_hdrlen;
	u32 network_hdrlen;
	u32 tcp_hdrlen;
	u8 data[0];
};

enum tsq_enum {
	TSQ_THROTTLED = 0,
	TSQ_QUEUED = 1,
	TCP_TSQ_DEFERRED = 2,
	TCP_WRITE_TIMER_DEFERRED = 3,
	TCP_DELACK_TIMER_DEFERRED = 4,
	TCP_MTU_REDUCED_DEFERRED = 5,
	TCP_ACK_DEFERRED = 6,
};

struct ip6_sf_list {
	struct ip6_sf_list *sf_next;
	struct in6_addr sf_addr;
	long unsigned int sf_count[2];
	unsigned char sf_gsresp;
	unsigned char sf_oldin;
	unsigned char sf_crcount;
	struct callback_head rcu;
};

struct ifmcaddr6 {
	struct in6_addr mca_addr;
	struct inet6_dev *idev;
	struct ifmcaddr6 *next;
	struct ip6_sf_list *mca_sources;
	struct ip6_sf_list *mca_tomb;
	unsigned int mca_sfmode;
	unsigned char mca_crcount;
	long unsigned int mca_sfcount[2];
	struct delayed_work mca_work;
	unsigned int mca_flags;
	int mca_users;
	refcount_t mca_refcnt;
	long unsigned int mca_cstamp;
	long unsigned int mca_tstamp;
	struct callback_head rcu;
};

struct ifacaddr6 {
	struct in6_addr aca_addr;
	struct fib6_info *aca_rt;
	struct ifacaddr6 *aca_next;
	struct hlist_node aca_addr_lst;
	int aca_users;
	refcount_t aca_refcnt;
	long unsigned int aca_cstamp;
	long unsigned int aca_tstamp;
	struct callback_head rcu;
};

struct rpc_xprt_iter_ops {
	void (*xpi_rewind)(struct rpc_xprt_iter *);
	struct rpc_xprt * (*xpi_xprt)(struct rpc_xprt_iter *);
	struct rpc_xprt * (*xpi_next)(struct rpc_xprt_iter *);
};

struct rpc_sysfs_client {
	struct kobject kobject;
	struct net *net;
	struct rpc_clnt *clnt;
	struct rpc_xprt_switch *xprt_switch;
};

struct rpc_version {
	u32 number;
	unsigned int nrprocs;
	const struct rpc_procinfo *procs;
	unsigned int *counts;
};

struct rpc_add_xprt_test {
	void (*add_xprt_test)(struct rpc_clnt *, struct rpc_xprt *, void *);
	void *data;
};

enum nfs_stat {
	NFS_OK = 0,
	NFSERR_PERM = 1,
	NFSERR_NOENT = 2,
	NFSERR_IO = 5,
	NFSERR_NXIO = 6,
	NFSERR_EAGAIN = 11,
	NFSERR_ACCES = 13,
	NFSERR_EXIST = 17,
	NFSERR_XDEV = 18,
	NFSERR_NODEV = 19,
	NFSERR_NOTDIR = 20,
	NFSERR_ISDIR = 21,
	NFSERR_INVAL = 22,
	NFSERR_FBIG = 27,
	NFSERR_NOSPC = 28,
	NFSERR_ROFS = 30,
	NFSERR_MLINK = 31,
	NFSERR_NAMETOOLONG = 63,
	NFSERR_NOTEMPTY = 66,
	NFSERR_DQUOT = 69,
	NFSERR_STALE = 70,
	NFSERR_REMOTE = 71,
	NFSERR_WFLUSH = 99,
	NFSERR_BADHANDLE = 10001,
	NFSERR_NOT_SYNC = 10002,
	NFSERR_BAD_COOKIE = 10003,
	NFSERR_NOTSUPP = 10004,
	NFSERR_TOOSMALL = 10005,
	NFSERR_SERVERFAULT = 10006,
	NFSERR_BADTYPE = 10007,
	NFSERR_JUKEBOX = 10008,
	NFSERR_SAME = 10009,
	NFSERR_DENIED = 10010,
	NFSERR_EXPIRED = 10011,
	NFSERR_LOCKED = 10012,
	NFSERR_GRACE = 10013,
	NFSERR_FHEXPIRED = 10014,
	NFSERR_SHARE_DENIED = 10015,
	NFSERR_WRONGSEC = 10016,
	NFSERR_CLID_INUSE = 10017,
	NFSERR_RESOURCE = 10018,
	NFSERR_MOVED = 10019,
	NFSERR_NOFILEHANDLE = 10020,
	NFSERR_MINOR_VERS_MISMATCH = 10021,
	NFSERR_STALE_CLIENTID = 10022,
	NFSERR_STALE_STATEID = 10023,
	NFSERR_OLD_STATEID = 10024,
	NFSERR_BAD_STATEID = 10025,
	NFSERR_BAD_SEQID = 10026,
	NFSERR_NOT_SAME = 10027,
	NFSERR_LOCK_RANGE = 10028,
	NFSERR_SYMLINK = 10029,
	NFSERR_RESTOREFH = 10030,
	NFSERR_LEASE_MOVED = 10031,
	NFSERR_ATTRNOTSUPP = 10032,
	NFSERR_NO_GRACE = 10033,
	NFSERR_RECLAIM_BAD = 10034,
	NFSERR_RECLAIM_CONFLICT = 10035,
	NFSERR_BAD_XDR = 10036,
	NFSERR_LOCKS_HELD = 10037,
	NFSERR_OPENMODE = 10038,
	NFSERR_BADOWNER = 10039,
	NFSERR_BADCHAR = 10040,
	NFSERR_BADNAME = 10041,
	NFSERR_BAD_RANGE = 10042,
	NFSERR_LOCK_NOTSUPP = 10043,
	NFSERR_OP_ILLEGAL = 10044,
	NFSERR_DEADLOCK = 10045,
	NFSERR_FILE_OPEN = 10046,
	NFSERR_ADMIN_REVOKED = 10047,
	NFSERR_CB_PATH_DOWN = 10048,
};

struct nfs_fh {
	short unsigned int size;
	unsigned char data[128];
};

enum nfs3_stable_how {
	NFS_UNSTABLE = 0,
	NFS_DATA_SYNC = 1,
	NFS_FILE_SYNC = 2,
	NFS_INVALID_STABLE_HOW = -1,
};

struct nfs4_label {
	uint32_t lfs;
	uint32_t pi;
	u32 len;
	char *label;
};

typedef struct {
	char data[8];
} nfs4_verifier;

struct nfs4_stateid_struct {
	union {
		char data[16];
		struct {
			__be32 seqid;
			char other[12];
		};
	};
	enum {
		NFS4_INVALID_STATEID_TYPE = 0,
		NFS4_SPECIAL_STATEID_TYPE = 1,
		NFS4_OPEN_STATEID_TYPE = 2,
		NFS4_LOCK_STATEID_TYPE = 3,
		NFS4_DELEGATION_STATEID_TYPE = 4,
		NFS4_LAYOUT_STATEID_TYPE = 5,
		NFS4_PNFS_DS_STATEID_TYPE = 6,
		NFS4_REVOKED_STATEID_TYPE = 7,
	} type;
};

typedef struct nfs4_stateid_struct nfs4_stateid;

enum nfs_opnum4 {
	OP_ACCESS = 3,
	OP_CLOSE = 4,
	OP_COMMIT = 5,
	OP_CREATE = 6,
	OP_DELEGPURGE = 7,
	OP_DELEGRETURN = 8,
	OP_GETATTR = 9,
	OP_GETFH = 10,
	OP_LINK = 11,
	OP_LOCK = 12,
	OP_LOCKT = 13,
	OP_LOCKU = 14,
	OP_LOOKUP = 15,
	OP_LOOKUPP = 16,
	OP_NVERIFY = 17,
	OP_OPEN = 18,
	OP_OPENATTR = 19,
	OP_OPEN_CONFIRM = 20,
	OP_OPEN_DOWNGRADE = 21,
	OP_PUTFH = 22,
	OP_PUTPUBFH = 23,
	OP_PUTROOTFH = 24,
	OP_READ = 25,
	OP_READDIR = 26,
	OP_READLINK = 27,
	OP_REMOVE = 28,
	OP_RENAME = 29,
	OP_RENEW = 30,
	OP_RESTOREFH = 31,
	OP_SAVEFH = 32,
	OP_SECINFO = 33,
	OP_SETATTR = 34,
	OP_SETCLIENTID = 35,
	OP_SETCLIENTID_CONFIRM = 36,
	OP_VERIFY = 37,
	OP_WRITE = 38,
	OP_RELEASE_LOCKOWNER = 39,
	OP_BACKCHANNEL_CTL = 40,
	OP_BIND_CONN_TO_SESSION = 41,
	OP_EXCHANGE_ID = 42,
	OP_CREATE_SESSION = 43,
	OP_DESTROY_SESSION = 44,
	OP_FREE_STATEID = 45,
	OP_GET_DIR_DELEGATION = 46,
	OP_GETDEVICEINFO = 47,
	OP_GETDEVICELIST = 48,
	OP_LAYOUTCOMMIT = 49,
	OP_LAYOUTGET = 50,
	OP_LAYOUTRETURN = 51,
	OP_SECINFO_NO_NAME = 52,
	OP_SEQUENCE = 53,
	OP_SET_SSV = 54,
	OP_TEST_STATEID = 55,
	OP_WANT_DELEGATION = 56,
	OP_DESTROY_CLIENTID = 57,
	OP_RECLAIM_COMPLETE = 58,
	OP_ALLOCATE = 59,
	OP_COPY = 60,
	OP_COPY_NOTIFY = 61,
	OP_DEALLOCATE = 62,
	OP_IO_ADVISE = 63,
	OP_LAYOUTERROR = 64,
	OP_LAYOUTSTATS = 65,
	OP_OFFLOAD_CANCEL = 66,
	OP_OFFLOAD_STATUS = 67,
	OP_READ_PLUS = 68,
	OP_SEEK = 69,
	OP_WRITE_SAME = 70,
	OP_CLONE = 71,
	OP_GETXATTR = 72,
	OP_SETXATTR = 73,
	OP_LISTXATTRS = 74,
	OP_REMOVEXATTR = 75,
	OP_ILLEGAL = 10044,
};

enum nfsstat4 {
	NFS4_OK = 0,
	NFS4ERR_PERM = 1,
	NFS4ERR_NOENT = 2,
	NFS4ERR_IO = 5,
	NFS4ERR_NXIO = 6,
	NFS4ERR_ACCESS = 13,
	NFS4ERR_EXIST = 17,
	NFS4ERR_XDEV = 18,
	NFS4ERR_NOTDIR = 20,
	NFS4ERR_ISDIR = 21,
	NFS4ERR_INVAL = 22,
	NFS4ERR_FBIG = 27,
	NFS4ERR_NOSPC = 28,
	NFS4ERR_ROFS = 30,
	NFS4ERR_MLINK = 31,
	NFS4ERR_NAMETOOLONG = 63,
	NFS4ERR_NOTEMPTY = 66,
	NFS4ERR_DQUOT = 69,
	NFS4ERR_STALE = 70,
	NFS4ERR_BADHANDLE = 10001,
	NFS4ERR_BAD_COOKIE = 10003,
	NFS4ERR_NOTSUPP = 10004,
	NFS4ERR_TOOSMALL = 10005,
	NFS4ERR_SERVERFAULT = 10006,
	NFS4ERR_BADTYPE = 10007,
	NFS4ERR_DELAY = 10008,
	NFS4ERR_SAME = 10009,
	NFS4ERR_DENIED = 10010,
	NFS4ERR_EXPIRED = 10011,
	NFS4ERR_LOCKED = 10012,
	NFS4ERR_GRACE = 10013,
	NFS4ERR_FHEXPIRED = 10014,
	NFS4ERR_SHARE_DENIED = 10015,
	NFS4ERR_WRONGSEC = 10016,
	NFS4ERR_CLID_INUSE = 10017,
	NFS4ERR_RESOURCE = 10018,
	NFS4ERR_MOVED = 10019,
	NFS4ERR_NOFILEHANDLE = 10020,
	NFS4ERR_MINOR_VERS_MISMATCH = 10021,
	NFS4ERR_STALE_CLIENTID = 10022,
	NFS4ERR_STALE_STATEID = 10023,
	NFS4ERR_OLD_STATEID = 10024,
	NFS4ERR_BAD_STATEID = 10025,
	NFS4ERR_BAD_SEQID = 10026,
	NFS4ERR_NOT_SAME = 10027,
	NFS4ERR_LOCK_RANGE = 10028,
	NFS4ERR_SYMLINK = 10029,
	NFS4ERR_RESTOREFH = 10030,
	NFS4ERR_LEASE_MOVED = 10031,
	NFS4ERR_ATTRNOTSUPP = 10032,
	NFS4ERR_NO_GRACE = 10033,
	NFS4ERR_RECLAIM_BAD = 10034,
	NFS4ERR_RECLAIM_CONFLICT = 10035,
	NFS4ERR_BADXDR = 10036,
	NFS4ERR_LOCKS_HELD = 10037,
	NFS4ERR_OPENMODE = 10038,
	NFS4ERR_BADOWNER = 10039,
	NFS4ERR_BADCHAR = 10040,
	NFS4ERR_BADNAME = 10041,
	NFS4ERR_BAD_RANGE = 10042,
	NFS4ERR_LOCK_NOTSUPP = 10043,
	NFS4ERR_OP_ILLEGAL = 10044,
	NFS4ERR_DEADLOCK = 10045,
	NFS4ERR_FILE_OPEN = 10046,
	NFS4ERR_ADMIN_REVOKED = 10047,
	NFS4ERR_CB_PATH_DOWN = 10048,
	NFS4ERR_BADIOMODE = 10049,
	NFS4ERR_BADLAYOUT = 10050,
	NFS4ERR_BAD_SESSION_DIGEST = 10051,
	NFS4ERR_BADSESSION = 10052,
	NFS4ERR_BADSLOT = 10053,
	NFS4ERR_COMPLETE_ALREADY = 10054,
	NFS4ERR_CONN_NOT_BOUND_TO_SESSION = 10055,
	NFS4ERR_DELEG_ALREADY_WANTED = 10056,
	NFS4ERR_BACK_CHAN_BUSY = 10057,
	NFS4ERR_LAYOUTTRYLATER = 10058,
	NFS4ERR_LAYOUTUNAVAILABLE = 10059,
	NFS4ERR_NOMATCHING_LAYOUT = 10060,
	NFS4ERR_RECALLCONFLICT = 10061,
	NFS4ERR_UNKNOWN_LAYOUTTYPE = 10062,
	NFS4ERR_SEQ_MISORDERED = 10063,
	NFS4ERR_SEQUENCE_POS = 10064,
	NFS4ERR_REQ_TOO_BIG = 10065,
	NFS4ERR_REP_TOO_BIG = 10066,
	NFS4ERR_REP_TOO_BIG_TO_CACHE = 10067,
	NFS4ERR_RETRY_UNCACHED_REP = 10068,
	NFS4ERR_UNSAFE_COMPOUND = 10069,
	NFS4ERR_TOO_MANY_OPS = 10070,
	NFS4ERR_OP_NOT_IN_SESSION = 10071,
	NFS4ERR_HASH_ALG_UNSUPP = 10072,
	NFS4ERR_CLIENTID_BUSY = 10074,
	NFS4ERR_PNFS_IO_HOLE = 10075,
	NFS4ERR_SEQ_FALSE_RETRY = 10076,
	NFS4ERR_BAD_HIGH_SLOT = 10077,
	NFS4ERR_DEADSESSION = 10078,
	NFS4ERR_ENCR_ALG_UNSUPP = 10079,
	NFS4ERR_PNFS_NO_LAYOUT = 10080,
	NFS4ERR_NOT_ONLY_OP = 10081,
	NFS4ERR_WRONG_CRED = 10082,
	NFS4ERR_WRONG_TYPE = 10083,
	NFS4ERR_DIRDELEG_UNAVAIL = 10084,
	NFS4ERR_REJECT_DELEG = 10085,
	NFS4ERR_RETURNCONFLICT = 10086,
	NFS4ERR_DELEG_REVOKED = 10087,
	NFS4ERR_PARTNER_NOTSUPP = 10088,
	NFS4ERR_PARTNER_NO_AUTH = 10089,
	NFS4ERR_UNION_NOTSUPP = 10090,
	NFS4ERR_OFFLOAD_DENIED = 10091,
	NFS4ERR_WRONG_LFS = 10092,
	NFS4ERR_BADLABEL = 10093,
	NFS4ERR_OFFLOAD_NO_REQS = 10094,
	NFS4ERR_NOXATTR = 10095,
	NFS4ERR_XATTR2BIG = 10096,
	NFS4ERR_FIRST_FREE = 10097,
};

enum nfs_ftype4 {
	NF4BAD = 0,
	NF4REG = 1,
	NF4DIR = 2,
	NF4BLK = 3,
	NF4CHR = 4,
	NF4LNK = 5,
	NF4SOCK = 6,
	NF4FIFO = 7,
	NF4ATTRDIR = 8,
	NF4NAMEDATTR = 9,
};

enum open_claim_type4 {
	NFS4_OPEN_CLAIM_NULL = 0,
	NFS4_OPEN_CLAIM_PREVIOUS = 1,
	NFS4_OPEN_CLAIM_DELEGATE_CUR = 2,
	NFS4_OPEN_CLAIM_DELEGATE_PREV = 3,
	NFS4_OPEN_CLAIM_FH = 4,
	NFS4_OPEN_CLAIM_DELEG_CUR_FH = 5,
	NFS4_OPEN_CLAIM_DELEG_PREV_FH = 6,
};

enum createmode4 {
	NFS4_CREATE_UNCHECKED = 0,
	NFS4_CREATE_GUARDED = 1,
	NFS4_CREATE_EXCLUSIVE = 2,
	NFS4_CREATE_EXCLUSIVE4_1 = 3,
};

enum open_delegation_type4 {
	NFS4_OPEN_DELEGATE_NONE = 0,
	NFS4_OPEN_DELEGATE_READ = 1,
	NFS4_OPEN_DELEGATE_WRITE = 2,
	NFS4_OPEN_DELEGATE_NONE_EXT = 3,
	NFS4_OPEN_DELEGATE_READ_ATTRS_DELEG = 4,
	NFS4_OPEN_DELEGATE_WRITE_ATTRS_DELEG = 5,
};

enum {
	FATTR4_SUPPORTED_ATTRS = 0,
	FATTR4_TYPE = 1,
	FATTR4_FH_EXPIRE_TYPE = 2,
	FATTR4_CHANGE = 3,
	FATTR4_SIZE = 4,
	FATTR4_LINK_SUPPORT = 5,
	FATTR4_SYMLINK_SUPPORT = 6,
	FATTR4_NAMED_ATTR = 7,
	FATTR4_FSID = 8,
	FATTR4_UNIQUE_HANDLES = 9,
	FATTR4_LEASE_TIME = 10,
	FATTR4_RDATTR_ERROR = 11,
	FATTR4_ACL = 12,
	FATTR4_ACLSUPPORT = 13,
	FATTR4_ARCHIVE = 14,
	FATTR4_CANSETTIME = 15,
	FATTR4_CASE_INSENSITIVE = 16,
	FATTR4_CASE_PRESERVING = 17,
	FATTR4_CHOWN_RESTRICTED = 18,
	FATTR4_FILEHANDLE = 19,
	FATTR4_FILEID = 20,
	FATTR4_FILES_AVAIL = 21,
	FATTR4_FILES_FREE = 22,
	FATTR4_FILES_TOTAL = 23,
	FATTR4_FS_LOCATIONS = 24,
	FATTR4_HIDDEN = 25,
	FATTR4_HOMOGENEOUS = 26,
	FATTR4_MAXFILESIZE = 27,
	FATTR4_MAXLINK = 28,
	FATTR4_MAXNAME = 29,
	FATTR4_MAXREAD = 30,
	FATTR4_MAXWRITE = 31,
	FATTR4_MIMETYPE = 32,
	FATTR4_MODE = 33,
	FATTR4_NO_TRUNC = 34,
	FATTR4_NUMLINKS = 35,
	FATTR4_OWNER = 36,
	FATTR4_OWNER_GROUP = 37,
	FATTR4_QUOTA_AVAIL_HARD = 38,
	FATTR4_QUOTA_AVAIL_SOFT = 39,
	FATTR4_QUOTA_USED = 40,
	FATTR4_RAWDEV = 41,
	FATTR4_SPACE_AVAIL = 42,
	FATTR4_SPACE_FREE = 43,
	FATTR4_SPACE_TOTAL = 44,
	FATTR4_SPACE_USED = 45,
	FATTR4_SYSTEM = 46,
	FATTR4_TIME_ACCESS = 47,
	FATTR4_TIME_ACCESS_SET = 48,
	FATTR4_TIME_BACKUP = 49,
	FATTR4_TIME_CREATE = 50,
	FATTR4_TIME_DELTA = 51,
	FATTR4_TIME_METADATA = 52,
	FATTR4_TIME_MODIFY = 53,
	FATTR4_TIME_MODIFY_SET = 54,
	FATTR4_MOUNTED_ON_FILEID = 55,
};

enum {
	FATTR4_DIR_NOTIF_DELAY = 56,
	FATTR4_DIRENT_NOTIF_DELAY = 57,
	FATTR4_DACL = 58,
	FATTR4_SACL = 59,
	FATTR4_CHANGE_POLICY = 60,
	FATTR4_FS_STATUS = 61,
	FATTR4_FS_LAYOUT_TYPES = 62,
	FATTR4_LAYOUT_HINT = 63,
	FATTR4_LAYOUT_TYPES = 64,
	FATTR4_LAYOUT_BLKSIZE = 65,
	FATTR4_LAYOUT_ALIGNMENT = 66,
	FATTR4_FS_LOCATIONS_INFO = 67,
	FATTR4_MDSTHRESHOLD = 68,
	FATTR4_RETENTION_GET = 69,
	FATTR4_RETENTION_SET = 70,
	FATTR4_RETENTEVT_GET = 71,
	FATTR4_RETENTEVT_SET = 72,
	FATTR4_RETENTION_HOLD = 73,
	FATTR4_MODE_SET_MASKED = 74,
	FATTR4_SUPPATTR_EXCLCREAT = 75,
	FATTR4_FS_CHARSET_CAP = 76,
};

enum {
	FATTR4_CLONE_BLKSIZE = 77,
	FATTR4_SPACE_FREED = 78,
	FATTR4_CHANGE_ATTR_TYPE = 79,
	FATTR4_SEC_LABEL = 80,
};

enum {
	FATTR4_MODE_UMASK = 81,
};

enum {
	FATTR4_XATTR_SUPPORT = 82,
};

enum {
	FATTR4_TIME_DELEG_ACCESS = 84,
	FATTR4_TIME_DELEG_MODIFY = 85,
	FATTR4_OPEN_ARGUMENTS = 86,
};

enum {
	NFSPROC4_CLNT_NULL = 0,
	NFSPROC4_CLNT_READ = 1,
	NFSPROC4_CLNT_WRITE = 2,
	NFSPROC4_CLNT_COMMIT = 3,
	NFSPROC4_CLNT_OPEN = 4,
	NFSPROC4_CLNT_OPEN_CONFIRM = 5,
	NFSPROC4_CLNT_OPEN_NOATTR = 6,
	NFSPROC4_CLNT_OPEN_DOWNGRADE = 7,
	NFSPROC4_CLNT_CLOSE = 8,
	NFSPROC4_CLNT_SETATTR = 9,
	NFSPROC4_CLNT_FSINFO = 10,
	NFSPROC4_CLNT_RENEW = 11,
	NFSPROC4_CLNT_SETCLIENTID = 12,
	NFSPROC4_CLNT_SETCLIENTID_CONFIRM = 13,
	NFSPROC4_CLNT_LOCK = 14,
	NFSPROC4_CLNT_LOCKT = 15,
	NFSPROC4_CLNT_LOCKU = 16,
	NFSPROC4_CLNT_ACCESS = 17,
	NFSPROC4_CLNT_GETATTR = 18,
	NFSPROC4_CLNT_LOOKUP = 19,
	NFSPROC4_CLNT_LOOKUP_ROOT = 20,
	NFSPROC4_CLNT_REMOVE = 21,
	NFSPROC4_CLNT_RENAME = 22,
	NFSPROC4_CLNT_LINK = 23,
	NFSPROC4_CLNT_SYMLINK = 24,
	NFSPROC4_CLNT_CREATE = 25,
	NFSPROC4_CLNT_PATHCONF = 26,
	NFSPROC4_CLNT_STATFS = 27,
	NFSPROC4_CLNT_READLINK = 28,
	NFSPROC4_CLNT_READDIR = 29,
	NFSPROC4_CLNT_SERVER_CAPS = 30,
	NFSPROC4_CLNT_DELEGRETURN = 31,
	NFSPROC4_CLNT_GETACL = 32,
	NFSPROC4_CLNT_SETACL = 33,
	NFSPROC4_CLNT_FS_LOCATIONS = 34,
	NFSPROC4_CLNT_RELEASE_LOCKOWNER = 35,
	NFSPROC4_CLNT_SECINFO = 36,
	NFSPROC4_CLNT_FSID_PRESENT = 37,
	NFSPROC4_CLNT_EXCHANGE_ID = 38,
	NFSPROC4_CLNT_CREATE_SESSION = 39,
	NFSPROC4_CLNT_DESTROY_SESSION = 40,
	NFSPROC4_CLNT_SEQUENCE = 41,
	NFSPROC4_CLNT_GET_LEASE_TIME = 42,
	NFSPROC4_CLNT_RECLAIM_COMPLETE = 43,
	NFSPROC4_CLNT_LAYOUTGET = 44,
	NFSPROC4_CLNT_GETDEVICEINFO = 45,
	NFSPROC4_CLNT_LAYOUTCOMMIT = 46,
	NFSPROC4_CLNT_LAYOUTRETURN = 47,
	NFSPROC4_CLNT_SECINFO_NO_NAME = 48,
	NFSPROC4_CLNT_TEST_STATEID = 49,
	NFSPROC4_CLNT_FREE_STATEID = 50,
	NFSPROC4_CLNT_GETDEVICELIST = 51,
	NFSPROC4_CLNT_BIND_CONN_TO_SESSION = 52,
	NFSPROC4_CLNT_DESTROY_CLIENTID = 53,
	NFSPROC4_CLNT_SEEK = 54,
	NFSPROC4_CLNT_ALLOCATE = 55,
	NFSPROC4_CLNT_DEALLOCATE = 56,
	NFSPROC4_CLNT_LAYOUTSTATS = 57,
	NFSPROC4_CLNT_CLONE = 58,
	NFSPROC4_CLNT_COPY = 59,
	NFSPROC4_CLNT_OFFLOAD_CANCEL = 60,
	NFSPROC4_CLNT_LOOKUPP = 61,
	NFSPROC4_CLNT_LAYOUTERROR = 62,
	NFSPROC4_CLNT_COPY_NOTIFY = 63,
	NFSPROC4_CLNT_GETXATTR = 64,
	NFSPROC4_CLNT_SETXATTR = 65,
	NFSPROC4_CLNT_LISTXATTRS = 66,
	NFSPROC4_CLNT_REMOVEXATTR = 67,
	NFSPROC4_CLNT_READ_PLUS = 68,
};

struct nfs4_sessionid {
	unsigned char data[16];
};

enum state_protect_how4 {
	SP4_NONE = 0,
	SP4_MACH_CRED = 1,
	SP4_SSV = 2,
};

enum pnfs_iomode {
	IOMODE_READ = 1,
	IOMODE_RW = 2,
	IOMODE_ANY = 3,
};

enum pnfs_notify_deviceid_type4 {
	NOTIFY_DEVICEID4_CHANGE = 2,
	NOTIFY_DEVICEID4_DELETE = 4,
};

struct nfs4_deviceid {
	char data[16];
};

struct nfs4_op_map {
	union {
		long unsigned int longs[2];
		u32 words[4];
	} u;
};

enum nfs4_change_attr_type {
	NFS4_CHANGE_TYPE_IS_MONOTONIC_INCR = 0,
	NFS4_CHANGE_TYPE_IS_VERSION_COUNTER = 1,
	NFS4_CHANGE_TYPE_IS_VERSION_COUNTER_NOPNFS = 2,
	NFS4_CHANGE_TYPE_IS_TIME_METADATA = 3,
	NFS4_CHANGE_TYPE_IS_UNDEFINED = 4,
};

enum netfs_io_source {
	NETFS_SOURCE_UNKNOWN = 0,
	NETFS_FILL_WITH_ZEROES = 1,
	NETFS_DOWNLOAD_FROM_SERVER = 2,
	NETFS_READ_FROM_CACHE = 3,
	NETFS_INVALID_READ = 4,
	NETFS_UPLOAD_TO_SERVER = 5,
	NETFS_WRITE_TO_CACHE = 6,
	NETFS_INVALID_WRITE = 7,
} __attribute__((mode(byte)));

typedef void (*netfs_io_terminated_t)(void *, ssize_t, bool);

struct netfs_request_ops;

struct fscache_cookie;

struct netfs_inode {
	struct inode inode;
	const struct netfs_request_ops *ops;
	struct fscache_cookie *cache;
	struct mutex wb_lock;
	loff_t remote_i_size;
	loff_t zero_point;
	atomic_t io_count;
	long unsigned int flags;
};

struct netfs_io_request;

struct netfs_io_subrequest;

struct netfs_io_stream;

struct netfs_request_ops {
	mempool_t *request_pool;
	mempool_t *subrequest_pool;
	int (*init_request)(struct netfs_io_request *, struct file *);
	void (*free_request)(struct netfs_io_request *);
	void (*free_subrequest)(struct netfs_io_subrequest *);
	void (*expand_readahead)(struct netfs_io_request *);
	int (*prepare_read)(struct netfs_io_subrequest *);
	void (*issue_read)(struct netfs_io_subrequest *);
	bool (*is_still_valid)(struct netfs_io_request *);
	int (*check_write_begin)(struct file *, loff_t, unsigned int, struct folio **, void **);
	void (*done)(struct netfs_io_request *);
	void (*update_i_size)(struct inode *, loff_t);
	void (*post_modify)(struct inode *);
	void (*begin_writeback)(struct netfs_io_request *);
	void (*prepare_write)(struct netfs_io_subrequest *);
	void (*issue_write)(struct netfs_io_subrequest *);
	void (*retry_request)(struct netfs_io_request *, struct netfs_io_stream *);
	void (*invalidate_cache)(struct netfs_io_request *);
};

enum fscache_cookie_state {
	FSCACHE_COOKIE_STATE_QUIESCENT = 0,
	FSCACHE_COOKIE_STATE_LOOKING_UP = 1,
	FSCACHE_COOKIE_STATE_CREATING = 2,
	FSCACHE_COOKIE_STATE_ACTIVE = 3,
	FSCACHE_COOKIE_STATE_INVALIDATING = 4,
	FSCACHE_COOKIE_STATE_FAILED = 5,
	FSCACHE_COOKIE_STATE_LRU_DISCARDING = 6,
	FSCACHE_COOKIE_STATE_WITHDRAWING = 7,
	FSCACHE_COOKIE_STATE_RELINQUISHING = 8,
	FSCACHE_COOKIE_STATE_DROPPED = 9,
} __attribute__((mode(byte)));

struct fscache_volume;

struct fscache_cookie {
	refcount_t ref;
	atomic_t n_active;
	atomic_t n_accesses;
	unsigned int debug_id;
	unsigned int inval_counter;
	spinlock_t lock;
	struct fscache_volume *volume;
	void *cache_priv;
	struct hlist_bl_node hash_link;
	struct list_head proc_link;
	struct list_head commit_link;
	struct work_struct work;
	loff_t object_size;
	long unsigned int unused_at;
	long unsigned int flags;
	enum fscache_cookie_state state;
	u8 advice;
	u8 key_len;
	u8 aux_len;
	u32 key_hash;
	union {
		void *key;
		u8 inline_key[16];
	};
	union {
		void *aux;
		u8 inline_aux[8];
	};
};

struct netfs_group {
	refcount_t ref;
	void (*free)(struct netfs_group *);
};

struct netfs_io_stream {
	struct netfs_io_subrequest *construct;
	size_t sreq_max_len;
	unsigned int sreq_max_segs;
	unsigned int submit_off;
	unsigned int submit_len;
	unsigned int submit_extendable_to;
	void (*prepare_write)(struct netfs_io_subrequest *);
	void (*issue_write)(struct netfs_io_subrequest *);
	struct list_head subrequests;
	struct netfs_io_subrequest *front;
	long long unsigned int collected_to;
	size_t transferred;
	enum netfs_io_source source;
	short unsigned int error;
	unsigned char stream_nr;
	bool avail;
	bool active;
	bool need_retry;
	bool failed;
	bool transferred_valid;
};

struct netfs_io_subrequest {
	struct netfs_io_request *rreq;
	struct work_struct work;
	struct list_head rreq_link;
	struct iov_iter io_iter;
	long long unsigned int start;
	size_t len;
	size_t transferred;
	size_t consumed;
	size_t prev_donated;
	size_t next_donated;
	refcount_t ref;
	short int error;
	short unsigned int debug_index;
	unsigned int nr_segs;
	enum netfs_io_source source;
	unsigned char stream_nr;
	unsigned char curr_folioq_slot;
	unsigned char curr_folio_order;
	struct folio_queue *curr_folioq;
	long unsigned int flags;
};

struct netfs_cache_ops;

struct netfs_cache_resources {
	const struct netfs_cache_ops *ops;
	void *cache_priv;
	void *cache_priv2;
	unsigned int debug_id;
	unsigned int inval_counter;
};

enum netfs_read_from_hole {
	NETFS_READ_HOLE_IGNORE = 0,
	NETFS_READ_HOLE_CLEAR = 1,
	NETFS_READ_HOLE_FAIL = 2,
};

struct netfs_cache_ops {
	void (*end_operation)(struct netfs_cache_resources *);
	int (*read)(struct netfs_cache_resources *, loff_t, struct iov_iter *, enum netfs_read_from_hole, netfs_io_terminated_t, void *);
	int (*write)(struct netfs_cache_resources *, loff_t, struct iov_iter *, netfs_io_terminated_t, void *);
	void (*issue_write)(struct netfs_io_subrequest *);
	void (*expand_readahead)(struct netfs_cache_resources *, long long unsigned int *, long long unsigned int *, long long unsigned int);
	enum netfs_io_source (*prepare_read)(struct netfs_io_subrequest *, long long unsigned int);
	void (*prepare_write_subreq)(struct netfs_io_subrequest *);
	int (*prepare_write)(struct netfs_cache_resources *, loff_t *, size_t *, size_t, loff_t, bool);
	enum netfs_io_source (*prepare_ondemand_read)(struct netfs_cache_resources *, loff_t, size_t *, loff_t, long unsigned int *, ino_t);
	int (*query_occupancy)(struct netfs_cache_resources *, loff_t, size_t, size_t, loff_t *, size_t *);
};

enum netfs_io_origin {
	NETFS_READAHEAD = 0,
	NETFS_READPAGE = 1,
	NETFS_READ_GAPS = 2,
	NETFS_READ_FOR_WRITE = 3,
	NETFS_DIO_READ = 4,
	NETFS_WRITEBACK = 5,
	NETFS_WRITETHROUGH = 6,
	NETFS_UNBUFFERED_WRITE = 7,
	NETFS_DIO_WRITE = 8,
	NETFS_PGPRIV2_COPY_TO_CACHE = 9,
	nr__netfs_io_origin = 10,
} __attribute__((mode(byte)));

struct netfs_io_request {
	union {
		struct work_struct work;
		struct callback_head rcu;
	};
	struct inode *inode;
	struct address_space *mapping;
	struct kiocb *iocb;
	struct netfs_cache_resources cache_resources;
	struct readahead_control *ractl;
	struct list_head proc_link;
	struct list_head subrequests;
	struct netfs_io_stream io_streams[2];
	struct netfs_group *group;
	struct folio_queue *buffer;
	struct folio_queue *buffer_tail;
	struct iov_iter iter;
	struct iov_iter io_iter;
	void *netfs_priv;
	void *netfs_priv2;
	struct bio_vec *direct_bv;
	unsigned int direct_bv_count;
	unsigned int debug_id;
	unsigned int rsize;
	unsigned int wsize;
	atomic_t subreq_counter;
	unsigned int nr_group_rel;
	spinlock_t lock;
	atomic_t nr_outstanding;
	long long unsigned int submitted;
	long long unsigned int len;
	size_t transferred;
	long int error;
	enum netfs_io_origin origin;
	bool direct_bv_unpin;
	u8 buffer_head_slot;
	u8 buffer_tail_slot;
	long long unsigned int i_size;
	long long unsigned int start;
	atomic64_t issued_to;
	long long unsigned int collected_to;
	long long unsigned int cleaned_to;
	long unsigned int no_unlock_folio;
	size_t prev_donated;
	refcount_t ref;
	long unsigned int flags;
	const struct netfs_request_ops *netfs_ops;
	void (*cleanup)(struct netfs_io_request *);
};

struct gss_api_mech;

struct gss_ctx {
	struct gss_api_mech *mech_type;
	void *internal_ctx_id;
	unsigned int slack;
	unsigned int align;
};

struct gss_api_ops;

struct pf_desc;

struct gss_api_mech {
	struct list_head gm_list;
	struct module *gm_owner;
	struct rpcsec_gss_oid gm_oid;
	char *gm_name;
	const struct gss_api_ops *gm_ops;
	int gm_pf_num;
	struct pf_desc *gm_pfs;
	const char *gm_upcall_enctypes;
};

struct auth_domain;

struct pf_desc {
	u32 pseudoflavor;
	u32 qop;
	u32 service;
	char *name;
	char *auth_domain_name;
	struct auth_domain *domain;
	bool datatouch;
};

struct auth_ops;

struct auth_domain {
	struct kref ref;
	struct hlist_node hash;
	char *name;
	struct auth_ops *flavour;
	struct callback_head callback_head;
};

struct gss_api_ops {
	int (*gss_import_sec_context)(const void *, size_t, struct gss_ctx *, time64_t *, gfp_t);
	u32 (*gss_get_mic)(struct gss_ctx *, struct xdr_buf *, struct xdr_netobj *);
	u32 (*gss_verify_mic)(struct gss_ctx *, struct xdr_buf *, struct xdr_netobj *);
	u32 (*gss_wrap)(struct gss_ctx *, int, struct xdr_buf *, struct page **);
	u32 (*gss_unwrap)(struct gss_ctx *, int, int, struct xdr_buf *);
	void (*gss_delete_sec_context)(void *);
};

struct nfs4_string {
	unsigned int len;
	char *data;
};

struct nfs_fsid {
	uint64_t major;
	uint64_t minor;
};

struct nfs4_threshold {
	__u32 bm;
	__u32 l_type;
	__u64 rd_sz;
	__u64 wr_sz;
	__u64 rd_io_sz;
	__u64 wr_io_sz;
};

struct nfs_fattr {
	unsigned int valid;
	umode_t mode;
	__u32 nlink;
	kuid_t uid;
	kgid_t gid;
	dev_t rdev;
	__u64 size;
	union {
		struct {
			__u32 blocksize;
			__u32 blocks;
		} nfs2;
		struct {
			__u64 used;
		} nfs3;
	} du;
	struct nfs_fsid fsid;
	__u64 fileid;
	__u64 mounted_on_fileid;
	struct timespec64 atime;
	struct timespec64 mtime;
	struct timespec64 ctime;
	__u64 change_attr;
	__u64 pre_change_attr;
	__u64 pre_size;
	struct timespec64 pre_mtime;
	struct timespec64 pre_ctime;
	long unsigned int time_start;
	long unsigned int gencount;
	struct nfs4_string *owner_name;
	struct nfs4_string *group_name;
	struct nfs4_threshold *mdsthreshold;
	struct nfs4_label *label;
};

struct nfs_fsinfo {
	struct nfs_fattr *fattr;
	__u32 rtmax;
	__u32 rtpref;
	__u32 rtmult;
	__u32 wtmax;
	__u32 wtpref;
	__u32 wtmult;
	__u32 dtpref;
	__u64 maxfilesize;
	struct timespec64 time_delta;
	__u32 lease_time;
	__u32 nlayouttypes;
	__u32 layouttype[8];
	__u32 blksize;
	__u32 clone_blksize;
	enum nfs4_change_attr_type change_attr_type;
	__u32 xattr_support;
};

struct nfs_fsstat {
	struct nfs_fattr *fattr;
	__u64 tbytes;
	__u64 fbytes;
	__u64 abytes;
	__u64 tfiles;
	__u64 ffiles;
	__u64 afiles;
};

struct nfs_pathconf {
	struct nfs_fattr *fattr;
	__u32 max_link;
	__u32 max_namelen;
};

struct nfs4_change_info {
	u32 atomic;
	u64 before;
	u64 after;
};

struct nfs4_channel_attrs {
	u32 max_rqst_sz;
	u32 max_resp_sz;
	u32 max_resp_sz_cached;
	u32 max_ops;
	u32 max_reqs;
};

struct nfs4_slot;

struct nfs4_sequence_args {
	struct nfs4_slot *sa_slot;
	u8 sa_cache_this: 1;
	u8 sa_privileged: 1;
};

struct nfs4_slot_table;

struct nfs4_slot {
	struct nfs4_slot_table *table;
	struct nfs4_slot *next;
	long unsigned int generation;
	u32 slot_nr;
	u32 seq_nr;
	u32 seq_nr_last_acked;
	u32 seq_nr_highest_sent;
	unsigned int privileged: 1;
	unsigned int seq_done: 1;
};

struct nfs4_sequence_res {
	struct nfs4_slot *sr_slot;
	long unsigned int sr_timestamp;
	int sr_status;
	u32 sr_status_flags;
	u32 sr_highest_slotid;
	u32 sr_target_highest_slotid;
};

struct nfs4_get_lease_time_args {
	struct nfs4_sequence_args la_seq_args;
};

struct nfs4_get_lease_time_res {
	struct nfs4_sequence_res lr_seq_res;
	struct nfs_fsinfo *lr_fsinfo;
};

struct nfs4_xdr_opaque_data;

struct nfs4_xdr_opaque_ops {
	void (*encode)(struct xdr_stream *, const void *, const struct nfs4_xdr_opaque_data *);
	void (*free)(struct nfs4_xdr_opaque_data *);
};

struct nfs4_xdr_opaque_data {
	const struct nfs4_xdr_opaque_ops *ops;
	void *data;
};

struct nfs4_layoutdriver_data {
	struct page **pages;
	__u32 pglen;
	__u32 len;
};

struct pnfs_layout_range {
	u32 iomode;
	u64 offset;
	u64 length;
};

struct nfs_open_context;

struct nfs4_layoutget_args {
	struct nfs4_sequence_args seq_args;
	__u32 type;
	struct pnfs_layout_range range;
	__u64 minlength;
	__u32 maxcount;
	struct inode *inode;
	struct nfs_open_context *ctx;
	nfs4_stateid stateid;
	struct nfs4_layoutdriver_data layout;
};

struct nfs_lock_context {
	refcount_t count;
	struct list_head list;
	struct nfs_open_context *open_context;
	fl_owner_t lockowner;
	atomic_t io_count;
	struct callback_head callback_head;
};

struct nfs4_state;

struct nfs_open_context {
	struct nfs_lock_context lock_context;
	fl_owner_t flock_owner;
	struct dentry *dentry;
	const struct cred *cred;
	struct rpc_cred *ll_cred;
	struct nfs4_state *state;
	fmode_t mode;
	long unsigned int flags;
	int error;
	struct list_head list;
	struct nfs4_threshold *mdsthreshold;
	struct callback_head callback_head;
};

struct nfs4_layoutget_res {
	struct nfs4_sequence_res seq_res;
	int status;
	__u32 return_on_close;
	struct pnfs_layout_range range;
	__u32 type;
	nfs4_stateid stateid;
	struct nfs4_layoutdriver_data *layoutp;
};

struct pnfs_layout_hdr;

struct nfs4_layoutget {
	struct nfs4_layoutget_args args;
	struct nfs4_layoutget_res res;
	const struct cred *cred;
	struct pnfs_layout_hdr *lo;
	gfp_t gfp_flags;
};

struct pnfs_layout_hdr {
	refcount_t plh_refcount;
	atomic_t plh_outstanding;
	struct list_head plh_layouts;
	struct list_head plh_bulk_destroy;
	struct list_head plh_segs;
	struct list_head plh_return_segs;
	long unsigned int plh_block_lgets;
	long unsigned int plh_retry_timestamp;
	long unsigned int plh_flags;
	nfs4_stateid plh_stateid;
	u32 plh_barrier;
	u32 plh_return_seq;
	enum pnfs_iomode plh_return_iomode;
	loff_t plh_lwb;
	const struct cred *plh_lc_cred;
	struct inode *plh_inode;
	struct callback_head plh_rcu;
};

struct pnfs_device;

struct nfs4_getdeviceinfo_args {
	struct nfs4_sequence_args seq_args;
	struct pnfs_device *pdev;
	__u32 notify_types;
};

struct pnfs_device {
	struct nfs4_deviceid dev_id;
	unsigned int layout_type;
	unsigned int mincount;
	unsigned int maxcount;
	struct page **pages;
	unsigned int pgbase;
	unsigned int pglen;
	unsigned char nocache: 1;
};

struct nfs4_getdeviceinfo_res {
	struct nfs4_sequence_res seq_res;
	struct pnfs_device *pdev;
	__u32 notification;
};

struct nfs4_layoutcommit_args {
	struct nfs4_sequence_args seq_args;
	nfs4_stateid stateid;
	__u64 lastbytewritten;
	struct inode *inode;
	const u32 *bitmask;
	size_t layoutupdate_len;
	struct page *layoutupdate_page;
	struct page **layoutupdate_pages;
	__be32 *start_p;
};

struct nfs_server;

struct nfs4_layoutcommit_res {
	struct nfs4_sequence_res seq_res;
	struct nfs_fattr *fattr;
	const struct nfs_server *server;
	int status;
};

struct nlm_host;

struct nfs_auth_info {
	unsigned int flavor_len;
	rpc_authflavor_t flavors[12];
};

struct nfs_client;

struct nfs_iostats;

struct pnfs_layoutdriver_type;

struct nfs_server {
	struct nfs_client *nfs_client;
	struct list_head client_link;
	struct list_head master_link;
	struct rpc_clnt *client;
	struct rpc_clnt *client_acl;
	struct nlm_host *nlm_host;
	struct nfs_iostats *io_stats;
	wait_queue_head_t write_congestion_wait;
	atomic_long_t writeback;
	unsigned int write_congested;
	unsigned int flags;
	unsigned int fattr_valid;
	unsigned int caps;
	unsigned int rsize;
	unsigned int rpages;
	unsigned int wsize;
	unsigned int wpages;
	unsigned int wtmult;
	unsigned int dtsize;
	short unsigned int port;
	unsigned int bsize;
	unsigned int gxasize;
	unsigned int sxasize;
	unsigned int lxasize;
	unsigned int acregmin;
	unsigned int acregmax;
	unsigned int acdirmin;
	unsigned int acdirmax;
	unsigned int namelen;
	unsigned int options;
	unsigned int clone_blksize;
	enum nfs4_change_attr_type change_attr_type;
	struct nfs_fsid fsid;
	int s_sysfs_id;
	__u64 maxfilesize;
	struct timespec64 time_delta;
	long unsigned int mount_time;
	struct super_block *super;
	dev_t s_dev;
	struct nfs_auth_info auth_info;
	struct fscache_volume *fscache;
	char *fscache_uniq;
	u32 fh_expire_type;
	u32 pnfs_blksize;
	u32 attr_bitmask[3];
	u32 attr_bitmask_nl[3];
	u32 exclcreat_bitmask[3];
	u32 cache_consistency_bitmask[3];
	u32 acl_bitmask;
	struct pnfs_layoutdriver_type *pnfs_curr_ld;
	struct rpc_wait_queue roc_rpcwaitq;
	void *pnfs_ld_data;
	struct rb_root state_owners;
	atomic64_t owner_ctr;
	struct list_head state_owners_lru;
	struct list_head layouts;
	struct list_head delegations;
	struct list_head ss_copies;
	struct list_head ss_src_copies;
	long unsigned int delegation_flags;
	long unsigned int delegation_gen;
	long unsigned int mig_gen;
	long unsigned int mig_status;
	void (*destroy)(struct nfs_server *);
	atomic_t active;
	struct __kernel_sockaddr_storage mountd_address;
	size_t mountd_addrlen;
	u32 mountd_version;
	short unsigned int mountd_port;
	short unsigned int mountd_protocol;
	struct rpc_wait_queue uoc_rpcwaitq;
	unsigned int read_hdrsize;
	const struct cred *cred;
	bool has_sec_mnt_opts;
	struct kobject kobj;
	struct callback_head rcu;
};

struct nfs4_layoutcommit_data {
	struct rpc_task task;
	struct nfs_fattr fattr;
	struct list_head lseg_list;
	const struct cred *cred;
	struct inode *inode;
	struct nfs4_layoutcommit_args args;
	struct nfs4_layoutcommit_res res;
};

struct nfs4_layoutreturn_args {
	struct nfs4_sequence_args seq_args;
	struct pnfs_layout_hdr *layout;
	struct inode *inode;
	struct pnfs_layout_range range;
	nfs4_stateid stateid;
	__u32 layout_type;
	struct nfs4_xdr_opaque_data *ld_private;
};

struct nfs4_layoutreturn_res {
	struct nfs4_sequence_res seq_res;
	u32 lrs_present;
	nfs4_stateid stateid;
};

struct nfs4_layoutreturn {
	struct nfs4_layoutreturn_args args;
	struct nfs4_layoutreturn_res res;
	const struct cred *cred;
	struct nfs_client *clp;
	struct inode *inode;
	int rpc_status;
	struct nfs4_xdr_opaque_data ld_private;
};

struct nfs_rpc_ops;

struct nfs_subversion;

struct idmap;

struct nfs4_minor_version_ops;

struct nfs4_session;

struct nfs41_server_owner;

struct nfs41_server_scope;

struct nfs41_impl_id;

struct nfs_client {
	refcount_t cl_count;
	atomic_t cl_mds_count;
	int cl_cons_state;
	long unsigned int cl_res_state;
	long unsigned int cl_flags;
	struct __kernel_sockaddr_storage cl_addr;
	size_t cl_addrlen;
	char *cl_hostname;
	char *cl_acceptor;
	struct list_head cl_share_link;
	struct list_head cl_superblocks;
	struct rpc_clnt *cl_rpcclient;
	const struct nfs_rpc_ops *rpc_ops;
	int cl_proto;
	struct nfs_subversion *cl_nfs_mod;
	u32 cl_minorversion;
	unsigned int cl_nconnect;
	unsigned int cl_max_connect;
	const char *cl_principal;
	struct xprtsec_parms cl_xprtsec;
	struct list_head cl_ds_clients;
	u64 cl_clientid;
	nfs4_verifier cl_confirm;
	long unsigned int cl_state;
	spinlock_t cl_lock;
	long unsigned int cl_lease_time;
	long unsigned int cl_last_renewal;
	struct delayed_work cl_renewd;
	struct rpc_wait_queue cl_rpcwaitq;
	struct idmap *cl_idmap;
	const char *cl_owner_id;
	u32 cl_cb_ident;
	const struct nfs4_minor_version_ops *cl_mvops;
	long unsigned int cl_mig_gen;
	struct nfs4_slot_table *cl_slot_tbl;
	u32 cl_seqid;
	u32 cl_exchange_flags;
	struct nfs4_session *cl_session;
	bool cl_preserve_clid;
	struct nfs41_server_owner *cl_serverowner;
	struct nfs41_server_scope *cl_serverscope;
	struct nfs41_impl_id *cl_implid;
	long unsigned int cl_sp4_flags;
	wait_queue_head_t cl_lock_waitq;
	char cl_ipaddr[48];
	struct net *cl_net;
	struct list_head pending_cb_stateids;
	struct callback_head rcu;
};

struct nfs42_layoutstat_devinfo;

struct nfs42_layoutstat_args {
	struct nfs4_sequence_args seq_args;
	struct nfs_fh *fh;
	struct inode *inode;
	nfs4_stateid stateid;
	int num_dev;
	struct nfs42_layoutstat_devinfo *devinfo;
};

struct nfs42_layoutstat_devinfo {
	struct nfs4_deviceid dev_id;
	__u64 offset;
	__u64 length;
	__u64 read_count;
	__u64 read_bytes;
	__u64 write_count;
	__u64 write_bytes;
	__u32 layout_type;
	struct nfs4_xdr_opaque_data ld_private;
};

struct pnfs_layout_segment {
	struct list_head pls_list;
	struct list_head pls_lc_list;
	struct list_head pls_commits;
	struct pnfs_layout_range pls_range;
	refcount_t pls_refcount;
	u32 pls_seq;
	long unsigned int pls_flags;
	struct pnfs_layout_hdr *pls_layout;
};

struct stateowner_id {
	__u64 create_time;
	__u64 uniquifier;
};

struct nfs4_open_delegation {
	__u32 open_delegation_type;
	union {
		struct {
			fmode_t type;
			__u32 do_recall;
			nfs4_stateid stateid;
			long unsigned int pagemod_limit;
		};
		struct {
			__u32 why_no_delegation;
			__u32 will_notify;
		};
	};
};

struct nfs_seqid;

struct nfs_openargs {
	struct nfs4_sequence_args seq_args;
	const struct nfs_fh *fh;
	struct nfs_seqid *seqid;
	int open_flags;
	fmode_t fmode;
	u32 share_access;
	u32 access;
	__u64 clientid;
	struct stateowner_id id;
	union {
		struct {
			struct iattr *attrs;
			nfs4_verifier verifier;
		};
		nfs4_stateid delegation;
		__u32 delegation_type;
	} u;
	const struct qstr *name;
	const struct nfs_server *server;
	const u32 *bitmask;
	const u32 *open_bitmap;
	enum open_claim_type4 claim;
	enum createmode4 createmode;
	const struct nfs4_label *label;
	umode_t umask;
	struct nfs4_layoutget_args *lg_args;
};

struct nfs_seqid_counter;

struct nfs_seqid {
	struct nfs_seqid_counter *sequence;
	struct list_head list;
	struct rpc_task *task;
};

struct nfs_openres {
	struct nfs4_sequence_res seq_res;
	nfs4_stateid stateid;
	struct nfs_fh fh;
	struct nfs4_change_info cinfo;
	__u32 rflags;
	struct nfs_fattr *f_attr;
	struct nfs_seqid *seqid;
	const struct nfs_server *server;
	__u32 attrset[3];
	struct nfs4_string *owner;
	struct nfs4_string *group_owner;
	struct nfs4_open_delegation delegation;
	__u32 access_request;
	__u32 access_supported;
	__u32 access_result;
	struct nfs4_layoutget_res *lg_res;
};

struct nfs_open_confirmargs {
	struct nfs4_sequence_args seq_args;
	const struct nfs_fh *fh;
	nfs4_stateid *stateid;
	struct nfs_seqid *seqid;
};

struct nfs_open_confirmres {
	struct nfs4_sequence_res seq_res;
	nfs4_stateid stateid;
	struct nfs_seqid *seqid;
};

struct nfs_closeargs {
	struct nfs4_sequence_args seq_args;
	struct nfs_fh *fh;
	nfs4_stateid stateid;
	struct nfs_seqid *seqid;
	fmode_t fmode;
	u32 share_access;
	const u32 *bitmask;
	u32 bitmask_store[3];
	struct nfs4_layoutreturn_args *lr_args;
};

struct nfs_closeres {
	struct nfs4_sequence_res seq_res;
	nfs4_stateid stateid;
	struct nfs_fattr *fattr;
	struct nfs_seqid *seqid;
	const struct nfs_server *server;
	struct nfs4_layoutreturn_res *lr_res;
	int lr_ret;
};

struct nfs_lowner {
	__u64 clientid;
	__u64 id;
	dev_t s_dev;
};

struct nfs_lock_args {
	struct nfs4_sequence_args seq_args;
	struct nfs_fh *fh;
	struct file_lock *fl;
	struct nfs_seqid *lock_seqid;
	nfs4_stateid lock_stateid;
	struct nfs_seqid *open_seqid;
	nfs4_stateid open_stateid;
	struct nfs_lowner lock_owner;
	unsigned char block: 1;
	unsigned char reclaim: 1;
	unsigned char new_lock: 1;
	unsigned char new_lock_owner: 1;
};

struct nfs_lock_res {
	struct nfs4_sequence_res seq_res;
	nfs4_stateid stateid;
	struct nfs_seqid *lock_seqid;
	struct nfs_seqid *open_seqid;
};

struct nfs_locku_args {
	struct nfs4_sequence_args seq_args;
	struct nfs_fh *fh;
	struct file_lock *fl;
	struct nfs_seqid *seqid;
	nfs4_stateid stateid;
};

struct nfs_locku_res {
	struct nfs4_sequence_res seq_res;
	nfs4_stateid stateid;
	struct nfs_seqid *seqid;
};

struct nfs_lockt_args {
	struct nfs4_sequence_args seq_args;
	struct nfs_fh *fh;
	struct file_lock *fl;
	struct nfs_lowner lock_owner;
};

struct nfs_lockt_res {
	struct nfs4_sequence_res seq_res;
	struct file_lock *denied;
};

struct nfs_release_lockowner_args {
	struct nfs4_sequence_args seq_args;
	struct nfs_lowner lock_owner;
};

struct nfs_release_lockowner_res {
	struct nfs4_sequence_res seq_res;
};

struct nfs4_delegattr {
	struct timespec64 atime;
	struct timespec64 mtime;
	bool atime_set;
	bool mtime_set;
};

struct nfs4_delegreturnargs {
	struct nfs4_sequence_args seq_args;
	const struct nfs_fh *fhandle;
	const nfs4_stateid *stateid;
	const u32 *bitmask;
	u32 bitmask_store[3];
	struct nfs4_layoutreturn_args *lr_args;
	struct nfs4_delegattr *sattr_args;
};

struct nfs4_delegreturnres {
	struct nfs4_sequence_res seq_res;
	struct nfs_fattr *fattr;
	struct nfs_server *server;
	struct nfs4_layoutreturn_res *lr_res;
	int lr_ret;
	bool sattr_res;
	int sattr_ret;
};

struct nfs_write_verifier {
	char data[8];
};

struct nfs_writeverf {
	struct nfs_write_verifier verifier;
	enum nfs3_stable_how committed;
};

struct nfs_pgio_args {
	struct nfs4_sequence_args seq_args;
	struct nfs_fh *fh;
	struct nfs_open_context *context;
	struct nfs_lock_context *lock_context;
	nfs4_stateid stateid;
	__u64 offset;
	__u32 count;
	unsigned int pgbase;
	struct page **pages;
	union {
		unsigned int replen;
		struct {
			const u32 *bitmask;
			u32 bitmask_store[3];
			enum nfs3_stable_how stable;
		};
	};
};

struct nfs_pgio_res {
	struct nfs4_sequence_res seq_res;
	struct nfs_fattr *fattr;
	__u64 count;
	__u32 op_status;
	union {
		struct {
			unsigned int replen;
			int eof;
			void *scratch;
		};
		struct {
			struct nfs_writeverf *verf;
			const struct nfs_server *server;
		};
	};
};

struct nfs_commitargs {
	struct nfs4_sequence_args seq_args;
	struct nfs_fh *fh;
	__u64 offset;
	__u32 count;
	const u32 *bitmask;
};

struct nfs_commitres {
	struct nfs4_sequence_res seq_res;
	__u32 op_status;
	struct nfs_fattr *fattr;
	struct nfs_writeverf *verf;
	const struct nfs_server *server;
};

struct nfs_removeargs {
	struct nfs4_sequence_args seq_args;
	const struct nfs_fh *fh;
	struct qstr name;
};

struct nfs_removeres {
	struct nfs4_sequence_res seq_res;
	struct nfs_server *server;
	struct nfs_fattr *dir_attr;
	struct nfs4_change_info cinfo;
};

struct nfs_renameargs {
	struct nfs4_sequence_args seq_args;
	const struct nfs_fh *old_dir;
	const struct nfs_fh *new_dir;
	const struct qstr *old_name;
	const struct qstr *new_name;
};

struct nfs_renameres {
	struct nfs4_sequence_res seq_res;
	struct nfs_server *server;
	struct nfs4_change_info old_cinfo;
	struct nfs_fattr *old_fattr;
	struct nfs4_change_info new_cinfo;
	struct nfs_fattr *new_fattr;
};

struct nfs_entry {
	__u64 ino;
	__u64 cookie;
	const char *name;
	unsigned int len;
	int eof;
	struct nfs_fh *fh;
	struct nfs_fattr *fattr;
	unsigned char d_type;
	struct nfs_server *server;
};

struct nfs_readdir_arg {
	struct dentry *dentry;
	const struct cred *cred;
	__be32 *verf;
	u64 cookie;
	struct page **pages;
	unsigned int page_len;
	bool plus;
};

struct nfs_readdir_res {
	__be32 *verf;
};

struct nfs_setattrargs {
	struct nfs4_sequence_args seq_args;
	struct nfs_fh *fh;
	nfs4_stateid stateid;
	struct iattr *iap;
	const struct nfs_server *server;
	const u32 *bitmask;
	const struct nfs4_label *label;
};

enum nfs4_acl_type {
	NFS4ACL_NONE = 0,
	NFS4ACL_ACL = 1,
	NFS4ACL_DACL = 2,
	NFS4ACL_SACL = 3,
};

struct nfs_setaclargs {
	struct nfs4_sequence_args seq_args;
	struct nfs_fh *fh;
	enum nfs4_acl_type acl_type;
	size_t acl_len;
	struct page **acl_pages;
};

struct nfs_setaclres {
	struct nfs4_sequence_res seq_res;
};

struct nfs_getaclargs {
	struct nfs4_sequence_args seq_args;
	struct nfs_fh *fh;
	enum nfs4_acl_type acl_type;
	size_t acl_len;
	struct page **acl_pages;
};

struct nfs_getaclres {
	struct nfs4_sequence_res seq_res;
	enum nfs4_acl_type acl_type;
	size_t acl_len;
	size_t acl_data_offset;
	int acl_flags;
	struct page *acl_scratch;
};

struct nfs_setattrres {
	struct nfs4_sequence_res seq_res;
	struct nfs_fattr *fattr;
	const struct nfs_server *server;
};

typedef u64 clientid4;

struct nfs4_accessargs {
	struct nfs4_sequence_args seq_args;
	const struct nfs_fh *fh;
	const u32 *bitmask;
	u32 access;
};

struct nfs4_accessres {
	struct nfs4_sequence_res seq_res;
	const struct nfs_server *server;
	struct nfs_fattr *fattr;
	u32 supported;
	u32 access;
};

struct nfs4_create_arg {
	struct nfs4_sequence_args seq_args;
	u32 ftype;
	union {
		struct {
			struct page **pages;
			unsigned int len;
		} symlink;
		struct {
			u32 specdata1;
			u32 specdata2;
		} device;
	} u;
	const struct qstr *name;
	const struct nfs_server *server;
	const struct iattr *attrs;
	const struct nfs_fh *dir_fh;
	const u32 *bitmask;
	const struct nfs4_label *label;
	umode_t umask;
};

struct nfs4_create_res {
	struct nfs4_sequence_res seq_res;
	const struct nfs_server *server;
	struct nfs_fh *fh;
	struct nfs_fattr *fattr;
	struct nfs4_change_info dir_cinfo;
};

struct nfs4_fsinfo_arg {
	struct nfs4_sequence_args seq_args;
	const struct nfs_fh *fh;
	const u32 *bitmask;
};

struct nfs4_fsinfo_res {
	struct nfs4_sequence_res seq_res;
	struct nfs_fsinfo *fsinfo;
};

struct nfs4_getattr_arg {
	struct nfs4_sequence_args seq_args;
	const struct nfs_fh *fh;
	const u32 *bitmask;
};

struct nfs4_getattr_res {
	struct nfs4_sequence_res seq_res;
	const struct nfs_server *server;
	struct nfs_fattr *fattr;
};

struct nfs4_link_arg {
	struct nfs4_sequence_args seq_args;
	const struct nfs_fh *fh;
	const struct nfs_fh *dir_fh;
	const struct qstr *name;
	const u32 *bitmask;
};

struct nfs4_link_res {
	struct nfs4_sequence_res seq_res;
	const struct nfs_server *server;
	struct nfs_fattr *fattr;
	struct nfs4_change_info cinfo;
	struct nfs_fattr *dir_attr;
};

struct nfs4_lookup_arg {
	struct nfs4_sequence_args seq_args;
	const struct nfs_fh *dir_fh;
	const struct qstr *name;
	const u32 *bitmask;
};

struct nfs4_lookup_res {
	struct nfs4_sequence_res seq_res;
	const struct nfs_server *server;
	struct nfs_fattr *fattr;
	struct nfs_fh *fh;
};

struct nfs4_lookupp_arg {
	struct nfs4_sequence_args seq_args;
	const struct nfs_fh *fh;
	const u32 *bitmask;
};

struct nfs4_lookupp_res {
	struct nfs4_sequence_res seq_res;
	const struct nfs_server *server;
	struct nfs_fattr *fattr;
	struct nfs_fh *fh;
};

struct nfs4_lookup_root_arg {
	struct nfs4_sequence_args seq_args;
	const u32 *bitmask;
};

struct nfs4_pathconf_arg {
	struct nfs4_sequence_args seq_args;
	const struct nfs_fh *fh;
	const u32 *bitmask;
};

struct nfs4_pathconf_res {
	struct nfs4_sequence_res seq_res;
	struct nfs_pathconf *pathconf;
};

struct nfs4_readdir_arg {
	struct nfs4_sequence_args seq_args;
	const struct nfs_fh *fh;
	u64 cookie;
	nfs4_verifier verifier;
	u32 count;
	struct page **pages;
	unsigned int pgbase;
	const u32 *bitmask;
	bool plus;
};

struct nfs4_readdir_res {
	struct nfs4_sequence_res seq_res;
	nfs4_verifier verifier;
	unsigned int pgbase;
};

struct nfs4_readlink {
	struct nfs4_sequence_args seq_args;
	const struct nfs_fh *fh;
	unsigned int pgbase;
	unsigned int pglen;
	struct page **pages;
};

struct nfs4_readlink_res {
	struct nfs4_sequence_res seq_res;
};

struct nfs4_setclientid {
	const nfs4_verifier *sc_verifier;
	u32 sc_prog;
	unsigned int sc_netid_len;
	char sc_netid[6];
	unsigned int sc_uaddr_len;
	char sc_uaddr[58];
	struct nfs_client *sc_clnt;
	struct rpc_cred *sc_cred;
};

struct nfs4_setclientid_res {
	u64 clientid;
	nfs4_verifier confirm;
};

struct nfs4_statfs_arg {
	struct nfs4_sequence_args seq_args;
	const struct nfs_fh *fh;
	const u32 *bitmask;
};

struct nfs4_statfs_res {
	struct nfs4_sequence_res seq_res;
	struct nfs_fsstat *fsstat;
};

struct nfs4_open_caps {
	u32 oa_share_access[1];
	u32 oa_share_deny[1];
	u32 oa_share_access_want[1];
	u32 oa_open_claim[1];
	u32 oa_createmode[1];
};

struct nfs4_server_caps_arg {
	struct nfs4_sequence_args seq_args;
	struct nfs_fh *fhandle;
	const u32 *bitmask;
};

struct nfs4_server_caps_res {
	struct nfs4_sequence_res seq_res;
	u32 attr_bitmask[3];
	u32 exclcreat_bitmask[3];
	u32 acl_bitmask;
	u32 has_links;
	u32 has_symlinks;
	u32 fh_expire_type;
	u32 case_insensitive;
	u32 case_preserving;
	struct nfs4_open_caps open_caps;
};

struct nfs4_pathname {
	unsigned int ncomponents;
	struct nfs4_string components[512];
};

struct nfs4_fs_location {
	unsigned int nservers;
	struct nfs4_string servers[10];
	struct nfs4_pathname rootpath;
};

struct nfs4_fs_locations {
	struct nfs_fattr *fattr;
	const struct nfs_server *server;
	struct nfs4_pathname fs_path;
	int nlocations;
	struct nfs4_fs_location locations[10];
};

struct nfs4_fs_locations_arg {
	struct nfs4_sequence_args seq_args;
	const struct nfs_fh *dir_fh;
	const struct nfs_fh *fh;
	const struct qstr *name;
	struct page *page;
	const u32 *bitmask;
	clientid4 clientid;
	unsigned char migration: 1;
	unsigned char renew: 1;
};

struct nfs4_fs_locations_res {
	struct nfs4_sequence_res seq_res;
	struct nfs4_fs_locations *fs_locations;
	unsigned char migration: 1;
	unsigned char renew: 1;
};

struct nfs4_secinfo4 {
	u32 flavor;
	struct rpcsec_gss_info flavor_info;
};

struct nfs4_secinfo_flavors {
	unsigned int num_flavors;
	struct nfs4_secinfo4 flavors[0];
};

struct nfs4_secinfo_arg {
	struct nfs4_sequence_args seq_args;
	const struct nfs_fh *dir_fh;
	const struct qstr *name;
};

struct nfs4_secinfo_res {
	struct nfs4_sequence_res seq_res;
	struct nfs4_secinfo_flavors *flavors;
};

struct nfs4_fsid_present_arg {
	struct nfs4_sequence_args seq_args;
	const struct nfs_fh *fh;
	clientid4 clientid;
	unsigned char renew: 1;
};

struct nfs4_fsid_present_res {
	struct nfs4_sequence_res seq_res;
	struct nfs_fh *fh;
	unsigned char renew: 1;
};

struct nfstime4 {
	u64 seconds;
	u32 nseconds;
};

struct pnfs_commit_ops;

struct pnfs_ds_commit_info {
	struct list_head commits;
	unsigned int nwritten;
	unsigned int ncommitting;
	const struct pnfs_commit_ops *ops;
};

struct nfs_commit_info;

struct nfs_page;

struct pnfs_commit_ops {
	void (*setup_ds_info)(struct pnfs_ds_commit_info *, struct pnfs_layout_segment *);
	void (*release_ds_info)(struct pnfs_ds_commit_info *, struct inode *);
	int (*commit_pagelist)(struct inode *, struct list_head *, int, struct nfs_commit_info *);
	void (*mark_request_commit)(struct nfs_page *, struct pnfs_layout_segment *, struct nfs_commit_info *, u32);
	void (*clear_request_commit)(struct nfs_page *, struct nfs_commit_info *);
	int (*scan_commit_lists)(struct nfs_commit_info *, int);
	void (*recover_commit_reqs)(struct list_head *, struct nfs_commit_info *);
};

struct nfs41_state_protection {
	u32 how;
	struct nfs4_op_map enforce;
	struct nfs4_op_map allow;
};

struct nfs41_exchange_id_args {
	struct nfs_client *client;
	nfs4_verifier verifier;
	u32 flags;
	struct nfs41_state_protection state_protect;
};

struct nfs41_server_owner {
	uint64_t minor_id;
	uint32_t major_id_sz;
	char major_id[1024];
};

struct nfs41_server_scope {
	uint32_t server_scope_sz;
	char server_scope[1024];
};

struct nfs41_impl_id {
	char domain[1025];
	char name[1025];
	struct nfstime4 date;
};

struct nfs41_bind_conn_to_session_args {
	struct nfs_client *client;
	struct nfs4_sessionid sessionid;
	u32 dir;
	bool use_conn_in_rdma_mode;
	int retries;
};

struct nfs41_bind_conn_to_session_res {
	struct nfs4_sessionid sessionid;
	u32 dir;
	bool use_conn_in_rdma_mode;
};

struct nfs41_exchange_id_res {
	u64 clientid;
	u32 seqid;
	u32 flags;
	struct nfs41_server_owner *server_owner;
	struct nfs41_server_scope *server_scope;
	struct nfs41_impl_id *impl_id;
	struct nfs41_state_protection state_protect;
};

struct nfs41_create_session_args {
	struct nfs_client *client;
	u64 clientid;
	uint32_t seqid;
	uint32_t flags;
	uint32_t cb_program;
	struct nfs4_channel_attrs fc_attrs;
	struct nfs4_channel_attrs bc_attrs;
};

struct nfs41_create_session_res {
	struct nfs4_sessionid sessionid;
	uint32_t seqid;
	uint32_t flags;
	struct nfs4_channel_attrs fc_attrs;
	struct nfs4_channel_attrs bc_attrs;
};

struct nfs41_reclaim_complete_args {
	struct nfs4_sequence_args seq_args;
	unsigned char one_fs: 1;
};

struct nfs41_reclaim_complete_res {
	struct nfs4_sequence_res seq_res;
};

struct nfs41_secinfo_no_name_args {
	struct nfs4_sequence_args seq_args;
	int style;
};

struct nfs41_test_stateid_args {
	struct nfs4_sequence_args seq_args;
	nfs4_stateid stateid;
};

struct nfs41_test_stateid_res {
	struct nfs4_sequence_res seq_res;
	unsigned int status;
};

struct nfs41_free_stateid_args {
	struct nfs4_sequence_args seq_args;
	nfs4_stateid stateid;
};

struct nfs41_free_stateid_res {
	struct nfs4_sequence_res seq_res;
	unsigned int status;
};

struct nfs_page_array {
	struct page **pagevec;
	unsigned int npages;
	struct page *page_array[8];
};

struct nfs_io_completion;

struct nfs_pgio_completion_ops;

struct nfs_rw_ops;

struct nfs_direct_req;

struct nfs_pgio_header {
	struct inode *inode;
	const struct cred *cred;
	struct list_head pages;
	struct nfs_page *req;
	struct nfs_writeverf verf;
	fmode_t rw_mode;
	struct pnfs_layout_segment *lseg;
	loff_t io_start;
	const struct rpc_call_ops *mds_ops;
	void (*release)(struct nfs_pgio_header *);
	const struct nfs_pgio_completion_ops *completion_ops;
	const struct nfs_rw_ops *rw_ops;
	struct nfs_io_completion *io_completion;
	struct nfs_direct_req *dreq;
	void *netfs;
	int pnfs_error;
	int error;
	unsigned int good_bytes;
	long unsigned int flags;
	struct rpc_task task;
	struct nfs_fattr fattr;
	struct nfs_pgio_args args;
	struct nfs_pgio_res res;
	long unsigned int timestamp;
	int (*pgio_done_cb)(struct rpc_task *, struct nfs_pgio_header *);
	__u64 mds_offset;
	struct nfs_page_array page_array;
	struct nfs_client *ds_clp;
	u32 ds_commit_idx;
	u32 pgio_mirror_idx;
};

struct nfs_page {
	struct list_head wb_list;
	union {
		struct page *wb_page;
		struct folio *wb_folio;
	};
	struct nfs_lock_context *wb_lock_context;
	long unsigned int wb_index;
	unsigned int wb_offset;
	unsigned int wb_pgbase;
	unsigned int wb_bytes;
	struct kref wb_kref;
	long unsigned int wb_flags;
	struct nfs_write_verifier wb_verf;
	struct nfs_page *wb_this_page;
	struct nfs_page *wb_head;
	short unsigned int wb_nio;
};

struct nfs_pgio_completion_ops {
	void (*error_cleanup)(struct list_head *, int);
	void (*init_hdr)(struct nfs_pgio_header *);
	void (*completion)(struct nfs_pgio_header *);
	void (*reschedule_io)(struct nfs_pgio_header *);
};

struct nfs_rw_ops {
	struct nfs_pgio_header * (*rw_alloc_header)();
	void (*rw_free_header)(struct nfs_pgio_header *);
	int (*rw_done)(struct rpc_task *, struct nfs_pgio_header *, struct inode *);
	void (*rw_result)(struct rpc_task *, struct nfs_pgio_header *);
	void (*rw_initiate)(struct nfs_pgio_header *, struct rpc_message *, const struct nfs_rpc_ops *, struct rpc_task_setup *, int);
};

struct nfs_mds_commit_info {
	atomic_t rpcs_out;
	atomic_long_t ncommit;
	struct list_head list;
};

struct nfs_direct_req {
	struct kref kref;
	struct nfs_open_context *ctx;
	struct nfs_lock_context *l_ctx;
	struct kiocb *iocb;
	struct inode *inode;
	atomic_t io_count;
	spinlock_t lock;
	loff_t io_start;
	ssize_t count;
	ssize_t max_count;
	ssize_t error;
	struct completion completion;
	struct nfs_mds_commit_info mds_cinfo;
	struct pnfs_ds_commit_info ds_cinfo;
	struct work_struct work;
	int flags;
};

struct nfs_commit_data;

struct nfs_commit_completion_ops {
	void (*completion)(struct nfs_commit_data *);
	void (*resched_write)(struct nfs_commit_info *, struct nfs_page *);
};

struct nfs_commit_data {
	struct rpc_task task;
	struct inode *inode;
	const struct cred *cred;
	struct nfs_fattr fattr;
	struct nfs_writeverf verf;
	struct list_head pages;
	struct list_head list;
	struct nfs_direct_req *dreq;
	struct nfs_commitargs args;
	struct nfs_commitres res;
	struct nfs_open_context *context;
	struct pnfs_layout_segment *lseg;
	struct nfs_client *ds_clp;
	int ds_commit_index;
	loff_t lwb;
	const struct rpc_call_ops *mds_ops;
	const struct nfs_commit_completion_ops *completion_ops;
	int (*commit_done_cb)(struct rpc_task *, struct nfs_commit_data *);
	long unsigned int flags;
};

struct nfs_commit_info {
	struct inode *inode;
	struct nfs_mds_commit_info *mds;
	struct pnfs_ds_commit_info *ds;
	struct nfs_direct_req *dreq;
	const struct nfs_commit_completion_ops *completion_ops;
};

struct nfs_unlinkdata {
	struct nfs_removeargs args;
	struct nfs_removeres res;
	struct dentry *dentry;
	wait_queue_head_t wq;
	const struct cred *cred;
	struct nfs_fattr dir_attr;
	long int timeout;
};

struct nfs_renamedata {
	struct nfs_renameargs args;
	struct nfs_renameres res;
	struct rpc_task task;
	const struct cred *cred;
	struct inode *old_dir;
	struct dentry *old_dentry;
	struct nfs_fattr old_fattr;
	struct inode *new_dir;
	struct dentry *new_dentry;
	struct nfs_fattr new_fattr;
	void (*complete)(struct rpc_task *, struct nfs_renamedata *);
	long int timeout;
	bool cancelled;
};

struct nlmclnt_operations;

struct nfs_access_entry;

struct nfs_client_initdata;

struct nfs_rpc_ops {
	u32 version;
	const struct dentry_operations *dentry_ops;
	const struct inode_operations *dir_inode_ops;
	const struct inode_operations *file_inode_ops;
	const struct file_operations *file_ops;
	const struct nlmclnt_operations *nlmclnt_ops;
	int (*getroot)(struct nfs_server *, struct nfs_fh *, struct nfs_fsinfo *);
	int (*submount)(struct fs_context *, struct nfs_server *);
	int (*try_get_tree)(struct fs_context *);
	int (*getattr)(struct nfs_server *, struct nfs_fh *, struct nfs_fattr *, struct inode *);
	int (*setattr)(struct dentry *, struct nfs_fattr *, struct iattr *);
	int (*lookup)(struct inode *, struct dentry *, struct nfs_fh *, struct nfs_fattr *);
	int (*lookupp)(struct inode *, struct nfs_fh *, struct nfs_fattr *);
	int (*access)(struct inode *, struct nfs_access_entry *, const struct cred *);
	int (*readlink)(struct inode *, struct page *, unsigned int, unsigned int);
	int (*create)(struct inode *, struct dentry *, struct iattr *, int);
	int (*remove)(struct inode *, struct dentry *);
	void (*unlink_setup)(struct rpc_message *, struct dentry *, struct inode *);
	void (*unlink_rpc_prepare)(struct rpc_task *, struct nfs_unlinkdata *);
	int (*unlink_done)(struct rpc_task *, struct inode *);
	void (*rename_setup)(struct rpc_message *, struct dentry *, struct dentry *);
	void (*rename_rpc_prepare)(struct rpc_task *, struct nfs_renamedata *);
	int (*rename_done)(struct rpc_task *, struct inode *, struct inode *);
	int (*link)(struct inode *, struct inode *, const struct qstr *);
	int (*symlink)(struct inode *, struct dentry *, struct folio *, unsigned int, struct iattr *);
	int (*mkdir)(struct inode *, struct dentry *, struct iattr *);
	int (*rmdir)(struct inode *, const struct qstr *);
	int (*readdir)(struct nfs_readdir_arg *, struct nfs_readdir_res *);
	int (*mknod)(struct inode *, struct dentry *, struct iattr *, dev_t);
	int (*statfs)(struct nfs_server *, struct nfs_fh *, struct nfs_fsstat *);
	int (*fsinfo)(struct nfs_server *, struct nfs_fh *, struct nfs_fsinfo *);
	int (*pathconf)(struct nfs_server *, struct nfs_fh *, struct nfs_pathconf *);
	int (*set_capabilities)(struct nfs_server *, struct nfs_fh *);
	int (*decode_dirent)(struct xdr_stream *, struct nfs_entry *, bool);
	int (*pgio_rpc_prepare)(struct rpc_task *, struct nfs_pgio_header *);
	void (*read_setup)(struct nfs_pgio_header *, struct rpc_message *);
	int (*read_done)(struct rpc_task *, struct nfs_pgio_header *);
	void (*write_setup)(struct nfs_pgio_header *, struct rpc_message *, struct rpc_clnt **);
	int (*write_done)(struct rpc_task *, struct nfs_pgio_header *);
	void (*commit_setup)(struct nfs_commit_data *, struct rpc_message *, struct rpc_clnt **);
	void (*commit_rpc_prepare)(struct rpc_task *, struct nfs_commit_data *);
	int (*commit_done)(struct rpc_task *, struct nfs_commit_data *);
	int (*lock)(struct file *, int, struct file_lock *);
	int (*lock_check_bounds)(const struct file_lock *);
	void (*clear_acl_cache)(struct inode *);
	void (*close_context)(struct nfs_open_context *, int);
	struct inode * (*open_context)(struct inode *, struct nfs_open_context *, int, struct iattr *, int *);
	int (*have_delegation)(struct inode *, fmode_t, int);
	int (*return_delegation)(struct inode *);
	struct nfs_client * (*alloc_client)(const struct nfs_client_initdata *);
	struct nfs_client * (*init_client)(struct nfs_client *, const struct nfs_client_initdata *);
	void (*free_client)(struct nfs_client *);
	struct nfs_server * (*create_server)(struct fs_context *);
	struct nfs_server * (*clone_server)(struct nfs_server *, struct nfs_fh *, struct nfs_fattr *, rpc_authflavor_t);
	int (*discover_trunking)(struct nfs_server *, struct nfs_fh *);
	void (*enable_swap)(struct inode *);
	void (*disable_swap)(struct inode *);
};

struct nfs_access_entry {
	struct rb_node rb_node;
	struct list_head lru;
	kuid_t fsuid;
	kgid_t fsgid;
	struct group_info *group_info;
	u64 timestamp;
	__u32 mask;
	struct callback_head callback_head;
};

struct nfs_client_initdata {
	long unsigned int init_flags;
	const char *hostname;
	const struct __kernel_sockaddr_storage *addr;
	const char *nodename;
	const char *ip_addr;
	size_t addrlen;
	struct nfs_subversion *nfs_mod;
	int proto;
	u32 minorversion;
	unsigned int nconnect;
	unsigned int max_connect;
	struct net *net;
	const struct rpc_timeout *timeparms;
	const struct cred *cred;
	struct xprtsec_parms xprtsec;
	long unsigned int connect_timeout;
	long unsigned int reconnect_timeout;
};

struct nfs4_state_recovery_ops;

struct nfs4_state_maintenance_ops;

struct nfs4_mig_recovery_ops;

struct nfs4_minor_version_ops {
	u32 minor_version;
	unsigned int init_caps;
	int (*init_client)(struct nfs_client *);
	void (*shutdown_client)(struct nfs_client *);
	bool (*match_stateid)(const nfs4_stateid *, const nfs4_stateid *);
	int (*find_root_sec)(struct nfs_server *, struct nfs_fh *, struct nfs_fsinfo *);
	void (*free_lock_state)(struct nfs_server *, struct nfs4_lock_state *);
	int (*test_and_free_expired)(struct nfs_server *, const nfs4_stateid *, const struct cred *);
	struct nfs_seqid * (*alloc_seqid)(struct nfs_seqid_counter *, gfp_t);
	void (*session_trunk)(struct rpc_clnt *, struct rpc_xprt *, void *);
	const struct rpc_call_ops *call_sync_ops;
	const struct nfs4_state_recovery_ops *reboot_recovery_ops;
	const struct nfs4_state_recovery_ops *nograce_recovery_ops;
	const struct nfs4_state_maintenance_ops *state_renewal_ops;
	const struct nfs4_mig_recovery_ops *mig_recovery_ops;
};

struct nfs4_slot_table {
	struct nfs4_session *session;
	struct nfs4_slot *slots;
	long unsigned int used_slots[16];
	spinlock_t slot_tbl_lock;
	struct rpc_wait_queue slot_tbl_waitq;
	wait_queue_head_t slot_waitq;
	u32 max_slots;
	u32 max_slotid;
	u32 highest_used_slotid;
	u32 target_highest_slotid;
	u32 server_highest_slotid;
	s32 d_target_highest_slotid;
	s32 d2_target_highest_slotid;
	long unsigned int generation;
	struct completion complete;
	long unsigned int slot_tbl_state;
};

struct nfs4_session {
	struct nfs4_sessionid sess_id;
	u32 flags;
	long unsigned int session_state;
	u32 hash_alg;
	u32 ssv_len;
	struct nfs4_channel_attrs fc_attrs;
	struct nfs4_slot_table fc_slot_table;
	struct nfs4_channel_attrs bc_attrs;
	struct nfs4_slot_table bc_slot_table;
	struct nfs_client *clp;
};

struct nfs_iostats {
	long long unsigned int bytes[8];
	long unsigned int events[27];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct fscache_cache;

struct fscache_volume {
	refcount_t ref;
	atomic_t n_cookies;
	atomic_t n_accesses;
	unsigned int debug_id;
	unsigned int key_hash;
	u8 *key;
	struct list_head proc_link;
	struct hlist_bl_node hash_link;
	struct work_struct work;
	struct fscache_cache *cache;
	void *cache_priv;
	spinlock_t lock;
	long unsigned int flags;
	u8 coherency_len;
	u8 coherency[0];
};

enum pnfs_try_status {
	PNFS_ATTEMPTED = 0,
	PNFS_NOT_ATTEMPTED = 1,
	PNFS_TRY_AGAIN = 2,
};

struct nfs_pageio_ops;

struct nfs4_deviceid_node;

struct pnfs_layoutdriver_type {
	struct list_head pnfs_tblid;
	const u32 id;
	const char *name;
	struct module *owner;
	unsigned int flags;
	unsigned int max_layoutget_response;
	int (*set_layoutdriver)(struct nfs_server *, const struct nfs_fh *);
	int (*clear_layoutdriver)(struct nfs_server *);
	struct pnfs_layout_hdr * (*alloc_layout_hdr)(struct inode *, gfp_t);
	void (*free_layout_hdr)(struct pnfs_layout_hdr *);
	struct pnfs_layout_segment * (*alloc_lseg)(struct pnfs_layout_hdr *, struct nfs4_layoutget_res *, gfp_t);
	void (*free_lseg)(struct pnfs_layout_segment *);
	void (*add_lseg)(struct pnfs_layout_hdr *, struct pnfs_layout_segment *, struct list_head *);
	void (*return_range)(struct pnfs_layout_hdr *, struct pnfs_layout_range *);
	const struct nfs_pageio_ops *pg_read_ops;
	const struct nfs_pageio_ops *pg_write_ops;
	struct pnfs_ds_commit_info * (*get_ds_info)(struct inode *);
	int (*sync)(struct inode *, bool);
	enum pnfs_try_status (*read_pagelist)(struct nfs_pgio_header *);
	enum pnfs_try_status (*write_pagelist)(struct nfs_pgio_header *, int);
	void (*free_deviceid_node)(struct nfs4_deviceid_node *);
	struct nfs4_deviceid_node * (*alloc_deviceid_node)(struct nfs_server *, struct pnfs_device *, gfp_t);
	int (*prepare_layoutreturn)(struct nfs4_layoutreturn_args *);
	void (*cleanup_layoutcommit)(struct nfs4_layoutcommit_data *);
	int (*prepare_layoutcommit)(struct nfs4_layoutcommit_args *);
	int (*prepare_layoutstats)(struct nfs42_layoutstat_args *);
	void (*cancel_io)(struct pnfs_layout_segment *);
};

struct nfs4_state_owner;

struct nfs4_state {
	struct list_head open_states;
	struct list_head inode_states;
	struct list_head lock_states;
	struct nfs4_state_owner *owner;
	struct inode *inode;
	long unsigned int flags;
	spinlock_t state_lock;
	seqlock_t seqlock;
	nfs4_stateid stateid;
	nfs4_stateid open_stateid;
	unsigned int n_rdonly;
	unsigned int n_wronly;
	unsigned int n_rdwr;
	fmode_t state;
	refcount_t count;
	wait_queue_head_t waitq;
	struct callback_head callback_head;
};

struct nfs4_cached_acl;

struct nfs_delegation;

struct nfs4_xattr_cache;

struct nfs_inode {
	__u64 fileid;
	struct nfs_fh fh;
	long unsigned int flags;
	long unsigned int cache_validity;
	long unsigned int read_cache_jiffies;
	long unsigned int attrtimeo;
	long unsigned int attrtimeo_timestamp;
	long unsigned int attr_gencount;
	struct rb_root access_cache;
	struct list_head access_cache_entry_lru;
	struct list_head access_cache_inode_lru;
	union {
		struct {
			long unsigned int cache_change_attribute;
			__be32 cookieverf[2];
			struct rw_semaphore rmdir_sem;
		};
		struct {
			atomic_long_t nrequests;
			atomic_long_t redirtied_pages;
			struct nfs_mds_commit_info commit_info;
			struct mutex commit_mutex;
		};
	};
	struct list_head open_files;
	struct {
		int cnt;
		struct {
			u64 start;
			u64 end;
		} gap[16];
	} *ooo;
	struct nfs4_cached_acl *nfs4_acl;
	struct list_head open_states;
	struct nfs_delegation *delegation;
	struct rw_semaphore rwsem;
	struct pnfs_layout_hdr *layout;
	__u64 write_io;
	__u64 read_io;
	struct nfs4_xattr_cache *xattr_cache;
	union {
		struct inode vfs_inode;
		struct netfs_inode netfs;
	};
};

struct nfs4_cached_acl {
	enum nfs4_acl_type type;
	int cached;
	size_t len;
	char data[0];
};

struct nfs_delegation {
	struct list_head super_list;
	const struct cred *cred;
	struct inode *inode;
	nfs4_stateid stateid;
	fmode_t type;
	long unsigned int pagemod_limit;
	__u64 change_attr;
	long unsigned int test_gen;
	long unsigned int flags;
	refcount_t refcount;
	spinlock_t lock;
	struct callback_head rcu;
};

struct nfs_pageio_descriptor;

struct nfs_pgio_mirror;

struct nfs_pageio_ops {
	void (*pg_init)(struct nfs_pageio_descriptor *, struct nfs_page *);
	size_t (*pg_test)(struct nfs_pageio_descriptor *, struct nfs_page *, struct nfs_page *);
	int (*pg_doio)(struct nfs_pageio_descriptor *);
	unsigned int (*pg_get_mirror_count)(struct nfs_pageio_descriptor *, struct nfs_page *);
	void (*pg_cleanup)(struct nfs_pageio_descriptor *);
	struct nfs_pgio_mirror * (*pg_get_mirror)(struct nfs_pageio_descriptor *, u32);
	u32 (*pg_set_mirror)(struct nfs_pageio_descriptor *, u32);
};

struct nfs_pgio_mirror {
	struct list_head pg_list;
	long unsigned int pg_bytes_written;
	size_t pg_count;
	size_t pg_bsize;
	unsigned int pg_base;
	unsigned char pg_recoalesce: 1;
};

struct nfs_pageio_descriptor {
	struct inode *pg_inode;
	const struct nfs_pageio_ops *pg_ops;
	const struct nfs_rw_ops *pg_rw_ops;
	int pg_ioflags;
	int pg_error;
	const struct rpc_call_ops *pg_rpc_callops;
	const struct nfs_pgio_completion_ops *pg_completion_ops;
	struct pnfs_layout_segment *pg_lseg;
	struct nfs_io_completion *pg_io_completion;
	struct nfs_direct_req *pg_dreq;
	void *pg_netfs;
	unsigned int pg_bsize;
	u32 pg_mirror_count;
	struct nfs_pgio_mirror *pg_mirrors;
	struct nfs_pgio_mirror pg_mirrors_static[1];
	struct nfs_pgio_mirror *pg_mirrors_dynamic;
	u32 pg_mirror_idx;
	short unsigned int pg_maxretrans;
	unsigned char pg_moreio: 1;
};

struct file_lock_operations {
	void (*fl_copy_lock)(struct file_lock *, struct file_lock *);
	void (*fl_release_private)(struct file_lock *);
};

struct lock_manager_operations {
	void *lm_mod_owner;
	fl_owner_t (*lm_get_owner)(fl_owner_t);
	void (*lm_put_owner)(fl_owner_t);
	void (*lm_notify)(struct file_lock *);
	int (*lm_grant)(struct file_lock *, int);
	bool (*lm_lock_expirable)(struct file_lock *);
	void (*lm_expire_lock)();
};

struct lease_manager_operations {
	bool (*lm_break)(struct file_lease *);
	int (*lm_change)(struct file_lease *, int, struct list_head *);
	void (*lm_setup)(struct file_lease *, void **);
	bool (*lm_breaker_owns_lease)(struct file_lease *);
};

struct nfs_seqid_counter {
	ktime_t create_time;
	u64 owner_id;
	int flags;
	u32 counter;
	spinlock_t lock;
	struct list_head list;
	struct rpc_wait_queue wait;
};

struct nfs4_lock_state {
	struct list_head ls_locks;
	struct nfs4_state *ls_state;
	long unsigned int ls_flags;
	struct nfs_seqid_counter ls_seqid;
	nfs4_stateid ls_stateid;
	refcount_t ls_count;
	fl_owner_t ls_owner;
};

enum nfs4_client_state {
	NFS4CLNT_MANAGER_RUNNING = 0,
	NFS4CLNT_CHECK_LEASE = 1,
	NFS4CLNT_LEASE_EXPIRED = 2,
	NFS4CLNT_RECLAIM_REBOOT = 3,
	NFS4CLNT_RECLAIM_NOGRACE = 4,
	NFS4CLNT_DELEGRETURN = 5,
	NFS4CLNT_SESSION_RESET = 6,
	NFS4CLNT_LEASE_CONFIRM = 7,
	NFS4CLNT_SERVER_SCOPE_MISMATCH = 8,
	NFS4CLNT_PURGE_STATE = 9,
	NFS4CLNT_BIND_CONN_TO_SESSION = 10,
	NFS4CLNT_MOVED = 11,
	NFS4CLNT_LEASE_MOVED = 12,
	NFS4CLNT_DELEGATION_EXPIRED = 13,
	NFS4CLNT_RUN_MANAGER = 14,
	NFS4CLNT_MANAGER_AVAILABLE = 15,
	NFS4CLNT_RECALL_RUNNING = 16,
	NFS4CLNT_RECALL_ANY_LAYOUT_READ = 17,
	NFS4CLNT_RECALL_ANY_LAYOUT_RW = 18,
	NFS4CLNT_DELEGRETURN_DELAYED = 19,
};

struct nfs4_state_recovery_ops {
	int owner_flag_bit;
	int state_flag_bit;
	int (*recover_open)(struct nfs4_state_owner *, struct nfs4_state *);
	int (*recover_lock)(struct nfs4_state *, struct file_lock *);
	int (*establish_clid)(struct nfs_client *, const struct cred *);
	int (*reclaim_complete)(struct nfs_client *, const struct cred *);
	int (*detect_trunking)(struct nfs_client *, struct nfs_client **, const struct cred *);
};

struct nfs4_state_maintenance_ops {
	int (*sched_state_renewal)(struct nfs_client *, const struct cred *, unsigned int);
	const struct cred * (*get_state_renewal_cred)(struct nfs_client *);
	int (*renew_lease)(struct nfs_client *, const struct cred *);
};

struct nfs4_mig_recovery_ops {
	int (*get_locations)(struct nfs_server *, struct nfs_fh *, struct nfs4_fs_locations *, struct page *, const struct cred *);
	int (*fsid_present)(struct inode *, const struct cred *);
};

struct nfs4_state_owner {
	struct nfs_server *so_server;
	struct list_head so_lru;
	long unsigned int so_expires;
	struct rb_node so_server_node;
	const struct cred *so_cred;
	spinlock_t so_lock;
	atomic_t so_count;
	long unsigned int so_flags;
	struct list_head so_states;
	struct nfs_seqid_counter so_seqid;
	struct mutex so_delegreturn_mutex;
};

enum {
	NFS_OWNER_RECLAIM_REBOOT = 0,
	NFS_OWNER_RECLAIM_NOGRACE = 1,
};

enum {
	LK_STATE_IN_USE = 0,
	NFS_DELEGATED_STATE = 1,
	NFS_OPEN_STATE = 2,
	NFS_O_RDONLY_STATE = 3,
	NFS_O_WRONLY_STATE = 4,
	NFS_O_RDWR_STATE = 5,
	NFS_STATE_RECLAIM_REBOOT = 6,
	NFS_STATE_RECLAIM_NOGRACE = 7,
	NFS_STATE_POSIX_LOCKS = 8,
	NFS_STATE_RECOVERY_FAILED = 9,
	NFS_STATE_MAY_NOTIFY_LOCK = 10,
	NFS_STATE_CHANGE_WAIT = 11,
	NFS_CLNT_DST_SSC_COPY_STATE = 12,
	NFS_CLNT_SRC_SSC_COPY_STATE = 13,
	NFS_SRV_SSC_COPY_STATE = 14,
};

struct nfs4_exception {
	struct nfs4_state *state;
	struct inode *inode;
	nfs4_stateid *stateid;
	long int timeout;
	short unsigned int retrans;
	unsigned char task_is_privileged: 1;
	unsigned char delay: 1;
	unsigned char recovering: 1;
	unsigned char retry: 1;
	bool interruptible;
};

struct nfs4_opendata {
	struct kref kref;
	struct nfs_openargs o_arg;
	struct nfs_openres o_res;
	struct nfs_open_confirmargs c_arg;
	struct nfs_open_confirmres c_res;
	struct nfs4_string owner_name;
	struct nfs4_string group_name;
	struct nfs4_label *a_label;
	struct nfs_fattr f_attr;
	struct dentry *dir;
	struct dentry *dentry;
	struct nfs4_state_owner *owner;
	struct nfs4_state *state;
	struct iattr attrs;
	struct nfs4_layoutget *lgp;
	long unsigned int timestamp;
	bool rpc_done;
	bool file_created;
	bool is_recover;
	bool cancelled;
	int rpc_status;
};

struct nfs4_add_xprt_data {
	struct nfs_client *clp;
	const struct cred *cred;
};

struct svc_procedure;

struct svc_version {
	u32 vs_vers;
	u32 vs_nproc;
	const struct svc_procedure *vs_proc;
	long unsigned int *vs_count;
	u32 vs_xdrsize;
	bool vs_hidden;
	bool vs_rpcb_optnl;
	bool vs_need_cong_ctrl;
	int (*vs_dispatch)(struct svc_rqst *);
};

enum {
	NFS_DELEGATION_NEED_RECLAIM = 0,
	NFS_DELEGATION_RETURN = 1,
	NFS_DELEGATION_RETURN_IF_CLOSED = 2,
	NFS_DELEGATION_REFERENCED = 3,
	NFS_DELEGATION_RETURNING = 4,
	NFS_DELEGATION_REVOKED = 5,
	NFS_DELEGATION_TEST_EXPIRED = 6,
	NFS_DELEGATION_INODE_FREEING = 7,
	NFS_DELEGATION_RETURN_DELAYED = 8,
	NFS_DELEGATION_DELEGTIME = 9,
};

enum fs_value_type {
	fs_value_is_undefined = 0,
	fs_value_is_flag = 1,
	fs_value_is_string = 2,
	fs_value_is_blob = 3,
	fs_value_is_filename = 4,
	fs_value_is_file = 5,
};

struct fs_parameter {
	const char *key;
	enum fs_value_type type: 8;
	union {
		char *string;
		void *blob;
		struct filename *name;
		struct file *file;
	};
	size_t size;
	int dirfd;
};

struct fc_log {
	refcount_t usage;
	u8 head;
	u8 tail;
	u8 need_free;
	struct module *owner;
	char *buffer[8];
};

struct fs_context_operations {
	void (*free)(struct fs_context *);
	int (*dup)(struct fs_context *, struct fs_context *);
	int (*parse_param)(struct fs_context *, struct fs_parameter *);
	int (*parse_monolithic)(struct fs_context *, void *);
	int (*get_tree)(struct fs_context *);
	int (*reconfigure)(struct fs_context *);
};

enum nfs_stat_bytecounters {
	NFSIOS_NORMALREADBYTES = 0,
	NFSIOS_NORMALWRITTENBYTES = 1,
	NFSIOS_DIRECTREADBYTES = 2,
	NFSIOS_DIRECTWRITTENBYTES = 3,
	NFSIOS_SERVERREADBYTES = 4,
	NFSIOS_SERVERWRITTENBYTES = 5,
	NFSIOS_READPAGES = 6,
	NFSIOS_WRITEPAGES = 7,
	__NFSIOS_BYTESMAX = 8,
};

enum nfs_stat_eventcounters {
	NFSIOS_INODEREVALIDATE = 0,
	NFSIOS_DENTRYREVALIDATE = 1,
	NFSIOS_DATAINVALIDATE = 2,
	NFSIOS_ATTRINVALIDATE = 3,
	NFSIOS_VFSOPEN = 4,
	NFSIOS_VFSLOOKUP = 5,
	NFSIOS_VFSACCESS = 6,
	NFSIOS_VFSUPDATEPAGE = 7,
	NFSIOS_VFSREADPAGE = 8,
	NFSIOS_VFSREADPAGES = 9,
	NFSIOS_VFSWRITEPAGE = 10,
	NFSIOS_VFSWRITEPAGES = 11,
	NFSIOS_VFSGETDENTS = 12,
	NFSIOS_VFSSETATTR = 13,
	NFSIOS_VFSFLUSH = 14,
	NFSIOS_VFSFSYNC = 15,
	NFSIOS_VFSLOCK = 16,
	NFSIOS_VFSRELEASE = 17,
	NFSIOS_CONGESTIONWAIT = 18,
	NFSIOS_SETATTRTRUNC = 19,
	NFSIOS_EXTENDWRITE = 20,
	NFSIOS_SILLYRENAME = 21,
	NFSIOS_SHORTREAD = 22,
	NFSIOS_SHORTWRITE = 23,
	NFSIOS_DELAY = 24,
	NFSIOS_PNFS_READ = 25,
	NFSIOS_PNFS_WRITE = 26,
	__NFSIOS_COUNTSMAX = 27,
};

struct cache_head {
	struct hlist_node cache_list;
	time64_t expiry_time;
	time64_t last_refresh;
	struct kref ref;
	long unsigned int flags;
};

struct cache_detail {
	struct module *owner;
	int hash_size;
	struct hlist_head *hash_table;
	spinlock_t hash_lock;
	char *name;
	void (*cache_put)(struct kref *);
	int (*cache_upcall)(struct cache_detail *, struct cache_head *);
	void (*cache_request)(struct cache_detail *, struct cache_head *, char **, int *);
	int (*cache_parse)(struct cache_detail *, char *, int);
	int (*cache_show)(struct seq_file *, struct cache_detail *, struct cache_head *);
	void (*warn_no_listener)(struct cache_detail *, int);
	struct cache_head * (*alloc)();
	void (*flush)();
	int (*match)(struct cache_head *, struct cache_head *);
	void (*init)(struct cache_head *, struct cache_head *);
	void (*update)(struct cache_head *, struct cache_head *);
	time64_t flush_time;
	struct list_head others;
	time64_t nextcheck;
	int entries;
	struct list_head queue;
	atomic_t writers;
	time64_t last_close;
	time64_t last_warn;
	union {
		struct proc_dir_entry *procfs;
		struct dentry *pipefs;
	};
	struct net *net;
};

struct cache_deferred_req;

struct cache_req {
	struct cache_deferred_req * (*defer)(struct cache_req *);
	long unsigned int thread_wait;
};

struct cache_deferred_req {
	struct hlist_node hash;
	struct list_head recent;
	struct cache_head *item;
	void *owner;
	void (*revisit)(struct cache_deferred_req *, int);
};

struct svc_cred {
	kuid_t cr_uid;
	kgid_t cr_gid;
	struct group_info *cr_group_info;
	u32 cr_flavor;
	char *cr_raw_principal;
	char *cr_principal;
	char *cr_targ_princ;
	struct gss_api_mech *cr_gss_mech;
};

struct auth_ops {
	char *name;
	struct module *owner;
	int flavour;
	enum svc_auth_status (*accept)(struct svc_rqst *);
	int (*release)(struct svc_rqst *);
	void (*domain_release)(struct auth_domain *);
	enum svc_auth_status (*set_client)(struct svc_rqst *);
	rpc_authflavor_t (*pseudoflavor)(struct svc_rqst *);
};

struct svc_deferred_req;

struct svc_rqst {
	struct list_head rq_all;
	struct llist_node rq_idle;
	struct callback_head rq_rcu_head;
	struct svc_xprt *rq_xprt;
	struct __kernel_sockaddr_storage rq_addr;
	size_t rq_addrlen;
	struct __kernel_sockaddr_storage rq_daddr;
	size_t rq_daddrlen;
	struct svc_serv *rq_server;
	struct svc_pool *rq_pool;
	const struct svc_procedure *rq_procinfo;
	struct auth_ops *rq_authop;
	struct svc_cred rq_cred;
	void *rq_xprt_ctxt;
	struct svc_deferred_req *rq_deferred;
	struct xdr_buf rq_arg;
	struct xdr_stream rq_arg_stream;
	struct xdr_stream rq_res_stream;
	struct page *rq_scratch_page;
	struct xdr_buf rq_res;
	struct page *rq_pages[260];
	struct page **rq_respages;
	struct page **rq_next_page;
	struct page **rq_page_end;
	struct folio_batch rq_fbatch;
	struct kvec rq_vec[259];
	struct bio_vec rq_bvec[259];
	__be32 rq_xid;
	u32 rq_prog;
	u32 rq_vers;
	u32 rq_proc;
	u32 rq_prot;
	int rq_cachetype;
	long unsigned int rq_flags;
	ktime_t rq_qtime;
	void *rq_argp;
	void *rq_resp;
	__be32 *rq_accept_statp;
	void *rq_auth_data;
	__be32 rq_auth_stat;
	int rq_auth_slack;
	int rq_reserved;
	ktime_t rq_stime;
	struct cache_req rq_chandle;
	struct auth_domain *rq_client;
	struct auth_domain *rq_gssclient;
	struct task_struct *rq_task;
	struct net *rq_bc_net;
	int rq_err;
	long unsigned int bc_to_initval;
	unsigned int bc_to_retries;
	void **rq_lease_breaker;
	unsigned int rq_status_counter;
};

struct svc_pool {
	unsigned int sp_id;
	struct lwq sp_xprts;
	unsigned int sp_nrthreads;
	struct list_head sp_all_threads;
	struct llist_head sp_idle_threads;
	struct percpu_counter sp_messages_arrived;
	struct percpu_counter sp_sockets_queued;
	struct percpu_counter sp_threads_woken;
	long unsigned int sp_flags;
};

struct svc_procedure {
	__be32 (*pc_func)(struct svc_rqst *);
	bool (*pc_decode)(struct svc_rqst *, struct xdr_stream *);
	bool (*pc_encode)(struct svc_rqst *, struct xdr_stream *);
	void (*pc_release)(struct svc_rqst *);
	unsigned int pc_argsize;
	unsigned int pc_argzero;
	unsigned int pc_ressize;
	unsigned int pc_cachetype;
	unsigned int pc_xdrressize;
	const char *pc_name;
};

struct svc_deferred_req {
	u32 prot;
	struct svc_xprt *xprt;
	struct __kernel_sockaddr_storage addr;
	size_t addrlen;
	struct __kernel_sockaddr_storage daddr;
	size_t daddrlen;
	void *xprt_ctxt;
	struct cache_deferred_req handle;
	int argslen;
	__be32 args[0];
};

struct svc_process_info {
	union {
		int (*dispatch)(struct svc_rqst *);
		struct {
			unsigned int lovers;
			unsigned int hivers;
		} mismatch;
	};
};

struct cb_notify_lock_args {
	struct nfs_fh cbnl_fh;
	struct nfs_lowner cbnl_owner;
	bool cbnl_valid;
};

enum {
	NFS_LAYOUT_RO_FAILED = 0,
	NFS_LAYOUT_RW_FAILED = 1,
	NFS_LAYOUT_BULK_RECALL = 2,
	NFS_LAYOUT_RETURN = 3,
	NFS_LAYOUT_RETURN_LOCK = 4,
	NFS_LAYOUT_RETURN_REQUESTED = 5,
	NFS_LAYOUT_INVALID_STID = 6,
	NFS_LAYOUT_FIRST_LAYOUTGET = 7,
	NFS_LAYOUT_INODE_FREEING = 8,
	NFS_LAYOUT_HASHED = 9,
	NFS_LAYOUT_DRAIN = 10,
};

enum layoutdriver_policy_flags {
	PNFS_LAYOUTRET_ON_SETATTR = 1,
	PNFS_LAYOUTRET_ON_ERROR = 2,
	PNFS_READ_WHOLE_PAGE = 4,
	PNFS_LAYOUTGET_ON_OPEN = 8,
};

struct nfs4_deviceid_node {
	struct hlist_node node;
	struct hlist_node tmpnode;
	const struct pnfs_layoutdriver_type *ld;
	const struct nfs_client *nfs_client;
	long unsigned int flags;
	long unsigned int timestamp_unavailable;
	struct nfs4_deviceid deviceid;
	struct callback_head rcu;
	atomic_t ref;
};

struct bl_dev_msg {
	int32_t status;
	uint32_t major;
	uint32_t minor;
};

struct nfs_netns_client;

struct nfs_net {
	struct cache_detail *nfs_dns_resolve;
	struct rpc_pipe *bl_device_pipe;
	struct bl_dev_msg bl_mount_reply;
	wait_queue_head_t bl_wq;
	struct mutex bl_mutex;
	struct list_head nfs_client_list;
	struct list_head nfs_volume_list;
	struct idr cb_ident_idr;
	short unsigned int nfs_callback_tcpport;
	short unsigned int nfs_callback_tcpport6;
	int cb_users[3];
	struct nfs_netns_client *nfs_client;
	spinlock_t nfs_client_lock;
	ktime_t boot_time;
	struct rpc_stat rpcstats;
	struct proc_dir_entry *proc_nfsfs;
};

struct nfs_netns_client {
	struct kobject kobject;
	struct kobject nfs_net_kobj;
	struct net *net;
	const char *identifier;
};

enum nfs4_slot_tbl_state {
	NFS4_SLOT_TBL_DRAINING = 0,
};

enum nfs4_session_state {
	NFS4_SESSION_INITING = 0,
	NFS4_SESSION_ESTABLISHED = 1,
};

struct swap_cluster_info {
	spinlock_t lock;
	u16 count;
	u8 flags;
	u8 order;
	struct list_head list;
};

struct percpu_cluster {
	unsigned int next[10];
};

struct nfs4_call_sync_data {
	const struct nfs_server *seq_server;
	struct nfs4_sequence_args *seq_args;
	struct nfs4_sequence_res *seq_res;
};

struct nfs4_open_createattrs {
	struct nfs4_label *label;
	struct iattr *sattr;
	const __u32 verf[2];
};

struct nfs4_closedata {
	struct inode *inode;
	struct nfs4_state *state;
	struct nfs_closeargs arg;
	struct nfs_closeres res;
	struct {
		struct nfs4_layoutreturn_args arg;
		struct nfs4_layoutreturn_res res;
		struct nfs4_xdr_opaque_data ld_private;
		u32 roc_barrier;
		bool roc;
	} lr;
	struct nfs_fattr fattr;
	long unsigned int timestamp;
};

struct nfs4_createdata {
	struct rpc_message msg;
	struct nfs4_create_arg arg;
	struct nfs4_create_res res;
	struct nfs_fh fh;
	struct nfs_fattr fattr;
};

struct nfs4_renewdata {
	struct nfs_client *client;
	long unsigned int timestamp;
};

struct nfs4_delegreturndata {
	struct nfs4_delegreturnargs args;
	struct nfs4_delegreturnres res;
	struct nfs_fh fh;
	nfs4_stateid stateid;
	long unsigned int timestamp;
	struct {
		struct nfs4_layoutreturn_args arg;
		struct nfs4_layoutreturn_res res;
		struct nfs4_xdr_opaque_data ld_private;
		u32 roc_barrier;
		bool roc;
	} lr;
	struct nfs4_delegattr sattr;
	struct nfs_fattr fattr;
	int rpc_status;
	struct inode *inode;
};

struct nfs4_unlockdata {
	struct nfs_locku_args arg;
	struct nfs_locku_res res;
	struct nfs4_lock_state *lsp;
	struct nfs_open_context *ctx;
	struct nfs_lock_context *l_ctx;
	struct file_lock fl;
	struct nfs_server *server;
	long unsigned int timestamp;
};

struct nfs4_lockdata {
	struct nfs_lock_args arg;
	struct nfs_lock_res res;
	struct nfs4_lock_state *lsp;
	struct nfs_open_context *ctx;
	struct file_lock fl;
	long unsigned int timestamp;
	int rpc_status;
	int cancelled;
	struct nfs_server *server;
};

struct nfs4_lock_waiter {
	struct inode *inode;
	struct nfs_lowner owner;
	wait_queue_entry_t wait;
};

struct nfs_release_lockowner_data {
	struct nfs4_lock_state *lsp;
	struct nfs_server *server;
	struct nfs_release_lockowner_args args;
	struct nfs_release_lockowner_res res;
	long unsigned int timestamp;
};

struct rpc_bind_conn_calldata {
	struct nfs_client *clp;
	const struct cred *cred;
};

struct nfs41_exchange_id_data {
	struct nfs41_exchange_id_res res;
	struct nfs41_exchange_id_args args;
};

struct nfs4_get_lease_time_data {
	struct nfs4_get_lease_time_args *args;
	struct nfs4_get_lease_time_res *res;
	struct nfs_client *clp;
};

struct nfs4_sequence_data {
	struct nfs_client *clp;
	struct nfs4_sequence_args args;
	struct nfs4_sequence_res res;
};

struct nfs4_reclaim_complete_data {
	struct nfs_client *clp;
	struct nfs41_reclaim_complete_args arg;
	struct nfs41_reclaim_complete_res res;
};

struct nfs_free_stateid_data {
	struct nfs_server *server;
	struct nfs41_free_stateid_args args;
	struct nfs41_free_stateid_res res;
};

enum opentype4 {
	NFS4_OPEN_NOCREATE = 0,
	NFS4_OPEN_CREATE = 1,
};

enum limit_by4 {
	NFS4_LIMIT_SIZE = 1,
	NFS4_LIMIT_BLOCKS = 2,
};

enum why_no_delegation4 {
	WND4_NOT_WANTED = 0,
	WND4_CONTENTION = 1,
	WND4_RESOURCE = 2,
	WND4_NOT_SUPP_FTYPE = 3,
	WND4_WRITE_DELEG_NOT_SUPP_FTYPE = 4,
	WND4_NOT_SUPP_UPGRADE = 5,
	WND4_NOT_SUPP_DOWNGRADE = 6,
	WND4_CANCELLED = 7,
	WND4_IS_DIR = 8,
};

enum lock_type4 {
	NFS4_UNLOCK_LT = 0,
	NFS4_READ_LT = 1,
	NFS4_WRITE_LT = 2,
	NFS4_READW_LT = 3,
	NFS4_WRITEW_LT = 4,
};

enum pnfs_layoutreturn_type {
	RETURN_FILE = 1,
	RETURN_FSID = 2,
	RETURN_ALL = 3,
};

enum data_content4 {
	NFS4_CONTENT_DATA = 0,
	NFS4_CONTENT_HOLE = 1,
};

struct nfs42_netaddr {
	char netid[5];
	char addr[58];
	u32 netid_len;
	u32 addr_len;
};

enum netloc_type4 {
	NL4_NAME = 1,
	NL4_URL = 2,
	NL4_NETADDR = 3,
};

struct nl4_server {
	enum netloc_type4 nl4_type;
	union {
		struct {
			int nl4_str_sz;
			char nl4_str[1025];
		};
		struct nfs42_netaddr nl4_addr;
	} u;
};

enum nfs4_setxattr_options {
	SETXATTR4_EITHER = 0,
	SETXATTR4_CREATE = 1,
	SETXATTR4_REPLACE = 2,
};

struct nfs42_layoutstat_res {
	struct nfs4_sequence_res seq_res;
	int num_dev;
	int rpc_status;
};

struct nfs42_device_error {
	struct nfs4_deviceid dev_id;
	int status;
	enum nfs_opnum4 opnum;
};

struct nfs42_layout_error {
	__u64 offset;
	__u64 length;
	nfs4_stateid stateid;
	struct nfs42_device_error errors[1];
};

struct nfs42_layouterror_args {
	struct nfs4_sequence_args seq_args;
	struct inode *inode;
	unsigned int num_errors;
	struct nfs42_layout_error errors[5];
};

struct nfs42_layouterror_res {
	struct nfs4_sequence_res seq_res;
	unsigned int num_errors;
	int rpc_status;
};

struct nfs42_clone_args {
	struct nfs4_sequence_args seq_args;
	struct nfs_fh *src_fh;
	struct nfs_fh *dst_fh;
	nfs4_stateid src_stateid;
	nfs4_stateid dst_stateid;
	__u64 src_offset;
	__u64 dst_offset;
	__u64 count;
	const u32 *dst_bitmask;
};

struct nfs42_clone_res {
	struct nfs4_sequence_res seq_res;
	unsigned int rpc_status;
	struct nfs_fattr *dst_fattr;
	const struct nfs_server *server;
};

struct nfs42_falloc_args {
	struct nfs4_sequence_args seq_args;
	struct nfs_fh *falloc_fh;
	nfs4_stateid falloc_stateid;
	u64 falloc_offset;
	u64 falloc_length;
	const u32 *falloc_bitmask;
};

struct nfs42_falloc_res {
	struct nfs4_sequence_res seq_res;
	unsigned int status;
	struct nfs_fattr *falloc_fattr;
	const struct nfs_server *falloc_server;
};

struct nfs42_copy_args {
	struct nfs4_sequence_args seq_args;
	struct nfs_fh *src_fh;
	nfs4_stateid src_stateid;
	u64 src_pos;
	struct nfs_fh *dst_fh;
	nfs4_stateid dst_stateid;
	u64 dst_pos;
	u64 count;
	bool sync;
	struct nl4_server *cp_src;
};

struct nfs42_write_res {
	nfs4_stateid stateid;
	u64 count;
	struct nfs_writeverf verifier;
};

struct nfs42_copy_res {
	struct nfs4_sequence_res seq_res;
	struct nfs42_write_res write_res;
	bool consecutive;
	bool synchronous;
	struct nfs_commitres commit_res;
};

struct nfs42_offload_status_args {
	struct nfs4_sequence_args osa_seq_args;
	struct nfs_fh *osa_src_fh;
	nfs4_stateid osa_stateid;
};

struct nfs42_offload_status_res {
	struct nfs4_sequence_res osr_seq_res;
	uint64_t osr_count;
	int osr_status;
};

struct nfs42_copy_notify_args {
	struct nfs4_sequence_args cna_seq_args;
	struct nfs_fh *cna_src_fh;
	nfs4_stateid cna_src_stateid;
	struct nl4_server cna_dst;
};

struct nfs42_copy_notify_res {
	struct nfs4_sequence_res cnr_seq_res;
	struct nfstime4 cnr_lease_time;
	nfs4_stateid cnr_stateid;
	struct nl4_server cnr_src;
};

struct nfs42_seek_args {
	struct nfs4_sequence_args seq_args;
	struct nfs_fh *sa_fh;
	nfs4_stateid sa_stateid;
	u64 sa_offset;
	u32 sa_what;
};

struct nfs42_seek_res {
	struct nfs4_sequence_res seq_res;
	unsigned int status;
	u32 sr_eof;
	u64 sr_offset;
};

struct nfs42_setxattrargs {
	struct nfs4_sequence_args seq_args;
	struct nfs_fh *fh;
	const u32 *bitmask;
	const char *xattr_name;
	u32 xattr_flags;
	size_t xattr_len;
	struct page **xattr_pages;
};

struct nfs42_setxattrres {
	struct nfs4_sequence_res seq_res;
	struct nfs4_change_info cinfo;
	struct nfs_fattr *fattr;
	const struct nfs_server *server;
};

struct nfs42_getxattrargs {
	struct nfs4_sequence_args seq_args;
	struct nfs_fh *fh;
	const char *xattr_name;
	size_t xattr_len;
	struct page **xattr_pages;
};

struct nfs42_getxattrres {
	struct nfs4_sequence_res seq_res;
	size_t xattr_len;
};

struct nfs42_listxattrsargs {
	struct nfs4_sequence_args seq_args;
	struct nfs_fh *fh;
	u32 count;
	u64 cookie;
	struct page **xattr_pages;
};

struct nfs42_listxattrsres {
	struct nfs4_sequence_res seq_res;
	struct page *scratch;
	void *xattr_buf;
	size_t xattr_len;
	u64 cookie;
	bool eof;
	size_t copied;
};

struct nfs42_removexattrargs {
	struct nfs4_sequence_args seq_args;
	struct nfs_fh *fh;
	const char *xattr_name;
};

struct nfs42_removexattrres {
	struct nfs4_sequence_res seq_res;
	struct nfs4_change_info cinfo;
};

struct compound_hdr {
	int32_t status;
	uint32_t nops;
	__be32 *nops_p;
	uint32_t taglen;
	char *tag;
	uint32_t replen;
	u32 minorversion;
};

struct read_plus_segment {
	enum data_content4 type;
	uint64_t offset;
	union {
		struct {
			uint64_t length;
		} hole;
		struct {
			uint32_t length;
			unsigned int from;
		} data;
	};
};

struct wait_bit_key {
	void *flags;
	int bit_nr;
	long unsigned int timeout;
};

struct wait_bit_queue_entry {
	struct wait_bit_key key;
	struct wait_queue_entry wq_entry;
};

typedef int wait_bit_action_f(struct wait_bit_key *, int);

struct nfs4_copy_state {
	struct list_head copies;
	struct list_head src_copies;
	nfs4_stateid stateid;
	struct completion completion;
	uint64_t count;
	struct nfs_writeverf verf;
	int error;
	int flags;
	struct nfs4_state *parent_src_state;
	struct nfs4_state *parent_dst_state;
};

enum wq_misc_consts {
	WORK_NR_COLORS = 16,
	WORK_CPU_UNBOUND = 64,
	WORK_BUSY_PENDING = 1,
	WORK_BUSY_RUNNING = 2,
	WORKER_DESC_LEN = 32,
};

struct nfs_subversion {
	struct module *owner;
	struct file_system_type *nfs_fs;
	const struct rpc_version *rpc_vers;
	const struct nfs_rpc_ops *rpc_ops;
	const struct super_operations *sops;
	const struct xattr_handler * const *xattr;
	struct list_head list;
};

struct nfs_clone_mount {
	struct super_block *sb;
	struct dentry *dentry;
	struct nfs_fattr *fattr;
	unsigned int inherited_bsize;
};

struct nfs_fs_context {
	bool internal;
	bool skip_reconfig_option_check;
	bool need_mount;
	bool sloppy;
	unsigned int flags;
	unsigned int rsize;
	unsigned int wsize;
	unsigned int timeo;
	unsigned int retrans;
	unsigned int acregmin;
	unsigned int acregmax;
	unsigned int acdirmin;
	unsigned int acdirmax;
	unsigned int namlen;
	unsigned int options;
	unsigned int bsize;
	struct nfs_auth_info auth_info;
	rpc_authflavor_t selected_flavor;
	struct xprtsec_parms xprtsec;
	char *client_address;
	unsigned int version;
	unsigned int minorversion;
	char *fscache_uniq;
	short unsigned int protofamily;
	short unsigned int mountfamily;
	bool has_sec_mnt_opts;
	int lock_status;
	struct {
		union {
			struct sockaddr address;
			struct __kernel_sockaddr_storage _address;
		};
		size_t addrlen;
		char *hostname;
		u32 version;
		int port;
		short unsigned int protocol;
	} mount_server;
	struct {
		union {
			struct sockaddr address;
			struct __kernel_sockaddr_storage _address;
		};
		size_t addrlen;
		char *hostname;
		char *export_path;
		int port;
		short unsigned int protocol;
		short unsigned int nconnect;
		short unsigned int max_connect;
		short unsigned int export_path_len;
	} nfs_server;
	struct nfs_fh *mntfh;
	struct nfs_server *server;
	struct nfs_subversion *nfs_mod;
	struct nfs_clone_mount clone_data;
};

struct nfs_referral_count {
	struct list_head list;
	const struct task_struct *task;
	unsigned int referral_count;
};

struct watch_queue;

struct pipe_buffer;

struct pipe_inode_info {
	struct mutex mutex;
	wait_queue_head_t rd_wait;
	wait_queue_head_t wr_wait;
	unsigned int head;
	unsigned int tail;
	unsigned int max_usage;
	unsigned int ring_size;
	unsigned int nr_accounted;
	unsigned int readers;
	unsigned int writers;
	unsigned int files;
	unsigned int r_counter;
	unsigned int w_counter;
	bool poll_usage;
	bool note_loss;
	struct page *tmp_page;
	struct fasync_struct *fasync_readers;
	struct fasync_struct *fasync_writers;
	struct pipe_buffer *bufs;
	struct user_struct *user;
	struct watch_queue *watch_queue;
};

enum inode_i_mutex_lock_class {
	I_MUTEX_NORMAL = 0,
	I_MUTEX_PARENT = 1,
	I_MUTEX_CHILD = 2,
	I_MUTEX_XATTR = 3,
	I_MUTEX_NONDIR2 = 4,
	I_MUTEX_PARENT2 = 5,
};

struct nfs4_ssc_client_ops {
	struct file * (*sco_open)(struct vfsmount *, struct nfs_fh *, nfs4_stateid *);
	void (*sco_close)(struct file *);
};

struct pipe_buf_operations;

struct pipe_buffer {
	struct page *page;
	unsigned int offset;
	unsigned int len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	long unsigned int private;
};

struct pipe_buf_operations {
	int (*confirm)(struct pipe_inode_info *, struct pipe_buffer *);
	void (*release)(struct pipe_inode_info *, struct pipe_buffer *);
	bool (*try_steal)(struct pipe_inode_info *, struct pipe_buffer *);
	bool (*get)(struct pipe_inode_info *, struct pipe_buffer *);
};

struct match_token {
	int token;
	const char *pattern;
};

typedef struct {
	char *from;
	char *to;
} substring_t;

struct rpc_pipe_dir_object_ops;

struct rpc_pipe_dir_object {
	struct list_head pdo_head;
	const struct rpc_pipe_dir_object_ops *pdo_ops;
	void *pdo_data;
};

struct rpc_pipe_dir_object_ops {
	int (*create)(struct dentry *, struct rpc_pipe_dir_object *);
	void (*destroy)(struct dentry *, struct rpc_pipe_dir_object *);
};

struct rpc_inode {
	struct inode vfs_inode;
	void *private;
	struct rpc_pipe *pipe;
	wait_queue_head_t waitq;
};

struct idmap_legacy_upcalldata;

struct idmap {
	struct rpc_pipe_dir_object idmap_pdo;
	struct rpc_pipe *idmap_pipe;
	struct idmap_legacy_upcalldata *idmap_upcall_data;
	struct mutex idmap_mutex;
	struct user_namespace *user_ns;
};

struct kernel_pkey_query {
	__u32 supported_ops;
	__u32 key_size;
	__u16 max_data_size;
	__u16 max_sig_size;
	__u16 max_enc_size;
	__u16 max_dec_size;
};

enum kernel_pkey_operation {
	kernel_pkey_encrypt = 0,
	kernel_pkey_decrypt = 1,
	kernel_pkey_sign = 2,
	kernel_pkey_verify = 3,
};

struct kernel_pkey_params {
	struct key *key;
	const char *encoding;
	const char *hash_algo;
	char *info;
	__u32 in_len;
	union {
		__u32 out_len;
		__u32 in2_len;
	};
	enum kernel_pkey_operation op: 8;
};

struct key_preparsed_payload {
	const char *orig_description;
	char *description;
	union key_payload payload;
	const void *data;
	size_t datalen;
	size_t quotalen;
	time64_t expiry;
};

struct key_match_data {
	bool (*cmp)(const struct key *, const struct key_match_data *);
	const void *raw_data;
	void *preparsed;
	unsigned int lookup_type;
};

struct user_key_payload {
	struct callback_head rcu;
	short unsigned int datalen;
	long: 0;
	char data[0];
};

struct request_key_auth {
	struct callback_head rcu;
	struct key *target_key;
	struct key *dest_keyring;
	const struct cred *cred;
	void *callout_info;
	size_t callout_len;
	pid_t pid;
	char op[8];
};

struct idmap_msg {
	__u8 im_type;
	__u8 im_conv;
	char im_name[128];
	__u32 im_id;
	__u8 im_status;
};

struct idmap_legacy_upcalldata {
	struct rpc_pipe_msg pipe_msg;
	struct idmap_msg idmap_msg;
	struct key *authkey;
	struct idmap *idmap;
};

enum {
	Opt_find_uid = 0,
	Opt_find_gid = 1,
	Opt_find_user = 2,
	Opt_find_group = 3,
	Opt_find_err = 4,
};

enum rpc_auth_stat {
	RPC_AUTH_OK = 0,
	RPC_AUTH_BADCRED = 1,
	RPC_AUTH_REJECTEDCRED = 2,
	RPC_AUTH_BADVERF = 3,
	RPC_AUTH_REJECTEDVERF = 4,
	RPC_AUTH_TOOWEAK = 5,
	RPCSEC_GSS_CREDPROBLEM = 13,
	RPCSEC_GSS_CTXPROBLEM = 14,
};

struct svc_xprt_class;

struct svc_xprt_ops;

struct svc_xprt {
	struct svc_xprt_class *xpt_class;
	const struct svc_xprt_ops *xpt_ops;
	struct kref xpt_ref;
	struct list_head xpt_list;
	struct lwq_node xpt_ready;
	long unsigned int xpt_flags;
	struct svc_serv *xpt_server;
	atomic_t xpt_reserved;
	atomic_t xpt_nr_rqsts;
	struct mutex xpt_mutex;
	spinlock_t xpt_lock;
	void *xpt_auth_cache;
	struct list_head xpt_deferred;
	struct __kernel_sockaddr_storage xpt_local;
	size_t xpt_locallen;
	struct __kernel_sockaddr_storage xpt_remote;
	size_t xpt_remotelen;
	char xpt_remotebuf[58];
	struct list_head xpt_users;
	struct net *xpt_net;
	netns_tracker ns_tracker;
	const struct cred *xpt_cred;
	struct rpc_xprt *xpt_bc_xprt;
	struct rpc_xprt_switch *xpt_bc_xps;
};

enum {
	SP_TASK_PENDING = 0,
	SP_NEED_VICTIM = 1,
	SP_VICTIM_REMAINS = 2,
};

enum {
	RQ_SECURE = 0,
	RQ_LOCAL = 1,
	RQ_USEDEFERRAL = 2,
	RQ_DROPME = 3,
	RQ_VICTIM = 4,
	RQ_DATA = 5,
};

struct svc_xprt_ops {
	struct svc_xprt * (*xpo_create)(struct svc_serv *, struct net *, struct sockaddr *, int, int);
	struct svc_xprt * (*xpo_accept)(struct svc_xprt *);
	int (*xpo_has_wspace)(struct svc_xprt *);
	int (*xpo_recvfrom)(struct svc_rqst *);
	int (*xpo_sendto)(struct svc_rqst *);
	int (*xpo_result_payload)(struct svc_rqst *, unsigned int, unsigned int);
	void (*xpo_release_ctxt)(struct svc_xprt *, void *);
	void (*xpo_detach)(struct svc_xprt *);
	void (*xpo_free)(struct svc_xprt *);
	void (*xpo_kill_temp_xprt)(struct svc_xprt *);
	void (*xpo_handshake)(struct svc_xprt *);
};

struct svc_xprt_class {
	const char *xcl_name;
	struct module *xcl_owner;
	const struct svc_xprt_ops *xcl_ops;
	struct list_head xcl_list;
	u32 xcl_max_payload;
	int xcl_ident;
};

enum nfs4_callback_procnum {
	CB_NULL = 0,
	CB_COMPOUND = 1,
};

struct nfs_callback_data {
	unsigned int users;
	struct svc_serv *serv;
};

enum rpc_accept_stat {
	RPC_SUCCESS = 0,
	RPC_PROG_UNAVAIL = 1,
	RPC_PROG_MISMATCH = 2,
	RPC_PROC_UNAVAIL = 3,
	RPC_GARBAGE_ARGS = 4,
	RPC_SYSTEM_ERR = 5,
	RPC_DROP_REPLY = 60000,
};

enum nfs_cb_opnum4 {
	OP_CB_GETATTR = 3,
	OP_CB_RECALL = 4,
	OP_CB_LAYOUTRECALL = 5,
	OP_CB_NOTIFY = 6,
	OP_CB_PUSH_DELEG = 7,
	OP_CB_RECALL_ANY = 8,
	OP_CB_RECALLABLE_OBJ_AVAIL = 9,
	OP_CB_RECALL_SLOT = 10,
	OP_CB_SEQUENCE = 11,
	OP_CB_WANTS_CANCELLED = 12,
	OP_CB_NOTIFY_LOCK = 13,
	OP_CB_NOTIFY_DEVICEID = 14,
	OP_CB_OFFLOAD = 15,
	OP_CB_ILLEGAL = 10044,
};

struct cb_process_state {
	struct nfs_client *clp;
	struct nfs4_slot *slot;
	struct net *net;
	u32 minorversion;
	__be32 drc_status;
	unsigned int referring_calls;
};

struct cb_compound_hdr_arg {
	unsigned int taglen;
	const char *tag;
	unsigned int minorversion;
	unsigned int cb_ident;
	unsigned int nops;
};

struct cb_compound_hdr_res {
	__be32 *status;
	unsigned int taglen;
	const char *tag;
	__be32 *nops;
};

struct cb_getattrargs {
	struct nfs_fh fh;
	uint32_t bitmap[3];
};

struct cb_getattrres {
	__be32 status;
	uint32_t bitmap[3];
	uint64_t size;
	uint64_t change_attr;
	struct timespec64 atime;
	struct timespec64 ctime;
	struct timespec64 mtime;
};

struct cb_recallargs {
	struct nfs_fh fh;
	nfs4_stateid stateid;
	uint32_t truncate;
};

struct referring_call {
	uint32_t rc_sequenceid;
	uint32_t rc_slotid;
};

struct referring_call_list {
	struct nfs4_sessionid rcl_sessionid;
	uint32_t rcl_nrefcalls;
	struct referring_call *rcl_refcalls;
};

struct cb_sequenceargs {
	struct sockaddr *csa_addr;
	struct nfs4_sessionid csa_sessionid;
	uint32_t csa_sequenceid;
	uint32_t csa_slotid;
	uint32_t csa_highestslotid;
	uint32_t csa_cachethis;
	uint32_t csa_nrclists;
	struct referring_call_list *csa_rclists;
};

struct cb_sequenceres {
	__be32 csr_status;
	struct nfs4_sessionid csr_sessionid;
	uint32_t csr_sequenceid;
	uint32_t csr_slotid;
	uint32_t csr_highestslotid;
	uint32_t csr_target_highestslotid;
};

struct cb_recallanyargs {
	uint32_t craa_objs_to_keep;
	uint32_t craa_type_mask;
};

struct cb_recallslotargs {
	uint32_t crsa_target_highest_slotid;
};

struct cb_layoutrecallargs {
	uint32_t cbl_recall_type;
	uint32_t cbl_layout_type;
	uint32_t cbl_layoutchanged;
	union {
		struct {
			struct nfs_fh cbl_fh;
			struct pnfs_layout_range cbl_range;
			nfs4_stateid cbl_stateid;
		};
		struct nfs_fsid cbl_fsid;
	};
};

struct cb_devicenotifyitem {
	uint32_t cbd_notify_type;
	uint32_t cbd_layout_type;
	struct nfs4_deviceid cbd_dev_id;
	uint32_t cbd_immediate;
};

struct cb_devicenotifyargs {
	uint32_t ndevs;
	struct cb_devicenotifyitem *devs;
};

struct cb_offloadargs {
	struct nfs_fh coa_fh;
	nfs4_stateid coa_stateid;
	uint32_t error;
	uint64_t wr_count;
	struct nfs_writeverf wr_writeverf;
};

struct callback_op {
	__be32 (*process_op)(void *, void *, struct cb_process_state *);
	__be32 (*decode_args)(struct svc_rqst *, struct xdr_stream *, void *);
	__be32 (*encode_res)(struct svc_rqst *, struct xdr_stream *, const void *);
	long int res_maxsize;
};

enum pnfs_layout_destroy_mode {
	PNFS_LAYOUT_INVALIDATE = 0,
	PNFS_LAYOUT_BULK_RETURN = 1,
	PNFS_LAYOUT_FILE_BULK_RETURN = 2,
};

typedef struct {
	int val[2];
} __kernel_fsid_t;

struct kstatfs {
	long int f_type;
	long int f_bsize;
	u64 f_blocks;
	u64 f_bfree;
	u64 f_bavail;
	u64 f_files;
	u64 f_ffree;
	__kernel_fsid_t f_fsid;
	long int f_namelen;
	long int f_frsize;
	long int f_flags;
	long int f_spare[4];
};

struct in_addr {
	__be32 s_addr;
};

struct sockaddr_in {
	__kernel_sa_family_t sin_family;
	__be16 sin_port;
	struct in_addr sin_addr;
	unsigned char __pad[8];
};

struct sockaddr_in6 {
	short unsigned int sin6_family;
	__be16 sin6_port;
	__be32 sin6_flowinfo;
	struct in6_addr sin6_addr;
	__u32 sin6_scope_id;
};

enum work_bits {
	WORK_STRUCT_PENDING_BIT = 0,
	WORK_STRUCT_INACTIVE_BIT = 1,
	WORK_STRUCT_PWQ_BIT = 2,
	WORK_STRUCT_LINKED_BIT = 3,
	WORK_STRUCT_FLAG_BITS = 4,
	WORK_STRUCT_COLOR_SHIFT = 4,
	WORK_STRUCT_COLOR_BITS = 4,
	WORK_STRUCT_PWQ_SHIFT = 8,
	WORK_OFFQ_FLAG_SHIFT = 4,
	WORK_OFFQ_BH_BIT = 4,
	WORK_OFFQ_FLAG_END = 5,
	WORK_OFFQ_FLAG_BITS = 1,
	WORK_OFFQ_DISABLE_SHIFT = 5,
	WORK_OFFQ_DISABLE_BITS = 16,
	WORK_OFFQ_POOL_SHIFT = 21,
	WORK_OFFQ_LEFT = 43,
	WORK_OFFQ_POOL_BITS = 31,
};

typedef struct {} local_lock_t;

struct xa_node {
	unsigned char shift;
	unsigned char offset;
	unsigned char count;
	unsigned char nr_values;
	struct xa_node *parent;
	struct xarray *array;
	union {
		struct list_head private_list;
		struct callback_head callback_head;
	};
	void *slots[64];
	union {
		long unsigned int tags[3];
		long unsigned int marks[3];
	};
};

struct radix_tree_preload {
	local_lock_t lock;
	unsigned int nr;
	struct xa_node *nodes;
};

enum xprt_transports {
	XPRT_TRANSPORT_UDP = 17,
	XPRT_TRANSPORT_TCP = 6,
	XPRT_TRANSPORT_BC_TCP = -2147483642,
	XPRT_TRANSPORT_RDMA = 256,
	XPRT_TRANSPORT_BC_RDMA = -2147483392,
	XPRT_TRANSPORT_LOCAL = 257,
	XPRT_TRANSPORT_TCP_TLS = 258,
};

struct nfs4_ds_server {
	struct list_head list;
	struct rpc_clnt *rpc_clnt;
};

enum pr_status {
	PR_STS_SUCCESS = 0,
	PR_STS_IOERR = 2,
	PR_STS_RESERVATION_CONFLICT = 24,
	PR_STS_RETRY_PATH_FAILURE = 917504,
	PR_STS_PATH_FAST_FAILED = 983040,
	PR_STS_PATH_FAILED = 65536,
};

typedef struct cpumask cpumask_var_t[1];

enum perf_event_state {
	PERF_EVENT_STATE_DEAD = -4,
	PERF_EVENT_STATE_EXIT = -3,
	PERF_EVENT_STATE_ERROR = -2,
	PERF_EVENT_STATE_OFF = -1,
	PERF_EVENT_STATE_INACTIVE = 0,
	PERF_EVENT_STATE_ACTIVE = 1,
};

struct perf_event_attr {
	__u32 type;
	__u32 size;
	__u64 config;
	union {
		__u64 sample_period;
		__u64 sample_freq;
	};
	__u64 sample_type;
	__u64 read_format;
	__u64 disabled: 1;
	__u64 inherit: 1;
	__u64 pinned: 1;
	__u64 exclusive: 1;
	__u64 exclude_user: 1;
	__u64 exclude_kernel: 1;
	__u64 exclude_hv: 1;
	__u64 exclude_idle: 1;
	__u64 mmap: 1;
	__u64 comm: 1;
	__u64 freq: 1;
	__u64 inherit_stat: 1;
	__u64 enable_on_exec: 1;
	__u64 task: 1;
	__u64 watermark: 1;
	__u64 precise_ip: 2;
	__u64 mmap_data: 1;
	__u64 sample_id_all: 1;
	__u64 exclude_host: 1;
	__u64 exclude_guest: 1;
	__u64 exclude_callchain_kernel: 1;
	__u64 exclude_callchain_user: 1;
	__u64 mmap2: 1;
	__u64 comm_exec: 1;
	__u64 use_clockid: 1;
	__u64 context_switch: 1;
	__u64 write_backward: 1;
	__u64 namespaces: 1;
	__u64 ksymbol: 1;
	__u64 bpf_event: 1;
	__u64 aux_output: 1;
	__u64 cgroup: 1;
	__u64 text_poke: 1;
	__u64 build_id: 1;
	__u64 inherit_thread: 1;
	__u64 remove_on_exec: 1;
	__u64 sigtrap: 1;
	__u64 __reserved_1: 26;
	union {
		__u32 wakeup_events;
		__u32 wakeup_watermark;
	};
	__u32 bp_type;
	union {
		__u64 bp_addr;
		__u64 kprobe_func;
		__u64 uprobe_path;
		__u64 config1;
	};
	union {
		__u64 bp_len;
		__u64 kprobe_addr;
		__u64 probe_offset;
		__u64 config2;
	};
	__u64 branch_sample_type;
	__u64 sample_regs_user;
	__u32 sample_stack_user;
	__s32 clockid;
	__u64 sample_regs_intr;
	__u32 aux_watermark;
	__u16 sample_max_stack;
	__u16 __reserved_2;
	__u32 aux_sample_size;
	union {
		__u32 aux_action;
		struct {
			__u32 aux_start_paused: 1;
			__u32 aux_pause: 1;
			__u32 aux_resume: 1;
			__u32 __reserved_3: 29;
		};
	};
	__u64 sig_data;
	__u64 config3;
};

struct hw_perf_event_extra {
	u64 config;
	unsigned int reg;
	int alloc;
	int idx;
};

struct arch_hw_breakpoint {
	long unsigned int address;
	long unsigned int mask;
	u8 len;
	u8 type;
};

struct rhlist_head {
	struct rhash_head rhead;
	struct rhlist_head *next;
};

struct hw_perf_event {
	union {
		struct {
			u64 config;
			u64 last_tag;
			long unsigned int config_base;
			long unsigned int event_base;
			int event_base_rdpmc;
			int idx;
			int last_cpu;
			int flags;
			struct hw_perf_event_extra extra_reg;
			struct hw_perf_event_extra branch_reg;
		};
		struct {
			u64 aux_config;
			unsigned int aux_paused;
		};
		struct {
			struct hrtimer hrtimer;
		};
		struct {
			struct list_head tp_list;
		};
		struct {
			u64 pwr_acc;
			u64 ptsc;
		};
		struct {
			struct arch_hw_breakpoint info;
			struct rhlist_head bp_list;
		};
		struct {
			u8 iommu_bank;
			u8 iommu_cntr;
			u16 padding;
			u64 conf;
			u64 conf1;
		};
	};
	struct task_struct *target;
	void *addr_filters;
	long unsigned int addr_filters_gen;
	int state;
	local64_t prev_count;
	u64 sample_period;
	union {
		struct {
			u64 last_period;
			local64_t period_left;
		};
		struct {
			u64 saved_metric;
			u64 saved_slots;
		};
	};
	u64 interrupts_seq;
	u64 interrupts;
	u64 freq_time_stamp;
	u64 freq_count_stamp;
};

struct perf_buffer;

struct irq_work {
	struct __call_single_node node;
	void (*func)(struct irq_work *);
	struct rcuwait irqwait;
};

struct perf_addr_filters_head {
	struct list_head list;
	raw_spinlock_t lock;
	unsigned int nr_file_filters;
};

struct perf_sample_data;

typedef void (*perf_overflow_handler_t)(struct perf_event *, struct perf_sample_data *, struct pt_regs *);

struct event_filter;

struct ftrace_regs;

typedef void (*ftrace_func_t)(long unsigned int, long unsigned int, struct ftrace_ops *, struct ftrace_regs *);

struct ftrace_hash;

struct ftrace_ops_hash {
	struct ftrace_hash *notrace_hash;
	struct ftrace_hash *filter_hash;
	struct mutex regex_lock;
};

enum ftrace_ops_cmd {
	FTRACE_OPS_CMD_ENABLE_SHARE_IPMODIFY_SELF = 0,
	FTRACE_OPS_CMD_ENABLE_SHARE_IPMODIFY_PEER = 1,
	FTRACE_OPS_CMD_DISABLE_SHARE_IPMODIFY_PEER = 2,
};

typedef int (*ftrace_ops_func_t)(struct ftrace_ops *, enum ftrace_ops_cmd);

struct ftrace_ops {
	ftrace_func_t func;
	struct ftrace_ops *next;
	long unsigned int flags;
	void *private;
	ftrace_func_t saved_func;
	struct ftrace_ops_hash local_hash;
	struct ftrace_ops_hash *func_hash;
	struct ftrace_ops_hash old_hash;
	long unsigned int trampoline;
	long unsigned int trampoline_size;
	struct list_head list;
	struct list_head subop_list;
	ftrace_ops_func_t ops_func;
	struct ftrace_ops *managed;
	long unsigned int direct_call;
};

struct pmu;

struct perf_event_pmu_context;

struct perf_addr_filter_range;

struct perf_cgroup;

struct perf_event {
	struct list_head event_entry;
	struct list_head sibling_list;
	struct list_head active_list;
	struct rb_node group_node;
	u64 group_index;
	struct list_head migrate_entry;
	struct hlist_node hlist_entry;
	struct list_head active_entry;
	int nr_siblings;
	int event_caps;
	int group_caps;
	unsigned int group_generation;
	struct perf_event *group_leader;
	struct pmu *pmu;
	void *pmu_private;
	enum perf_event_state state;
	unsigned int attach_state;
	local64_t count;
	atomic64_t child_count;
	u64 total_time_enabled;
	u64 total_time_running;
	u64 tstamp;
	struct perf_event_attr attr;
	u16 header_size;
	u16 id_header_size;
	u16 read_size;
	struct hw_perf_event hw;
	struct perf_event_context *ctx;
	struct perf_event_pmu_context *pmu_ctx;
	atomic_long_t refcount;
	atomic64_t child_total_time_enabled;
	atomic64_t child_total_time_running;
	struct mutex child_mutex;
	struct list_head child_list;
	struct perf_event *parent;
	int oncpu;
	int cpu;
	struct list_head owner_entry;
	struct task_struct *owner;
	struct mutex mmap_mutex;
	atomic_t mmap_count;
	struct perf_buffer *rb;
	struct list_head rb_entry;
	long unsigned int rcu_batches;
	int rcu_pending;
	wait_queue_head_t waitq;
	struct fasync_struct *fasync;
	unsigned int pending_wakeup;
	unsigned int pending_kill;
	unsigned int pending_disable;
	long unsigned int pending_addr;
	struct irq_work pending_irq;
	struct irq_work pending_disable_irq;
	struct callback_head pending_task;
	unsigned int pending_work;
	atomic_t event_limit;
	struct perf_addr_filters_head addr_filters;
	struct perf_addr_filter_range *addr_filter_ranges;
	long unsigned int addr_filters_gen;
	struct perf_event *aux_event;
	void (*destroy)(struct perf_event *);
	struct callback_head callback_head;
	struct pid_namespace *ns;
	u64 id;
	atomic64_t lost_samples;
	u64 (*clock)();
	perf_overflow_handler_t overflow_handler;
	void *overflow_handler_context;
	struct bpf_prog *prog;
	u64 bpf_cookie;
	struct trace_event_call *tp_event;
	struct event_filter *filter;
	struct ftrace_ops ftrace_ops;
	struct perf_cgroup *cgrp;
	void *security;
	struct list_head sb_list;
	__u32 orig_type;
};

struct fs_pin;

struct pid_namespace {
	struct idr idr;
	struct callback_head rcu;
	unsigned int pid_allocated;
	struct task_struct *child_reaper;
	struct kmem_cache *pid_cachep;
	unsigned int level;
	struct pid_namespace *parent;
	struct fs_pin *bacct;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	int reboot;
	struct ns_common ns;
	int memfd_noexec_scope;
};

struct request;

struct rq_list {
	struct request *head;
	struct request *tail;
};

struct blk_plug {
	struct rq_list mq_list;
	struct rq_list cached_rqs;
	u64 cur_ktime;
	short unsigned int nr_ios;
	short unsigned int rq_count;
	bool multiple_queues;
	bool has_elevator;
	struct list_head cb_list;
};

struct perf_event_groups {
	struct rb_root tree;
	u64 index;
};

struct perf_event_context {
	raw_spinlock_t lock;
	struct mutex mutex;
	struct list_head pmu_ctx_list;
	struct perf_event_groups pinned_groups;
	struct perf_event_groups flexible_groups;
	struct list_head event_list;
	int nr_events;
	int nr_user;
	int is_active;
	int nr_task_data;
	int nr_stat;
	int nr_freq;
	int rotate_disable;
	refcount_t refcount;
	struct task_struct *task;
	u64 time;
	u64 timestamp;
	u64 timeoffset;
	struct perf_event_context *parent_ctx;
	u64 parent_gen;
	u64 generation;
	int pin_count;
	int nr_cgroups;
	struct callback_head callback_head;
	local_t nr_no_switch_fast;
};

struct timer_rand_state;

struct disk_events;

struct cdrom_device_info;

struct badblocks;

typedef unsigned int blk_mode_t;

struct block_device_operations;

struct blk_independent_access_ranges;

struct gendisk {
	int major;
	int first_minor;
	int minors;
	char disk_name[32];
	short unsigned int events;
	short unsigned int event_flags;
	struct xarray part_tbl;
	struct block_device *part0;
	const struct block_device_operations *fops;
	struct request_queue *queue;
	void *private_data;
	struct bio_set bio_split;
	int flags;
	long unsigned int state;
	struct mutex open_mutex;
	unsigned int open_partitions;
	struct backing_dev_info *bdi;
	struct kobject queue_kobj;
	struct kobject *slave_dir;
	struct list_head slave_bdevs;
	struct timer_rand_state *random;
	atomic_t sync_io;
	struct disk_events *ev;
	unsigned int nr_zones;
	unsigned int zone_capacity;
	unsigned int last_zone_capacity;
	long unsigned int *conv_zones_bitmap;
	unsigned int zone_wplugs_hash_bits;
	atomic_t nr_zone_wplugs;
	spinlock_t zone_wplugs_lock;
	struct mempool_s *zone_wplugs_pool;
	struct hlist_head *zone_wplugs_hash;
	struct workqueue_struct *zone_wplugs_wq;
	struct cdrom_device_info *cdi;
	int node_id;
	struct badblocks *bb;
	struct lockdep_map lockdep_map;
	u64 diskseq;
	blk_mode_t open_mode;
	struct blk_independent_access_ranges *ia_ranges;
};

struct trace_print_flags {
	long unsigned int mask;
	const char *name;
};

struct elevator_queue;

struct blk_mq_ops;

struct blk_mq_ctx;

typedef unsigned int blk_features_t;

typedef unsigned int blk_flags_t;

enum blk_integrity_checksum {
	BLK_INTEGRITY_CSUM_NONE = 0,
	BLK_INTEGRITY_CSUM_IP = 1,
	BLK_INTEGRITY_CSUM_CRC = 2,
	BLK_INTEGRITY_CSUM_CRC64 = 3,
} __attribute__((mode(byte)));

struct blk_integrity {
	unsigned char flags;
	enum blk_integrity_checksum csum_type;
	unsigned char tuple_size;
	unsigned char pi_offset;
	unsigned char interval_exp;
	unsigned char tag_size;
};

struct queue_limits {
	blk_features_t features;
	blk_flags_t flags;
	long unsigned int seg_boundary_mask;
	long unsigned int virt_boundary_mask;
	unsigned int max_hw_sectors;
	unsigned int max_dev_sectors;
	unsigned int chunk_sectors;
	unsigned int max_sectors;
	unsigned int max_user_sectors;
	unsigned int max_segment_size;
	unsigned int physical_block_size;
	unsigned int logical_block_size;
	unsigned int alignment_offset;
	unsigned int io_min;
	unsigned int io_opt;
	unsigned int max_discard_sectors;
	unsigned int max_hw_discard_sectors;
	unsigned int max_user_discard_sectors;
	unsigned int max_secure_erase_sectors;
	unsigned int max_write_zeroes_sectors;
	unsigned int max_zone_append_sectors;
	unsigned int discard_granularity;
	unsigned int discard_alignment;
	unsigned int zone_write_granularity;
	unsigned int atomic_write_hw_max;
	unsigned int atomic_write_max_sectors;
	unsigned int atomic_write_hw_boundary;
	unsigned int atomic_write_boundary_sectors;
	unsigned int atomic_write_hw_unit_min;
	unsigned int atomic_write_unit_min;
	unsigned int atomic_write_hw_unit_max;
	unsigned int atomic_write_unit_max;
	short unsigned int max_segments;
	short unsigned int max_integrity_segments;
	short unsigned int max_discard_segments;
	unsigned int max_open_zones;
	unsigned int max_active_zones;
	unsigned int dma_alignment;
	unsigned int dma_pad_mask;
	struct blk_integrity integrity;
};

struct blk_queue_stats;

struct rq_qos;

struct blk_crypto_profile;

struct blk_mq_tags;

struct blk_trace;

struct blk_flush_queue;

struct throtl_data;

struct blk_mq_tag_set;

struct request_queue {
	void *queuedata;
	struct elevator_queue *elevator;
	const struct blk_mq_ops *mq_ops;
	struct blk_mq_ctx *queue_ctx;
	long unsigned int queue_flags;
	unsigned int rq_timeout;
	unsigned int queue_depth;
	refcount_t refs;
	unsigned int nr_hw_queues;
	struct xarray hctx_table;
	struct percpu_ref q_usage_counter;
	struct lock_class_key io_lock_cls_key;
	struct lockdep_map io_lockdep_map;
	struct lock_class_key q_lock_cls_key;
	struct lockdep_map q_lockdep_map;
	struct request *last_merge;
	spinlock_t queue_lock;
	int quiesce_depth;
	struct gendisk *disk;
	struct kobject *mq_kobj;
	struct queue_limits limits;
	struct device *dev;
	enum rpm_status rpm_status;
	atomic_t pm_only;
	struct blk_queue_stats *stats;
	struct rq_qos *rq_qos;
	struct mutex rq_qos_mutex;
	int id;
	long unsigned int nr_requests;
	struct blk_crypto_profile *crypto_profile;
	struct kobject *crypto_kobject;
	struct timer_list timeout;
	struct work_struct timeout_work;
	atomic_t nr_active_requests_shared_tags;
	struct blk_mq_tags *sched_shared_tags;
	struct list_head icq_list;
	long unsigned int blkcg_pols[1];
	struct blkcg_gq *root_blkg;
	struct list_head blkg_list;
	struct mutex blkcg_mutex;
	int node;
	spinlock_t requeue_lock;
	struct list_head requeue_list;
	struct delayed_work requeue_work;
	struct blk_trace *blk_trace;
	struct blk_flush_queue *fq;
	struct list_head flush_list;
	struct mutex sysfs_lock;
	struct mutex sysfs_dir_lock;
	struct mutex limits_lock;
	struct list_head unused_hctx_list;
	spinlock_t unused_hctx_lock;
	int mq_freeze_depth;
	struct throtl_data *td;
	struct callback_head callback_head;
	wait_queue_head_t mq_freeze_wq;
	struct mutex mq_freeze_lock;
	struct blk_mq_tag_set *tag_set;
	struct list_head tag_set_list;
	struct dentry *debugfs_dir;
	struct dentry *sched_debugfs_dir;
	struct dentry *rqos_debugfs_dir;
	struct mutex debugfs_mutex;
	bool mq_sysfs_init_done;
};

struct io_comp_batch {
	struct rq_list req_list;
	bool need_ts;
	void (*complete)(struct io_comp_batch *);
};

struct trace_event_functions;

struct trace_event {
	struct hlist_node node;
	int type;
	struct trace_event_functions *funcs;
};

struct trace_event_class;

struct trace_event_call {
	struct list_head list;
	struct trace_event_class *class;
	union {
		const char *name;
		struct tracepoint *tp;
	};
	struct trace_event event;
	char *print_fmt;
	struct event_filter *filter;
	union {
		void *module;
		atomic_t refcnt;
	};
	void *data;
	int flags;
	int perf_refcount;
	struct hlist_head *perf_events;
	struct bpf_prog_array *prog_array;
	int (*perf_perm)(struct trace_event_call *, struct perf_event *);
};

struct partition_meta_info {
	char uuid[37];
	u8 volname[64];
};

struct blk_zone {
	__u64 start;
	__u64 len;
	__u64 wp;
	__u8 type;
	__u8 cond;
	__u8 non_seq;
	__u8 reset;
	__u8 resv[4];
	__u64 capacity;
	__u8 reserved[24];
};

struct hd_geometry;

typedef int (*report_zones_cb)(struct blk_zone *, unsigned int, void *);

enum blk_unique_id {
	BLK_UID_T10 = 1,
	BLK_UID_EUI64 = 2,
	BLK_UID_NAA = 3,
};

struct pr_ops;

struct block_device_operations {
	void (*submit_bio)(struct bio *);
	int (*poll_bio)(struct bio *, struct io_comp_batch *, unsigned int);
	int (*open)(struct gendisk *, blk_mode_t);
	void (*release)(struct gendisk *);
	int (*ioctl)(struct block_device *, blk_mode_t, unsigned int, long unsigned int);
	int (*compat_ioctl)(struct block_device *, blk_mode_t, unsigned int, long unsigned int);
	unsigned int (*check_events)(struct gendisk *, unsigned int);
	void (*unlock_native_capacity)(struct gendisk *);
	int (*getgeo)(struct block_device *, struct hd_geometry *);
	int (*set_read_only)(struct block_device *, bool);
	void (*free_disk)(struct gendisk *);
	void (*swap_slot_free_notify)(struct block_device *, long unsigned int);
	int (*report_zones)(struct gendisk *, sector_t, unsigned int, report_zones_cb, void *);
	char * (*devnode)(struct gendisk *, umode_t *);
	int (*get_unique_id)(struct gendisk *, u8 *, enum blk_unique_id);
	struct module *owner;
	const struct pr_ops *pr_ops;
	int (*alternative_gpt_sector)(struct gendisk *, sector_t *);
};

struct blk_independent_access_range {
	struct kobject kobj;
	sector_t sector;
	sector_t nr_sectors;
};

struct blk_independent_access_ranges {
	struct kobject kobj;
	bool sysfs_registered;
	unsigned int nr_ia_ranges;
	struct blk_independent_access_range ia_range[0];
};

enum bpf_link_type {
	BPF_LINK_TYPE_UNSPEC = 0,
	BPF_LINK_TYPE_RAW_TRACEPOINT = 1,
	BPF_LINK_TYPE_TRACING = 2,
	BPF_LINK_TYPE_CGROUP = 3,
	BPF_LINK_TYPE_ITER = 4,
	BPF_LINK_TYPE_NETNS = 5,
	BPF_LINK_TYPE_XDP = 6,
	BPF_LINK_TYPE_PERF_EVENT = 7,
	BPF_LINK_TYPE_KPROBE_MULTI = 8,
	BPF_LINK_TYPE_STRUCT_OPS = 9,
	BPF_LINK_TYPE_NETFILTER = 10,
	BPF_LINK_TYPE_TCX = 11,
	BPF_LINK_TYPE_UPROBE_MULTI = 12,
	BPF_LINK_TYPE_NETKIT = 13,
	BPF_LINK_TYPE_SOCKMAP = 14,
	__MAX_BPF_LINK_TYPE = 15,
};

struct bpf_link_info {
	__u32 type;
	__u32 id;
	__u32 prog_id;
	union {
		struct {
			__u64 tp_name;
			__u32 tp_name_len;
		} raw_tracepoint;
		struct {
			__u32 attach_type;
			__u32 target_obj_id;
			__u32 target_btf_id;
		} tracing;
		struct {
			__u64 cgroup_id;
			__u32 attach_type;
		} cgroup;
		struct {
			__u64 target_name;
			__u32 target_name_len;
			union {
				struct {
					__u32 map_id;
				} map;
			};
			union {
				struct {
					__u64 cgroup_id;
					__u32 order;
				} cgroup;
				struct {
					__u32 tid;
					__u32 pid;
				} task;
			};
		} iter;
		struct {
			__u32 netns_ino;
			__u32 attach_type;
		} netns;
		struct {
			__u32 ifindex;
		} xdp;
		struct {
			__u32 map_id;
		} struct_ops;
		struct {
			__u32 pf;
			__u32 hooknum;
			__s32 priority;
			__u32 flags;
		} netfilter;
		struct {
			__u64 addrs;
			__u32 count;
			__u32 flags;
			__u64 missed;
			__u64 cookies;
		} kprobe_multi;
		struct {
			__u64 path;
			__u64 offsets;
			__u64 ref_ctr_offsets;
			__u64 cookies;
			__u32 path_size;
			__u32 count;
			__u32 flags;
			__u32 pid;
		} uprobe_multi;
		struct {
			__u32 type;
			union {
				struct {
					__u64 file_name;
					__u32 name_len;
					__u32 offset;
					__u64 cookie;
				} uprobe;
				struct {
					__u64 func_name;
					__u32 name_len;
					__u32 offset;
					__u64 addr;
					__u64 missed;
					__u64 cookie;
				} kprobe;
				struct {
					__u64 tp_name;
					__u32 name_len;
					__u64 cookie;
				} tracepoint;
				struct {
					__u64 config;
					__u32 type;
					__u64 cookie;
				} event;
			};
		} perf_event;
		struct {
			__u32 ifindex;
			__u32 attach_type;
		} tcx;
		struct {
			__u32 ifindex;
			__u32 attach_type;
		} netkit;
		struct {
			__u32 map_id;
			__u32 attach_type;
		} sockmap;
	};
};

struct bpf_link_ops;

struct bpf_link {
	atomic64_t refcnt;
	u32 id;
	enum bpf_link_type type;
	const struct bpf_link_ops *ops;
	struct bpf_prog *prog;
	union {
		struct callback_head rcu;
		struct work_struct work;
	};
};

struct bpf_link_ops {
	void (*release)(struct bpf_link *);
	void (*dealloc)(struct bpf_link *);
	void (*dealloc_deferred)(struct bpf_link *);
	int (*detach)(struct bpf_link *);
	int (*update_prog)(struct bpf_link *, struct bpf_prog *, struct bpf_prog *);
	void (*show_fdinfo)(const struct bpf_link *, struct seq_file *);
	int (*fill_link_info)(const struct bpf_link *, struct bpf_link_info *);
	int (*update_map)(struct bpf_link *, struct bpf_map *, struct bpf_map *);
	__poll_t (*poll)(struct file *, struct poll_table_struct *);
};

struct bpf_raw_tp_link {
	struct bpf_link link;
	struct bpf_raw_event_map *btp;
	u64 cookie;
};

enum pnfs_update_layout_reason {
	PNFS_UPDATE_LAYOUT_UNKNOWN = 0,
	PNFS_UPDATE_LAYOUT_NO_PNFS = 1,
	PNFS_UPDATE_LAYOUT_RD_ZEROLEN = 2,
	PNFS_UPDATE_LAYOUT_MDSTHRESH = 3,
	PNFS_UPDATE_LAYOUT_NOMEM = 4,
	PNFS_UPDATE_LAYOUT_BULK_RECALL = 5,
	PNFS_UPDATE_LAYOUT_IO_TEST_FAIL = 6,
	PNFS_UPDATE_LAYOUT_FOUND_CACHED = 7,
	PNFS_UPDATE_LAYOUT_RETURN = 8,
	PNFS_UPDATE_LAYOUT_RETRY = 9,
	PNFS_UPDATE_LAYOUT_BLOCKED = 10,
	PNFS_UPDATE_LAYOUT_INVALID_OPEN = 11,
	PNFS_UPDATE_LAYOUT_SEND_LAYOUTGET = 12,
	PNFS_UPDATE_LAYOUT_EXIT = 13,
};

struct ring_buffer_event {
	u32 type_len: 5;
	u32 time_delta: 27;
	u32 array[0];
};

struct seq_buf {
	char *buffer;
	size_t size;
	size_t len;
};

struct trace_seq {
	char buffer[8156];
	struct seq_buf seq;
	size_t readpos;
	int full;
};

enum perf_sw_ids {
	PERF_COUNT_SW_CPU_CLOCK = 0,
	PERF_COUNT_SW_TASK_CLOCK = 1,
	PERF_COUNT_SW_PAGE_FAULTS = 2,
	PERF_COUNT_SW_CONTEXT_SWITCHES = 3,
	PERF_COUNT_SW_CPU_MIGRATIONS = 4,
	PERF_COUNT_SW_PAGE_FAULTS_MIN = 5,
	PERF_COUNT_SW_PAGE_FAULTS_MAJ = 6,
	PERF_COUNT_SW_ALIGNMENT_FAULTS = 7,
	PERF_COUNT_SW_EMULATION_FAULTS = 8,
	PERF_COUNT_SW_DUMMY = 9,
	PERF_COUNT_SW_BPF_OUTPUT = 10,
	PERF_COUNT_SW_CGROUP_SWITCHES = 11,
	PERF_COUNT_SW_MAX = 12,
};

enum perf_branch_sample_type_shift {
	PERF_SAMPLE_BRANCH_USER_SHIFT = 0,
	PERF_SAMPLE_BRANCH_KERNEL_SHIFT = 1,
	PERF_SAMPLE_BRANCH_HV_SHIFT = 2,
	PERF_SAMPLE_BRANCH_ANY_SHIFT = 3,
	PERF_SAMPLE_BRANCH_ANY_CALL_SHIFT = 4,
	PERF_SAMPLE_BRANCH_ANY_RETURN_SHIFT = 5,
	PERF_SAMPLE_BRANCH_IND_CALL_SHIFT = 6,
	PERF_SAMPLE_BRANCH_ABORT_TX_SHIFT = 7,
	PERF_SAMPLE_BRANCH_IN_TX_SHIFT = 8,
	PERF_SAMPLE_BRANCH_NO_TX_SHIFT = 9,
	PERF_SAMPLE_BRANCH_COND_SHIFT = 10,
	PERF_SAMPLE_BRANCH_CALL_STACK_SHIFT = 11,
	PERF_SAMPLE_BRANCH_IND_JUMP_SHIFT = 12,
	PERF_SAMPLE_BRANCH_CALL_SHIFT = 13,
	PERF_SAMPLE_BRANCH_NO_FLAGS_SHIFT = 14,
	PERF_SAMPLE_BRANCH_NO_CYCLES_SHIFT = 15,
	PERF_SAMPLE_BRANCH_TYPE_SAVE_SHIFT = 16,
	PERF_SAMPLE_BRANCH_HW_INDEX_SHIFT = 17,
	PERF_SAMPLE_BRANCH_PRIV_SAVE_SHIFT = 18,
	PERF_SAMPLE_BRANCH_COUNTERS_SHIFT = 19,
	PERF_SAMPLE_BRANCH_MAX_SHIFT = 20,
};

union perf_mem_data_src {
	__u64 val;
	struct {
		__u64 mem_op: 5;
		__u64 mem_lvl: 14;
		__u64 mem_snoop: 5;
		__u64 mem_lock: 2;
		__u64 mem_dtlb: 7;
		__u64 mem_lvl_num: 4;
		__u64 mem_remote: 1;
		__u64 mem_snoopx: 2;
		__u64 mem_blk: 3;
		__u64 mem_hops: 3;
		__u64 mem_rsvd: 18;
	};
};

struct perf_branch_entry {
	__u64 from;
	__u64 to;
	__u64 mispred: 1;
	__u64 predicted: 1;
	__u64 in_tx: 1;
	__u64 abort: 1;
	__u64 cycles: 16;
	__u64 type: 4;
	__u64 spec: 2;
	__u64 new_type: 4;
	__u64 priv: 3;
	__u64 reserved: 31;
};

union perf_sample_weight {
	__u64 full;
	struct {
		__u32 var1_dw;
		__u16 var2_w;
		__u16 var3_w;
	};
};

enum exception_stack_ordering {
	ESTACK_DF = 0,
	ESTACK_NMI = 1,
	ESTACK_DB = 2,
	ESTACK_MCE = 3,
	ESTACK_VC = 4,
	ESTACK_VC2 = 5,
	N_EXCEPTION_STACKS = 6,
};

struct perf_cpu_pmu_context;

struct perf_output_handle;

struct pmu {
	struct list_head entry;
	struct module *module;
	struct device *dev;
	struct device *parent;
	const struct attribute_group **attr_groups;
	const struct attribute_group **attr_update;
	const char *name;
	int type;
	int capabilities;
	unsigned int scope;
	int *pmu_disable_count;
	struct perf_cpu_pmu_context *cpu_pmu_context;
	atomic_t exclusive_cnt;
	int task_ctx_nr;
	int hrtimer_interval_ms;
	unsigned int nr_addr_filters;
	void (*pmu_enable)(struct pmu *);
	void (*pmu_disable)(struct pmu *);
	int (*event_init)(struct perf_event *);
	void (*event_mapped)(struct perf_event *, struct mm_struct *);
	void (*event_unmapped)(struct perf_event *, struct mm_struct *);
	int (*add)(struct perf_event *, int);
	void (*del)(struct perf_event *, int);
	void (*start)(struct perf_event *, int);
	void (*stop)(struct perf_event *, int);
	void (*read)(struct perf_event *);
	void (*start_txn)(struct pmu *, unsigned int);
	int (*commit_txn)(struct pmu *);
	void (*cancel_txn)(struct pmu *);
	int (*event_idx)(struct perf_event *);
	void (*sched_task)(struct perf_event_pmu_context *, bool);
	struct kmem_cache *task_ctx_cache;
	void (*swap_task_ctx)(struct perf_event_pmu_context *, struct perf_event_pmu_context *);
	void * (*setup_aux)(struct perf_event *, void **, int, bool);
	void (*free_aux)(void *);
	long int (*snapshot_aux)(struct perf_event *, struct perf_output_handle *, long unsigned int);
	int (*addr_filters_validate)(struct list_head *);
	void (*addr_filters_sync)(struct perf_event *);
	int (*aux_output_match)(struct perf_event *);
	bool (*filter)(struct pmu *, int);
	int (*check_period)(struct perf_event *, u64);
};

struct ftrace_regs {
	struct pt_regs regs;
};

struct perf_regs {
	__u64 abi;
	struct pt_regs *regs;
};

struct perf_callchain_entry {
	__u64 nr;
	__u64 ip[0];
};

typedef long unsigned int (*perf_copy_f)(void *, const void *, long unsigned int, long unsigned int);

struct perf_raw_frag {
	union {
		struct perf_raw_frag *next;
		long unsigned int pad;
	};
	perf_copy_f copy;
	void *data;
	u32 size;
} __attribute__((packed));

struct perf_raw_record {
	struct perf_raw_frag frag;
	u32 size;
};

struct perf_branch_stack {
	__u64 nr;
	__u64 hw_idx;
	struct perf_branch_entry entries[0];
};

struct perf_event_pmu_context {
	struct pmu *pmu;
	struct perf_event_context *ctx;
	struct list_head pmu_ctx_entry;
	struct list_head pinned_active;
	struct list_head flexible_active;
	unsigned int embedded: 1;
	unsigned int nr_events;
	unsigned int nr_cgroups;
	unsigned int nr_freq;
	atomic_t refcount;
	struct callback_head callback_head;
	void *task_ctx_data;
	int rotate_necessary;
};

struct perf_cpu_pmu_context {
	struct perf_event_pmu_context epc;
	struct perf_event_pmu_context *task_epc;
	struct list_head sched_cb_entry;
	int sched_cb_usage;
	int active_oncpu;
	int exclusive;
	raw_spinlock_t hrtimer_lock;
	struct hrtimer hrtimer;
	ktime_t hrtimer_interval;
	unsigned int hrtimer_active;
};

struct perf_output_handle {
	struct perf_event *event;
	struct perf_buffer *rb;
	long unsigned int wakeup;
	long unsigned int size;
	union {
		u64 flags;
		u64 aux_flags;
		struct {
			u64 skip_read: 1;
		};
	};
	union {
		void *addr;
		long unsigned int head;
	};
	int page;
};

struct perf_addr_filter_range {
	long unsigned int start;
	long unsigned int size;
};

struct perf_sample_data {
	u64 sample_flags;
	u64 period;
	u64 dyn_size;
	u64 type;
	struct {
		u32 pid;
		u32 tid;
	} tid_entry;
	u64 time;
	u64 id;
	struct {
		u32 cpu;
		u32 reserved;
	} cpu_entry;
	u64 ip;
	struct perf_callchain_entry *callchain;
	struct perf_raw_record *raw;
	struct perf_branch_stack *br_stack;
	u64 *br_stack_cntr;
	union perf_sample_weight weight;
	union perf_mem_data_src data_src;
	u64 txn;
	struct perf_regs regs_user;
	struct perf_regs regs_intr;
	u64 stack_user_size;
	u64 stream_id;
	u64 cgroup;
	u64 addr;
	u64 phys_addr;
	u64 data_page_size;
	u64 code_page_size;
	u64 aux_size;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct perf_cgroup_info;

struct perf_cgroup {
	struct cgroup_subsys_state css;
	struct perf_cgroup_info *info;
};

struct perf_cgroup_info {
	u64 time;
	u64 timestamp;
	u64 timeoffset;
	int active;
};

struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

struct trace_array;

struct tracer;

struct array_buffer;

struct ring_buffer_iter;

struct trace_iterator {
	struct trace_array *tr;
	struct tracer *trace;
	struct array_buffer *array_buffer;
	void *private;
	int cpu_file;
	struct mutex mutex;
	struct ring_buffer_iter **buffer_iter;
	long unsigned int iter_flags;
	void *temp;
	unsigned int temp_size;
	char *fmt;
	unsigned int fmt_size;
	atomic_t wait_index;
	struct trace_seq tmp_seq;
	cpumask_var_t started;
	bool closed;
	bool snapshot;
	struct trace_seq seq;
	struct trace_entry *ent;
	long unsigned int lost_events;
	int leftover;
	int ent_size;
	int cpu;
	u64 ts;
	loff_t pos;
	long int idx;
};

enum print_line_t {
	TRACE_TYPE_PARTIAL_LINE = 0,
	TRACE_TYPE_HANDLED = 1,
	TRACE_TYPE_UNHANDLED = 2,
	TRACE_TYPE_NO_CONSUME = 3,
};

typedef enum print_line_t (*trace_print_func)(struct trace_iterator *, int, struct trace_event *);

struct trace_event_functions {
	trace_print_func trace;
	trace_print_func raw;
	trace_print_func hex;
	trace_print_func binary;
};

enum trace_reg {
	TRACE_REG_REGISTER = 0,
	TRACE_REG_UNREGISTER = 1,
	TRACE_REG_PERF_REGISTER = 2,
	TRACE_REG_PERF_UNREGISTER = 3,
	TRACE_REG_PERF_OPEN = 4,
	TRACE_REG_PERF_CLOSE = 5,
	TRACE_REG_PERF_ADD = 6,
	TRACE_REG_PERF_DEL = 7,
};

struct trace_event_fields {
	const char *type;
	union {
		struct {
			const char *name;
			const int size;
			const int align;
			const unsigned int is_signed: 1;
			unsigned int needs_test: 1;
			const int filter_type;
			const int len;
		};
		int (*define_fields)(struct trace_event_call *);
	};
};

struct trace_event_class {
	const char *system;
	void *probe;
	void *perf_probe;
	int (*reg)(struct trace_event_call *, enum trace_reg, void *);
	struct trace_event_fields *fields_array;
	struct list_head * (*get_fields)(struct trace_event_call *);
	struct list_head fields;
	int (*raw_init)(struct trace_event_call *);
};

struct trace_buffer;

struct trace_event_file;

struct trace_event_buffer {
	struct trace_buffer *buffer;
	struct ring_buffer_event *event;
	struct trace_event_file *trace_file;
	void *entry;
	unsigned int trace_ctx;
	struct pt_regs *regs;
};

struct eventfs_inode;

struct trace_subsystem_dir;

struct trace_event_file {
	struct list_head list;
	struct trace_event_call *event_call;
	struct event_filter *filter;
	struct eventfs_inode *ei;
	struct trace_array *tr;
	struct trace_subsystem_dir *system;
	struct list_head triggers;
	long unsigned int flags;
	refcount_t ref;
	atomic_t sm_ref;
	atomic_t tm_ref;
};

enum {
	TRACE_EVENT_FL_FILTERED_BIT = 0,
	TRACE_EVENT_FL_CAP_ANY_BIT = 1,
	TRACE_EVENT_FL_NO_SET_FILTER_BIT = 2,
	TRACE_EVENT_FL_IGNORE_ENABLE_BIT = 3,
	TRACE_EVENT_FL_TRACEPOINT_BIT = 4,
	TRACE_EVENT_FL_DYNAMIC_BIT = 5,
	TRACE_EVENT_FL_KPROBE_BIT = 6,
	TRACE_EVENT_FL_UPROBE_BIT = 7,
	TRACE_EVENT_FL_EPROBE_BIT = 8,
	TRACE_EVENT_FL_FPROBE_BIT = 9,
	TRACE_EVENT_FL_CUSTOM_BIT = 10,
	TRACE_EVENT_FL_TEST_STR_BIT = 11,
};

enum {
	TRACE_EVENT_FL_FILTERED = 1,
	TRACE_EVENT_FL_CAP_ANY = 2,
	TRACE_EVENT_FL_NO_SET_FILTER = 4,
	TRACE_EVENT_FL_IGNORE_ENABLE = 8,
	TRACE_EVENT_FL_TRACEPOINT = 16,
	TRACE_EVENT_FL_DYNAMIC = 32,
	TRACE_EVENT_FL_KPROBE = 64,
	TRACE_EVENT_FL_UPROBE = 128,
	TRACE_EVENT_FL_EPROBE = 256,
	TRACE_EVENT_FL_FPROBE = 512,
	TRACE_EVENT_FL_CUSTOM = 1024,
	TRACE_EVENT_FL_TEST_STR = 2048,
};

enum {
	EVENT_FILE_FL_ENABLED_BIT = 0,
	EVENT_FILE_FL_RECORDED_CMD_BIT = 1,
	EVENT_FILE_FL_RECORDED_TGID_BIT = 2,
	EVENT_FILE_FL_FILTERED_BIT = 3,
	EVENT_FILE_FL_NO_SET_FILTER_BIT = 4,
	EVENT_FILE_FL_SOFT_MODE_BIT = 5,
	EVENT_FILE_FL_SOFT_DISABLED_BIT = 6,
	EVENT_FILE_FL_TRIGGER_MODE_BIT = 7,
	EVENT_FILE_FL_TRIGGER_COND_BIT = 8,
	EVENT_FILE_FL_PID_FILTER_BIT = 9,
	EVENT_FILE_FL_WAS_ENABLED_BIT = 10,
	EVENT_FILE_FL_FREED_BIT = 11,
};

enum {
	EVENT_FILE_FL_ENABLED = 1,
	EVENT_FILE_FL_RECORDED_CMD = 2,
	EVENT_FILE_FL_RECORDED_TGID = 4,
	EVENT_FILE_FL_FILTERED = 8,
	EVENT_FILE_FL_NO_SET_FILTER = 16,
	EVENT_FILE_FL_SOFT_MODE = 32,
	EVENT_FILE_FL_SOFT_DISABLED = 64,
	EVENT_FILE_FL_TRIGGER_MODE = 128,
	EVENT_FILE_FL_TRIGGER_COND = 256,
	EVENT_FILE_FL_PID_FILTER = 512,
	EVENT_FILE_FL_WAS_ENABLED = 1024,
	EVENT_FILE_FL_FREED = 2048,
};

enum {
	FILTER_OTHER = 0,
	FILTER_STATIC_STRING = 1,
	FILTER_DYN_STRING = 2,
	FILTER_RDYN_STRING = 3,
	FILTER_PTR_STRING = 4,
	FILTER_TRACE_FN = 5,
	FILTER_CPUMASK = 6,
	FILTER_COMM = 7,
	FILTER_CPU = 8,
	FILTER_STACKTRACE = 9,
};

struct trace_event_raw_nfs4_clientid_event {
	struct trace_entry ent;
	u32 __data_loc_dstaddr;
	long unsigned int error;
	char __data[0];
};

struct trace_event_raw_nfs4_trunked_exchange_id {
	struct trace_entry ent;
	u32 __data_loc_main_addr;
	u32 __data_loc_trunk_addr;
	long unsigned int error;
	char __data[0];
};

struct trace_event_raw_nfs4_sequence_done {
	struct trace_entry ent;
	unsigned int session;
	unsigned int slot_nr;
	unsigned int seq_nr;
	unsigned int highest_slotid;
	unsigned int target_highest_slotid;
	long unsigned int status_flags;
	long unsigned int error;
	char __data[0];
};

struct trace_event_raw_nfs4_cb_sequence {
	struct trace_entry ent;
	unsigned int session;
	unsigned int slot_nr;
	unsigned int seq_nr;
	unsigned int highest_slotid;
	unsigned int cachethis;
	long unsigned int error;
	char __data[0];
};

struct trace_event_raw_nfs4_cb_seqid_err {
	struct trace_entry ent;
	unsigned int session;
	unsigned int slot_nr;
	unsigned int seq_nr;
	unsigned int highest_slotid;
	unsigned int cachethis;
	long unsigned int error;
	char __data[0];
};

struct trace_event_raw_nfs4_cb_offload {
	struct trace_entry ent;
	long unsigned int error;
	u32 fhandle;
	loff_t cb_count;
	int cb_how;
	int cb_stateid_seq;
	u32 cb_stateid_hash;
	char __data[0];
};

struct trace_event_raw_nfs4_setup_sequence {
	struct trace_entry ent;
	unsigned int session;
	unsigned int slot_nr;
	unsigned int seq_nr;
	unsigned int highest_used_slotid;
	char __data[0];
};

struct trace_event_raw_nfs4_state_mgr {
	struct trace_entry ent;
	long unsigned int state;
	u32 __data_loc_hostname;
	char __data[0];
};

struct trace_event_raw_nfs4_state_mgr_failed {
	struct trace_entry ent;
	long unsigned int error;
	long unsigned int state;
	u32 __data_loc_hostname;
	u32 __data_loc_section;
	char __data[0];
};

struct trace_event_raw_nfs4_xdr_bad_operation {
	struct trace_entry ent;
	unsigned int task_id;
	unsigned int client_id;
	u32 xid;
	u32 op;
	u32 expected;
	char __data[0];
};

struct trace_event_raw_nfs4_xdr_event {
	struct trace_entry ent;
	unsigned int task_id;
	unsigned int client_id;
	u32 xid;
	u32 op;
	long unsigned int error;
	char __data[0];
};

struct trace_event_raw_nfs4_cb_error_class {
	struct trace_entry ent;
	u32 xid;
	u32 cbident;
	char __data[0];
};

struct trace_event_raw_nfs4_open_event {
	struct trace_entry ent;
	long unsigned int error;
	long unsigned int flags;
	long unsigned int fmode;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	u64 dir;
	u32 __data_loc_name;
	int stateid_seq;
	u32 stateid_hash;
	int openstateid_seq;
	u32 openstateid_hash;
	char __data[0];
};

struct trace_event_raw_nfs4_cached_open {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	unsigned int fmode;
	int stateid_seq;
	u32 stateid_hash;
	char __data[0];
};

struct trace_event_raw_nfs4_close {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	unsigned int fmode;
	long unsigned int error;
	int stateid_seq;
	u32 stateid_hash;
	char __data[0];
};

struct trace_event_raw_nfs4_lock_event {
	struct trace_entry ent;
	long unsigned int error;
	long unsigned int cmd;
	long unsigned int type;
	loff_t start;
	loff_t end;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	int stateid_seq;
	u32 stateid_hash;
	char __data[0];
};

struct trace_event_raw_nfs4_set_lock {
	struct trace_entry ent;
	long unsigned int error;
	long unsigned int cmd;
	long unsigned int type;
	loff_t start;
	loff_t end;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	int stateid_seq;
	u32 stateid_hash;
	int lockstateid_seq;
	u32 lockstateid_hash;
	char __data[0];
};

struct trace_event_raw_nfs4_state_lock_reclaim {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	long unsigned int state_flags;
	long unsigned int lock_flags;
	int stateid_seq;
	u32 stateid_hash;
	char __data[0];
};

struct trace_event_raw_nfs4_set_delegation_event {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	unsigned int fmode;
	char __data[0];
};

struct trace_event_raw_nfs4_delegreturn_exit {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	long unsigned int error;
	int stateid_seq;
	u32 stateid_hash;
	char __data[0];
};

struct trace_event_raw_nfs4_test_stateid_event {
	struct trace_entry ent;
	long unsigned int error;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	int stateid_seq;
	u32 stateid_hash;
	char __data[0];
};

struct trace_event_raw_nfs4_lookup_event {
	struct trace_entry ent;
	dev_t dev;
	long unsigned int error;
	u64 dir;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_raw_nfs4_lookupp {
	struct trace_entry ent;
	dev_t dev;
	u64 ino;
	long unsigned int error;
	char __data[0];
};

struct trace_event_raw_nfs4_rename {
	struct trace_entry ent;
	dev_t dev;
	long unsigned int error;
	u64 olddir;
	u32 __data_loc_oldname;
	u64 newdir;
	u32 __data_loc_newname;
	char __data[0];
};

struct trace_event_raw_nfs4_inode_event {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	long unsigned int error;
	char __data[0];
};

struct trace_event_raw_nfs4_inode_stateid_event {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	long unsigned int error;
	int stateid_seq;
	u32 stateid_hash;
	char __data[0];
};

struct trace_event_raw_nfs4_getattr_event {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	unsigned int valid;
	long unsigned int error;
	char __data[0];
};

struct trace_event_raw_nfs4_inode_callback_event {
	struct trace_entry ent;
	long unsigned int error;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	u32 __data_loc_dstaddr;
	char __data[0];
};

struct trace_event_raw_nfs4_inode_stateid_callback_event {
	struct trace_entry ent;
	long unsigned int error;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	u32 __data_loc_dstaddr;
	int stateid_seq;
	u32 stateid_hash;
	char __data[0];
};

struct trace_event_raw_nfs4_idmap_event {
	struct trace_entry ent;
	long unsigned int error;
	u32 id;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_raw_nfs4_read_event {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	loff_t offset;
	u32 arg_count;
	u32 res_count;
	long unsigned int error;
	int stateid_seq;
	u32 stateid_hash;
	int layoutstateid_seq;
	u32 layoutstateid_hash;
	char __data[0];
};

struct trace_event_raw_nfs4_write_event {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	loff_t offset;
	u32 arg_count;
	u32 res_count;
	long unsigned int error;
	int stateid_seq;
	u32 stateid_hash;
	int layoutstateid_seq;
	u32 layoutstateid_hash;
	char __data[0];
};

struct trace_event_raw_nfs4_commit_event {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	long unsigned int error;
	loff_t offset;
	u32 count;
	int layoutstateid_seq;
	u32 layoutstateid_hash;
	char __data[0];
};

struct trace_event_raw_nfs4_layoutget {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	u32 iomode;
	u64 offset;
	u64 count;
	long unsigned int error;
	int stateid_seq;
	u32 stateid_hash;
	int layoutstateid_seq;
	u32 layoutstateid_hash;
	char __data[0];
};

struct trace_event_raw_pnfs_update_layout {
	struct trace_entry ent;
	dev_t dev;
	u64 fileid;
	u32 fhandle;
	loff_t pos;
	u64 count;
	enum pnfs_iomode iomode;
	int layoutstateid_seq;
	u32 layoutstateid_hash;
	long int lseg;
	enum pnfs_update_layout_reason reason;
	char __data[0];
};

struct trace_event_raw_pnfs_layout_event {
	struct trace_entry ent;
	dev_t dev;
	u64 fileid;
	u32 fhandle;
	loff_t pos;
	u64 count;
	enum pnfs_iomode iomode;
	int layoutstateid_seq;
	u32 layoutstateid_hash;
	long int lseg;
	char __data[0];
};

struct trace_event_raw_nfs4_deviceid_event {
	struct trace_entry ent;
	u32 __data_loc_dstaddr;
	unsigned char deviceid[16];
	char __data[0];
};

struct trace_event_raw_nfs4_deviceid_status {
	struct trace_entry ent;
	dev_t dev;
	int status;
	u32 __data_loc_dstaddr;
	unsigned char deviceid[16];
	char __data[0];
};

struct trace_event_raw_fl_getdevinfo {
	struct trace_entry ent;
	u32 __data_loc_mds_addr;
	unsigned char deviceid[16];
	u32 __data_loc_ds_ips;
	char __data[0];
};

struct trace_event_raw_nfs4_flexfiles_io_event {
	struct trace_entry ent;
	long unsigned int error;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	loff_t offset;
	u32 count;
	int stateid_seq;
	u32 stateid_hash;
	u32 __data_loc_dstaddr;
	char __data[0];
};

struct trace_event_raw_ff_layout_commit_error {
	struct trace_entry ent;
	long unsigned int error;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	loff_t offset;
	u32 count;
	u32 __data_loc_dstaddr;
	char __data[0];
};

struct trace_event_raw_pnfs_bl_pr_key_class {
	struct trace_entry ent;
	u64 key;
	dev_t dev;
	u32 __data_loc_device;
	char __data[0];
};

struct trace_event_raw_pnfs_bl_pr_key_err_class {
	struct trace_entry ent;
	u64 key;
	dev_t dev;
	long unsigned int status;
	u32 __data_loc_device;
	char __data[0];
};

struct trace_event_raw_nfs4_llseek {
	struct trace_entry ent;
	long unsigned int error;
	u32 fhandle;
	u32 fileid;
	dev_t dev;
	int stateid_seq;
	u32 stateid_hash;
	loff_t offset_s;
	u32 what;
	loff_t offset_r;
	u32 eof;
	char __data[0];
};

struct trace_event_raw_nfs4_sparse_event {
	struct trace_entry ent;
	long unsigned int error;
	loff_t offset;
	loff_t len;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	int stateid_seq;
	u32 stateid_hash;
	char __data[0];
};

struct trace_event_raw_nfs4_copy {
	struct trace_entry ent;
	long unsigned int error;
	u32 src_fhandle;
	u32 src_fileid;
	u32 dst_fhandle;
	u32 dst_fileid;
	dev_t src_dev;
	dev_t dst_dev;
	int src_stateid_seq;
	u32 src_stateid_hash;
	int dst_stateid_seq;
	u32 dst_stateid_hash;
	loff_t src_offset;
	loff_t dst_offset;
	bool sync;
	loff_t len;
	int res_stateid_seq;
	u32 res_stateid_hash;
	loff_t res_count;
	bool res_sync;
	bool res_cons;
	bool intra;
	char __data[0];
};

struct trace_event_raw_nfs4_clone {
	struct trace_entry ent;
	long unsigned int error;
	u32 src_fhandle;
	u32 src_fileid;
	u32 dst_fhandle;
	u32 dst_fileid;
	dev_t src_dev;
	dev_t dst_dev;
	loff_t src_offset;
	loff_t dst_offset;
	int src_stateid_seq;
	u32 src_stateid_hash;
	int dst_stateid_seq;
	u32 dst_stateid_hash;
	loff_t len;
	char __data[0];
};

struct trace_event_raw_nfs4_copy_notify {
	struct trace_entry ent;
	long unsigned int error;
	u32 fhandle;
	u32 fileid;
	dev_t dev;
	int stateid_seq;
	u32 stateid_hash;
	int res_stateid_seq;
	u32 res_stateid_hash;
	char __data[0];
};

struct trace_event_raw_nfs4_offload_cancel {
	struct trace_entry ent;
	long unsigned int error;
	u32 fhandle;
	int stateid_seq;
	u32 stateid_hash;
	char __data[0];
};

struct trace_event_raw_nfs4_xattr_event {
	struct trace_entry ent;
	long unsigned int error;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_data_offsets_nfs4_clientid_event {
	u32 dstaddr;
	const void *dstaddr_ptr_;
};

struct trace_event_data_offsets_nfs4_trunked_exchange_id {
	u32 main_addr;
	const void *main_addr_ptr_;
	u32 trunk_addr;
	const void *trunk_addr_ptr_;
};

struct trace_event_data_offsets_nfs4_sequence_done {};

struct trace_event_data_offsets_nfs4_cb_sequence {};

struct trace_event_data_offsets_nfs4_cb_seqid_err {};

struct trace_event_data_offsets_nfs4_cb_offload {};

struct trace_event_data_offsets_nfs4_setup_sequence {};

struct trace_event_data_offsets_nfs4_state_mgr {
	u32 hostname;
	const void *hostname_ptr_;
};

struct trace_event_data_offsets_nfs4_state_mgr_failed {
	u32 hostname;
	const void *hostname_ptr_;
	u32 section;
	const void *section_ptr_;
};

struct trace_event_data_offsets_nfs4_xdr_bad_operation {};

struct trace_event_data_offsets_nfs4_xdr_event {};

struct trace_event_data_offsets_nfs4_cb_error_class {};

struct trace_event_data_offsets_nfs4_open_event {
	u32 name;
	const void *name_ptr_;
};

struct trace_event_data_offsets_nfs4_cached_open {};

struct trace_event_data_offsets_nfs4_close {};

struct trace_event_data_offsets_nfs4_lock_event {};

struct trace_event_data_offsets_nfs4_set_lock {};

struct trace_event_data_offsets_nfs4_state_lock_reclaim {};

struct trace_event_data_offsets_nfs4_set_delegation_event {};

struct trace_event_data_offsets_nfs4_delegreturn_exit {};

struct trace_event_data_offsets_nfs4_test_stateid_event {};

struct trace_event_data_offsets_nfs4_lookup_event {
	u32 name;
	const void *name_ptr_;
};

struct trace_event_data_offsets_nfs4_lookupp {};

struct trace_event_data_offsets_nfs4_rename {
	u32 oldname;
	const void *oldname_ptr_;
	u32 newname;
	const void *newname_ptr_;
};

struct trace_event_data_offsets_nfs4_inode_event {};

struct trace_event_data_offsets_nfs4_inode_stateid_event {};

struct trace_event_data_offsets_nfs4_getattr_event {};

struct trace_event_data_offsets_nfs4_inode_callback_event {
	u32 dstaddr;
	const void *dstaddr_ptr_;
};

struct trace_event_data_offsets_nfs4_inode_stateid_callback_event {
	u32 dstaddr;
	const void *dstaddr_ptr_;
};

struct trace_event_data_offsets_nfs4_idmap_event {
	u32 name;
	const void *name_ptr_;
};

struct trace_event_data_offsets_nfs4_read_event {};

struct trace_event_data_offsets_nfs4_write_event {};

struct trace_event_data_offsets_nfs4_commit_event {};

struct trace_event_data_offsets_nfs4_layoutget {};

struct trace_event_data_offsets_pnfs_update_layout {};

struct trace_event_data_offsets_pnfs_layout_event {};

struct trace_event_data_offsets_nfs4_deviceid_event {
	u32 dstaddr;
	const void *dstaddr_ptr_;
};

struct trace_event_data_offsets_nfs4_deviceid_status {
	u32 dstaddr;
	const void *dstaddr_ptr_;
};

struct trace_event_data_offsets_fl_getdevinfo {
	u32 mds_addr;
	const void *mds_addr_ptr_;
	u32 ds_ips;
	const void *ds_ips_ptr_;
};

struct trace_event_data_offsets_nfs4_flexfiles_io_event {
	u32 dstaddr;
	const void *dstaddr_ptr_;
};

struct trace_event_data_offsets_ff_layout_commit_error {
	u32 dstaddr;
	const void *dstaddr_ptr_;
};

struct trace_event_data_offsets_pnfs_bl_pr_key_class {
	u32 device;
	const void *device_ptr_;
};

struct trace_event_data_offsets_pnfs_bl_pr_key_err_class {
	u32 device;
	const void *device_ptr_;
};

struct trace_event_data_offsets_nfs4_llseek {};

struct trace_event_data_offsets_nfs4_sparse_event {};

struct trace_event_data_offsets_nfs4_copy {};

struct trace_event_data_offsets_nfs4_clone {};

struct trace_event_data_offsets_nfs4_copy_notify {};

struct trace_event_data_offsets_nfs4_offload_cancel {};

struct trace_event_data_offsets_nfs4_xattr_event {
	u32 name;
	const void *name_ptr_;
};

typedef void (*btf_trace_nfs4_setclientid)(void *, const struct nfs_client *, int);

typedef void (*btf_trace_nfs4_setclientid_confirm)(void *, const struct nfs_client *, int);

typedef void (*btf_trace_nfs4_renew)(void *, const struct nfs_client *, int);

typedef void (*btf_trace_nfs4_renew_async)(void *, const struct nfs_client *, int);

typedef void (*btf_trace_nfs4_exchange_id)(void *, const struct nfs_client *, int);

typedef void (*btf_trace_nfs4_create_session)(void *, const struct nfs_client *, int);

typedef void (*btf_trace_nfs4_destroy_session)(void *, const struct nfs_client *, int);

typedef void (*btf_trace_nfs4_destroy_clientid)(void *, const struct nfs_client *, int);

typedef void (*btf_trace_nfs4_bind_conn_to_session)(void *, const struct nfs_client *, int);

typedef void (*btf_trace_nfs4_sequence)(void *, const struct nfs_client *, int);

typedef void (*btf_trace_nfs4_reclaim_complete)(void *, const struct nfs_client *, int);

typedef void (*btf_trace_nfs4_trunked_exchange_id)(void *, const struct nfs_client *, const char *, int);

typedef void (*btf_trace_nfs4_sequence_done)(void *, const struct nfs4_session *, const struct nfs4_sequence_res *);

typedef void (*btf_trace_nfs4_cb_sequence)(void *, const struct cb_sequenceargs *, const struct cb_sequenceres *, __be32);

typedef void (*btf_trace_nfs4_cb_seqid_err)(void *, const struct cb_sequenceargs *, __be32);

typedef void (*btf_trace_nfs4_cb_offload)(void *, const struct nfs_fh *, const nfs4_stateid *, uint64_t, int, int);

typedef void (*btf_trace_nfs4_setup_sequence)(void *, const struct nfs4_session *, const struct nfs4_sequence_args *);

typedef void (*btf_trace_nfs4_state_mgr)(void *, const struct nfs_client *);

typedef void (*btf_trace_nfs4_state_mgr_failed)(void *, const struct nfs_client *, const char *, int);

typedef void (*btf_trace_nfs4_xdr_bad_operation)(void *, const struct xdr_stream *, u32, u32);

typedef void (*btf_trace_nfs4_xdr_status)(void *, const struct xdr_stream *, u32, u32);

typedef void (*btf_trace_nfs4_xdr_bad_filehandle)(void *, const struct xdr_stream *, u32, u32);

typedef void (*btf_trace_nfs_cb_no_clp)(void *, __be32, u32);

typedef void (*btf_trace_nfs_cb_badprinc)(void *, __be32, u32);

typedef void (*btf_trace_nfs4_open_reclaim)(void *, const struct nfs_open_context *, int, int);

typedef void (*btf_trace_nfs4_open_expired)(void *, const struct nfs_open_context *, int, int);

typedef void (*btf_trace_nfs4_open_file)(void *, const struct nfs_open_context *, int, int);

typedef void (*btf_trace_nfs4_cached_open)(void *, const struct nfs4_state *);

typedef void (*btf_trace_nfs4_close)(void *, const struct nfs4_state *, const struct nfs_closeargs *, const struct nfs_closeres *, int);

typedef void (*btf_trace_nfs4_get_lock)(void *, const struct file_lock *, const struct nfs4_state *, int, int);

typedef void (*btf_trace_nfs4_unlock)(void *, const struct file_lock *, const struct nfs4_state *, int, int);

typedef void (*btf_trace_nfs4_set_lock)(void *, const struct file_lock *, const struct nfs4_state *, const nfs4_stateid *, int, int);

typedef void (*btf_trace_nfs4_state_lock_reclaim)(void *, const struct nfs4_state *, const struct nfs4_lock_state *);

typedef void (*btf_trace_nfs4_set_delegation)(void *, const struct inode *, fmode_t);

typedef void (*btf_trace_nfs4_reclaim_delegation)(void *, const struct inode *, fmode_t);

typedef void (*btf_trace_nfs4_delegreturn_exit)(void *, const struct nfs4_delegreturnargs *, const struct nfs4_delegreturnres *, int);

typedef void (*btf_trace_nfs4_test_delegation_stateid)(void *, const struct nfs4_state *, const struct nfs4_lock_state *, int);

typedef void (*btf_trace_nfs4_test_open_stateid)(void *, const struct nfs4_state *, const struct nfs4_lock_state *, int);

typedef void (*btf_trace_nfs4_test_lock_stateid)(void *, const struct nfs4_state *, const struct nfs4_lock_state *, int);

typedef void (*btf_trace_nfs4_lookup)(void *, const struct inode *, const struct qstr *, int);

typedef void (*btf_trace_nfs4_symlink)(void *, const struct inode *, const struct qstr *, int);

typedef void (*btf_trace_nfs4_mkdir)(void *, const struct inode *, const struct qstr *, int);

typedef void (*btf_trace_nfs4_mknod)(void *, const struct inode *, const struct qstr *, int);

typedef void (*btf_trace_nfs4_remove)(void *, const struct inode *, const struct qstr *, int);

typedef void (*btf_trace_nfs4_get_fs_locations)(void *, const struct inode *, const struct qstr *, int);

typedef void (*btf_trace_nfs4_secinfo)(void *, const struct inode *, const struct qstr *, int);

typedef void (*btf_trace_nfs4_lookupp)(void *, const struct inode *, int);

typedef void (*btf_trace_nfs4_rename)(void *, const struct inode *, const struct qstr *, const struct inode *, const struct qstr *, int);

typedef void (*btf_trace_nfs4_access)(void *, const struct inode *, int);

typedef void (*btf_trace_nfs4_readlink)(void *, const struct inode *, int);

typedef void (*btf_trace_nfs4_readdir)(void *, const struct inode *, int);

typedef void (*btf_trace_nfs4_get_acl)(void *, const struct inode *, int);

typedef void (*btf_trace_nfs4_set_acl)(void *, const struct inode *, int);

typedef void (*btf_trace_nfs4_get_security_label)(void *, const struct inode *, int);

typedef void (*btf_trace_nfs4_set_security_label)(void *, const struct inode *, int);

typedef void (*btf_trace_nfs4_setattr)(void *, const struct inode *, const nfs4_stateid *, int);

typedef void (*btf_trace_nfs4_delegreturn)(void *, const struct inode *, const nfs4_stateid *, int);

typedef void (*btf_trace_nfs4_open_stateid_update)(void *, const struct inode *, const nfs4_stateid *, int);

typedef void (*btf_trace_nfs4_open_stateid_update_wait)(void *, const struct inode *, const nfs4_stateid *, int);

typedef void (*btf_trace_nfs4_close_stateid_update_wait)(void *, const struct inode *, const nfs4_stateid *, int);

typedef void (*btf_trace_nfs4_getattr)(void *, const struct nfs_server *, const struct nfs_fh *, const struct nfs_fattr *, int);

typedef void (*btf_trace_nfs4_lookup_root)(void *, const struct nfs_server *, const struct nfs_fh *, const struct nfs_fattr *, int);

typedef void (*btf_trace_nfs4_fsinfo)(void *, const struct nfs_server *, const struct nfs_fh *, const struct nfs_fattr *, int);

typedef void (*btf_trace_nfs4_cb_getattr)(void *, const struct nfs_client *, const struct nfs_fh *, const struct inode *, int);

typedef void (*btf_trace_nfs4_cb_recall)(void *, const struct nfs_client *, const struct nfs_fh *, const struct inode *, const nfs4_stateid *, int);

typedef void (*btf_trace_nfs4_cb_layoutrecall_file)(void *, const struct nfs_client *, const struct nfs_fh *, const struct inode *, const nfs4_stateid *, int);

typedef void (*btf_trace_nfs4_map_name_to_uid)(void *, const char *, int, u32, int);

typedef void (*btf_trace_nfs4_map_group_to_gid)(void *, const char *, int, u32, int);

typedef void (*btf_trace_nfs4_map_uid_to_name)(void *, const char *, int, u32, int);

typedef void (*btf_trace_nfs4_map_gid_to_group)(void *, const char *, int, u32, int);

typedef void (*btf_trace_nfs4_read)(void *, const struct nfs_pgio_header *, int);

typedef void (*btf_trace_nfs4_pnfs_read)(void *, const struct nfs_pgio_header *, int);

typedef void (*btf_trace_nfs4_write)(void *, const struct nfs_pgio_header *, int);

typedef void (*btf_trace_nfs4_pnfs_write)(void *, const struct nfs_pgio_header *, int);

typedef void (*btf_trace_nfs4_commit)(void *, const struct nfs_commit_data *, int);

typedef void (*btf_trace_nfs4_pnfs_commit_ds)(void *, const struct nfs_commit_data *, int);

typedef void (*btf_trace_nfs4_layoutget)(void *, const struct nfs_open_context *, const struct pnfs_layout_range *, const struct pnfs_layout_range *, const nfs4_stateid *, int);

typedef void (*btf_trace_nfs4_layoutcommit)(void *, const struct inode *, const nfs4_stateid *, int);

typedef void (*btf_trace_nfs4_layoutreturn)(void *, const struct inode *, const nfs4_stateid *, int);

typedef void (*btf_trace_nfs4_layoutreturn_on_close)(void *, const struct inode *, const nfs4_stateid *, int);

typedef void (*btf_trace_nfs4_layouterror)(void *, const struct inode *, const nfs4_stateid *, int);

typedef void (*btf_trace_nfs4_layoutstats)(void *, const struct inode *, const nfs4_stateid *, int);

typedef void (*btf_trace_pnfs_update_layout)(void *, struct inode *, loff_t, u64, enum pnfs_iomode, struct pnfs_layout_hdr *, struct pnfs_layout_segment *, enum pnfs_update_layout_reason);

typedef void (*btf_trace_pnfs_mds_fallback_pg_init_read)(void *, struct inode *, loff_t, u64, enum pnfs_iomode, struct pnfs_layout_hdr *, struct pnfs_layout_segment *);

typedef void (*btf_trace_pnfs_mds_fallback_pg_init_write)(void *, struct inode *, loff_t, u64, enum pnfs_iomode, struct pnfs_layout_hdr *, struct pnfs_layout_segment *);

typedef void (*btf_trace_pnfs_mds_fallback_pg_get_mirror_count)(void *, struct inode *, loff_t, u64, enum pnfs_iomode, struct pnfs_layout_hdr *, struct pnfs_layout_segment *);

typedef void (*btf_trace_pnfs_mds_fallback_read_done)(void *, struct inode *, loff_t, u64, enum pnfs_iomode, struct pnfs_layout_hdr *, struct pnfs_layout_segment *);

typedef void (*btf_trace_pnfs_mds_fallback_write_done)(void *, struct inode *, loff_t, u64, enum pnfs_iomode, struct pnfs_layout_hdr *, struct pnfs_layout_segment *);

typedef void (*btf_trace_pnfs_mds_fallback_read_pagelist)(void *, struct inode *, loff_t, u64, enum pnfs_iomode, struct pnfs_layout_hdr *, struct pnfs_layout_segment *);

typedef void (*btf_trace_pnfs_mds_fallback_write_pagelist)(void *, struct inode *, loff_t, u64, enum pnfs_iomode, struct pnfs_layout_hdr *, struct pnfs_layout_segment *);

typedef void (*btf_trace_nfs4_deviceid_free)(void *, const struct nfs_client *, const struct nfs4_deviceid *);

typedef void (*btf_trace_nfs4_getdeviceinfo)(void *, const struct nfs_server *, const struct nfs4_deviceid *, int);

typedef void (*btf_trace_nfs4_find_deviceid)(void *, const struct nfs_server *, const struct nfs4_deviceid *, int);

typedef void (*btf_trace_fl_getdevinfo)(void *, const struct nfs_server *, const struct nfs4_deviceid *, char *);

typedef void (*btf_trace_ff_layout_read_error)(void *, const struct nfs_pgio_header *);

typedef void (*btf_trace_ff_layout_write_error)(void *, const struct nfs_pgio_header *);

typedef void (*btf_trace_ff_layout_commit_error)(void *, const struct nfs_commit_data *);

typedef void (*btf_trace_bl_pr_key_reg)(void *, const struct block_device *, u64);

typedef void (*btf_trace_bl_pr_key_unreg)(void *, const struct block_device *, u64);

typedef void (*btf_trace_bl_pr_key_reg_err)(void *, const struct block_device *, u64, int);

typedef void (*btf_trace_bl_pr_key_unreg_err)(void *, const struct block_device *, u64, int);

typedef void (*btf_trace_nfs4_llseek)(void *, const struct inode *, const struct nfs42_seek_args *, const struct nfs42_seek_res *, int);

typedef void (*btf_trace_nfs4_fallocate)(void *, const struct inode *, const struct nfs42_falloc_args *, int);

typedef void (*btf_trace_nfs4_deallocate)(void *, const struct inode *, const struct nfs42_falloc_args *, int);

typedef void (*btf_trace_nfs4_copy)(void *, const struct inode *, const struct inode *, const struct nfs42_copy_args *, const struct nfs42_copy_res *, const struct nl4_server *, int);

typedef void (*btf_trace_nfs4_clone)(void *, const struct inode *, const struct inode *, const struct nfs42_clone_args *, int);

typedef void (*btf_trace_nfs4_copy_notify)(void *, const struct inode *, const struct nfs42_copy_notify_args *, const struct nfs42_copy_notify_res *, int);

typedef void (*btf_trace_nfs4_offload_cancel)(void *, const struct nfs42_offload_status_args *, int);

typedef void (*btf_trace_nfs4_getxattr)(void *, const struct inode *, const char *, int);

typedef void (*btf_trace_nfs4_setxattr)(void *, const struct inode *, const char *, int);

typedef void (*btf_trace_nfs4_removexattr)(void *, const struct inode *, const char *, int);

typedef void (*btf_trace_nfs4_listxattr)(void *, const struct inode *, int);

typedef void (*swap_func_t)(void *, void *, int);

typedef int (*cmp_func_t)(const void *, const void *);

enum pnfs_layouttype {
	LAYOUT_NFSV4_1_FILES = 1,
	LAYOUT_OSD2_OBJECTS = 2,
	LAYOUT_BLOCK_VOLUME = 3,
	LAYOUT_FLEX_FILES = 4,
	LAYOUT_SCSI = 5,
	LAYOUT_TYPE_MAX = 6,
};

struct nfs42_layoutstat_data {
	struct inode *inode;
	struct nfs42_layoutstat_args args;
	struct nfs42_layoutstat_res res;
};

enum {
	NFS_IOHDR_ERROR = 0,
	NFS_IOHDR_EOF = 1,
	NFS_IOHDR_REDO = 2,
	NFS_IOHDR_STAT = 3,
	NFS_IOHDR_RESEND_PNFS = 4,
	NFS_IOHDR_RESEND_MDS = 5,
	NFS_IOHDR_UNSTABLE_WRITES = 6,
};

enum {
	NFS_LSEG_VALID = 0,
	NFS_LSEG_ROC = 1,
	NFS_LSEG_LAYOUTCOMMIT = 2,
	NFS_LSEG_LAYOUTRETURN = 3,
	NFS_LSEG_UNAVAILABLE = 4,
};

enum {
	NFS_DEVICEID_INVALID = 0,
	NFS_DEVICEID_UNAVAILABLE = 1,
	NFS_DEVICEID_NOCACHE = 2,
};

enum node_stat_item {
	NR_LRU_BASE = 0,
	NR_INACTIVE_ANON = 0,
	NR_ACTIVE_ANON = 1,
	NR_INACTIVE_FILE = 2,
	NR_ACTIVE_FILE = 3,
	NR_UNEVICTABLE = 4,
	NR_SLAB_RECLAIMABLE_B = 5,
	NR_SLAB_UNRECLAIMABLE_B = 6,
	NR_ISOLATED_ANON = 7,
	NR_ISOLATED_FILE = 8,
	WORKINGSET_NODES = 9,
	WORKINGSET_REFAULT_BASE = 10,
	WORKINGSET_REFAULT_ANON = 10,
	WORKINGSET_REFAULT_FILE = 11,
	WORKINGSET_ACTIVATE_BASE = 12,
	WORKINGSET_ACTIVATE_ANON = 12,
	WORKINGSET_ACTIVATE_FILE = 13,
	WORKINGSET_RESTORE_BASE = 14,
	WORKINGSET_RESTORE_ANON = 14,
	WORKINGSET_RESTORE_FILE = 15,
	WORKINGSET_NODERECLAIM = 16,
	NR_ANON_MAPPED = 17,
	NR_FILE_MAPPED = 18,
	NR_FILE_PAGES = 19,
	NR_FILE_DIRTY = 20,
	NR_WRITEBACK = 21,
	NR_WRITEBACK_TEMP = 22,
	NR_SHMEM = 23,
	NR_SHMEM_THPS = 24,
	NR_SHMEM_PMDMAPPED = 25,
	NR_FILE_THPS = 26,
	NR_FILE_PMDMAPPED = 27,
	NR_ANON_THPS = 28,
	NR_VMSCAN_WRITE = 29,
	NR_VMSCAN_IMMEDIATE = 30,
	NR_DIRTIED = 31,
	NR_WRITTEN = 32,
	NR_THROTTLED_WRITTEN = 33,
	NR_KERNEL_MISC_RECLAIMABLE = 34,
	NR_FOLL_PIN_ACQUIRED = 35,
	NR_FOLL_PIN_RELEASED = 36,
	NR_KERNEL_STACK_KB = 37,
	NR_PAGETABLE = 38,
	NR_SECONDARY_PAGETABLE = 39,
	NR_IOMMU_PAGES = 40,
	NR_SWAPCACHE = 41,
	PGPROMOTE_SUCCESS = 42,
	PGPROMOTE_CANDIDATE = 43,
	PGDEMOTE_KSWAPD = 44,
	PGDEMOTE_DIRECT = 45,
	PGDEMOTE_KHUGEPAGED = 46,
	NR_VM_NODE_STAT_ITEMS = 47,
};

typedef struct pglist_data pg_data_t;

enum wb_stat_item {
	WB_RECLAIMABLE = 0,
	WB_WRITEBACK = 1,
	WB_DIRTIED = 2,
	WB_WRITTEN = 3,
	NR_WB_STAT_ITEMS = 4,
};

struct pnfs_commit_bucket {
	struct list_head written;
	struct list_head committing;
	struct pnfs_layout_segment *lseg;
	struct nfs_writeverf direct_verf;
};

struct pnfs_commit_array {
	struct list_head cinfo_list;
	struct list_head lseg_list;
	struct pnfs_layout_segment *lseg;
	struct callback_head rcu;
	refcount_t refcount;
	unsigned int nbuckets;
	struct pnfs_commit_bucket buckets[0];
};

enum {
	PG_BUSY = 0,
	PG_MAPPED = 1,
	PG_FOLIO = 2,
	PG_CLEAN = 3,
	PG_COMMIT_TO_DS = 4,
	PG_INODE_REF = 5,
	PG_HEADLOCK = 6,
	PG_TEARDOWN = 7,
	PG_UNLOCKPAGE = 8,
	PG_UPTODATE = 9,
	PG_WB_END = 10,
	PG_REMOVE = 11,
	PG_CONTENDED1 = 12,
	PG_CONTENDED2 = 13,
};

struct nfs4_pnfs_ds_addr {
	struct __kernel_sockaddr_storage da_addr;
	size_t da_addrlen;
	struct list_head da_node;
	char *da_remotestr;
	const char *da_netid;
	int da_transport;
};

struct nfs4_pnfs_ds {
	struct list_head ds_node;
	char *ds_remotestr;
	struct list_head ds_addrs;
	const struct net *ds_net;
	struct nfs_client *ds_clp;
	refcount_t ds_count;
	long unsigned int ds_state;
};

struct nfsd_file;

enum {
	IPPROTO_IP = 0,
	IPPROTO_ICMP = 1,
	IPPROTO_IGMP = 2,
	IPPROTO_IPIP = 4,
	IPPROTO_TCP = 6,
	IPPROTO_EGP = 8,
	IPPROTO_PUP = 12,
	IPPROTO_UDP = 17,
	IPPROTO_IDP = 22,
	IPPROTO_TP = 29,
	IPPROTO_DCCP = 33,
	IPPROTO_IPV6 = 41,
	IPPROTO_RSVP = 46,
	IPPROTO_GRE = 47,
	IPPROTO_ESP = 50,
	IPPROTO_AH = 51,
	IPPROTO_MTP = 92,
	IPPROTO_BEETPH = 94,
	IPPROTO_ENCAP = 98,
	IPPROTO_PIM = 103,
	IPPROTO_COMP = 108,
	IPPROTO_L2TP = 115,
	IPPROTO_SCTP = 132,
	IPPROTO_UDPLITE = 136,
	IPPROTO_MPLS = 137,
	IPPROTO_ETHERNET = 143,
	IPPROTO_RAW = 255,
	IPPROTO_SMC = 256,
	IPPROTO_MPTCP = 262,
	IPPROTO_MAX = 263,
};

struct nfs42_layouterror_data {
	struct nfs42_layouterror_args args;
	struct nfs42_layouterror_res res;
	struct inode *inode;
	struct pnfs_layout_segment *lseg;
};

struct nfs42_offloadcancel_data {
	struct nfs_server *seq_server;
	struct nfs42_offload_status_args args;
	struct nfs42_offload_status_res res;
};

enum _slab_flag_bits {
	_SLAB_CONSISTENCY_CHECKS = 0,
	_SLAB_RED_ZONE = 1,
	_SLAB_POISON = 2,
	_SLAB_KMALLOC = 3,
	_SLAB_HWCACHE_ALIGN = 4,
	_SLAB_CACHE_DMA = 5,
	_SLAB_CACHE_DMA32 = 6,
	_SLAB_STORE_USER = 7,
	_SLAB_PANIC = 8,
	_SLAB_TYPESAFE_BY_RCU = 9,
	_SLAB_TRACE = 10,
	_SLAB_NOLEAKTRACE = 11,
	_SLAB_NO_MERGE = 12,
	_SLAB_ACCOUNT = 13,
	_SLAB_NO_USER_FLAGS = 14,
	_SLAB_SKIP_KFENCE = 15,
	_SLAB_RECLAIM_ACCOUNT = 16,
	_SLAB_OBJECT_POISON = 17,
	_SLAB_CMPXCHG_DOUBLE = 18,
	_SLAB_NO_OBJ_EXT = 19,
	_SLAB_FLAGS_LAST_BIT = 20,
};

struct kmem_cache_args {
	unsigned int align;
	unsigned int useroffset;
	unsigned int usersize;
	unsigned int freeptr_offset;
	bool use_freeptr_offset;
	void (*ctor)(void *);
};

typedef struct kmem_cache *kmem_buckets[14];

enum lru_status {
	LRU_REMOVED = 0,
	LRU_REMOVED_RETRY = 1,
	LRU_ROTATE = 2,
	LRU_SKIP = 3,
	LRU_RETRY = 4,
	LRU_STOP = 5,
};

typedef enum lru_status (*list_lru_walk_cb)(struct list_head *, struct list_lru_one *, spinlock_t *, void *);

struct __una_u32 {
	u32 x;
};

struct nfs4_xattr_bucket {
	spinlock_t lock;
	struct hlist_head hlist;
	struct nfs4_xattr_cache *cache;
	bool draining;
};

struct nfs4_xattr_entry;

struct nfs4_xattr_cache {
	struct kref ref;
	struct nfs4_xattr_bucket buckets[64];
	struct list_head lru;
	struct list_head dispose;
	atomic_long_t nent;
	spinlock_t listxattr_lock;
	struct inode *inode;
	struct nfs4_xattr_entry *listxattr;
};

struct nfs4_xattr_entry {
	struct kref ref;
	struct hlist_node hnode;
	struct list_head lru;
	struct list_head dispose;
	char *xattr_name;
	void *xattr_value;
	size_t xattr_size;
	struct nfs4_xattr_bucket *bucket;
	uint32_t flags;
};

typedef long unsigned int (*count_objects_cb)(struct shrinker *, struct shrink_control *);

typedef long unsigned int (*scan_objects_cb)(struct shrinker *, struct shrink_control *);

enum hrtimer_base_type {
	HRTIMER_BASE_MONOTONIC = 0,
	HRTIMER_BASE_REALTIME = 1,
	HRTIMER_BASE_BOOTTIME = 2,
	HRTIMER_BASE_TAI = 3,
	HRTIMER_BASE_MONOTONIC_SOFT = 4,
	HRTIMER_BASE_REALTIME_SOFT = 5,
	HRTIMER_BASE_BOOTTIME_SOFT = 6,
	HRTIMER_BASE_TAI_SOFT = 7,
	HRTIMER_MAX_CLOCK_BASES = 8,
};

enum {
	DQF_ROOT_SQUASH_B = 0,
	DQF_SYS_FILE_B = 16,
	DQF_PRIVATE = 17,
};

enum {
	DQST_LOOKUPS = 0,
	DQST_DROPS = 1,
	DQST_READS = 2,
	DQST_WRITES = 3,
	DQST_CACHE_HITS = 4,
	DQST_ALLOC_DQUOTS = 5,
	DQST_FREE_DQUOTS = 6,
	DQST_SYNCS = 7,
	_DQST_DQSTAT_LAST = 8,
};

enum {
	SB_UNFROZEN = 0,
	SB_FREEZE_WRITE = 1,
	SB_FREEZE_PAGEFAULT = 2,
	SB_FREEZE_FS = 3,
	SB_FREEZE_COMPLETE = 4,
};

struct modversion_info {
	long unsigned int crc;
	char name[56];
};

enum mod_mem_type {
	MOD_TEXT = 0,
	MOD_DATA = 1,
	MOD_RODATA = 2,
	MOD_RO_AFTER_INIT = 3,
	MOD_INIT_TEXT = 4,
	MOD_INIT_DATA = 5,
	MOD_INIT_RODATA = 6,
	MOD_MEM_NUM_TYPES = 7,
	MOD_INVALID = -1,
};

typedef __u32 Elf32_Word;

struct elf32_note {
	Elf32_Word n_namesz;
	Elf32_Word n_descsz;
	Elf32_Word n_type;
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_H__ */
