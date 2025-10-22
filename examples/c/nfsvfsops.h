#define FILE 100
#define INODE 101
#define SUPER 102
#define ADSPACE 103

/* File Operation Callbacks */
#define nfs_file_read 1
#define nfs_file_write 2
#define nfs_file_mmap 3
#define nfs4_file_open 4
#define nfs4_file_flush 5
#define nfs_file_release 6
#define nfs_file_fsync 7
#define nfs_lock 8
#define nfs_flock 9
#define nfs_file_splice_read 10
#define iter_file_splice_write 11
#define nfs_check_flags 12
#define nfs4_setlease 13

//dir
#define nfs_llseek_dir 14
#define generic_read_dir 15
#define nfs_readdir 16
#define nfs_opendir 17
#define nfs_closedir 18
#define nfs_fsync_dir 19

/* Inode Operation Callbacks */
#define nfs_permission 20
#define nfs_getattr 21
#define nfs_setattr 22
#define nfs4_listxattr 23   // probably not needed

// dir
#define nfs_create 24
#define nfs_lookup 25
#define nfs_atomic_open 26
#define nfs_link 27
#define nfs_unlink 28
#define nfs_symlink 29
#define nfs_mkdir 30
#define nfs_rmdir 31
#define nfs_mknod 32
#define nfs_rename 33

/* Address-space Operation Callbacks */

/* Super-block Operation Callbacks */

/* dentry ops */