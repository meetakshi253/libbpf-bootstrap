/* File Operation Callbacks */
#define cifs_loose_read_iter F0,
#define cifs_file_write_iter F1,
#define cifs_open F2,
#define cifs_close F3,
#define cifs_lock F4,
#define cifs_flock F5,
#define cifs_fsync F6,
#define cifs_flush F7,
#define cifs_file_mmap F8,
#define filemap_splice_read F9,
#define iter_file_splice_write F10,
#define cifs_llseek F11,
#define cifs_ioctl F12,
#define cifs_copy_file_range F13,
#define cifs_remap_file_range F14,
#define cifs_setlease F15,
#define cifs_fallocate F16,

#define cifs_strict_readv F17,
#define cifs_strict_writev F18,
#define cifs_strict_fsync F19,
#define cifs_file_strict_mmap F20,

#define cifs_direct_readv F21,
#define cifs_direct_writev F22,
#define copy_splice_read F23,

#define cifs_readdir F24,
#define cifs_closedir F25,
#define generic_read_dir F26,
#define generic_file_llseek F27,
#define cifs_dir_fsync F28,

/* Inode Operation Callbacks */
#define cifs_create I0
#define cifs_atomic_open I1 
#define cifs_lookup I2
#define cifs_getattr I3
#define cifs_unlink I4
#define cifs_hardlink I5
#define cifs_mkdir I6
#define cifs_rmdir I7
#define cifs_rename2 I8
#define cifs_permission I9
#define cifs_setattr I10
#define cifs_symlink I11
#define cifs_mknod I12
#define cifs_listxattr I13 
#define cifs_get_acl I14
#define cifs_set_acl I15
#define cifs_fiemap I16
#define cifs_get_link I17

/* Address-space Operation Callbacks */
#define cifs_read_folio A0
#define cifs_readahead A1
#define cifs_writepages A2
#define cifs_write_begin A3
#define cifs_write_end A4
#define netfs_dirty_folio A5
#define netfs_release_folio A6
#define cifs_direct_io A7
#define cifs_invalidate_folio A8
#define cifs_launder_folio A9
#define filemap_migrate_folio A10
#define cifs_swap_activate A11
#define cifs_swap_deactivate A12

/* Super-block Operation Callbacks */
#define cifs_statfs S0
#define cifs_alloc_inode S1 
#define cifs_write_inode S2
#define cifs_free_inode S3
#define cifs_drop_inode S4
#define cifs_evict_inode S5
#define cifs_show_devname S6
#define cifs_show_options S7
#define cifs_umount_begin S8
#define cifs_freeze S9