/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Minor modifications and note by Andy Sayler (2012) <www.andysayler.com>

  Additional modifications by Michael Brandt (2013) <www.github.com/michaeljb>

  Source: fuse-2.8.7.tar.gz examples directory
  http://sourceforge.net/projects/fuse/files/fuse-2.X/

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags` pa4_encfs.c -o pa4_encfs `pkg-config fuse --libs`

  Note: This implementation is largely stateless and does not maintain
  open file handels between open and release calls (fi->fh).
  Instead, files are opened and closed as necessary inside read(), write(),
  etc calls. As such, the functions that rely on maintaining file handles are
  not implmented (fgetattr(), etc). Those seeking a more efficient and
  more complete implementation may wish to add fi->fh support to minimize
  open() and close() calls and support fh dependent functions.

*/

#include "pa4-encfs.h"

static int enc_error(char *str) {
  int ret = -errno;
  (void) str;

  return ret;
}

//  All the paths I see are relative to the root of the mounted
//  filesystem.  In order to get to the underlying filesystem, I need to
//  have the mountpoint.  I'll save it away early on in main(), and then
//  whenever I need a path for something I'll call this to construct
//  it.
static void enc_fullpath(char fpath[PATH_MAX], const char *path) {
  strcpy(fpath, ENC_DATA->rootdir);
  strncat(fpath, path, PATH_MAX); // ridiculously long paths will break here
}

static int enc_getattr(const char *path, struct stat *statbuf) {
  int retstat = 0;
  char fpath[PATH_MAX];

  enc_fullpath(fpath, path);

  retstat = lstat(fpath, statbuf);
  if (retstat != 0)
    retstat = enc_error("enc_getattr lstat");

  return retstat;
}

static int enc_access(const char *path, int mask) {
  int res;
  char fpath[PATH_MAX];

  enc_fullpath(fpath, path);

  res = access(fpath, mask);
  if (res == -1)
    return -errno;

  return 0;
}

static int enc_readlink(const char *path, char *buf, size_t size) {
  int res;
  char fpath[PATH_MAX];

  enc_fullpath(fpath, path);

  res = readlink(fpath, buf, size - 1);
  if (res == -1)
    return -errno;

  buf[res] = '\0';
  return 0;
}

static int enc_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
  int retstat = 0;
  DIR *dp;
  struct dirent *de;

  (void) path;
  (void) offset;

  dp = (DIR *) (uintptr_t) fi->fh;

  de = readdir(dp);
  if (de == 0) {
    retstat = enc_error("enc_readdir readdir");
    return retstat;
  }

  // This will copy the entire directory into the buffer.  The loop exits
  // when either the system readdir() returns NULL, or filler()
  // returns something non-zero.  The first case just means I've
  // read the whole directory; the second means the buffer is full.
  do {
    if (filler(buf, de->d_name, NULL, 0) != 0) {
      return -ENOMEM;
    }
  } while ((de = readdir(dp)) != NULL);

  return retstat;
}

static int enc_mknod(const char *path, mode_t mode, dev_t rdev) {
  int res;
  char fpath[PATH_MAX];

  enc_fullpath(fpath, path);

  /* On Linux this could just be 'mknod(path, mode, rdev)' but this
     is more portable */
  if (S_ISREG(mode)) {
    res = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
    if (res >= 0)
      res = close(res);
  } else if (S_ISFIFO(mode))
    res = mkfifo(fpath, mode);
  else
    res = mknod(fpath, mode, rdev);
  if (res == -1)
    return -errno;

  return 0;
}

static int enc_mkdir(const char *path, mode_t mode) {
  int res;
  char fpath[PATH_MAX];

  enc_fullpath(fpath, path);

  res = mkdir(fpath, mode);
  if (res == -1)
    return -errno;

  return 0;
}

static int enc_unlink(const char *path) {
  int res;
  char fpath[PATH_MAX];

  enc_fullpath(fpath, path);

  res = unlink(fpath);
  if (res == -1)
    return -errno;

  return 0;
}

static int enc_rmdir(const char *path) {
  int res;
  char fpath[PATH_MAX];

  enc_fullpath(fpath, path);

  res = rmdir(fpath);
  if (res == -1)
    return -errno;

  return 0;
}

static int enc_symlink(const char *from, const char *to) {
  int res;

  res = symlink(from, to);
  if (res == -1)
    return -errno;

  return 0;
}

static int enc_rename(const char *from, const char *to) {
  int res;

  res = rename(from, to);
  if (res == -1)
    return -errno;

  return 0;
}

static int enc_link(const char *from, const char *to) {
  int res;

  res = link(from, to);
  if (res == -1)
    return -errno;

  return 0;
}

static int enc_chmod(const char *path, mode_t mode) {
  int res;
  char fpath[PATH_MAX];

  enc_fullpath(fpath, path);

  res = chmod(fpath, mode);
  if (res == -1)
    return -errno;

  return 0;
}

static int enc_chown(const char *path, uid_t uid, gid_t gid) {
  int res;
  char fpath[PATH_MAX];

  enc_fullpath(fpath, path);

  res = lchown(fpath, uid, gid);
  if (res == -1)
    return -errno;

  return 0;
}

static int enc_truncate(const char *path, off_t size) {
  int res;
  char fpath[PATH_MAX];

  enc_fullpath(fpath, path);

  res = truncate(fpath, size);
  if (res == -1)
    return -errno;

  return 0;
}

static int enc_utimens(const char *path, const struct timespec ts[2]) {
  int res;
  struct timeval tv[2];
  char fpath[PATH_MAX];

  enc_fullpath(fpath, path);

  tv[0].tv_sec = ts[0].tv_sec;
  tv[0].tv_usec = ts[0].tv_nsec / 1000;
  tv[1].tv_sec = ts[1].tv_sec;
  tv[1].tv_usec = ts[1].tv_nsec / 1000;

  res = utimes(fpath, tv);
  if (res == -1)
    return -errno;

  return 0;
}

static int enc_open(const char *path, struct fuse_file_info *fi) {
  int res;
  char fpath[PATH_MAX];

  enc_fullpath(fpath, path);

  res = open(fpath, fi->flags);
  if (res == -1)
    return -errno;

  close(res);
  return 0;
}

static int enc_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  int res;
  FILE *f, *memfile;
  char fpath[PATH_MAX];
  char *memtext;
  size_t memsize;
  int crypt_action = AES_PASSTHRU;
  char xattr_value[8];
  ssize_t xattr_len;

  enc_fullpath(fpath, path);

  // void out unused params
  (void) fi;

  // open the file for reading
  f = fopen(fpath, "r");
  if (f == NULL)
    return -errno;

  // open an in-memory "file"
  memfile = open_memstream(&memtext, &memsize);
  if (memfile == NULL)
    return -errno;

  // check the file's xattr to see if we're decrypting it
  xattr_len = getxattr(fpath, XATTR_ENCRYPTED, xattr_value, 8);
  if (xattr_len != -1 && !memcmp(xattr_value, ENCRYPTED, 4)){
    crypt_action = AES_DECRYPT;
  }

  // decrypt the real file's bytes into the in-memory "file"
  do_crypt(f, memfile, crypt_action, ENC_DATA->passPhrase);
  fclose(f);

  // read the decrypted bytes into the buffer param
  fflush(memfile);
  fseek(memfile, offset, SEEK_SET);
  res = fread(buf, 1, size, memfile);
  if (res == -1)
    res = -errno;

  fclose(memfile);

  return res;
}

// get the file's bytes and decrypt them in memory, then add the bytes to be written,
// then encrypt them all and write them
static int enc_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  int res;
  char fpath[PATH_MAX];
  FILE *f, *memfile;
  char *memtext;
  size_t memsize;
  int crypt_action = AES_PASSTHRU;
  char xattr_value[8];
  ssize_t xattr_len;

  enc_fullpath(fpath, path);

  // void out unused params
  (void) fi;

  // open the file for reading so we can get its bytes, unencrypted, in memory
  f = fopen(fpath, "r");
  if (f == NULL)
    return -errno;

  // open an in-memory "file"
  memfile = open_memstream(&memtext, &memsize);
  if (memfile == NULL)
    return -errno;

  // check the file's xattr to see if we're decrypting it
  xattr_len = getxattr(fpath, XATTR_ENCRYPTED, xattr_value, 8);
  if (xattr_len != -1 && !memcmp(xattr_value, ENCRYPTED, 4)){
    crypt_action = AES_DECRYPT;
  }

  // get the file decrypted and in memory
  do_crypt(f, memfile, crypt_action, ENC_DATA->passPhrase);
  fclose(f);

  // add the bytes in buf to the in-memory "file"
  fseek(memfile, offset, SEEK_SET);
  res = fwrite(buf, 1, size, memfile);
  if (res == -1)
    res = -errno;
  fflush(memfile);

  // if we decrypted when we opened the file, switch to encrypting now
  if (crypt_action == AES_DECRYPT) {
    crypt_action = AES_ENCRYPT;
  }

  // re-open the real file for writing, encrypt & add the new contents
  f = fopen(fpath, "w");
  fseek(memfile, 0, SEEK_SET);
  do_crypt(memfile, f, crypt_action, ENC_DATA->passPhrase);

  fclose(memfile);
  fclose(f);

  return res;
}

static int enc_statfs(const char *path, struct statvfs *stbuf) {
  int res;
  char fpath[PATH_MAX];

  enc_fullpath(fpath, path);

  res = statvfs(fpath, stbuf);
  if (res == -1)
    return -errno;

  return 0;
}

static int enc_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
  char fpath[PATH_MAX];
  FILE *f, *memfile;
  char *memtext;
  size_t memsize;

  enc_fullpath(fpath, path);

  (void) fi;
  (void) mode;

  // create the file
  f = fopen(fpath, "w");
  if (f == NULL)
    return -errno;

  // open an in-memory "file"
  memfile = open_memstream(&memtext, &memsize);
  if (memfile == NULL)
    return -errno;

  // encrypt the in-memory "file" into the opened file
  do_crypt(memfile, f, AES_ENCRYPT, ENC_DATA->passPhrase);
  fclose(memfile);

  // set the xattr so we know how to open the file later
  if (setxattr(fpath, XATTR_ENCRYPTED, ENCRYPTED, 4, 0)){
    return -errno;
  }

  fclose(f);

  return 0;
}

static int enc_release(const char *path, struct fuse_file_info *fi) {
  /* Just a stub. This method is optional and can safely be left
     unimplemented */

  (void) path;
  (void) fi;
  return 0;
}

static int enc_fsync(const char *path, int isdatasync, struct fuse_file_info *fi) {
  /* Just a stub. This method is optional and can safely be left
     unimplemented */

  (void) path;
  (void) isdatasync;
  (void) fi;
  return 0;
}

static int enc_setxattr(const char *path, const char *name, const char *value, size_t size, int flags) {
  int res;
  char fpath[PATH_MAX];

  enc_fullpath(fpath, path);

  res = lsetxattr(fpath, name, value, size, flags);
  if (res == -1)
    return -errno;
  return 0;
}

static int enc_getxattr(const char *path, const char *name, char *value, size_t size) {
  int res;
  char fpath[PATH_MAX];

  enc_fullpath(fpath, path);

  res = lgetxattr(fpath, name, value, size);
  if (res == -1)
    return -errno;
  return res;
}

static int enc_listxattr(const char *path, char *list, size_t size) {
  int res;
  char fpath[PATH_MAX];

  enc_fullpath(fpath, path);

  res = llistxattr(fpath, list, size);
  if (res == -1)
    return -errno;
  return res;
}

static int enc_removexattr(const char *path, const char *name) {
  int res;
  char fpath[PATH_MAX];

  enc_fullpath(fpath, path);

  res = lremovexattr(fpath, name);
  if (res == -1)
    return -errno;
  return 0;
}

void *enc_init(struct fuse_conn_info *conn) {
  (void) conn;
  return ENC_DATA;
}

/** Open directory
 *
 * This method should check if the open operation is permitted for
 * this  directory
 *
 * Introduced in version 2.3
 */
int enc_opendir(const char *path, struct fuse_file_info *fi) {
    DIR *dp;
    int retstat = 0;
    char fpath[PATH_MAX];

    enc_fullpath(fpath, path);

    dp = opendir(fpath);
    if (dp == NULL)
      retstat = enc_error("enc_opendir opendir");

    fi->fh = (intptr_t) dp;

    return retstat;
}

/**
 * Release directory
 */
int enc_releasedir(const char *path, struct fuse_file_info *fi) {
    int retstat = 0;
    (void) path;

    closedir((DIR *) (uintptr_t) fi->fh);

    return retstat;
}

void enc_usage() {
    fprintf(stderr, "usage:  encfs [FUSE and mount options] passPhrase rootDir mountPoint\n");
    abort();
}

static struct fuse_operations enc_oper = {
  .getattr	= enc_getattr,
  .access	= enc_access,
  .readlink	= enc_readlink,
  .readdir	= enc_readdir,
  .mknod	= enc_mknod,
  .mkdir	= enc_mkdir,
  .symlink	= enc_symlink,
  .unlink	= enc_unlink,
  .rmdir	= enc_rmdir,
  .rename	= enc_rename,
  .link		= enc_link,
  .chmod	= enc_chmod,
  .chown	= enc_chown,
  .truncate	= enc_truncate,
  .utimens	= enc_utimens,
  .open		= enc_open,
  .read		= enc_read,
  .write	= enc_write,
  .statfs	= enc_statfs,
  .create	= enc_create,
  .release	= enc_release,
  .fsync	= enc_fsync,
  .setxattr	= enc_setxattr,
  .getxattr	= enc_getxattr,
  .listxattr	= enc_listxattr,
  .removexattr	= enc_removexattr,
  .init		= enc_init,
  .releasedir	= enc_releasedir,
  .opendir	= enc_opendir
};

int main(int argc, char *argv[]) {
  umask(0);

  int fuse_stat;
  struct enc_state *enc_data;

  // from Pfeiffer - disallow root to run the file system
  //
  // bbfs doesn't do any access checking on its own (the comment
  // blocks in fuse.h mention some of the functions that need
  // accesses checked -- but note there are other functions, like
  // chown(), that also need checking!).  Since running bbfs as root
  // will therefore open Metrodome-sized holes in the system
  // security, we'll check if root is trying to mount the filesystem
  // and refuse if it is.  The somewhat smaller hole of an ordinary
  // user doing it with the allow_other flag is still there because
  // I don't want to parse the options string.
  if ((getuid() == 0) || (geteuid() == 0)) {
    fprintf(stderr, "Running ENCFS as root opens unnacceptable security holes\n");
    return 1;
  }

  // from Pfeiffer - a bit of command line parsing
  //
  // Perform some sanity checking on the command line:  make sure
  // there are enough arguments, and that neither of the last two
  // start with a hyphen (this will break if you actually have a
  // rootpoint or mountpoint whose name starts with a hyphen, but so
  // will a zillion other programs)
  //
  // also make sure the pass phrase (third to last argument) does
  // not start with a hyphen
  /* if ((argc < 4) || (argv[argc-3][0] == '-') || (argv[argc-2][0] == '-') || (argv[argc-1][0] == '-')) */
  /*   enc_usage(); */

  if ((argc < 3) || (argv[argc-2][0] == '-') || (argv[argc-1][0] == '-'))
    enc_usage();

  enc_data = malloc(sizeof(struct enc_state));
  if (enc_data == NULL) {
    perror("main calloc");
    abort();
  }

  // pull the pass phrase and rootdir out of the argument list
  enc_data->passPhrase = argv[argc-3];
  enc_data->rootdir = realpath(argv[argc-2], NULL);

  argv[argc-3] = argv[argc-1];
  argv[argc-2] = NULL;
  argv[argc-1] = NULL;
  argc -= 2;

  // turn over control to fuse
  fprintf(stderr, "about to call fuse_main\n");
  fuse_stat = fuse_main(argc, argv, &enc_oper, enc_data);
  fprintf(stderr, "fuse_main returned %d\n", fuse_stat);

  return fuse_stat;
}

