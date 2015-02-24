//Kara James
//PA 4
//mount: ./file cryptphrase mirror mount
//make new file: 		touch <filename>
//add text to file:		echo text >> <filename>
//print to cmd:			cat file

#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#define _POSIX_C_SOURCE 200809L
#endif

#include <ctype.h>
#include <libgen.h>
#include <sys/types.h>
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <stdlib.h>
#include <linux/limits.h>

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include "aes-crypt.h"
#include "params.h"

#define ENCRYPT 1
#define DECRYPT 0
#define PASS -1

#define XATTR_ENCRYPTED "user.encrypted"
#define ENCRYPTED "true"
#define UNENCRYPTED "false"

//append root-to-mount to the front of every path = fullpath
static void bb_fullpath(char fpath[PATH_MAX], const char *path)
{
    strcpy(fpath, BB_DATA->rootdir);
    strncat(fpath, path, PATH_MAX); 
}

//fullpathed
static int xmp_getattr(const char *path, struct stat *stbuf)
{
	int res;
	char fpath[PATH_MAX];
    
    bb_fullpath(fpath, path);
	
	res = lstat(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

//fullpathed
static int xmp_access(const char *path, int mask)
{
	int res;
	char fpath[PATH_MAX];
    
    bb_fullpath(fpath, path);
	res = access(fpath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

//fullpathed
static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res;
	char fpath[PATH_MAX];
    
    bb_fullpath(fpath, path);
	res = readlink(fpath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}

//fullpathed
static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;
	char fpath[PATH_MAX];
    
    bb_fullpath(fpath, path);
	dp = opendir(fpath);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

//fullpathed
static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;
	char fpath[PATH_MAX];
    
    bb_fullpath(fpath, path);
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

//fullpathed
static int xmp_mkdir(const char *path, mode_t mode)
{
	int res;
	char fpath[PATH_MAX];
    
    bb_fullpath(fpath, path);
	res = mkdir(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

//fullpathed
static int xmp_unlink(const char *path)
{
	int res;
	char fpath[PATH_MAX];
    
    bb_fullpath(fpath, path);
	res = unlink(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

//fullpathed
static int xmp_rmdir(const char *path)
{
	int res;
	char fpath[PATH_MAX];
    
    bb_fullpath(fpath, path);
	res = rmdir(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

//fullpathed
static int xmp_symlink(const char *from, const char *to)
{
	int res;
	
	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

//fullpathed
static int xmp_rename(const char *from, const char *to)
{
	int res;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

//fullpathed
static int xmp_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

//fullpathed
static int xmp_chmod(const char *path, mode_t mode)
{
	int res;
	char fpath[PATH_MAX];
    
    bb_fullpath(fpath, path);
	res = chmod(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

//fullpathed
static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;
	char fpath[PATH_MAX];
    
    bb_fullpath(fpath, path);
	res = lchown(fpath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

//fullpathed
static int xmp_truncate(const char *path, off_t size)
{
	int res;
	char fpath[PATH_MAX];
    
    bb_fullpath(fpath, path);
	res = truncate(fpath, size);
	if (res == -1)
		return -errno;

	return 0;
}

//fullpathed
static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];
	char fpath[PATH_MAX];
    
    bb_fullpath(fpath, path);
	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(fpath, tv);
	if (res == -1)
		return -errno;

	return 0;
}

//fullpathed
static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int res;
	char fpath[PATH_MAX];
    
    bb_fullpath(fpath, path);
	res = open(fpath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

//fullpathed
static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{   		
	FILE *fp, *memfp;
	char *memdata;
	size_t memsize;
	int res;
	char fpath[PATH_MAX];
	bb_fullpath(fpath, path);

	int crypt_action = PASS;
	char xattr_value[8];
	ssize_t xattr_len;
    //open the file for reading 
	(void) fi;
	fp = fopen(fpath, "r");
	if (fp == NULL)
		return -errno;
	//open an in-memory 'file'
	memfp = open_memstream(&memdata, &memsize);
	if (memfp == NULL)
		return -errno;
	//read file's flag to see if need to be decrypted
	xattr_len = getxattr(fpath, XATTR_ENCRYPTED, xattr_value, 8);
	if(xattr_len != -1 && !memcmp(xattr_value, ENCRYPTED, 4))
		crypt_action = DECRYPT; 
	//decrypt the file's bytes into the in-memory 'file'
	do_crypt(fp, memfp, crypt_action, BB_DATA->passphrase);
	fclose(fp);
	
	fflush(memfp);
	fseek(memfp, offset, SEEK_SET);
	//read the decrypted bytes into the buffer param
	res = fread(buf, 1, size, memfp);
	if (res == -1)
		res = -errno;

	fclose(memfp);

	return res;
}

//fullpathed
static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{	
	//open the file for reading so we can get its bytes, unencrypted, in memory
	//open an in-memory 'file'
	//check the file's xattr to see if we're decrypting it
	//decrypt file into memfile, or pass through if not encrypted, and
	//also into memory
	//add the bytes in buf to the in-memory 'file'
	//if we decrypted when opening the file, switch to encrypting
	//re-open real file for writing, add new contents & encrypt
	int res;
	FILE *fp, *memfp;
	char *memdata;
	size_t memsize;
	char fpath[PATH_MAX];
	bb_fullpath(fpath, path);
	int crypt_action = PASS;
    char xattr_value[8];
    ssize_t xattr_len;
  
	(void) fi;

	fp = fopen(fpath, "r");
	if (fp == NULL){
		return -errno;
	}

	memfp = open_memstream(&memdata, &memsize);
	if (memfp == NULL) {
		return -errno;
	}

	xattr_len = getxattr(fpath, XATTR_ENCRYPTED, xattr_value, 8);
	if(xattr_len != -1 && !memcmp(xattr_value, ENCRYPTED, 4))
		crypt_action = DECRYPT; 

	// decrypt file into memfile
	do_crypt(fp, memfp, crypt_action, BB_DATA->passphrase);
	fclose(fp);

	// add buffer to memfile
	fseek(memfp, offset, SEEK_SET);
	res = fwrite(buf, 1, size, memfp);
	if (res == -1)
		res = -errno;
	fflush(memfp);

    if (crypt_action == DECRYPT) 
		crypt_action = ENCRYPT;
    
		// reopen file for writing, encrypt contents of memfile
		// into file
	fp = fopen(fpath, "w");
	fseek(memfp, 0, SEEK_SET);
	do_crypt(memfp, fp, crypt_action, BB_DATA->passphrase);

	fclose(memfp);
	fclose(fp);

	return res;
}

//fullpathed
static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;
	char fpath[PATH_MAX];
    
    bb_fullpath(fpath, path);
	res = statvfs(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

//fullpathed
static int xmp_create(const char* path, mode_t mode, struct fuse_file_info* fi) {

    (void) fi;
	char fpath[PATH_MAX];
    
    bb_fullpath(fpath, path);
    
    FILE *fp;
    
    int res;
    res = creat(fpath, mode);
    if(res == -1)
		return -errno;
	fp =fdopen(res, "w");
	close(res);
	do_crypt(fp, fp, ENCRYPT, BB_DATA->passphrase);
	fclose(fp);

	if (setxattr(fpath, XATTR_ENCRYPTED, ENCRYPTED, 4, 0)){
		return -errno;
	}

    return 0;
}


static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_SETXATTR
//fullpathed
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	char fpath[PATH_MAX];
    
    bb_fullpath(fpath, path);
	int res = lsetxattr(fpath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

//fullpathed
static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	char fpath[PATH_MAX];
    
    bb_fullpath(fpath, path);
	int res = lgetxattr(fpath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

//fullpathed
static int xmp_listxattr(const char *path, char *list, size_t size)
{
	char fpath[PATH_MAX];
    
    bb_fullpath(fpath, path);
	int res = llistxattr(fpath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

//fullpathed
static int xmp_removexattr(const char *path, const char *name)
{
	char fpath[PATH_MAX];
    
    bb_fullpath(fpath, path);
	int res = lremovexattr(fpath, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations xmp_oper = {
	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
	.utimens	= xmp_utimens,
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.create         = xmp_create,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
};

int main(int argc, char *argv[])
{
	//pull passphrase and root directory out
    //send to fuse GO!
	umask(0);
	
	struct bb_state *bb_data;
    bb_data = malloc(sizeof(struct bb_state));
	if (bb_data == NULL) {
		perror("main calloc");
		abort();
    }
    
	bb_data->rootdir = realpath(argv[argc-2], NULL);
	bb_data->passphrase = argv[argc-3];
	argv[argc-3] = argv[argc-1];
    argv[argc-2] = NULL;
    argv[argc-1] = NULL;
    argc-= 2;
	return fuse_main(argc, argv, &xmp_oper, bb_data);
}
