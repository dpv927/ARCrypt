#include <linux/limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
#include <sys/stat.h>
#include "superkey.h"
#include "params.h"
#include "files.h"

int check_file(const char* path) 
{
  struct stat f_inode;
  struct stat d_inode;
  char cpy[PATH_MAX];
  char* parent;

  /* Check file details */
  if(!stat(path, &f_inode)) {
    if((f_inode.st_mode & S_IFMT) == S_IFDIR)
      return FileIsAFolder; 
    if(!(f_inode.st_mode & S_IRUSR))
      return FileNotReadPermission;
  } else { return FileNotExists; }

  /* Check parent folder details */
  strcpy(cpy, path);
  parent = dirname(cpy);
  stat(parent, &d_inode);
        
  if(!(d_inode.st_mode & S_IRUSR))
    return DirNotReadPermission;
  if(!(d_inode.st_mode & S_IWUSR))
    return DirNotWritePermission;
  return FileIsGood;
}

