#ifndef _LOG_H_
#define _LOG_H_

#include "params.h"
#include <fuse.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

#define log_struct(st, field, format, typecast) \
  log_msg("    " #field " = " #format "\n", typecast st->field)

FILE *log_open(char path[PATH_MAX]);
void log_msg(const char *format, ...);
void log_conn(struct fuse_conn_info *conn);
void log_fi(struct fuse_file_info *fi);
void log_fuse_context(struct fuse_context *context);
void log_retstat(char *func, int retstat);
void log_stat(struct stat *si);
void log_statvfs(struct statvfs *sv);
int log_syscall(char *func, int retstat, int min_ret);
void log_utime(struct utimbuf *buf);

#endif