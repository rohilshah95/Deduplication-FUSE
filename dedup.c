/*
 * This project has been built over the Big Brother File System (BBFS) developed and distributed by : Joseph J. Pfeiffer, Jr., Ph.D. <pfeiffer@cs.nmsu.edu>
 * References : https://www.cs.nmsu.edu/~pfeiffer/fuse-tutorial/
*/

#include "params.h"
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fuse.h>
#include <ctype.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <openssl/evp.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include "log.h"

/* A utility function to open a databse */
sqlite3 *db_open(const char *database_path)
{
    sqlite3 *database;
    int rs = sqlite3_open(database_path, &database);
    if (rs)
    {
        sqlite3_close(database);
    }
    char *error = 0;
    char *query =
        "CREATE TABLE IF NOT EXISTS data("
        "filepath TEXT PRIMARY KEY ON CONFLICT FAIL,"
        "size INTEGER NOT NULL ON CONFLICT FAIL,"
        "sha TEXT NOT NULL ON CONFLICT FAIL,"
        "datapath TEXT NOT NULL ON CONFLICT FAIL,"
        "deduplication INTEGER NOT NULL ON CONFLICT FAIL"
        ");";

    rs = sqlite3_exec(database, query, NULL, 0, &error);
    return database;
}

/* Rettrieve from database */
int db_get(const char *database_path, struct database *entry)
{
    sqlite3 *map = BB_DATA->db;
    int present = 0;
    static sqlite3_stmt *stmt;

    sqlite3_prepare_v2(map, "SELECT * FROM data WHERE (filepath = ?1)", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, database_path, -1, SQLITE_TRANSIENT);
    int rs = sqlite3_step(stmt);
    if (rs == SQLITE_ROW)
    {
        strcpy(entry->filepath, (char *)sqlite3_column_text(stmt, 0));
        entry->size = sqlite3_column_int(stmt, 1);
        strcpy(entry->sha1, (char *)sqlite3_column_text(stmt, 2));
        strcpy(entry->datapath, (char *)sqlite3_column_text(stmt, 3));
        entry->duplicates = sqlite3_column_int(stmt, 4);
        present = 1;
    }
    sqlite3_finalize(stmt);
    return present;
}

/* Insert into the database */
int db_insert(const char *database_path, const char *shasum, const char *datapath, unsigned int size, int deduplication)
{
    sqlite3 *database = BB_DATA->db;
    static sqlite3_stmt *stmt;
    sqlite3_prepare_v2(database, "INSERT OR REPLACE INTO data VALUES ( ?1, ?2, ?3, ?4, ?5)", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, database_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, size);
    sqlite3_bind_text(stmt, 3, shasum, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, datapath, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, deduplication);
    int rs = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rs;
}

/* Retreive hash from database */
int db_digest(const char *hash, char *database_path, int *deduplication)
{
    sqlite3 *map = BB_DATA->db;
    static sqlite3_stmt *stmt;
    int present = 0;

    sqlite3_prepare_v2(map, "SELECT datapath,deduplication FROM data WHERE (sha = ?1)", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, hash, -1, SQLITE_TRANSIENT);
    int rs = sqlite3_step(stmt);
    if (rs == SQLITE_ROW)
    {
        strcpy(database_path, (char *)sqlite3_column_text(stmt, 0));
        *deduplication = sqlite3_column_int(stmt, 1);
        present = 1;
    }
    sqlite3_finalize(stmt);
    return present;
}

/* Increment the counter of deduplication */
void db_increment_duplicate(const char *hash)
{
    static sqlite3_stmt *stmt;
    sqlite3 *map = BB_DATA->db;
    sqlite3_prepare_v2(map, "UPDATE data SET deduplication = deduplication+1 WHERE (sha = ?1)", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, hash, -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

/* Decrement the counter of deduplication */
void db_decrement_duplicate(const char *hash)
{
    static sqlite3_stmt *stmt;
    sqlite3 *map = BB_DATA->db;
    sqlite3_prepare_v2(map, "UPDATE data SET deduplication = deduplication-1 WHERE (sha = ?1)", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, hash, -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

/* Remove database entry */
int db_remove(const char *path)
{
    sqlite3 *map = BB_DATA->db;
    static sqlite3_stmt *stmt;
    sqlite3_prepare_v2(map, "DELETE FROM data WHERE (filepath = ?1)", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_TRANSIENT);
    int rs = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    rs = 1;
    return rs;
}

/* Close the database */
int db_close(sqlite3 *database)
{
    return sqlite3_close(database);
}

/* Create a map for open files */
sqlite3 *map_open()
{
    sqlite3 *map;
    char *error = 0;
    int rs = sqlite3_open(":memory:", &map);
    if (rs!=0)
    {
        sqlite3_close(map);
        abort();
    }
    char *query =
        "CREATE TABLE IF NOT EXISTS map("
        "filehandler INTEGER PRIMARY KEY,"
        "duplicates INTEGER DEFAULT 0,"
        "modified INTEGER DEFAULT 0,"
        "filepath TEXT NOT NULL"
        ");";
    if (sqlite3_exec(map, query, NULL, 0, &error) != SQLITE_OK)
    {
        sqlite3_free(error);
        abort();
    }
    return map;
}

/* Close the map */
int map_close()
{
    return sqlite3_close(BB_DATA->map);
}

/* Indicate that the file has been modified */
void map_set_modified(unsigned long long int filehandler)
{
    sqlite3 *map = BB_DATA->map;
    char *error, *query;
    asprintf(&query, "UPDATE map SET modified = 1 WHERE filehandler=%llu", filehandler);
    if (sqlite3_exec(map, query, NULL, 0, &error) != SQLITE_OK)
    {
        sqlite3_free(error);
    }
    free(query);
}

/* Insert into map */
int map_add(unsigned long long int fh, const char *path, char modified,int deduplication )
{
    sqlite3 *map = BB_DATA->map;
    static sqlite3_stmt *stmt;
    sqlite3_prepare_v2(map, "INSERT INTO map VALUES ( ?1, ?2, ?3, ?4)", -1, &stmt, NULL);
    sqlite3_bind_int64(stmt, 1, fh);
    sqlite3_bind_int(stmt, 2, deduplication);
    sqlite3_bind_int(stmt, 3, modified);
    sqlite3_bind_text(stmt, 4, path, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE)
    {
        int rs=0;
        return rs;
    }
    sqlite3_finalize(stmt);
    return 1;
}

/* Retrieve from map */
int map_extract(unsigned long long int fh, struct memorymap *entry)
{
    sqlite3 *map = BB_DATA->map;
    static sqlite3_stmt *stmt_select, *stmt_delete;
    int present = 0;

    sqlite3_prepare_v2(map, "SELECT * FROM map WHERE (filehandler = ?1)", -1, &stmt_select, NULL);
    sqlite3_bind_int64(stmt_select, 1, fh);
    if (sqlite3_step(stmt_select) == SQLITE_ROW)
    {
        entry->fh = sqlite3_column_int64(stmt_select, 0);
        entry->duplicates = sqlite3_column_int(stmt_select, 1);
        entry->modified = sqlite3_column_int(stmt_select, 2);
        strcpy(entry->filepath, (char *)sqlite3_column_text(stmt_select, 3));
        sqlite3_prepare_v2(map, "DELETE FROM map WHERE (filehandler = ?1)", -1, &stmt_delete, NULL);
        sqlite3_bind_int64(stmt_delete, 1, fh);
        sqlite3_step(stmt_delete);
        sqlite3_finalize(stmt_delete);
        present = 1;
    }
    sqlite3_finalize(stmt_select);
    return present;
}

/* Count occurences in map */
int map_count(const char *path)
{
    sqlite3 *map = BB_DATA->map;
    int count;
    static sqlite3_stmt *stmt_count;
    sqlite3_prepare_v2(map, "SELECT COUNT(filehandler) FROM map WHERE (filepath = ?1)", -1, &stmt_count, NULL);
    sqlite3_bind_text(stmt_count, 1, path, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt_count) == SQLITE_ROW)
    {
        count = sqlite3_column_int(stmt_count, 0);
    }
    else if (sqlite3_step(stmt_count) != SQLITE_DONE)
    {
        count = -1;
    }
    sqlite3_finalize(stmt_count);
    return count;
}

/* Update the new datapath in the database */
void db_rename(const char *database_path, const char *newpath)
{
    sqlite3 *db = BB_DATA->db;
    char *error = 0, *query;
    asprintf(&query, "UPDATE data SET filepath = '%s' WHERE filepath = '%s' ;",newpath, database_path);
    if (sqlite3_exec(db, query, NULL, 0, &error) != SQLITE_OK)
    {
        sqlite3_free(error);
    }
    free(query);
}

/* Create a two-level hierarchical folder structure */
static void prepare_datapath(char *hash, char *datapath)
{
    sprintf(datapath, "%s/.deduplication/hash/%c/", BB_DATA->rootdir, hash[0]);
    mkdir(datapath, 0777); // We Create the directory for X
    sprintf(datapath, "%s%c/", datapath, hash[1]);
    mkdir(datapath, 0777); // We create the directory for Y
    sprintf(datapath, "/.deduplication/hash/%c/%c/%s", hash[0], hash[1], hash);
}

/* Calculate the hash in chunks of 8kb */
static void calculate_hash(const char *path, char *hashOut, unsigned int *size)
{
    ssize_t readfile=1;
    unsigned int hashvalue, i;
    int fd;
    unsigned char sha1[20];
    char buffer[8192], *result;
    *size = 0;
    EVP_MD_CTX *context = EVP_MD_CTX_create();
    EVP_DigestInit_ex(context, EVP_sha1(), NULL);
    fd = open(path, O_RDONLY);
    lseek(fd, 0, SEEK_SET);
    readfile = read(fd, buffer, 8192);
    if (readfile >= 0)
    {
        EVP_DigestUpdate(context, buffer, readfile);
        *size += readfile;
        do 
        {
            if (readfile!=8192)
                break;
            readfile = read(fd, buffer, 8192);
            EVP_DigestUpdate(context, buffer, readfile);
            *size += readfile;
        } while (readfile == 8192);
    }
    close(fd);
    EVP_DigestFinal_ex(context, sha1, &hashvalue);
    EVP_MD_CTX_destroy(context);

    result = hashOut;
    for (i = 0; i < hashvalue; i++, result+=2)
    {
        sprintf(result, "%02x", sha1[i]);
    }
    result[0] = 0;
}

/* Copy file into data block */
static void copyfile(const char *s, const char *d)
{
    unsigned char buffer[8192];
    int source, destination, readfile;
    source = open(s, 0444);
    destination = creat(d, 0777);
    readfile = read(source, buffer, 8192);
    write(destination, buffer, readfile);
    do 
    {
        if(readfile!=8192)
            break;
        readfile = read(source, buffer, 8192);
        write(destination, buffer, readfile);
    } while (readfile == 8192);
    close(source);
    close(destination);
}

/* Get the complete path, function in BBFS */
static void bb_fullpath(char fpath[PATH_MAX], const char *path)
{
    printf("fullpath called\n");
    strcpy(fpath, BB_DATA->rootdir);
    strncat(fpath, path, PATH_MAX);
    printf("fullpath: %s\n", fpath);
}

/* Read natural links of the files, function in BBFS */
int bb_readlink(const char *path, char *link, size_t size)
{
    int retstat = 0;
    char fpath[PATH_MAX];

    bb_fullpath(fpath, path);

    retstat = readlink(fpath, link, size - 1);
    if (retstat < 0)
        retstat = -errno;
    else
    {
        link[retstat] = '\0';
        retstat = 0;
    }

    return retstat;
}

/* Get the file attributes, function in BBFS */
int bb_getattr(const char *path, struct stat *statbuf)
{
    int retstat = 0;
    char fpath[PATH_MAX];
    struct database input;

    bb_fullpath(fpath, path);

    retstat = lstat(fpath, statbuf);
    int db = db_get(path, &input);
     if (retstat != 0)
        retstat = -errno;

    if (db)
    {
        if(input.size>0)
        {
            statbuf->st_blocks = (input.size / 8192 + (input.size % 8192 > 0)) * 8;
            statbuf->st_size = input.size;
        }
    }
    log_stat(statbuf);

    return retstat;
}

/* Create new node, function in BBFS */
int bb_mknod(const char *path, mode_t mode, dev_t dev)
{
    int retstat = 0;
    char fpath[PATH_MAX];

    bb_fullpath(fpath, path);

    if (S_ISREG(mode))
    {
        retstat = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
        if (retstat < 0)
            retstat = -errno;
        else
        {
            retstat = close(retstat);
            if (retstat < 0)
                retstat = -errno;
        }
    }
    else if (S_ISFIFO(mode))
    {
        retstat = mkfifo(fpath, mode);
        if (retstat < 0)
            retstat = -errno;
    }
    else
    {
        retstat = mknod(fpath, mode, dev);
        if (retstat < 0)
            retstat = -errno;
    }

    return retstat;
}

/* Create new directory, function in BBFS */
int bb_mkdir(const char *path, mode_t mode)
{
    int retstat = 0;
    char fpath[PATH_MAX];

    bb_fullpath(fpath, path);

    retstat = mkdir(fpath, mode);
    if (retstat < 0)
        retstat = -errno;

    return retstat;
}

/* Remove directory, function in BBFS */
int bb_rmdir(const char *path)
{
    int retstat = 0;
    char fpath[PATH_MAX];

    bb_fullpath(fpath, path);

    retstat = rmdir(fpath);
    if (retstat < 0)
        retstat = -errno;

    return retstat;
}

/* Rename file, function in BBFS */
int bb_rename(const char *path, const char *newpath)
{
    int retstat = 0;
    char fpath[PATH_MAX];
    char fnewpath[PATH_MAX];

    bb_fullpath(fpath, path);
    bb_fullpath(fnewpath, newpath);

    retstat = rename(fpath, fnewpath);
    if (retstat >= 0)
        db_rename(path, newpath);
    else
        retstat=-errno;
    return retstat;
}

/* Create new symlink, function in BBFS */
int bb_symlink(const char *path, const char *link)
{
    int retstat = 0;
    char flink[PATH_MAX];

    bb_fullpath(flink, link);

    retstat = symlink(path, flink);
    if (retstat < 0)
        retstat = -errno;

    return retstat;
}

/* Link files, function in BBFS */
int bb_link(const char *path, const char *newpath)
{
    int retstat = 0;
    char fpath[PATH_MAX], fnewpath[PATH_MAX];

    bb_fullpath(fpath, path);
    bb_fullpath(fnewpath, newpath);

    retstat = link(fpath, fnewpath);
    if (retstat < 0)
        retstat = -errno;
    
    return retstat;
}

/* Unlink files, function in BBFS */
int bb_unlink(const char *path)
{
    int retstat = 0;
    char fpath[PATH_MAX];

    bb_fullpath(fpath, path);

    retstat = unlink(fpath);
    if (retstat < 0)
    {
        retstat = -errno;
    }
    else
    {
        struct database input;
        if (db_get(path, &input))
        {
                db_remove(path);
                /* If the file is not deduplicated, the data is deleted */
                if (input.duplicates == 0)
                {
                    bb_fullpath(fpath, input.datapath);
                    unlink(fpath);
                }
                else
                { 
                    /* If the file is deduplicated, counter is decremented */
                    db_decrement_duplicate(input.sha1);
                }
            
        }
    }

    return retstat;
}

/* Access rights, function from BBFS */
int bb_chmod(const char *path, mode_t mode)
{
    int retstat = 0;
    char fpath[PATH_MAX];

    bb_fullpath(fpath, path);

    retstat = chmod(fpath, mode);
    if (retstat < 0)
        retstat = -errno;

    return retstat;
}

/* Owner rights, function from BBFS */
int bb_chown(const char *path, uid_t uid, gid_t gid)
{
    int retstat = 0;
    char fpath[PATH_MAX];

    bb_fullpath(fpath, path);

    retstat = chown(fpath, uid, gid);
    if (retstat < 0)
        retstat = -errno;

    return retstat;
}

int bb_fgetattr(const char *path, struct stat *statbuf, struct fuse_file_info *fi)
{
    int retstat = 0;
    log_fi(fi);

    retstat = fstat(fi->fh, statbuf);
    if (retstat < 0)
    {
        retstat = -errno;
        return retstat;
    }
    
    log_stat(statbuf);

    return retstat;
}

/* Update time, function from BBFS */
int bb_utime(const char *path, struct utimbuf *ubuf)
{
    int retstat = 0;
    char fpath[PATH_MAX];

    bb_fullpath(fpath, path);

    retstat = utime(fpath, ubuf);
    if (retstat < 0)
        retstat = -errno;

    return retstat;
}

/* Open file, function from BBFS */
int bb_open(const char *path, struct fuse_file_info *fi)
{
    int fd;
    char fpath[PATH_MAX];
    struct database input;
    int retstat = 0;
    char writeval = 0;

    /* We check if marker can be opened */
    bb_fullpath(fpath, path);
    fd = open(fpath, fi->flags);
    if (fd == -1)
    {
        //It does not open
        retstat = -errno;
        return retstat;
    }
    else
    {
        /* Continue if opened properly */
        close(fd);
        fd = 0;
        retstat = 0;
    }

    if ((fi->flags & O_RDWR) == O_RDWR || (fi->flags & O_WRONLY) == O_WRONLY)
    {
        writeval = 1;
    }

    int db = db_get(path, &input);

    if (db)
    {
        bb_fullpath(fpath, input.datapath);
        if (writeval==1)
        {
            if (input.duplicates > 0)
            {
                if (map_count(path) != 0)
                {
                    strcat(fpath, "w");
                }
                else
                {
                    char *oldfpath = strdup(fpath);
                    strcat(fpath, "w");
                    copyfile(oldfpath, fpath);
                    free(oldfpath);
                }
            }
        }
    }
    else
    {
        bb_fullpath(fpath, path);
        input.duplicates = 0; 
    }
    fd = open(fpath, fi->flags);
    fi->fh = fd;
    log_fi(fi);
    if (fd < 0)
        retstat = -errno;
    
    if (writeval==1)
    {
        map_add(fi->fh, path, 0, input.duplicates);
    }

    return retstat;
}

/* Read file, function from BBFS */
int bb_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    int retstat = 0;

    log_fi(fi);

    retstat = pread(fi->fh, buf, size, offset);
    if (retstat < 0)
        retstat = -errno;

    return retstat;
}

/* Close directory */
int bb_releasedir(const char *path, struct fuse_file_info *fi)
{
    int retstat = 0;

    log_fi(fi);

    closedir((DIR *)(uintptr_t)fi->fh);

    return retstat;
}

/* Write file, function from BBFS */
int bb_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    int retstat = 0;

    log_fi(fi);

    retstat = pwrite(fi->fh, buf, size, offset);
    if (retstat < 0)
        retstat = -errno;

    map_set_modified(fi->fh);

    return retstat;
}

/* Get file stats, function from BBFS */
int bb_statfs(const char *path, struct statvfs *statv)
{
    int retstat = 0;
    char fpath[PATH_MAX];

    bb_fullpath(fpath, path);

    retstat = statvfs(fpath, statv);
    if (retstat < 0)
        retstat = -errno;

    log_statvfs(statv);

    return retstat;
}


int bb_flush(const char *path, struct fuse_file_info *fi)
{
    int retstat = 0;

    log_fi(fi);

    return retstat;
}

/* 
    Close the file, function from BBFS 
    Most important function of the project
*/
int bb_release(const char *path, struct fuse_file_info *fi)
{
    int retstat = 0;
    struct memorymap inputmap;
    char newhash[41];
    log_fi(fi);
 
    retstat = close(fi->fh);
    char *fpath = malloc(PATH_MAX);
    bb_fullpath(fpath, path);
    utime(fpath, NULL);
    free(fpath);
    if (map_extract(fi->fh, &inputmap) && inputmap.modified)
    { 
        unsigned int size;
        struct database inputdb;
        char actual[PATH_MAX];
        char hashlocation[PATH_MAX];
        if (db_get(path, &inputdb))
        {
            if (inputmap.duplicates > 0)
            {
                strcat(inputdb.datapath, "w");
            }
            bb_fullpath(hashlocation, inputdb.datapath);
            calculate_hash(hashlocation, newhash, &size);
            if (size == 0 && inputdb.duplicates > 0)
            {
                db_remove(path);
                db_decrement_duplicate(inputdb.sha1);
            }
            else if (size == 0)
            {
                unlink(hashlocation);
            }
            else if (strcmp(inputdb.sha1, newhash))
            {
                if (db_digest(newhash, inputdb.datapath, &(inputdb.duplicates)))
                {
                    db_insert(path, newhash, inputdb.datapath, size, inputdb.duplicates);
                    db_increment_duplicate(newhash);
                    unlink(hashlocation);
                }
                else
                {
                    prepare_datapath(newhash, inputdb.datapath);
                    char *newdatapath = actual; 
                    bb_fullpath(newdatapath, inputdb.datapath);
                    db_insert(path, newhash, inputdb.datapath, size, 0);
                    if (rename(hashlocation, newdatapath))
                    {
                        retstat=-errno;
                    }
                }
                db_decrement_duplicate(inputdb.sha1);
            }
        }
        else
        {
            bb_fullpath(actual, path);
            calculate_hash(actual, newhash, &size);
            if (size > 0)
            { 
                if (db_digest(newhash, inputdb.datapath, &(inputdb.duplicates)))
                {
                    
                    db_insert(path, newhash, inputdb.datapath, size, inputdb.duplicates);
                    db_increment_duplicate(newhash);
                  
                    truncate(actual, 0);
                }
                else
                {
                    
                    int fd;
                    struct stat *prestat = malloc(sizeof(struct stat));
                    if (stat(actual, prestat))
                    {
                        retstat=-errno;
                    }
                    
                    prepare_datapath(newhash, inputdb.datapath);
                    bb_fullpath(hashlocation, inputdb.datapath);
                    if (rename(actual, hashlocation))
                    {
                        retstat=-errno;
                    }
                    fd = creat(actual, prestat->st_mode);
                    if (fd == -1)
                    {
                        retstat=-errno;
                    }
                    close(fd);
                    free(prestat);
                    db_insert(path, newhash, inputdb.datapath, size, 0);
                }
            }
        }
    }
    return retstat;
}

void bb_usage()
{
    fprintf(stderr, "usage:  ./dedup -s [FUSE and mount options] rootDir mountPoint\n");
    abort();
}

int bb_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
    char fpath[PATH_MAX];

    bb_fullpath(fpath, path);

    return (lsetxattr(fpath, name, value, size, flags));
}

/* Utility function from BBFS */
int bb_fsync(const char *path, int datasync, struct fuse_file_info *fi)
{
    int retstat = 0;

    log_fi(fi);

    if (datasync)
        retstat = fdatasync(fi->fh);
    else
        retstat = fsync(fi->fh);

    if (retstat < 0)
        retstat = -errno;
    return retstat;
}

int bb_getxattr(const char *path, const char *name, char *value, size_t size)
{
    char fpath[PATH_MAX];

    bb_fullpath(fpath, path);

    return (lgetxattr(fpath, name, value, size));
}

int bb_listxattr(const char *path, char *list, size_t size)
{
    char fpath[PATH_MAX];

    bb_fullpath(fpath, path);

    return (llistxattr(fpath, list, size));
}

int bb_removexattr(const char *path, const char *name)
{
    int retstat = 0;
    char fpath[PATH_MAX];

    bb_fullpath(fpath, path);

    retstat = lremovexattr(fpath, name);
    if (retstat < 0)
        retstat = -errno;

    return retstat;
}

int bb_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
               struct fuse_file_info *fi)
{
    int retstat = 0;
    DIR *dp;
    struct dirent *de;

    dp = (DIR *)(uintptr_t)fi->fh;
    
    de = readdir(dp);
    if (de == 0)
    {
        return -errno;
    }

    do
    {
        if (filler(buf, de->d_name, NULL, 0) != 0)
        {
            return -ENOMEM;
        }
    } while ((de = readdir(dp)) != NULL);

    log_fi(fi);

    return retstat;
}

int bb_opendir(const char *path, struct fuse_file_info *fi)
{
    DIR *dp;
    int retstat = 0;
    char fpath[PATH_MAX];

    bb_fullpath(fpath, path);

    dp = opendir(fpath);
    if (dp == NULL)
        retstat = -errno;
    fi->fh = (intptr_t)dp;
    log_fi(fi);
    return retstat;
}

int bb_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi)
{
    int retstat = 0;

    log_fi(fi);

    return retstat;
}

/* Initialise the deduplication directory */
void *bb_init(struct fuse_conn_info *conn)
{
    
    char *database;
    database = malloc(sizeof(char) * PATH_MAX);
    struct bb_state *bb_data = BB_DATA;
    //Open the Database
    bb_fullpath(database, "/.deduplication/dedup.db");
    printf("Dedup.db path: %s\n", database);
    bb_data->db = db_open(database);
    free(database);
    bb_data->map = map_open();
    return bb_data;
}

void bb_destroy(void *userdata)
{
    map_close(BB_DATA->map);
    db_close(BB_DATA->db);
}

int bb_access(const char *path, int mask)
{
    char fpath[PATH_MAX];

    bb_fullpath(fpath, path);

    return (access(fpath, mask));
}

int bb_ftruncate(const char *path, off_t offset, struct fuse_file_info *fi)
{
    log_fi(fi);

    map_set_modified(fi->fh);

    return (ftruncate(fi->fh, offset));
}

int bb_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    int retstat = 0;
    char fpath[PATH_MAX];
    int fd;

    bb_fullpath(fpath, path);

    fd = creat(fpath, mode);
    if (fd < 0)
        retstat = -errno;

    fi->fh = fd;

    log_fi(fi);

    map_add(fi->fh, path, 0, 0);

    return retstat;
}


int bb_truncate(const char *path, off_t newsize)
{
    int retstat = 0;

    struct fuse_file_info *fi = malloc(sizeof(struct fuse_file_info));
    fi->flags = O_RDWR;
    retstat = bb_open(path, fi);
    if (retstat == 0)
    {
        log_fi(fi);
        map_set_modified(fi->fh);
        retstat = ftruncate(fi->fh, newsize);
        if (retstat == 0)
        {
            retstat = bb_release(path, fi);
        }
    }
    free(fi);

    if (retstat < 0)
    {
        retstat=-errno;
        close(fi->fh);
    }

    return retstat;
}



/* Implementation of fuse operations */
struct fuse_operations bb_oper = {
    .getattr = bb_getattr,
    .readlink = bb_readlink,
    .mknod = bb_mknod,
    .mkdir = bb_mkdir,
    .rmdir = bb_rmdir,
    .symlink = bb_symlink,
    .rename = bb_rename,
    .link = bb_link,
    .unlink = bb_unlink,
    .chmod = bb_chmod,
    .chown = bb_chown,
    .truncate = bb_truncate,
    .utime = bb_utime,
    .open = bb_open,
    .read = bb_read,
    .write = bb_write,
    .statfs = bb_statfs,
    .flush = bb_flush,
    .release = bb_release,
    .fsync = bb_fsync,
    .setxattr = bb_setxattr,
    .getxattr = bb_getxattr,
    .listxattr = bb_listxattr,
    .removexattr = bb_removexattr,
    .opendir = bb_opendir,
    .readdir = bb_readdir,
    .releasedir = bb_releasedir,
    .fsyncdir = bb_fsyncdir,
    .init = bb_init,
    .destroy = bb_destroy,
    .access = bb_access,
    .create = bb_create,
    .ftruncate = bb_ftruncate,
    .fgetattr = bb_fgetattr
};



/* Check if the dedupuplication directory exists in the directory tree and create it if it does not exist */
static void create_dedup_dir(char rootdir[PATH_MAX])
{
    char *destination = malloc(sizeof(char) * PATH_MAX);
    char *hash = malloc(sizeof(char) * PATH_MAX);
    struct stat s;
    strcpy(destination, rootdir);
    strcpy(hash, rootdir);
    strncat(destination, "/.deduplication", PATH_MAX);
    strncat(hash, "/.deduplication/hash", PATH_MAX);
    if (stat(destination, &s)== -1)
    {
        mkdir(destination, 0777);
        mkdir(hash, 0777);
    }
    fprintf(stderr, "Dedup directory: %s\n", hash);
    free(destination);
    free(hash);
}

int main(int argc, char *argv[])
{
    int fuse_stat;
    struct bb_state *bb_data;

    if ((getuid() == 0) || (geteuid() == 0))
    {
        fprintf(stderr, "Running BBFS as root opens unnacceptable security holes\n");
        return 1;
    }

    /* Check arguments */
    if ((argc < 3) || (argv[argc - 2][0] == '-') || (argv[argc - 1][0] == '-'))
        bb_usage();

    bb_data = malloc(sizeof(struct bb_state));
    if (bb_data == NULL)
    {
        perror("main calloc");
        abort();
    }
    bb_data->logfile = log_open("log.log");
    bb_data->rootdir = realpath(argv[argc - 2], NULL);
    create_dedup_dir(bb_data->rootdir);
    fprintf(stderr, "Deduplication directory: %s\n", realpath(argv[argc - 2], NULL));
    argv[argc - 2] = argv[argc - 1];
    argv[argc - 1] = NULL;
    argc--;

    fprintf(stderr, "about to call fuse_main\n");
    fuse_stat = fuse_main(argc, argv, &bb_oper, bb_data);
    fprintf(stderr, "fuse_main returned %d\n", fuse_stat);

    return fuse_stat;
}