#ifndef _PARAMS_H_
#define _PARAMS_H_


// The FUSE API has been changed a number of times.  So, our code
// needs to define the version of the API that we assume.  As of this
// writing, the most current API version is 26
#define FUSE_USE_VERSION 26

// need this to get pwrite().  I have to use setvbuf() instead of
// setlinebuf() later in consequence.
#define _XOPEN_SOURCE 500

// maintain bbfs state in here
#include <limits.h>
#include <stdio.h>

struct memorymap
{
    unsigned long long int fh;
    int duplicates;
    char modified;
    char filepath[PATH_MAX];
};

struct database
{
    char filepath[PATH_MAX];
    char datapath[PATH_MAX];
    unsigned int size;
    char sha1[41];
    int duplicates;
};

struct bb_state
{
    FILE *logfile;
    char *rootdir;
    void *db;       // Database that stores the information of the files
    void *map; // Map that manages the open files for writing
};


#define BB_DATA ((struct bb_state *)fuse_get_context()->private_data)

#endif