#ifndef TYPES_H
#define TYPES_H

#include <stddef.h>

struct flagables {
    char *strings;
    int warning_lvl;
};

struct pkg_metadata {
    int votes;
    int out_of_date;
    long first_submitted;
    long last_modified;
    char maintainer[64];
};

struct memory {
    char *data;
    size_t size;
};

struct suspicion {
    char *reason;
};

typedef struct {
    char bash[512];
    char zsh[512];
    char fish[512];
} rc_paths;

#endif
