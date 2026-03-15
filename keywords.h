#ifndef KEYWORDS_H
#define KEYWORDS_H

struct flagables keyphrases[] = {
    {" curl",                    5},
    {" wget",                    5},
    {"chmod+x /",               10},
    {"raw.githubusercontent.com", 7},
    {"-patched",                  3},
    {"-cracked",                  5},
    {"-unlock",                   5},
    {"| bash",                   10},
    {"| sh",                     10},
    {"eval",                      5},
    {"python -c",                 5},
    {"| bash",    10},
    {"| sh",      10},
    {"eval ",      8},
    {"python -c",  7},
    {"base64 -d",  8},
    {"md5sums=('')", 8},
    {"sha256sums=('')", 8},
};

int num_keywords = sizeof(keyphrases) / sizeof(keyphrases[0]);

#endif
