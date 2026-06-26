#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <sys/wait.h>
#include <cjson/cJSON.h>
#include "types.h"
#include <time.h>
#include <unistd.h>

#define RESET   "\033[0m"
#define RED     "\033[31m"
#define YELLOW  "\033[33m"
#define GREEN   "\033[32m"
#define CYAN    "\033[36m"
#define BOLD    "\033[1m"

#define HOOK_MARKER_START "# [pkgscan] shell hook"
#define HOOK_MARKER_END   "# [pkgscan] end"

void hook_disable(const char *home);

static void resolve_rc_paths(const char *home, rc_paths *paths) {
    snprintf(paths->bash, sizeof(paths->bash), "%s/.bashrc",                  home);
    snprintf(paths->zsh,  sizeof(paths->zsh),  "%s/.zshrc",                   home);
    snprintf(paths->fish, sizeof(paths->fish), "%s/.config/fish/config.fish", home);
}

static int hook_present(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char *line = NULL;
    size_t cap = 0;
    int found = 0;
    while (getline(&line, &cap, f) != -1)
        if (strncmp(line, HOOK_MARKER_START, strlen(HOOK_MARKER_START)) == 0) { found = 1; break; }
    free(line);
    fclose(f);
    return found;
}

static int hook_strip(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.pkgscan_tmp", path);
    FILE *tmp = fopen(tmp_path, "w");
    if (!tmp) { perror(tmp_path); fclose(f); return -1; }
    int in_block = 0;
    char *line = NULL;
    size_t cap = 0;
    while (getline(&line, &cap, f) != -1) {
        if (strncmp(line, HOOK_MARKER_START, strlen(HOOK_MARKER_START)) == 0) { in_block = 1; continue; }
        if (in_block && strncmp(line, HOOK_MARKER_END, strlen(HOOK_MARKER_END)) == 0) { in_block = 0; continue; }
        if (!in_block) fputs(line, tmp);
    }
    free(line);
    fclose(f);
    fflush(tmp);
    fsync(fileno(tmp));
    fclose(tmp);

    if (rename(tmp_path, path) != 0) {
        perror(tmp_path);
        remove(tmp_path);
        return -1;
    }
    return 0;
}

static int hook_has_valid_block(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char *line = NULL;
    size_t cap = 0;
    int seen_start = 0, seen_end = 0;
    while (getline(&line, &cap, f) != -1) {
        if (strncmp(line, HOOK_MARKER_START, strlen(HOOK_MARKER_START)) == 0)
            seen_start = 1;
        if (strncmp(line, HOOK_MARKER_END, strlen(HOOK_MARKER_END)) == 0)
            seen_end = 1;
    }
    free(line);
    fclose(f);
    return seen_start && seen_end;
}

void hook_enable(const char *home) {
    // 1. Clean up legacy shell hooks
    hook_disable(home);

    // 2. Write the new ALPM hook
    const char *hook_dir = "/etc/pacman.d/hooks";
    char hook_path[512];
    snprintf(hook_path, sizeof(hook_path), "%s/pkgscan.hook", hook_dir);

    // Create hook dir if it doesn't exist
    char mkdir_cmd[512];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", hook_dir);
    if (system(mkdir_cmd) != 0) {
        printf(RED "Failed to create hook directory. Please run with sudo: 'sudo pkgscan --hook enable'\n" RESET);
        return;
    }

    FILE *f = fopen(hook_path, "w");
    if (!f) {
        perror("Error creating pacman hook file (requires root privileges/sudo)");
        printf(RED "Failed to enable hook. Please run with sudo: 'sudo pkgscan --hook enable'\n" RESET);
        return;
    }

    fprintf(f, "[Trigger]\n");
    fprintf(f, "Operation = Install\n");
    fprintf(f, "Operation = Upgrade\n");
    fprintf(f, "Type = Package\n");
    fprintf(f, "Target = *\n\n");
    fprintf(f, "[Action]\n");
    fprintf(f, "Description = Running pkgscan on package updates...\n");
    fprintf(f, "When = PreTransaction\n");
    fprintf(f, "Exec = /usr/local/bin/pkgscan --hook-mode\n");
    fprintf(f, "NeedsTargets\n");
    fclose(f);

    printf(GREEN "ALPM pacman hook successfully created at %s\n" RESET, hook_path);
}

void hook_disable(const char *home) {
    // 1. Clean up shell hooks
    rc_paths paths;
    resolve_rc_paths(home, &paths);
    const char *rcs[] = { paths.bash, paths.zsh, paths.fish };
    for (int i = 0; i < 3; i++) {
        if (!hook_has_valid_block(rcs[i])) {
            if (hook_present(rcs[i]))
                printf(RED "Malformed hook block in %s: skipping cleanup\n" RESET, rcs[i]);
            continue;
        }
        if (hook_strip(rcs[i]) == 0)
            printf(GREEN "Disabled shell hook in: %s\n" RESET, rcs[i]);
        else
            printf(RED "Could not rewrite %s\n" RESET, rcs[i]);
    }

    // 2. Remove the ALPM hook
    const char *hook_path = "/etc/pacman.d/hooks/pkgscan.hook";
    if (access(hook_path, F_OK) == 0) {
        if (remove(hook_path) == 0) {
            printf(GREEN "Removed ALPM pacman hook at %s\n" RESET, hook_path);
        } else {
            perror("Error removing pacman hook file");
            printf(RED "Failed to remove hook. Please run with sudo: 'sudo pkgscan --hook disable'\n" RESET);
        }
    }
}

void hook_status(const char *home) {
    rc_paths paths;
    resolve_rc_paths(home, &paths);
    const char *rcs[] = { paths.bash, paths.zsh, paths.fish };
    printf(BOLD "Shell Hook Status:\n" RESET);
    for (int i = 0; i < 3; i++) {
        printf("  %-45s %s\n", rcs[i],
               hook_present(rcs[i]) ? GREEN "enabled (legacy wrapper)" RESET : YELLOW "not installed" RESET);
    }
    const char *hook_path = "/etc/pacman.d/hooks/pkgscan.hook";
    printf(BOLD "ALPM Hook Status:\n" RESET);
    printf("  %-45s %s\n", hook_path,
           (access(hook_path, F_OK) == 0) ? GREEN "active" RESET : YELLOW "not active" RESET);
}
