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

static const char *BASH_ZSH_SNIPPET =
    "\n"
    "_pkgscan_wrap_aur() {\n"
    "    local helper=\"$1\"; shift\n"
    "    local do_scan=0\n"
    "    for arg in \"$@\"; do\n"
    "        case \"$arg\" in\n"
    "            -S|--sync) do_scan=1; break ;;\n"
    "            -*) ;;\n"
    "            *) do_scan=1; break ;;\n"
    "        esac\n"
    "    done\n"
    "    if (( do_scan )); then\n"
    "        local pkgs=()\n"
    "        local skip_next=0\n"
    "        for arg in \"$@\"; do\n"
    "            if (( skip_next )); then skip_next=0; continue; fi\n"
    "            case \"$arg\" in\n"
    "                --mflags|--config|--makepkgconf) skip_next=1 ;;\n"
    "                -*) ;;\n"
    "                *) pkgs+=(\"$arg\") ;;\n"
    "            esac\n"
    "        done\n"
    "        if (( ${#pkgs[@]} > 0 )); then\n"
    "            if ! command -v pkgscan &>/dev/null; then\n"
    "                printf '\\033[33mpkgscan not found — hook inactive\\033[0m\\n'\n"
    "            else\n"
    "                pkgscan \"${pkgs[@]}\"\n"
    "            fi\n"
    "        fi\n"
    "    fi\n"
    "    command \"$helper\" \"$@\"\n"
        "}\n"
       "if command -v paru &>/dev/null; then\n"
    "    paru() { _pkgscan_wrap_aur paru \"$@\"; }\n"
    "fi\n"
    "if command -v yay &>/dev/null; then\n"
    "    yay() { _pkgscan_wrap_aur yay \"$@\"; }\n"
    "fi\n"
    "\n";

static const char *FISH_SNIPPET =
    "\n"
    "function _pkgscan_wrap_aur\n"
    "    set helper $argv[1]\n"
    "    set args $argv[2..]\n"
    "    set do_scan 0\n"
    "    for arg in $args\n"
    "        switch $arg\n"
    "            case '-S' '--sync'\n"
    "                set do_scan 1\n"
    "            case '-*'\n"
    "                true\n"
    "            case '*'\n"
    "                set do_scan 1\n"
    "        end\n"
    "        if test $do_scan -eq 1; break; end\n"
    "    end\n"
    "    if test $do_scan -eq 1\n"
    "        set pkgs\n"
    "        set skip_next 0\n"
    "        for arg in $args\n"
    "            if test $skip_next -eq 1; set skip_next 0; continue; end\n"
    "            switch $arg\n"
    "                case '--mflags' '--config' '--makepkgconf'\n"
    "                    set skip_next 1\n"
    "                case '-*'\n"
    "                    true\n"
    "                case '*'\n"
    "                    set pkgs $pkgs $arg\n"
    "            end\n"
    "        end\n"
    "        if test (count $pkgs) -gt 0\n"
    "            if not command -v pkgscan &>/dev/null\n"
    "                echo (set_color yellow)'pkgscan not found — hook inactive'(set_color normal)\n"
    "            else\n"
    "                pkgscan $pkgs\n"
    "            end\n"
    "        end\n"
    "    end\n"
    "    command $helper $args\n"
    "end\n"
    "if command -v paru &>/dev/null\n"
    "    function paru; _pkgscan_wrap_aur paru $argv; end\n"
    "end\n"
    "if command -v yay &>/dev/null\n"
    "    function yay; _pkgscan_wrap_aur yay $argv; end\n"
    "end\n"
    "\n";

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

static int hook_append(const char *path, const char *snippet) {
    char date_str[16];
    time_t now = time(NULL);
    strftime(date_str, sizeof(date_str), "%Y-%m-%d", localtime(&now));

    FILE *f = fopen(path, "a+");
    if (!f) { perror(path); return -1; }
    if (fseek(f, -1, SEEK_END) == 0 && fgetc(f) != '\n')
        fputc('\n', f);
    fprintf(f, "\n%s added %s — do not edit manually\n", HOOK_MARKER_START, date_str);
    fputs(snippet, f);
    fprintf(f, "%s\n", HOOK_MARKER_END);
    fclose(f);
    return 0;
}

static int hook_strip(const char *path) {
    FILE *f = fopen(path, "r");
if (!f) { perror(path); return -1; }

    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.pkgscan_tmp", path);
    FILE *tmp = fopen(tmp_path, "w");
if (!tmp) { perror(tmp_path); fclose(f); return -1; }    int in_block = 0;
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
    };
    return 0;
}

static int copy_file(const char *src, const char *dst) {
    FILE *in = fopen(src, "rb");
    if (!in) return -1;
    FILE *out = fopen(dst, "wb");
    if (!out) { fclose(in); return -1; }
    char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            fclose(in); fclose(out);
            return -1;
        }
    }
    fclose(in);
    fclose(out);
    return 0;
}

static void backup_rc(const char *path) {
    char backup[512];
    snprintf(backup, sizeof(backup), "%s.pkgscan_bak", path);
    if (copy_file(path, backup) != 0)
        perror("backup");
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
    rc_paths paths;
    resolve_rc_paths(home, &paths);

    const char *posix_rcs[] = { paths.bash, paths.zsh };
    for (int i = 0; i < 2; i++) {
        if (hook_present(posix_rcs[i]))
            printf(YELLOW "Already enabled: %s\n" RESET, posix_rcs[i]);
        else {
            backup_rc(posix_rcs[i]);
            if (hook_append(posix_rcs[i], BASH_ZSH_SNIPPET) == 0)
                printf(GREEN "Enabled: %s\n" RESET, posix_rcs[i]);
            else
            printf(RED "Could not write to %s\n" RESET, posix_rcs[i]);
        }
    }
    if (hook_present(paths.fish))
        printf(YELLOW "Already enabled: %s\n" RESET, paths.fish);
    else {
    backup_rc(paths.fish);
    if (hook_append(paths.fish, FISH_SNIPPET) == 0)
        printf(GREEN "Enabled: %s\n" RESET, paths.fish);
    else
        printf(RED "Could not write to %s\n" RESET, paths.fish);
    }
    printf(BOLD "\nRestart Shell to apply changes\n" RESET);
}

void hook_disable(const char *home) {
    rc_paths paths;
    resolve_rc_paths(home, &paths);
    const char *rcs[] = { paths.bash, paths.zsh, paths.fish };
    for (int i = 0; i < 3; i++) {
        if (!hook_has_valid_block(rcs[i])) {
    if (hook_present(rcs[i]))
        printf(RED "Malformed hook block in %s: skipping\n" RESET, rcs[i]);
    continue;
}
        if (hook_strip(rcs[i]) == 0)
            printf(GREEN "Disabled: %s\n" RESET, rcs[i]);
        else
            printf(RED "Could not rewrite %s\n" RESET, rcs[i]);
    }
    printf(BOLD "\nRestart your shell to apply changes\n" RESET);
}

void hook_status(const char *home) {
    rc_paths paths;
    resolve_rc_paths(home, &paths);
    const char *rcs[] = { paths.bash, paths.zsh, paths.fish };
    printf(BOLD "Hook status:\n" RESET);
    for (int i = 0; i < 3; i++)
        printf("  %-45s %s\n", rcs[i],
               hook_present(rcs[i]) ? GREEN "enabled" RESET : YELLOW "not installed" RESET);
}


