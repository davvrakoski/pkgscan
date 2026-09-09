#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <sys/wait.h>
#include <cjson/cJSON.h>
#include "types.h"
#include <time.h>
#include <ctype.h>
#include "keywords.h"
#include <unistd.h>
#include "hook.h"
#include <dirent.h>
#include <sys/stat.h>

#define RESET   "\033[0m"
#define RED     "\033[31m"
#define YELLOW  "\033[33m"
#define GREEN   "\033[32m"
#define CYAN    "\033[36m"
#define BOLD    "\033[1m"

#define LINE_LENGTH 256

char s[LINE_LENGTH];

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp);
int validate_pkg_name(const char *pkg);
int fetch_metadata(const char *pkg, struct pkg_metadata *meta);
int check_suspicion(struct pkg_metadata *meta, struct suspicion *flags);
int parser(FILE *file, char *s);
void aur_clone(char *pkg, char *clone_dir);
void rm_pkg(char *clone_dir);
int prompt_install(char *pkg, int danger);
void do_install(char *pkg, char *clone_dir);
void print_risk(char *name, int danger, int suspicion_count, struct suspicion *flags);
int scan_pkgbuild(char *clone_dir);

// --- Database & Verification Helpers ---

cJSON *load_db(const char *db_path) {
    FILE *f = fopen(db_path, "r");
    if (!f) {
        return cJSON_CreateArray();
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *data = malloc(len + 1);
    if (!data) {
        fclose(f);
        return cJSON_CreateArray();
    }
    size_t read_bytes = fread(data, 1, len, f);
    data[read_bytes] = 0;
    fclose(f);
    cJSON *json = cJSON_Parse(data);
    free(data);
    if (!json) {
        return cJSON_CreateArray();
    }
    return json;
}

void save_db(cJSON *db, const char *db_path) {
    char dir[512];
    strncpy(dir, db_path, sizeof(dir));
    char *last_slash = strrchr(dir, '/');
    if (last_slash) {
        *last_slash = 0;
        char cmd[1024];
        snprintf(cmd, sizeof(cmd), "mkdir -p \"%s\"", dir);
        if (system(cmd) != 0) {
            // Ignore failure, we will try to write anyway
        }
    }
    FILE *f = fopen(db_path, "w");
    if (f) {
        char *str = cJSON_Print(db);
        fputs(str, f);
        free(str);
        fclose(f);
    }
}

void log_scan(const char *log_path, const char *pkgname, const char *source, 
              const char *hash, const char *sign_key, int danger_score, const char *status) {
    char dir[512];
    strncpy(dir, log_path, sizeof(dir));
    char *last_slash = strrchr(dir, '/');
    if (last_slash) {
        *last_slash = 0;
        char cmd[1024];
        snprintf(cmd, sizeof(cmd), "mkdir -p \"%s\"", dir);
        if (system(cmd) != 0) {}
    }
    FILE *f = fopen(log_path, "a");
    if (f) {
        time_t now = time(NULL);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(f, "[%s] PKG: %s | SRC: %s | HASH: %s | KEY: %s | DANGER: %d | STATUS: %s\n",
                time_str, pkgname, source, hash && strlen(hash) > 0 ? hash : "none", 
                sign_key && strlen(sign_key) > 0 ? sign_key : "none", danger_score, status);
        fclose(f);
    }
}

int get_file_sha256(const char *filepath, char *hash_out) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "sha256sum \"%s\" 2>/dev/null", filepath);
    FILE *p = popen(cmd, "r");
    if (!p) return -1;
    if (fscanf(p, "%64s", hash_out) != 1) {
        pclose(p);
        return -1;
    }
    pclose(p);
    return 0;
}

int get_file_signature_key(const char *filepath, char *key_out) {
    char sigpath[1024];
    snprintf(sigpath, sizeof(sigpath), "%s.sig", filepath);
    if (access(sigpath, F_OK) != 0) {
        return 0; // No signature file
    }
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "gpg --status-fd 1 --verify \"%s\" \"%s\" 2>/dev/null", sigpath, filepath);
    FILE *p = popen(cmd, "r");
    if (!p) return -1;
    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), p)) {
        char *p_sig = strstr(line, "VALIDSIG");
        if (p_sig) {
            sscanf(p_sig, "VALIDSIG %40s", key_out);
            found = 1;
            break;
        }
    }
    pclose(p);
    return found ? 1 : 0;
}

int find_package_file(const char *pkgname, char *path_out, size_t max_len) {
    const char *dir_path = "/var/cache/pacman/pkg";
    DIR *dir = opendir(dir_path);
    if (!dir) return -1;
    struct dirent *entry;
    time_t latest_mtime = 0;
    char latest_path[512] = {0};

    size_t name_len = strlen(pkgname);
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, pkgname, name_len) == 0 && entry->d_name[name_len] == '-') {
            char *ext = strstr(entry->d_name, ".pkg.tar.zst");
            if (ext && strcmp(ext, ".pkg.tar.zst") == 0) {
                char full_path[1024];
                snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);
                struct stat st;
                if (stat(full_path, &st) == 0) {
                    if (st.st_mtime > latest_mtime) {
                        latest_mtime = st.st_mtime;
                        strncpy(latest_path, full_path, sizeof(latest_path) - 1);
                    }
                }
            }
        }
    }
    closedir(dir);

    if (latest_mtime > 0) {
        strncpy(path_out, latest_path, max_len - 1);
        return 0;
    }
    return -1;
}

int get_package_source(const char *pkgname, char *source_out, size_t max_len) {
    char check_cmd[512];
    snprintf(check_cmd, sizeof(check_cmd), "pacman -Si %s 2>/dev/null", pkgname);
    FILE *p = popen(check_cmd, "r");
    if (!p) {
        strncpy(source_out, "aur", max_len - 1);
        return 0;
    }
    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), p)) {
        if (strncmp(line, "Repository", 10) == 0) {
            char *colon = strchr(line, ':');
            if (colon) {
                char *val = colon + 1;
                while (*val && isspace((unsigned char)*val)) val++;
                char *end = val;
                while (*end && !isspace((unsigned char)*end)) end++;
                *end = 0;
                strncpy(source_out, val, max_len - 1);
                found = 1;
                break;
            }
        }
    }
    pclose(p);
    if (!found) {
        strncpy(source_out, "aur", max_len - 1);
    }
    return 0;
}

const char *get_user_home() {
    const char *sudo_user = getenv("SUDO_USER");
    if (sudo_user) {
        static char home_path[256];
        snprintf(home_path, sizeof(home_path), "/home/%s", sudo_user);
        return home_path;
    }
    return getenv("HOME");
}

int check_db_valid_by_signature(const char *db_path, const char *pkgname, const char *source, 
                                const char *sign_key, int scan_all) {
    if (scan_all) return 0;
    if (!sign_key || strlen(sign_key) == 0) return 0;

    cJSON *db = load_db(db_path);
    if (!db) return 0;

    int valid = 0;
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, db) {
        cJSON *name_obj = cJSON_GetObjectItem(item, "name");
        cJSON *source_obj = cJSON_GetObjectItem(item, "source");
        if (name_obj && source_obj &&
            strcmp(name_obj->valuestring, pkgname) == 0 &&
            strcmp(source_obj->valuestring, source) == 0) {
            
            cJSON *db_sign_key = cJSON_GetObjectItem(item, "sign_key");
            if (db_sign_key && strcmp(db_sign_key->valuestring, sign_key) == 0) {
                valid = 1;
                break;
            }
        }
    }
    cJSON_Delete(db);
    return valid;
}

int check_db_valid(const char *db_path, const char *pkgname, const char *source, 
                   const char *hash, const char *sign_key, int scan_all, int force_hash) {
    if (scan_all) return 0;

    cJSON *db = load_db(db_path);
    if (!db) return 0;

    int valid = 0;
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, db) {
        cJSON *name_obj = cJSON_GetObjectItem(item, "name");
        cJSON *source_obj = cJSON_GetObjectItem(item, "source");
        if (name_obj && source_obj &&
            strcmp(name_obj->valuestring, pkgname) == 0 &&
            strcmp(source_obj->valuestring, source) == 0) {
            
            cJSON *db_sign_key = cJSON_GetObjectItem(item, "sign_key");
            cJSON *db_hash = cJSON_GetObjectItem(item, "hash");

            if (sign_key && strlen(sign_key) > 0 && db_sign_key && 
                strcmp(db_sign_key->valuestring, sign_key) == 0 && !force_hash) {
                valid = 1;
                break;
            }

            if (hash && strlen(hash) > 0 && db_hash && 
                strcmp(db_hash->valuestring, hash) == 0) {
                valid = 1;
                break;
            }
        }
    }
    cJSON_Delete(db);
    return valid;
}

void update_db(const char *db_path, const char *pkgname, const char *source, 
               const char *hash, const char *sign_key, int danger_score) {
    cJSON *db = load_db(db_path);
    cJSON *found_item = NULL;
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, db) {
        cJSON *name_obj = cJSON_GetObjectItem(item, "name");
        cJSON *source_obj = cJSON_GetObjectItem(item, "source");
        if (name_obj && source_obj &&
            strcmp(name_obj->valuestring, pkgname) == 0 &&
            strcmp(source_obj->valuestring, source) == 0) {
            found_item = item;
            break;
        }
    }

    if (found_item) {
        cJSON_ReplaceItemInObject(found_item, "hash", cJSON_CreateString(hash ? hash : ""));
        cJSON_ReplaceItemInObject(found_item, "sign_key", cJSON_CreateString(sign_key ? sign_key : ""));
        cJSON_ReplaceItemInObject(found_item, "danger_score", cJSON_CreateNumber(danger_score));
        cJSON_ReplaceItemInObject(found_item, "scan_date", cJSON_CreateNumber(time(NULL)));
    } else {
        cJSON *new_item = cJSON_CreateObject();
        cJSON_AddStringToObject(new_item, "name", pkgname);
        cJSON_AddStringToObject(new_item, "source", source);
        cJSON_AddStringToObject(new_item, "hash", hash ? hash : "");
        cJSON_AddStringToObject(new_item, "sign_key", sign_key ? sign_key : "");
        cJSON_AddNumberToObject(new_item, "danger_score", danger_score);
        cJSON_AddNumberToObject(new_item, "scan_date", time(NULL));
        cJSON_AddItemToArray(db, new_item);
    }
    save_db(db, db_path);
    cJSON_Delete(db);
}

int find_local_pkgbuild_via_proc(const char *pkgname, char *path_out, size_t max_len) {
    pid_t pid = getpid();
    for (int depth = 0; depth < 5; depth++) {
        char stat_path[256];
        snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
        FILE *f = fopen(stat_path, "r");
        if (!f) break;
        pid_t ppid = 0;
        char comm[256];
        if (fscanf(f, "%*d %255s %*c %d", comm, &ppid) != 2) {
            fclose(f);
            break;
        }
        fclose(f);

        if (ppid <= 1) break;

        char cwd_link[512];
        snprintf(cwd_link, sizeof(cwd_link), "/proc/%d/cwd", ppid);
        char cwd_path[512];
        ssize_t len = readlink(cwd_link, cwd_path, sizeof(cwd_path) - 1);
        if (len > 0) {
            cwd_path[len] = 0;
            
            char pkgbuild_path[1024];
            snprintf(pkgbuild_path, sizeof(pkgbuild_path), "%s/PKGBUILD", cwd_path);
            if (access(pkgbuild_path, F_OK) == 0) {
                strncpy(path_out, cwd_path, max_len - 1);
                path_out[max_len - 1] = 0;
                return 0;
            }

            snprintf(pkgbuild_path, sizeof(pkgbuild_path), "%s/%s/PKGBUILD", cwd_path, pkgname);
            if (access(pkgbuild_path, F_OK) == 0) {
                snprintf(path_out, max_len, "%s/%s", cwd_path, pkgname);
                return 0;
            }
        }
        pid = ppid;
    }
    return -1;
}

int prompt_install_tty(const char *pkg, int danger) {
    if (danger >= 16) {
        FILE *tty_err = fopen("/dev/tty", "w");
        if (tty_err) {
            fprintf(tty_err, RED BOLD "\n*** WARNING: High risk score. Suspicious patterns found in PKGBUILD. ***\n" RESET);
            fclose(tty_err);
        }
    }
    FILE *tty = fopen("/dev/tty", "r+");
    if (!tty) {
        return prompt_install((char *)pkg, danger);
    }
    fprintf(tty, "Do you want to install '%s'? [y/N] ", pkg);
    char ans[8] = "";
    if (fgets(ans, sizeof(ans), tty) && (ans[0] == 'y' || ans[0] == 'Y')) {
        fclose(tty);
        return 1;
    }
    fprintf(tty, "Install cancelled.\n");
    fclose(tty);
    return 0;
}

// --- End Helpers ---

int validate_pkg_name(const char *pkg) {
    if (strlen(pkg) > 64) {
        printf(RED "Error: Package name too long\n" RESET);
        return 0;
    }
    for (int i = 0; pkg[i]; i++) {
        if (!isalnum(pkg[i]) && pkg[i] != '-' && pkg[i] != '_' && pkg[i] != '.') {
            printf(RED "Error: Invalid character '%c' in package name\n" RESET, pkg[i]);
            return 0;
        }
    }
    if (strstr(pkg, "..") != NULL) {
        printf(RED "Error: Path traversal detected\n" RESET);
        return 0;
    }
    return 1;
}

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct memory *mem = (struct memory *)userp;
    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if (!ptr) return 0;
    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;
    return realsize;
}

int fetch_metadata(const char *pkg, struct pkg_metadata *meta) {
    CURL *curl;
    CURLcode res;
    struct memory chunk = {0};
    char url[256];
    snprintf(url, sizeof(url), "https://aur.archlinux.org/rpc/v5/info?arg=%s", pkg);

    curl = curl_easy_init();
    if (!curl) return -1;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) { free(chunk.data); return -1; }

    cJSON *json = cJSON_Parse(chunk.data);
    free(chunk.data);
    if (!json) return -1;

    cJSON *results = cJSON_GetObjectItem(json, "results");
    if (!cJSON_IsArray(results) || cJSON_GetArraySize(results) == 0) {
        cJSON_Delete(json);
        return -1;
    }

    cJSON *pkg_json = cJSON_GetArrayItem(results, 0);
    meta->votes         = cJSON_GetObjectItem(pkg_json, "NumVotes")->valueint;
    meta->out_of_date   = cJSON_IsNull(cJSON_GetObjectItem(pkg_json, "OutOfDate")) ? 0 : 1;
    meta->first_submitted = (long)cJSON_GetObjectItem(pkg_json, "FirstSubmitted")->valuedouble;
    meta->last_modified   = (long)cJSON_GetObjectItem(pkg_json, "LastModified")->valuedouble;
    strncpy(meta->maintainer,
            cJSON_GetObjectItem(pkg_json, "Maintainer")->valuestring, 63);

    cJSON_Delete(json);
    return 0;
}

int check_suspicion(struct pkg_metadata *meta, struct suspicion *flags) {
    int count = 0;
    time_t now = time(NULL);

    if (meta->votes < 5)
        flags[count++].reason = "Package has very few votes";
    if (meta->out_of_date)
        flags[count++].reason = "Package is flagged out of date";
    if ((now - meta->first_submitted) < 60 * 60 * 24 * 30)
        flags[count++].reason = "Package is less than 30 days old";
    if ((now - meta->last_modified) < 60 * 60 * 24 * 7 &&
        (now - meta->first_submitted) > 60 * 60 * 24 * 180)
        flags[count++].reason = "Package modified recently after long inactivity";

    return count;
}

void print_risk(char *name, int danger, int suspicion_count, struct suspicion *flags) {
    printf("\n" BOLD "=== pkgscan Results for '%s' ===" RESET "\n\n", name);
    if (suspicion_count > 0) {
        printf(YELLOW "Suspicion Flags (%i):\n" RESET, suspicion_count);
        for (int i = 0; i < suspicion_count; i++)
            printf(YELLOW "  - %s\n" RESET, flags[i].reason);
    }
    if (danger == 0 && suspicion_count == 0)
        printf(GREEN BOLD "Low Risk" RESET " | Danger: %i\n", danger);
    else if (danger <= 15)
        printf(YELLOW BOLD "Medium Risk" RESET " | Danger: %i\n", danger);
    else if (danger <= 35)
        printf(RED BOLD "High Risk" RESET " | Danger: %i\n", danger);
    else
        printf(RED BOLD "CRITICAL" RESET " | Danger: %i\n", danger);
}

int scan_pkgbuild(char *clone_dir) {
    char full_directory[512];
    snprintf(full_directory, sizeof(full_directory), "%s/PKGBUILD", clone_dir);
    FILE *file = fopen(full_directory, "r");
    if (file == NULL) {
        return -1;
    }
    if (fgets(s, LINE_LENGTH, file) == NULL) {
        fclose(file);
        return -1;
    }
    rewind(file);
    int danger = parser(file, s);
    fclose(file);
    return danger;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <package> [package2 ...]\n", argv[0]);
        return 1;
    }
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        printf(BOLD "pkgscan" RESET " - AUR Package Security Scanner\n\n");
        printf(BOLD "Usage:\n" RESET);
        printf("  pkgscan --test <path>   Scan a local PKGBUILD directory\n");
        printf("  pkgscan --hook enable    Install ALPM pacman hook\n");
        printf("  pkgscan --hook disable   Remove ALPM pacman hook\n");
        printf("  pkgscan --hook status    Show ALPM hook status\n");
        printf("  pkgscan <package>        Scan an AUR package before installing\n");
        printf("  pkgscan [flags]\n\n");
        printf(BOLD "Flags:\n" RESET);
        printf("  --hook-mode             Run as pacman hook (reads packages from stdin)\n");
        printf("  --scan-all              Force scanning regardless of database cache\n");
        printf("  --force-hash            Always check hashes even if PGP signature matches\n");
        printf("  --database <path>       Specify custom database JSON path\n");
        printf("  --log <path>            Specify custom log file path\n\n");
        printf(BOLD "Danger Levels:\n" RESET);
        printf(GREEN "  Low     " RESET "0        No suspicious patterns found\n");
        printf(YELLOW "  Medium  " RESET "1-15     Some patterns detected, review recommended\n");
        printf(RED "  High    " RESET "16-35    Suspicious patterns found\n");
        printf(RED "  Critical" RESET " 35+     Multiple serious patterns detected\n\n");
        return 0;
    }
    if (system("command -v git > /dev/null 2>&1") != 0) {
        printf(RED "Error: git is not installed\n" RESET);
        return 1;
    }
    if (system("command -v makepkg > /dev/null 2>&1") != 0) {
        printf(RED "Error: makepkg is not installed (base-devel required)\n" RESET);
        return 1;
    }

    if (argc == 3 && strcmp(argv[1], "--test") == 0) {
        struct suspicion flags[16] = {0};
        int danger = scan_pkgbuild(argv[2]);
        if (danger >= 0) print_risk(argv[2], danger, 0, flags);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--hook") == 0) {
        const char *home = getenv("HOME");
        if (!home) { home = get_user_home(); }
        if (!home) { printf(RED "Error: $HOME not set\n" RESET); return 1; }
        if      (strcmp(argv[2], "enable")  == 0) hook_enable(home);
        else if (strcmp(argv[2], "disable") == 0) hook_disable(home);
        else if (strcmp(argv[2], "status")  == 0) hook_status(home);
        else printf(RED "Usage: pkgscan --hook [enable|disable|status]\n" RESET);
        return 0;
    }

    int hook_mode = 0;
    int scan_all = 0;
    int force_hash = 0;
    const char *db_path = "/var/lib/pkgscan/database.json";
    const char *log_path = "/var/log/pkgscan.log";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--hook-mode") == 0) {
            hook_mode = 1;
        } else if (strcmp(argv[i], "--scan-all") == 0) {
            scan_all = 1;
        } else if (strcmp(argv[i], "--force-hash") == 0) {
            force_hash = 1;
        } else if (strcmp(argv[i], "--database") == 0 && i + 1 < argc) {
            db_path = argv[++i];
        } else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) {
            log_path = argv[++i];
        }
    }

    // Build package names array
    int max_pkgs = 128;
    char **pkgs = malloc(max_pkgs * sizeof(char *));
    int total_pkgs = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--hook-mode") == 0 ||
            strcmp(argv[i], "--scan-all") == 0 ||
            strcmp(argv[i], "--force-hash") == 0) {
            continue;
        }
        if (strcmp(argv[i], "--database") == 0 || strcmp(argv[i], "--log") == 0) {
            i++;
            continue;
        }
        if (argv[i][0] == '-') continue;

        pkgs[total_pkgs++] = strdup(argv[i]);
        if (total_pkgs >= max_pkgs) {
            max_pkgs *= 2;
            pkgs = realloc(pkgs, max_pkgs * sizeof(char *));
        }
    }

    if (hook_mode && total_pkgs == 0) {
        char line[256];
        while (fgets(line, sizeof(line), stdin)) {
            line[strcspn(line, "\r\n")] = 0;
            char *start = line;
            while (*start && isspace((unsigned char)*start)) start++;
            char *end = start + strlen(start) - 1;
            while (end > start && isspace((unsigned char)*end)) end--;
            *(end + 1) = 0;

            if (strlen(start) > 0) {
                pkgs[total_pkgs++] = strdup(start);
                if (total_pkgs >= max_pkgs) {
                    max_pkgs *= 2;
                    pkgs = realloc(pkgs, max_pkgs * sizeof(char *));
                }
            }
        }
    }

    int rejected = 0;
    for (int i = 0; i < total_pkgs; i++) {
        char *pkg = pkgs[i];
        if (!validate_pkg_name(pkg)) {
            rejected = 1;
            continue;
        }

        char source[64] = "aur";
        get_package_source(pkg, source, sizeof(source));

        if (strcmp(source, "aur") != 0) {
            printf(GREEN "Package '%s' (%s) is a repository package. Skipping scan.\n" RESET, pkg, source);
            continue;
        }

        char pkg_file[512] = "";
        char hash[65] = "";
        char sign_key[41] = "";
        int has_pkg_file = (find_package_file(pkg, pkg_file, sizeof(pkg_file)) == 0);

        if (has_pkg_file) {
            get_file_signature_key(pkg_file, sign_key);
        }

        int is_valid = 0;
        if (has_pkg_file) {
            int sig_valid = 0;
            if (strlen(sign_key) > 0) {
                sig_valid = check_db_valid_by_signature(db_path, pkg, source, sign_key, scan_all);
            }
            
            if (sig_valid && !force_hash) {
                is_valid = 1;
            } else {
                get_file_sha256(pkg_file, hash);
                is_valid = check_db_valid(db_path, pkg, source, hash, sign_key, scan_all, force_hash);
            }
        }

        if (is_valid) {
            printf(GREEN "Package '%s' (%s) already scanned and verified. Skipping scan.\n" RESET, pkg, source);
            log_scan(log_path, pkg, source, hash, sign_key, 0, "VERIFIED_FROM_DB");
            continue;
        }

        // Perform scan
        printf(BOLD "\n=== Scanning package: '%s' ===\n" RESET, pkg);
        int danger = -1;

        char local_pkgbuild_dir[512] = "";
        
        // 1. Try process tree search
        if (find_local_pkgbuild_via_proc(pkg, local_pkgbuild_dir, sizeof(local_pkgbuild_dir)) == 0) {
            danger = scan_pkgbuild(local_pkgbuild_dir);
        }

        // 2. Try paru cache
        if (danger < 0) {
            const char *user_home = get_user_home();
            if (user_home) {
                snprintf(local_pkgbuild_dir, sizeof(local_pkgbuild_dir), "%s/.cache/paru/clone/%s", user_home, pkg);
                char full_local_path[1024];
                snprintf(full_local_path, sizeof(full_local_path), "%s/PKGBUILD", local_pkgbuild_dir);
                if (access(full_local_path, F_OK) == 0) {
                    danger = scan_pkgbuild(local_pkgbuild_dir);
                }
            }
        }

        // 3. Try yay cache
        if (danger < 0) {
            const char *user_home = get_user_home();
            if (user_home) {
                snprintf(local_pkgbuild_dir, sizeof(local_pkgbuild_dir), "%s/.cache/yay/%s", user_home, pkg);
                char full_local_path[1024];
                snprintf(full_local_path, sizeof(full_local_path), "%s/PKGBUILD", local_pkgbuild_dir);
                if (access(full_local_path, F_OK) == 0) {
                    danger = scan_pkgbuild(local_pkgbuild_dir);
                }
            }
        }

        int cloned_tmp = 0;
        char clone_dir[256] = "";
        if (danger < 0) {
            snprintf(clone_dir, sizeof(clone_dir), "/tmp/pkgscan-%s", pkg);
            aur_clone(pkg, clone_dir);
            danger = scan_pkgbuild(clone_dir);
            cloned_tmp = 1;
        }

        if (danger >= 0) {
            struct suspicion flags[16];
            struct pkg_metadata meta;
            int suspicion_count = 0;

            if (fetch_metadata(pkg, &meta) == 0) {
                suspicion_count = check_suspicion(&meta, flags);
            }
            print_risk(pkg, danger, suspicion_count, flags);

            if (cloned_tmp) {
                rm_pkg(clone_dir);
            }

            int proceed = 1;
            if (hook_mode) {
                proceed = prompt_install_tty(pkg, danger);
            } else {
                proceed = prompt_install(pkg, danger);
            }

            if (proceed) {
                if (has_pkg_file && strlen(hash) == 0) {
                    get_file_sha256(pkg_file, hash);
                }
                update_db(db_path, pkg, source, hash, sign_key, danger);
                log_scan(log_path, pkg, source, hash, sign_key, danger, "SCAN_PASSED");

                if (!hook_mode) {
                    do_install(pkg, local_pkgbuild_dir[0] ? local_pkgbuild_dir : clone_dir);
                }
            } else {
                rejected = 1;
                log_scan(log_path, pkg, source, hash, sign_key, danger, "SCAN_REJECTED");
            }
        } else {
            if (cloned_tmp) {
                rm_pkg(clone_dir);
            }
            printf(RED "Error: Could not scan package '%s'\n" RESET, pkg);
            log_scan(log_path, pkg, source, hash, sign_key, -1, "SCAN_ERROR");
            rejected = 1;
        }
    }

    for (int i = 0; i < total_pkgs; i++) {
        free(pkgs[i]);
    }
    free(pkgs);

    if (rejected) {
        exit(1);
    }
    return 0;
}

void aur_clone(char *pkg, char *clone_dir) {
    const char *repo_url = "https://aur.archlinux.org/";
    const char *command = "git clone ";
    char full_command[256]; 
    snprintf(full_command, sizeof(full_command), "%s%s%s.git %s", command, repo_url, pkg, clone_dir);

    int status = system(full_command);
    if (status == -1) {
        perror("system");
    } else {
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            printf("git clone failed\n");
        }
    }
}

void rm_pkg(char *clone_dir) {
    char rm_cmd[256];
    snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf %s", clone_dir);
    int status = system(rm_cmd);
    if (status == -1) {
        perror("system");
    }
}

int prompt_install(char *pkg, int danger) {
    if (danger >= 16)
        printf(RED BOLD "\n*** WARNING: High risk score. Suspicious patterns found in PKGBUILD. ***\n" RESET);
    printf("Do you want to install '%s'? [y/N] ", pkg);
    char ans[8];
    if (fgets(ans, sizeof(ans), stdin) && (ans[0] == 'y' || ans[0] == 'Y'))
        return 1;
    printf("Install cancelled.\n");
    return 0;
}

void do_install(char *pkg, char *clone_dir) {
    aur_clone(pkg, clone_dir);
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "cd %s && makepkg -si", clone_dir);
    int status = system(cmd);
    rm_pkg(clone_dir);
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
        printf("Installation of '%s' failed.\n", pkg);
}

int parser(FILE *file, char *s) {
    int danger = 0;
    int keywordsfound = 0;
    int linecount = 1;

    while (fgets(s, LINE_LENGTH, file) != NULL) {
        for (int i = 0; i < num_keywords; i++) {
            if (strstr(s, keyphrases[i].strings) != NULL) {
                keywordsfound += 1;
                danger += keyphrases[i].warning_lvl;
                printf(YELLOW "  [Line %i] Matched: '%s' (weight: %i)\n" RESET,
                linecount, keyphrases[i].strings, keyphrases[i].warning_lvl);
            }
        }
        if (keywordsfound > 0) {
            printf(YELLOW "  ^ %i keyword(s) on line %i\n" RESET, keywordsfound, linecount);
        }
        keywordsfound = 0;
        linecount += 1;
        int b64_len = 0;
        int has_b64_chars = 0;
        for (int j = 0; s[j]; j++) {
            if ((s[j] >= 'A' && s[j] <= 'Z') || (s[j] >= 'a' && s[j] <= 'z') ||
                (s[j] >= '0' && s[j] <= '9') || s[j] == '+' || s[j] == '/' || s[j] == '=')
                b64_len++;
            else
                b64_len = 0;
            if (s[j] == '+' || s[j] == '/') has_b64_chars = 1;
            if (b64_len > 50 && has_b64_chars &&
                strstr(s, "sha256sums") == NULL &&
                strstr(s, "md5sums") == NULL) {
                printf(YELLOW "  Possible base64 payload detected on line %i\n" RESET, linecount);
                danger += 7;
                break;
            }
        }
        if (strstr(s, "source=") != NULL) {
            int dots = 0, digits = 0;
            for (int j = 0; s[j]; j++) {
                if (s[j] == '.') dots++;
                if (s[j] >= '0' && s[j] <= '9') digits++;
            }
            if (dots == 3 && digits >= 4) {
                printf(YELLOW "  Suspicious IP address in source URL on line %i\n" RESET, linecount);
                danger += 8;
            }
        }
    }
    return danger;
}
