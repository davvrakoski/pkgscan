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

void aur_clone(char *pkg);

void rm_pkg(char *pkg);

int prompt_install(char *pkg, int danger);

void do_install(char *pkg);

void cleanup(char *pkg, FILE *file);

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


int main(int argc, char *argv[]) {
	if (argc != 2) {
		printf("Usage: %s filename\n", argv[0]);
		return 0;
	}
	char *pkg = argv[1];
	if (!validate_pkg_name(pkg)) return 1;
	aur_clone(pkg);
	struct pkg_metadata meta;
	struct suspicion flags[16];
		int suspicion_count = 0;

		if (fetch_metadata(pkg, &meta) == 0) {
	    printf("Maintainer: %s | Votes: %i | Out of date: %s\n",
		meta.maintainer,
		meta.votes,
		meta.out_of_date ? "YES" : "No");
	    suspicion_count = check_suspicion(&meta, flags);
	    if (suspicion_count > 0) {
		printf(YELLOW"\nSuspicion Flags (%i):\n", suspicion_count);
		for (int i = 0; i < suspicion_count; i++)
		    printf(YELLOW "  - %s\n" RESET, flags[i].reason);
	    }
	} else {
	    printf("Warning: Could not fetch AUR metadata\n");
	}
	FILE *file;
	char full_directory[256];
	snprintf(full_directory, sizeof(full_directory), "%s/PKGBUILD", pkg);
	file = fopen(full_directory, "r");
	 if (file == NULL) {
        printf("Error: Could not open file %s\n", full_directory);
	cleanup(pkg, file);
        return 0;
    	} else {
        printf("File %s opened successfully!\n", full_directory);
	}
	if (fgets(s, LINE_LENGTH, file) == NULL) {
		cleanup(pkg, file);
		return 0;
	}
	else {
	rewind(file);
	printf("File %s read successfully!\n", full_directory);
	}
	int danger = parser(file, s);

	printf("\n" BOLD "=== PKGInspect Results for '%s' ===" RESET "\n\n", pkg);

	if (danger == 0 && suspicion_count == 0)
	    printf(GREEN BOLD "✔ Low Risk" RESET " | Danger: %i\n", danger);
	else if (danger <= 10)
	    printf(YELLOW BOLD "⚠ Medium Risk" RESET " | Danger: %i\n", danger);
	else if (danger < 20)
	    printf(RED BOLD "✘ High Risk" RESET " | Danger: %i\n", danger);
	else
	    printf(RED BOLD "✘ CRITICAL" RESET " | Danger: %i\n", danger);
	fclose(file);
	rm_pkg(pkg);
	if (prompt_install(pkg, danger))
	do_install(pkg);
}

void aur_clone(char *pkg){
	const char *repo_url = "https://aur.archlinux.org/";
	const char *command = "git clone ";
	char full_command[256]; 
	snprintf(full_command, sizeof(full_command), "%s%s%s.git", command, repo_url, pkg);

	int status = system(full_command);
	
    if (status == -1) {
        perror("system");
    } else {
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            printf("git clone successful\n");

        } else {
            printf("git clone failed\n");
        }
    }
}
void rm_pkg(char *pkg){
	char rm_cmd[256];
	snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf %s", pkg);
	int status = system(rm_cmd);
	if (status == -1) {
	perror("system");
	}
	else {
	printf("Package %s removed successfully\n", pkg);
	}
}

void cleanup(char *pkg, FILE *file) {
    if (file != NULL) fclose(file);
    rm_pkg(pkg);
}

int prompt_install(char *pkg, int danger) {
    if (danger >= 10)
        printf(RED BOLD "\n*** WARNING: High risk score. Suspicious patterns found in PKGBUILD. ***\n" RESET);
    printf("Do you want to install '%s'? [y/N] ", pkg);
    char ans[8];
    if (fgets(ans, sizeof(ans), stdin) && (ans[0] == 'y' || ans[0] == 'Y'))
        return 1;
    printf("Install cancelled.\n");
    return 0;
}
void do_install(char *pkg) {
    aur_clone(pkg);
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "cd %s && makepkg -si", pkg);
    int status = system(cmd);
    rm_pkg(pkg);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        printf("'%s' installed successfully.\n", pkg);
    else
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
			}
		};
		if (keywordsfound > 0) {
			printf(YELLOW "Warning: %i Keyword(s) Found On Line %i \n" RESET, 
	  		keywordsfound, linecount);
		}
		keywordsfound = 0;
		linecount += 1;
		int b64_len = 0;
		for (int j = 0; s[j]; j++) {
		    if ((s[j] >= 'A' && s[j] <= 'Z') || (s[j] >= 'a' && s[j] <= 'z') ||
			(s[j] >= '0' && s[j] <= '9') || s[j] == '+' || s[j] == '/' || s[j] == '=')
			b64_len++;
		    else
			b64_len = 0;
		    if (b64_len > 50) {
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
