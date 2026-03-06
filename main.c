#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <sys/wait.h>

int num_keywords = 8;

struct flagables {
	char *strings;
	int warning_lvl;
};
struct 	flagables keyphrases[] = {
	{" curl", 5}, 
	{" wget", 5},
	{"chmod\\+x /", 10},
	{"raw.githubusercontent.com", 5},
	{"-patched", 3},
	{"-cracked", 5},
	{"-pro", 3},
	{"-unlock", 5},
};

#define LINE_LENGTH 256

char s[LINE_LENGTH];

int parser(FILE *file, char *s);

void aur_clone(char *pkg);

void rm_pkg(char *pkg);

int main(int argc, char *argv[]) {
	if (argc != 2) {
		printf("Usage: %s filename\n", argv[0]);
		return 0;
	}
	char *pkg = argv[1];
	aur_clone(pkg);
	FILE *file;
	char full_directory[256];
	int len = snprintf(full_directory, sizeof(full_directory), "%s/PKGBUILD", pkg);
	file = fopen(full_directory, "r");
	 if (file == NULL) {
        printf("Error: Could not open file %s\n", full_directory);
        return 0;
    	} else {
        printf("File %s opened successfully!\n", full_directory);
	}
	if (fgets(s, LINE_LENGTH, file) == NULL) {
		return 0;
	}
	else {
	rewind(file);
	printf("File %s read successfully!\n", full_directory);
	}
	int danger = parser(file, s);
	if (danger > 0 && danger <= 10) {
	printf("Medium Risk; Danger Level: %i\n", danger);	
	}
	else if (danger > 10 && danger < 20) {
	printf("High Risk; Danger Level: %i\n", danger);
	}
	else if (danger > 20) {
	printf("Dude What Are You Doing How Did You Get Here; Danger Level: %i\n", danger);
	}
	else {
	printf("Low Risk; Danger Level: %i\n", danger);
	}
	fclose(file);
	rm_pkg(pkg);
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
	int len= snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf %s", pkg);
	int status = system(rm_cmd);
	if (status == -1) {
	perror("system");
	}
	else {
	printf("Package %s removed successfully\n", pkg);
	}
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
		}
		if (keywordsfound > 0) {
			printf("Warning: %i Keyword(s) Found On Line %i \n", 
	  		keywordsfound, linecount);
		}
		keywordsfound = 0;
		linecount += 1;
	}
	return danger;
}


