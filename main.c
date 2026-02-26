#include <stdio.h>
#include <string.h>

char *keywords[] = {"hack into computer", "breach firewall", "delete system 32", "steal e-girls"};
int num_keywords = 4;
#define LINE_LENGTH 256
char s[LINE_LENGTH];

void parser(FILE *file, char *s) {
	int keywordsfound = 0;
	int linecount = 1;

	while (fgets(s, LINE_LENGTH, file) != NULL) {
		for (int i = 0; i < num_keywords; i++) {
			if (strstr(s, keywords[i]) != NULL) {
				keywordsfound += 1;
			}
		}
		if (keywordsfound > 0) {
			printf("Warning: %i Keyword(s) Found On Line %i \n", 
	  		keywordsfound, linecount);
		}
		keywordsfound = 0;
		linecount += 1;
	}
}

int main(int argc, char *argv[]) {
	if (argc != 2) {
		printf("Usage: %s filename\n", argv[0]);
		return 0;
	}
	FILE *file;
	file = fopen(argv[1], "r");
	 if (file == NULL) {
        printf("Error: Could not open file %s\n", argv[1]);
        return 0;
    	} else {
        printf("File %s opened successfully!\n", argv[1]);
	}
	if (fgets(s, LINE_LENGTH, file) == NULL) {
		return 0;
	}
	else {
	rewind(file);
	printf("File %s read successfully!\n", argv[1]);
	}
	parser(file, s);
	fclose(file);
}


