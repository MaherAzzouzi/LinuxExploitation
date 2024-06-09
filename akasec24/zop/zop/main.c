#include "pkzip.h"

char *zip_file;

uint64_t read_zip(char *filename){
	FILE *zip = fopen(filename, "r");
	uint64_t file_size;

	fseek (zip, 0, SEEK_END);
	file_size = ftell(zip);
	fseek (zip, 0, SEEK_SET);
	fread(zip_file, 1, file_size, zip);
	return (file_size);
}

int main(int argc, char **argv){
	size_t		read_size;
	char		**files;
	int		fd = 0;
	int		i = -1;

	setvbuf(stdin, 0, _IONBF, 0);
	setvbuf(stdout, 0, _IONBF, 0);
	alarm(140);
	zip_file = malloc(0x4000);
	if (argc < 2){
		printf("include your zip file (base64)>> ");
		fgets(zip_file, 0x4000, stdin);
		read_size = strlen(zip_file);
		zip_file = (char *) base64_decode(zip_file, &read_size);
	} else {
		read_size = read_zip(argv[1]);
	}

	if (read_size < 30)
		return (EXIT_FAILURE);
	files = extract_zip(zip_file, read_size);
	// printing the content of the files
	while (files[++i] != NULL){
		printf("-- %s \n", files[i]);
		fd = open(files[i], O_RDONLY, 0644);
		if (fd < 0){
			printf("%s: %s %m\n", argv[0], files[i]);
			return (EXIT_FAILURE);
		}
		read_size = lseek(fd, 0, SEEK_END);
		lseek(fd, 0, SEEK_SET);
		if (read_size > 0x4000)
			read_size = 0x4000;
		read(fd, zip_file, read_size);
		zip_file[read_size] = '\0';
		printf("------------------------------------------------------------------------\n\n");
		printf("%s\n", zip_file);
		printf("------------------------------------------------------------------------\n\n");
	}
}
