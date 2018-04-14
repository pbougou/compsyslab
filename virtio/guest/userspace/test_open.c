#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
int main(int argc, char **argv) {

	if(argc != 2) {
		printf("Usage: %s /dev/cryptodev*\n", argv[0]);
		exit(1);
	}

	int fd = open(argv[1], O_RDWR);
	if(fd < 0) {
		perror("open");
		exit(1);
	}
	printf("Success\n");
	return 0;
}
