#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<sys/types.h>
#include<stdint.h>
#include<unistd.h>

#define BUFFER_LENGTH 256

int main(int argc, char **argv)
{
    printf("--beginning of program\n");
	
	
	int fd;
	printf("Starting device test code example...\nProceess opens lunix0-temp...\n");
	fd = open("/dev/lunix0-temp", O_RDONLY);           

    int counter = 0;
    pid_t pid = fork();

    if (pid == 0)
    {
        // child process

		char child_receive[BUFFER_LENGTH];
		memset(child_receive, 0, BUFFER_LENGTH);
		printf("Child process attempts to read 3 bytes...\n");
		int ret = read(fd, child_receive, 3 * sizeof(char));
		//child_receive[3] = '\0';
		printf("Child process return from read with %d and buffer contents:  %s \n", ret, child_receive);

    }
    else if (pid > 0)
    {
        // parent process
		int *status;
		waitpid(pid, status, WCONTINUED | WUNTRACED);	
		char parent_receive[BUFFER_LENGTH];
		memset(parent_receive, 0, BUFFER_LENGTH);
		printf("Parent process attempts to read 256 bytes...\n");
		int ret = read(fd, parent_receive, BUFFER_LENGTH);

		printf("Parent process return from read with %d and buffer contents:  %s \n", ret, parent_receive);
    }

    printf("--end of program--\n");

    return 0;
}
