#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<sys/types.h>
#include<stdint.h>
#include<unistd.h>

#include "src/lunix-chrdev.h"
 
#define BUFFER_LENGTH 256               ///< The buffer length (crude but fine)
char receive[BUFFER_LENGTH];     ///< The receive buffer from the LKM
 
int main(){
   int ret, fd;
   printf("Starting device test code example...\n");
   fd = open("/dev/lunix0-temp", O_RDONLY);             // Open the device with read/write access
   //fd = open("/dev/lunix0-temp", O_NONBLOCK);             

   if (fd < 0){
      perror("Failed to open the device...");
      return errno;
   }
 
   while(1)
   {

	   memset(receive, 0, BUFFER_LENGTH);

	   printf("Reading from the device 256 BYTES...\n");
	   ret = read(fd, receive, BUFFER_LENGTH);        // Read the response from the LKM

	   if (ret < 0){
		  perror("Failed to read the message from the device.");
		  return errno;
	   }

	   printf("h read epestrepse : %d kai h metrhsh einai : %s\n", ret, receive);
	   int c = ioctl(fd, LUNIX_IO_SET_MODE);

	}
	printf("End of the program\n");


	return 0;
}
