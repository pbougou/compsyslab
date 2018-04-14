#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>


#include <signal.h>


#include <crypto/cryptodev.h>
#include "crypt.h"

#define MAX_HOSTNAME_SIZE 80
#define MAX_MESSAGE_SIZE  100

int force_send(int s, char *buf, int *len)
{
	int total = 0;
	int bytesleft = *len;

	int n;
	while(total < *len)
	{
		n = send(s, buf+total, bytesleft, 0);
		if(n == -1) 
		{
			break;
		}
		total += n;
		bytesleft -= n;
	}
	*len = total;

	if(total < *len)
	{
		printf("Warning: message had been truncated\n");
	}
	return n==-1 ? -1 : 0;
}


struct {
	char ein[DATA_SIZE], 
		 din[DATA_SIZE], 
		 encrypted[DATA_SIZE], 
		 decrypted[DATA_SIZE], 
		 iv[BLOCK_SIZE], 
		 key[KEY_SIZE];
} data;


int main(int argc, char *argv[])
{
	signal(SIGPIPE, SIG_IGN);
	//Check Command Line Arguments
	if(argc != 3)
	{
		printf("Usage: chat HOSTNAME PORT\n");
		exit(1);
	}

	//get hostname
	char hostname[MAX_HOSTNAME_SIZE];
	strcpy(hostname, argv[1]);	
	//get port
	int port = atoi(argv[2]);

	//look for host name and port
	struct hostent *hostinfo;
	if((hostinfo = gethostbyname(hostname)) == NULL)
	{
		perror("gethostbyname");
		exit(1);
	}

	/* 
	 * Details of host
	 *	printf("Host name : %s\n", hostinfo->h_name);
	 *  printf("IP Address : %s\n", inet_ntoa(*((struct in_addr *)hostinfo->h_addr)));
	 */

	struct sockaddr_in host_address;

	host_address.sin_family = AF_INET;
	host_address.sin_port = htons(port); // short, network byte order
	host_address.sin_addr = *((struct in_addr *)hostinfo->h_addr);
	bzero(&(host_address.sin_zero), 8); // zero the rest of the struct

	//Create my socket
	int my_sock;
	if ((my_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}

	//Try to connect
	if (connect(my_sock, (struct sockaddr *)&host_address, sizeof(struct sockaddr)) == -1) {
		perror("connect");
		exit(1);
	}

	printf("\n*** Client program: Successfully connected to chat server running on %s\n",inet_ntoa(*((struct in_addr *)hostinfo->h_addr)) );
	

	//Create set of descriptors
	fd_set client_fds, read_fds;

	FD_ZERO(&client_fds);
	FD_SET(my_sock, &client_fds);
	FD_SET(0, &client_fds); // ADD stdin to descriptors set

	int fdmax = my_sock; //for select

	// char buff[256];

	int cfd = open("/dev/cryptodev0", O_RDWR);
	struct session_op sess;
	struct crypt_op cryp;
	memset(&sess, 0, sizeof(sess));
	memset(&cryp, 0, sizeof(cryp));
	memset(data.ein, '\0', sizeof(data.ein));
	memset(data.din, '\0', sizeof(data.din));
	memset(data.encrypted, '\0', sizeof(data.encrypted));
	memset(data.decrypted, '\0', sizeof(data.decrypted));
	memset(data.key, '\0', sizeof(data.key));
	memset(data.iv, '\0', sizeof(data.iv));


	memcpy(data.key, KEY, KEY_SIZE);
	memcpy(data.iv, IV, BLOCK_SIZE);

	sess.cipher = CRYPTO_AES_CBC;
	sess.keylen = KEY_SIZE;
	sess.key    = data.key;

	if(ioctl(cfd, CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		return 1;
	}

	cryp.ses = sess.ses;
	cryp.iv  = data.iv;
	cryp.op  = COP_DECRYPT;
	

	for(;;) {
		read_fds = client_fds;
		if (select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1) {
			perror("select");
			exit(1);
		}

		for(int i = 0; i <= fdmax; i++) {
			if(FD_ISSET(i, &read_fds)) {
				// ith file descriptor has something ready to read
				if(i == my_sock) {
					//server data
					int nbytes;
					if((nbytes = recv(i, data.ein, sizeof(data.ein), 0)) <= 0) {
						/*  Close cryptosession  */
						//got error or connection closed by server
						if(nbytes == 0) {
							//connection closed
							printf("selectclient: socket %d hung up\n", i); 
						}
						else {
							perror("recv");
							exit(1);
						}
					} else {
						/* Successfully received by client  */
						cryp.len = sizeof(data.ein);
						cryp.src = data.ein;
						cryp.dst = data.decrypted;
						cryp.op  = COP_DECRYPT;
						if (ioctl(cfd, CIOCCRYPT, &cryp)) {
							perror("ioctl(CIOCCRYPT)");
							return 1;
						}

						for (i = 0; i < nbytes; i++)	{
							printf("%c", data.decrypted[i]);
						}

						memset(data.ein, '\0', sizeof(data.din));
						memset(data.decrypted, '\0', sizeof(data.encrypted));
						// printf("%.*s", nbytes, data.decrypted);
						fflush(stdout);
					}
				}
				// Send from stdin to other clients
				else if( i == 0) {
					// Client reads from stdin up to 256 chars
					int n;
					if((n = read(0, data.din, DATA_SIZE)) < 0) {
						perror("read: client stdin\n");
						exit(1);
					}


					int bytes_to_send = DATA_SIZE;
					cryp.src = data.din;
					cryp.dst = data.encrypted;
					cryp.len = sizeof(data.din);

					cryp.op  = COP_ENCRYPT;

					if (ioctl(cfd, CIOCCRYPT, &cryp)) {
						perror("ioctl(CIOCCRYPT)");
						return 1;
					}

					force_send(my_sock, data.encrypted, &bytes_to_send);  

					memset(data.din, '\0', sizeof(data.din));
					memset(data.encrypted, '\0', sizeof(data.encrypted));

				}
			}
		}

	}

	return 0;
}


