/*
 ** selectserver.c - a cheezy multiperson chat server
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>
#include "crypt.h"
// port we’re listening on
#define PORT 9034

struct {
            char    ein[DATA_SIZE],
                    din[DATA_SIZE],
                    encrypted[DATA_SIZE],
                    decrypted[DATA_SIZE],
                    iv[BLOCK_SIZE],
                    key[KEY_SIZE];
} data;


int main(int argc, char **argv) {
	fd_set master;					// master file descriptor list
	fd_set read_fds;				// temp file descriptor list for select()
	struct sockaddr_in myaddr;		// server address
	struct sockaddr_in remoteaddr;	// client address
	int fdmax;						// maximum file descriptor number
	int listener;					// listening socket descriptor
	int newfd;						// newly accept()ed socket descriptor
	char buf[256];					// buffer for client data
	int nbytes;
	int yes=1;						// for setsockopt() SO_REUSEADDR, below
	int addrlen;
	int i, j;

	FD_ZERO(&master);				// clear the master and temp sets
	FD_ZERO(&read_fds);
	
	// get the listener
	if ((listener = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}

	 if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
		perror("setsockopt");
	 	exit(1);
	 }

	/* 
	 * lose the pesky "address already in use" error message
	 *
	 * if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
	 *	perror("setsockopt");
	 *	exit(1);
	 * }
	 * 
	 */

	// bind
	myaddr.sin_family      = AF_INET;
	myaddr.sin_addr.s_addr = INADDR_ANY;
	myaddr.sin_port        = htons(PORT);

	memset(&(myaddr.sin_zero), '\0', 8);
	if (bind(listener, (struct sockaddr *)&myaddr, sizeof(myaddr)) == -1) {
		perror("bind");
		exit(1);
	}

	// listen
	if (listen(listener, 10) == -1) {
		perror("listen");
		exit(1);
	}

	// add the listener to the master set
	FD_SET(listener, &master);

	// keep track of the biggest file descriptor
	fdmax = listener; // so far, it’s this one

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
    sess.key    = (__u8 __user *)data.key;

    if(ioctl(cfd, CIOCGSESSION, &sess)) {
        perror("ioctl(CIOCGSESSION)");
        return 1;
    }

    cryp.ses = sess.ses;
    cryp.iv  = data.iv;
    cryp.op  = COP_DECRYPT;


	// main loop
	for(;;) {
		read_fds = master; // copy it
		/*  select(int nfds, fd_set readfds, fd_set writefds, fd_set exceptfds, struct timeval *timeout) */
		if (select(fdmax + 1, &read_fds, NULL, NULL, NULL) == -1) {
			perror("select");
			exit(1);
		}

		// run through the existing connections looking for data to read
		for(i = 0; i <= fdmax; i++) {
			if (FD_ISSET(i, &read_fds)) { // we got one!!
				if (i == listener) {
					// handle new connections
					addrlen = sizeof(remoteaddr);
					if ((newfd = accept(listener, (struct sockaddr *)&remoteaddr, &addrlen)) == -1) {
						perror("accept");
					} else {
						FD_SET(newfd, &master); // add to master set
						if (newfd > fdmax) {
							// keep track of the maximum
							fdmax = newfd;
						}
						printf("selectserver: new connection from %s on "
						"socket %d\n", inet_ntoa(remoteaddr.sin_addr), newfd);
					}
				} else {
						// handle data from a client
						if ((nbytes = recv(i, data.ein, sizeof(data.ein), 0)) <= 0) {
						// got error or connection closed by client
							if (nbytes == 0) {
							// connection closed
								printf("selectserver: socket %d hung up\n", i);
							} else {
								perror("recv");
							}
							close(i); // bye!
							FD_CLR(i, &master); // remove from master set
						} else {
								cryp.len = sizeof(data.ein);
    		                    cryp.src = data.ein;
	        	                cryp.dst = data.decrypted;
            		            cryp.op  = COP_DECRYPT;
                		        if (ioctl(cfd, CIOCCRYPT, &cryp)) {
                        		    perror("ioctl(CIOCCRYPT)");
                            		return 1;
                        		}

								if(memcmp(data.decrypted, "#unicast", 8*sizeof(char)) == 0) {
									printf("\nUnicast from client %d...\n", i);
									
									int index = 0;
									while(data.decrypted[index] != '=') { index++; }
									char *temp = (char *)malloc((index - 7) * sizeof(char));
									strncpy(temp, &data.decrypted[8],  (index - 8) * sizeof(char));
									temp[index - 7] = '\0';
									int temp_sd = atoi(temp);
									
									char *pref = (char *)malloc(DATA_SIZE * sizeof(char));
									memset(pref, '\0', DATA_SIZE);
									strncpy(pref, "Send from ", 10 * sizeof(char));
									/*FIXME: Nothing send from *temp*. *i* sends
									 *	Possible fix: Convert i to string with snprintf
									 *	*/
									strcat(pref, temp);
									strcat(pref, &data.decrypted[index]);

									// printf("pref %s with length = %d\n", pref, strlen(pref));
									memcpy(data.din, pref, DATA_SIZE);

									
									cryp.len = sizeof(data.din);
									cryp.src = data.din;
									cryp.dst = data.encrypted;
									cryp.op  = COP_ENCRYPT;
									if (ioctl(cfd, CIOCCRYPT, &cryp)) {
									    perror("ioctl(CIOCCRYPT)");
										return 1;
									}


									// Send from i

									if (send(temp_sd, data.encrypted, DATA_SIZE, 0) == -1) {
										perror("send");
									}
									
									memset(data.ein, '\0', sizeof(data.din));
									memset(data.encrypted, '\0', sizeof(data.encrypted));
									memset(data.decrypted, '\0', sizeof(data.decrypted));
								}
								else {
									printf("Broadcast from client %d...\n", i);
								
									/* ********************************
									 * we got some data from a client 
									 *	1) unicast
									 *	2) default: broadcast
									 * ********************************
									 * */

									for(j = 0; j <= fdmax; j++) {
										// send to everyone!
										if (FD_ISSET(j, &master)) {
											// except the listener and ourselves
											if (j != listener && j != i) {
												if (send(j, data.ein, nbytes, 0) == -1) {
													perror("send");
												}
											}
										}
									}
								}
						}
				}
			}
		}
	}
	return 0;
}


