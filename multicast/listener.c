/*
 * listener.c -- joins a multicast group and echoes all data it receives from
 *		the group to its stdout...
 *
 * Usage: listener <multicast IP address> <port>
 *
 * Petr Matousek, 2015
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>

#define BUFFER (1024)

int main(int argc, char *argv[]){
  struct sockaddr_in addr;    // address data structure
  int fd;                     // a multicast socket
  int n;
  socklen_t addrlen;          // length of addr data structure
  struct ip_mreq mreq;        // multicast request data structure
  char buffer[BUFFER];        // buffer with data to be sent
  u_int on=1;                 // socket option flag

  if (argc != 3)              // three parameters required on the command line
    errx(1,"Usage: %s <multicast IP address> <port>",argv[0]);

  if ((fd=socket(AF_INET,SOCK_DGRAM,0)) < 0) // create a UDP socket for multicast
    errx(1,"socket");

  //  allow multiple instances of this program to use the same PORT number 
  if (setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)) < 0)
    errx(1,"setsockopt() reause address failed");
  
  // initialize a socket data address structure 
  memset(&addr,0,sizeof(addr));
  addr.sin_family=AF_INET;
  addr.sin_addr.s_addr=htonl(INADDR_ANY); // listen to any interface (IP address)
  addr.sin_port=htons(atoi(argv[2]));     // port number given as the second argument
  
  // assing the multicast port with the socket using bind()
  if (bind(fd,(struct sockaddr *) &addr,sizeof(addr)) < 0)
    errx(1,"bind() failed");
     
  // initialize multicast request data structure "mreq"
  mreq.imr_multiaddr.s_addr=inet_addr(argv[1]); // multicast IP address given by the first argument
  mreq.imr_interface.s_addr=htonl(INADDR_ANY);  // listen to a local interface given by the kernel

  // send the join request (IGMP message)
  if (setsockopt(fd,IPPROTO_IP,IP_ADD_MEMBERSHIP,&mreq,sizeof(mreq)) < 0)
    errx(1,"setsockopt() failed");
  printf("Joining the multicast group %s, port %d \n",argv[1],atoi(argv[2]));
     
  // read data from the multicast socket and print them on stdout until "END." is received
  while ((n= recvfrom(fd, buffer, BUFFER, 0, (struct sockaddr *)&addr, &addrlen)) >= 0){
    printf("Data \"%.*s\" received\n",n,buffer);
    if (strncmp(buffer,"END.",4) == 0){          // "END." string received

      if (setsockopt(fd,IPPROTO_IP,IP_DROP_MEMBERSHIP,&mreq,sizeof(mreq)) < 0)
	errx(1,"setsockopt() failed");
      printf("Leaving the multicast group %s, port %d ...\n",argv[1],atoi(argv[2]));
      close(fd);
      printf("Closing socket\n");
      exit(0);
    }
  }
  exit(0);
}
