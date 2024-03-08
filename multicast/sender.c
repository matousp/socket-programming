/*
 * sender.c -- multicasts data from the input line to a multicast group until CTRL-D
 *
 * Usage: sender <multicast IP address> <port> <ttl>
 *
 * (c) Petr Matousek, 2015-18
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
#define TTL 1

int main(int argc, char *argv[])
{
  int fd;                    // multicast sender socket
  int n;            
  struct sockaddr_in addr;   // socket data structure
  u_char ttl, loop;          // multicast options
  char buffer[BUFFER];       // sender buffer
  
  if (argc != 4)                          // three parameters required
    errx(1,"Usage: %s <multicast IP address> <port> <ttl>",argv[0]);

  if ((fd=socket(AF_INET,SOCK_DGRAM,0)) < 0) // create a UDP socket for multicast
    errx(1,"Socket() failed");


  // set address and port of the multicast group
  memset(&addr,0,sizeof(addr));
  addr.sin_family=AF_INET;
  addr.sin_addr.s_addr=inet_addr(argv[1]);  // multicast IP given as the first argument
  addr.sin_port=htons(atoi(argv[2]));       // multicast port number given as the second argument

  // set the scope of multicast by TTL value
  ttl = atoi(argv[3]);
  printf("Sending multicast data to %s:%d with ttl=%d\n",argv[1],atoi(argv[2]),ttl);
  if (setsockopt(fd,IPPROTO_IP,IP_MULTICAST_TTL,&ttl,sizeof(ttl)) == -1)
    errx(1,"setsockopt() failed in ttl");

  loop=1;  // enable receiving of sent multicast data on the local loopback interface 
  if (setsockopt(fd,IPPROTO_IP,IP_MULTICAST_LOOP,&loop,sizeof(loop)) == -1)
    errx(1,"setsockopt() failed in loop");

  // sent data to the multicast group 
  while((n=read(STDIN_FILENO,buffer,BUFFER)) > 0){                           // read the command line 
    if (sendto(fd,buffer,n-1,0,(struct sockaddr *) &addr, sizeof(addr)) < 0) // send data without EOL
      errx(1,"sendto");
    printf("Sending \"%.*s\" to %s, port %d\n",n-1,buffer,argv[1],atoi(argv[2]));
  } // until EOF (CTRL-D)

  if (close(fd) == -1)           
    errx(1,"close() failed\n");

  printf("Closing socket ...\n");
  exit(0);
}
