/*
 * send-broadcast.c -- broadcast data from the input line to a local network
 *
 * Usage: send-broadcast <broadcast IP address> <port>
 *
 * (c) Petr Matousek, 2016
 *
 * Last update, Sept 2019
 * 
 */

#include <stdio.h>        
#include <stdlib.h>
#include <string.h>       
#include <sys/socket.h>   
#include <arpa/inet.h>    
#include <netinet/in.h>   
#include <unistd.h>
#include <netdb.h>        
#include <err.h>

#define BUFFER (1024)

int main(int argc, char *argv[]){
  int  fd;                     // UDP socket
  struct sockaddr_in   addr;   // address data structure
  char  buffer[BUFFER]; 
  int on;                      // socket option
  int msg_size;

  if (argc != 3)                          // three parameters required
    err(1,"Usage: %s <broacast IP address> <port>",argv[0]);

  if ((fd=socket(AF_INET,SOCK_DGRAM,0)) < 0) // create a UDP socket for broadcast
    err(1,"* Socket() failed");

  memset(&addr,0,sizeof(addr));
  addr.sin_family=AF_INET;
  addr.sin_addr.s_addr=inet_addr(argv[1]);  // set the broadcast address
  addr.sin_port=htons(atoi(argv[2]));       // set the broadcast port

  on = 1;                                   // set socket to send broadcast messages
  if ((setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on))) == -1)
    err(1,"setsockopt failed()");

  while((msg_size=read(STDIN_FILENO,buffer,BUFFER)) > 0){                           // read the command line 
    if (sendto(fd,buffer,msg_size-1,0,(struct sockaddr *) &addr, sizeof(addr)) < 0) // send data without EOL
      err(1,"sendto");
    printf("* Sending \"%.*s\" to %s, port %d\n",msg_size-1,buffer,argv[1],atoi(argv[2]));
  } // until EOF (CTRL-D)

  
  if ((close(fd)) == -1)      // close the socket
    err(1,"close() failed");
  printf("* Closing socket ...\n");

  exit(0);
}
