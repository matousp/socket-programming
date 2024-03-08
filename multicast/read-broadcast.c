/*

 UDP server that reads data sent to a broadcast address and given port until "END." is received

 Usage: ./read-broadcast <port-number>

 (c) Petr Matousek, 2016

 Last update: Sept 2019

*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <err.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFFER	(1024)   // length of the receiving buffer

int main(int argc, char *argv[])
{
  int fd;                           // an incoming socket descriptor
  struct sockaddr_in server;        // data address structures
  int msg_size;     
  char buffer[BUFFER];              // receiving buffer
  struct sockaddr_in from;          // sender's data address structure
  socklen_t length;
  
  if (argc != 2)               // read the first parameter: a port number
    errx(1,"Usage %s <port number>",argv[0]);
  
  server.sin_family = AF_INET;                     // set IPv4 addressing
  server.sin_addr.s_addr = htonl(INADDR_ANY);      // the server listens to any interface
  server.sin_port = htons(atoi(argv[1]));          // the server listens on this port
  
  printf("* Opening UDP socket ...\n");
  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) // create the server UDP socket
    err(1, "socket() failed");

  printf("* Binding to the port %d (%d)\n",htons(server.sin_port),server.sin_port);
  if (bind(fd, (struct sockaddr *)&server, sizeof(server)) == -1) // binding with the port
    err(1, "bind() failed");
  length = sizeof(from);
  
  while ((msg_size = recvfrom(fd, buffer, BUFFER, 0, (struct sockaddr *)&from, &length)) >= 0) 
    {
      printf("* UDP packet received from %s, port %d (%d)\n",inet_ntoa(from.sin_addr),ntohs(from.sin_port),from.sin_port);
      printf("* Message=\"%.*s\"\n",msg_size,buffer);

      if (strncmp(buffer,"END.",4) == 0){    // "END." string exits application
	printf("* Closing socket\n");
	close(fd);
	exit(0);
      }
    }
  printf("* Closing socket\n");
  close(fd);
  
  return 0;
}

