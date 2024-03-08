/*

 Simple echo UDP server

 Usage: ./echo-udp-server1 <port-number>

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
  struct sockaddr_in server;        // server's address structure
  int n, r;     
  char buffer[BUFFER];              // receiving buffer
  struct sockaddr_in client;        // client's address structure
  socklen_t length;
  
  if (argc != 2)               // read the first parameter: a port number
    errx(1,"Usage %s <port number>",argv[0]);
  
  server.sin_family = AF_INET;                     // set IPv4 addressing
  server.sin_addr.s_addr = htonl(INADDR_ANY);      // the server listens to any interface
  server.sin_port = htons(atoi(argv[1]));          // the server listens on this port
  
  printf("* Opening an UDP socket ...\n");
  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) // create the server UDP socket
    err(1, "socket() failed");

  printf("* Binding to the port %d (%d)\n",atoi(argv[1]), server.sin_port);
  if (bind(fd, (struct sockaddr *)&server, sizeof(server)) == -1) // binding with the port
    err(1, "bind() failed");

  length = sizeof(client);
  while ((n= recvfrom(fd, buffer, BUFFER, 0, (struct sockaddr *)&client, &length)) >= 0) 
    {
      printf("* Request received from %s, port %d\n",inet_ntoa(client.sin_addr),ntohs(client.sin_port));
      
      for (r = 0; r < n; r++)
	if (islower(buffer[r]))
	  buffer[r] = toupper(buffer[r]);
	else if (isupper(buffer[r]))
	  buffer[r] = tolower(buffer[r]);

      r = sendto(fd, buffer, n, 0, (struct sockaddr *)&client, length); // send the answer
      if (r == -1)
	err(1, "sendto()");
      else if (r != n)
	errx(1, "sendto(): Buffer written just partially");
      else
	printf("* Data \"%.*s\" sent from local port %d to %s, port %d\n",r-1,buffer,ntohs(server.sin_port), inet_ntoa(client.sin_addr),ntohs(client.sin_port));
    }
  printf("* Closing the socket\n");
  close(fd);
  
  return 0;
}

