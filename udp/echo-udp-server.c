/*

 Simple echo UDP server: with a fixed port number

 Usage: ./echo-udp-server

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

#define PORT 3009        // server port number
#define BUFFER	(1024)   // length of the receiving buffer

int main(int argc, char *argv[])
{
  int fd;                           // an incoming socket descriptor
  struct sockaddr_in server;        // server's address structure
  int msg_size, i;     
  char buffer[BUFFER];              // receiving buffer
  struct sockaddr_in client;        // client's address structure
  socklen_t length;
  
  server.sin_family = AF_INET;                     // set IPv4 addressing
  server.sin_addr.s_addr = htonl(INADDR_ANY);      // the server listens to any interface
  server.sin_port = htons(PORT);                   // the server listens on this port
  
  printf("* Opening an UDP socket ...\n");
  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) // create the server UDP socket
    err(1, "socket() failed");

  printf("* Binding to the port %d (%d)\n",PORT,server.sin_port);
  if (bind(fd, (struct sockaddr *)&server, sizeof(server)) == -1) // binding with the port
    err(1, "bind() failed");
  length = sizeof(client);
  
  while ((msg_size = recvfrom(fd, buffer, BUFFER, 0, (struct sockaddr *)&client, &length)) >= 0) 
    {
      printf("* Request received from %s, port %d\n",inet_ntoa(client.sin_addr),ntohs(client.sin_port));
      
      for (i = 0; i < msg_size; i++)
	if (islower(buffer[i]))
	  buffer[i] = toupper(buffer[i]);
	else if (isupper(buffer[i]))
	  buffer[i] = tolower(buffer[i]);

      i = sendto(fd, buffer, msg_size, 0, (struct sockaddr *)&client, length); // send the answer
      if (i == -1)
	err(1, "sendto()");
      else if (i != msg_size)
	errx(1, "sendto(): Buffer written just partially");
      else
	printf("* Data \"%.*s\" sent from port %d to %s, port %d\n",i-1,buffer,ntohs(server.sin_port), inet_ntoa(client.sin_addr),ntohs(client.sin_port));
    }
  printf("* Closing the socket\n");
  close(fd);
  
  return 0;
}

