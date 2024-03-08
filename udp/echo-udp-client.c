/*

 Simple echo UDP client: with a fixed IP address and port number of the server

 Usage: echo-udp-client

 (c) Petr Matousek, 2016

 Last update: Sept 2019

*/

#include<stdio.h> 
#include<string.h>    
#include<sys/socket.h>
#include<arpa/inet.h> 
#include<netinet/in.h>
#include<unistd.h>
#include<netdb.h>
#include<err.h>

#define IP_ADDR "127.0.0.1"      // a fixed server IP address
#define PORT 3009                // a fixed server port
#define BUFFER 1024              // buffer length 

int main(int argc , char *argv[])
{
  int sock, msg_size, i;
  struct sockaddr_in server, from;
  socklen_t len;
  char buffer[BUFFER];
   
  if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1)   //create a client socket
    err(1,"socket() failed\n");
  
  printf("* Socket created\n");
     
  server.sin_addr.s_addr = inet_addr(IP_ADDR);   // set the server address
  server.sin_family = AF_INET;                   
  server.sin_port = htons(PORT);                 // set the server port (network byte order)

  len = sizeof(server);

  // read data from a user and send them to the server
  while((msg_size=read(STDIN_FILENO,buffer,BUFFER)) > 0) 
      // read input data from STDIN (console) until end-of-line (Enter) is pressed
      // when end-of-file (CTRL-D) is received, n == 0
  { 
    i = sendto(sock,buffer,msg_size,0,(struct sockaddr *) &server, len);  // send data to the server
    if (i == -1)                                 // check if data was sent correctly
      err(1,"sendto() failed");
    else if (i != msg_size)
      err(1,"sendto(): buffer written partially");
    len = sizeof(from);

    // obtain the local port number assigned by the OS
    if (getsockname(sock,(struct sockaddr *) &from, &len) == -1) 
      err(1,"getsockname() failed");
    
    printf("* Data sent from port %d (%d) to %s, port %d (%d)\n",ntohs(from.sin_port),from.sin_port, inet_ntoa(server.sin_addr),ntohs(server.sin_port), server.sin_port); 
    
    // read the answer from the server 
    if ((i = recvfrom(sock,buffer, BUFFER,0,(struct sockaddr *) &from, &len)) == -1)   
      err(1,"recvfrom() failed");
    else if (i > 0){
      printf("* UDP packet received from %s, port %d (%d)\n",inet_ntoa(from.sin_addr),ntohs(from.sin_port), from.sin_port);
      printf("%.*s",i,buffer);                   // print the answer
    }
  } 
  // read data until end-of-file (CTRL-D)

  if (msg_size == -1)
    err(1,"reading failed");
  close(sock);
  printf("* Closing the client socket ...\n");
  return 0;
}
