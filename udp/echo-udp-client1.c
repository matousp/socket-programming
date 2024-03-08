/*

 Simple echo UDP client with two parameters

 Usage: echo-udp-client2 <server IP address/domain name> <port number>

 (c) Petr Matousek, 2016

 Last update: Sept 2019

*/

#include<stdio.h> 
#include<stdlib.h>
#include<string.h>    
#include<sys/socket.h>
#include<arpa/inet.h> 
#include<netinet/in.h>
#include<unistd.h>
#include<netdb.h>
#include<err.h>

#define BUFFER 1024              // buffer length 

int main(int argc , char *argv[])
{
  int sock, msg_size, i;
  struct sockaddr_in server, from;
  struct hostent *servent;
  socklen_t len; //, fromlen;
  char buffer[BUFFER];

  if (argc != 3)                  // two parameters expected
    errx(1,"Usage: %s <address> <port>",argv[0]);
  
  memset(&server,0,sizeof(server)); // erase the server structure
  server.sin_family = AF_INET;                   

  // make DNS resolution of the first parameter using gethostbyname()
  if ((servent = gethostbyname(argv[1])) == NULL) // check the first parameter
    errx(1,"gethostbyname() failed\n");

  // copy the first parameter to the server.sin_addr structure
  memcpy(&server.sin_addr,servent->h_addr,servent->h_length); 

  server.sin_port = htons(atoi(argv[2]));        // server port (network byte order)
   
  if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1)   //create a client socket
    err(1,"socket() failed\n");
  
  printf("* Socket created\n");

  len = sizeof(server);

  //send data to the server
  while((msg_size=read(STDIN_FILENO,buffer,BUFFER)) > 0) 
      // read input data from STDIN (console) until end-of-line (Enter) is pressed
      // when end-of-file (CTRL-D) is received, n == 0
  { 
    i = sendto(sock,buffer,msg_size,0,(struct sockaddr *) &server, len);  // send data to the server
    if (i == -1)                                 // check if data was sent correctly
      err(1,"sendto() failed");
    else if (i != msg_size)
      err(1,"sendto(): buffer written partially");

    // find out the local port assigned by the OS 
    if (getsockname(sock,(struct sockaddr *) &from, &len) == -1)
      err(1,"getsockname() failed");
    
    printf("* Data sent from local port %d (%d) to %s, port %d (%d)\n",ntohs(from.sin_port),from.sin_port, inet_ntoa(server.sin_addr),ntohs(server.sin_port), server.sin_port); 
    
    // read the answer from the server 
    if ((i = recvfrom(sock,buffer, BUFFER,0,(struct sockaddr *) &from, &len)) == -1)   
      err(1,"recvfrom() failed");
    else if (i > 0){
      printf("* UDP packet received from %s, port %d\n",inet_ntoa(from.sin_addr),ntohs(from.sin_port));
      printf("%.*s",i,buffer);                   // print the answer
    }
  } 
  // reading data until end-of-file (CTRL-D)

  if (msg_size == -1)
    err(1,"reading failed");
  close(sock);
  printf("* Closing client socket ...\n");
  return 0;
}
