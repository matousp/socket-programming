/*

 Simple echo server that converts upper/lower case letters
 - with a dynamic port number
 - concurrent server (with fork() and handling the CHILD signal
 - CTRL-C stops running the server

 Usage: echo-server2 <port number>

 (c) Petr Matousek, 2016

 last update: Feb 2022
*/
 
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<signal.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<err.h>
#include<ctype.h>

#define BUFFER 256          // buffer for incoming messages
#define QUEUE 1             // queue length for  waiting connections
 
int main(int argc , char *argv[]){ // expect one parameter: port number
  int fd;
  int newsock;
  int len, msg_size, i;
  struct sockaddr_in server;   // the server configuration (socket info)
  struct sockaddr_in from;     // configuration of an incoming client (socket info)
  char buffer[BUFFER];
  pid_t pid; long p;           // process ID number (PID)
  struct sigaction sa;         // a signal action when CHILD process is finished
     
  
  if (argc != 2)               // read the first parameter: a port numberq
    errx(1,"Usage %s <port number>",argv[0]);

  // handling SIG_CHILD for concurrent processes
  // necessary for correct processing of child's PID 

  sa.sa_handler = SIG_IGN;      // ignore signals - no specific action when SIG_CHILD received
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);     // no mask needed 
  if (sigaction(SIGCHLD,&sa,NULL) == -1)  // when SIGCHLD received, no action required
    err (1,"sigaction() failed");


  if ((fd = socket(AF_INET , SOCK_STREAM , 0)) == -1)   //create a server socket
    err(1,"socket(): could not create the socket");
  
  printf("* Socket successfully created by socket()\n");

  server.sin_family = AF_INET;             // initialize server's sockaddr_in structure
  server.sin_addr.s_addr = INADDR_ANY;     // wait on every network interface, see <netinet/in.h>
  server.sin_port = htons(atoi(argv[1]));  // set the port where server is waiting
     

  if( bind(fd,(struct sockaddr *)&server , sizeof(server)) < 0)  //bind the socket to the port
    err(1,"bind() failed");

  printf("* Socket succesfully bound to the port using bind()\n");
     
  if (listen(fd,QUEUE) != 0)   //set a queue for incoming connections
    err(1,"listen() failed");
     
  printf("* Waiting for incoming connections on port %d (%d)...\n", atoi(argv[1]),server.sin_port);
     
  // accept new connection from an incoming client
  // parameter "from" retrieves information about the client socket
  // newsock is a file descriptor to a new socket where incoming connection is processed

  len = sizeof(from);
  while(1){  // wait for incoming connections (concurrent server)
    // accept a new connection
    if ((newsock = accept(fd, (struct sockaddr *)&from, (socklen_t*)&len)) == -1)
      err(1,"accept failed");

    if ((pid = fork()) > 0){  // this is parent process
      printf("parent: closing newsock and continue to listen to new incoming connections\n");
      close(newsock);
    }
    else if (pid == 0){  // this is a child process that will handle an incoming request
      p = (long) getpid(); // current child's PID
      printf("* Closing parent's socket fd, my PID=%ld\n",p);
      close(fd);

      printf("* A new connection accepted from  %s, port %d (%d)\n",inet_ntoa(from.sin_addr),ntohs(from.sin_port), from.sin_port);
      strcpy(buffer,"200 OK: Echo server2 is listening\n"); // sends confirmation to the client
      msg_size = strlen(buffer);
      i = write(newsock,buffer,msg_size);
      if (i != msg_size){
	err(1,"initial write() failed");
      }

      // process incoming messages from the client using "newsock" socket
      // until the client stops sending data (CRLF)

      while((msg_size = read(newsock, buffer, BUFFER)) > 0){    // read the message
	printf("received data = \"%.*s\"\n",msg_size-2,buffer); // tear off CR+LF from the receiving buffer
	
	for (i = 0; i < msg_size; i++)          // convert data to upper/lower case
	  if (islower(buffer[i]))
	    buffer[i] = toupper(buffer[i]);
	  else if (isupper(buffer[i]))
	    buffer[i] = tolower(buffer[i]);
	
	i = write(newsock,buffer,msg_size);    // send a converted message to the client
	if (i == -1)                           // check if data was successfully sent out
	  err(1,"write() failed.");
	else if (i != msg_size)
	  err(1,"write(): buffer written partially");
      }
      // no other data from the client -> close the client and wait for another
      
      printf("* Closing newsock\n");
      close(newsock);                          // close the new socket
      exit(0);                                 // exit the child process
    } 
    else
      err(1,"fork() failed");
  } 
  
  // close the server 
  printf("*Closing the original socket\n");
  close(fd);                               // close an original server socket
  return 0;
}
