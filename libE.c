/*
libE.c
Written by, Sohail Qayum Malik
*/

#include "cliServ.h"
#include "dnsCli.h"

extern short int sendRequest(void *);

extern unsigned char request[];
extern unsigned char reply[];

extern short int sendRequest(void * serverIp){
   
   struct sockaddr_in serv;
   int sockfd, n;
   
   if((sockfd = socket(PF_INET, SOCK_DGRAM, ZERO)) < ZERO)
      return(LESS_THAN_ZERO); 
   
   memset(&serv, ZERO, sizeof(serv)); 
   serv.sin_family = AF_INET;
   serv.sin_addr.s_addr = inet_addr(serverIp);
   serv.sin_port = htons(DNS_SERV_PORT);

   if(sendto(sockfd, request,REQUEST, ZERO, (SA)&serv, sizeof(serv)) != REQUEST)
      return(LESS_THAN_ZERO);
   
   if((n = recvfrom(sockfd, reply, REPLY, ZERO, (SA)NULL, (int *)NULL)) < ZERO)
      return(LESS_THAN_ZERO);
   
   return(ZERO); 
}

