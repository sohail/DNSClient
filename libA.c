/*
libA.c
Written by, Sohail Qayum Malik
*/

#include <signal.h>
#include "cliServ.h"
#include "dnsCli.h"

extern short int sendRequest(void *);
extern short int init(void **);
extern void createRequest(short int, unsigned short int, char *);
extern void pareseReply(void);

unsigned char request[REQUEST];
unsigned char reply[REPLY];

extern unsigned char argumentFlags[];
extern short int alarmCount;

short int init(void ** argumentValue){
   
   short int idValue             = ZERO;
   unsigned short int flagsValue = ZERO;
   
   short int status = ZERO;   
  
  if( argumentFlags[ID] != ZERO ) 
  idValue=(short int)atoi(((unsigned char **)argumentValue)[argumentFlags[ID]]);
  else
  idValue=LESS_THAN_ZERO;

  if( argumentFlags[AUTHORITY] == ZERO )
     flagsValue += RECURSIVE_QUERY;
  
  if( argumentFlags[PTR] != ZERO )
     flagsValue += INVERSE_QUERY;

if( argumentFlags[PTR] == ZERO ) 
  createRequest(idValue, flagsValue, ((unsigned char **)argumentValue)[ argumentFlags[DOMAIN] ] );
else
  createRequest(idValue, flagsValue, ((unsigned char **)argumentValue)[ argumentFlags[PTR] ]  );

/*--------------------------------------------------------------------------*/

/* 
 The alarm clock, defaults to 5 seconds use -c or --clock parameter to give time in seconds, which should be (clock > 0x05) ? alarm(clock) : alarm(FIVE). 
*/
  
  if( alarmCount < FIVE)
     alarm(FIVE);
  else
     alarm(alarmCount);      


/* --------------------------------------------------------------------------*/

 status=sendRequest(((unsigned char **)argumentValue)[argumentFlags[SERVERIP]]);
  if(status == (short int)LESS_THAN_ZERO){
     printf("No DNS server IP adress!\n");
     return(LESS_THAN_ZERO);
  }
  status = ZERO; 

  parseReply();
 
  return(ZERO); 

}

