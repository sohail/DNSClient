/*
libB.c
Written by, Sohail Qayum Malik[sqm@hackers.pk]
*/

#include "dnsCli.h"
#include "cliServ.h"

extern void createRequest(short int, unsigned short int, char *);
extern void interprateFlags(unsigned short int *);

extern unsigned char argumentFlags[];
extern unsigned char request[];
extern unsigned char ptrIpDotCount[];
extern unsigned short int domainCharCount;
extern unsigned char firstDomainTag;
extern unsigned short rrType;

unsigned short int ptrArgumentError = ZERO;

void createRequest(short int idValue, unsigned short int flagsValue, char * ptrDomain){

   unsigned short int localCount = ZERO;
   short int dotCount            = THREE;
   unsigned short int strIndex   = ZERO;
   unsigned short int charCount  = ZERO;

   ((short int *)request)[ZERO]  = idValue;
   ((short int *)request)[ONE]   = flagsValue;
   ((short int *)request)[TWO]   = NUMBER_OF_QUESTIONS;
   ((short int *)request)[THREE] = ZERO;
   ((short int *)request)[FOUR]  = ZERO;
   ((short int *)request)[FIVE]  = ZERO;

if( argumentFlags[PTR] == ZERO ){

   request[TWELVE] = firstDomainTag; 
   
   while( localCount < domainCharCount){
       request[THERTEEN + localCount] = ptrDomain[localCount];       
       localCount++; 
   }  
  

   if( firstDomainTag > ZERO ){
      request[THERTEEN + domainCharCount] = DOMAIN_NAME_END;   
      domainCharCount++;
   }
   
*((unsigned short int *)&request[THERTEEN + domainCharCount])=rrType;
*((unsigned short int *)&request[THERTEEN + domainCharCount + TWO])=CLASS_TYPE;
}
else{
/* form request when the ptr request is made.... */
/* assign localCount value of ZERO. */
/* the first index into the request array is TWELVE + localCount */
strIndex = (unsigned short int)(ptrIpDotCount[ZERO] + ptrIpDotCount[ONE] + ptrIpDotCount[TWO] + THREE);

while( dotCount >= ZERO ){

   if( ptrIpDotCount[dotCount] > ZERO){
      request[TWELVE + localCount] = ptrIpDotCount[dotCount];
      localCount++;  
   }
   else{
      /* 
         REMEMBER TO GENERATE AN ERROR MESSAGE  
         on second thought, on the basis of GIGO 
         the inverse query with in-addre.arpa will
         result in further lookup of root servers.
      */      
      ptrArgumentError = ERROR;
      break;
   }    
   for(charCount = ZERO; charCount < (unsigned short int)ptrIpDotCount[dotCount]; charCount++){
      request[TWELVE + localCount] = ptrDomain[strIndex + charCount];      
      localCount++;
   }
   
   if( dotCount > ZERO )
      strIndex = strIndex - (ptrIpDotCount[dotCount - ONE] + ONE);
   
dotCount--;
}

request[TWELVE + localCount + ZERO] = SEVEN;
request[TWELVE + localCount + ONE] = 'i';
request[TWELVE + localCount + TWO] = 'n';
request[TWELVE + localCount + THREE] = '-';
request[TWELVE + localCount + FOUR] = 'a';
request[TWELVE + localCount + FIVE] = 'd';
request[TWELVE + localCount + SIX] = 'd';
request[TWELVE + localCount + SEVEN] = 'r';
request[TWELVE + localCount + EIGHT] = FOUR;
request[TWELVE + localCount + NINE] = 'a';
request[TWELVE + localCount + TEN] = 'r';
request[TWELVE + localCount + ELEVEN] = 'p';
request[TWELVE + localCount + TWELVE] = 'a';
request[TWELVE + localCount + THERTEEN] = DOMAIN_NAME_END;
localCount += (THERTEEN + ONE);

*((unsigned short int *)&request[TWELVE + localCount]) = RR_TYPE_PTR;
*((unsigned short int *)&request[TWELVE + localCount + TWO]) = CLASS_TYPE;

}

/* Display request begins.... */    
if( argumentFlags[VERBOSE] > ZERO ){
   printf("Request....\n");
   printf("ID = %d, ",*((short int *)request));
   printf("Flags = %x",((unsigned short int *)request)[ONE]);

/* PLACE TO CALL INTERPRATE FLAGS */
interprateFlags( ( (unsigned short int *)request + ONE ) ); 

   printf(", Number of questions = %d, ",((unsigned short int *)request)[TWO] / RIGHT_SHIFT);

if( argumentFlags[PTR] == ZERO ){
   printf("domain = ");
   for(localCount = ZERO; localCount < domainCharCount; localCount++)
   printf("%c",request[TWELVE + localCount]);
   printf(", ");
}
else{
/* display the in-addr.arpa domain-name */
printf("IP address = ");
for(charCount = ZERO; charCount < (localCount - ONE); charCount++)
printf("%c",request[TWELVE + charCount]);
printf(", ");
}

if( argumentFlags[PTR] == ZERO ) {
   printf("RR type = %d, ", *((unsigned short int *)&request[THERTEEN + domainCharCount]) / RIGHT_SHIFT);
   printf("CLASS type = %d, ", *((unsigned short int *)&request[THERTEEN + domainCharCount + TWO]) / RIGHT_SHIFT);
}
else{
printf("RR type = %d, ", *((unsigned short int *)&request[TWELVE + localCount]) / RIGHT_SHIFT);
printf("CLASS type = %d, ",*((unsigned short int *)&request[TWELVE + localCount + TWO]) / RIGHT_SHIFT);
}
printf("\n");

}  
/* Display request ends.... */


}

