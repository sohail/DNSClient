/*
libC.c
Written by, Sohail Qayum Malik[sqm@hackers.pk]
*/
#include "dnsCli.h"
#include "cliServ.h"

extern void parseReply(void);
extern void interprateFlags(unsigned short int *);

extern unsigned char reply[];
extern unsigned char argumentFlags[];
extern unsigned short rrTypeStillNotImplemented;
extern unsigned short int ptrArgumentError;
extern unsigned short int alarmCount;

/* ---------------------------------------------------------------- */

extern unsigned short int domainParser(void *);
extern unsigned short int typeParser(void *);
extern unsigned short int classParser(void *);
extern unsigned short int ttlParser(void *);
extern unsigned short int dataParser(void *);
   
/* ---------------------------------------------------------------- */

void parseReply(void){
    
    unsigned short int localCount = ZERO;
    unsigned short int x = ZERO; 
     
 
printf("Reply....\n");
   printf("ID = %d, ", ((short int *)reply)[ZERO]);
   printf("Flags = %x", ((unsigned short int *)reply)[ONE]);

if( argumentFlags[VERBOSE] > ZERO)
/* PLACE TO CALL INTERPRATE FLAGS */
   interprateFlags( ( (unsigned short int *)reply + ONE ) ) ;

if( argumentFlags[VERBOSE] == ZERO )
printf(", Number of questions = %d", ((unsigned short int *)reply)[TWO] / RIGHT_SHIFT);
   printf(", Number of answer RRs = %d, ",((short int *)reply)[THREE] / RIGHT_SHIFT); 
  printf("Number of authority RRs = %d, ",((short int *)reply)[FOUR] / RIGHT_SHIFT);
 printf("Number of additional RRs = %d, ",((short int *)reply)[FIVE] / RIGHT_SHIFT);
 
   printf("\n");


/* ----------------------------------------------------------------------- */
/* First Parse the Question, returned in reply */

printf("\nQuestion/s....\n");
if( (((unsigned short int *)reply)[TWO] / RIGHT_SHIFT) > ZERO)
for(localCount=ZERO; localCount < ((unsigned short int *)reply)[TWO] / RIGHT_SHIFT; localCount++){
x = domainParser( (unsigned int *)reply + THREE);
x = x + typeParser( ( (unsigned char *) ((unsigned int *)reply + THREE) + x ));
x = x + classParser( ( (unsigned char *)((unsigned int *)reply + THREE) + x ));
printf("\n");
}
else
   printf("none.\n");

/* ----------------------------------------------------------------------- */
/* Now parase the Resource Record */

printf("Resource Record/s....\n");

if( (((unsigned short int *)reply)[THREE] / RIGHT_SHIFT) > ZERO)
   
   for(localCount = ZERO; localCount < ((unsigned short int *)reply)[THREE] / RIGHT_SHIFT; localCount++){

      x = x + domainParser( ( (unsigned char *)((unsigned int *)reply + THREE) + x));

      x = x + typeParser( ( (unsigned char *) ((unsigned int *)reply + THREE) + x ));           

      x = x + classParser( ( (unsigned char *) ((unsigned int *)reply + THREE) + x ));      
        
      x = x + ttlParser( ( (unsigned char *) ((unsigned int *)reply + THREE) + x ));

      x = x + dataParser( ( (unsigned char *) ((unsigned int *)reply + THREE) + x ));
 
      printf("\n");      
   }
else
   printf("none.\n");

 
/*-------------------------------------------------------------------------*/
/* Now parse Authority Records */

printf("Authority Record/s....\n");
if( (((unsigned short int *)reply)[FOUR] / RIGHT_SHIFT) > ZERO)
   for(localCount = ZERO; localCount < ((unsigned short int *)reply)[FOUR] / RIGHT_SHIFT; localCount++)
      {
      x = x + domainParser( ( ( unsigned char *)((unsigned int *)reply + THREE) + x)); 
      x = x + typeParser( ( (unsigned char *) ((unsigned int *)reply + THREE) + x));
      x = x + classParser( ( (unsigned char *) ((unsigned int *)reply + THREE) +
x ));
      x = x + ttlParser( ( (unsigned char *) ((unsigned int *)reply + THREE) + x));
      x = x + dataParser( ( (unsigned char *) ((unsigned int *)reply + THREE) + x)); 

      printf("\n");
      }
   

else
   printf("none.\n");

/*-------------------------------------------------------------------------*/
/* Now parse the Additional Records */

printf("Additional Record/s....\n");
if( (((unsigned short int *)reply)[FIVE] / RIGHT_SHIFT) > ZERO)
   for(localCount = ZERO; localCount < ((unsigned short int *)reply)[FIVE] / RIGHT_SHIFT; localCount++){
      x = x + domainParser( ( (unsigned char *)((unsigned int *)reply + THREE) + x));
      x = x + typeParser( ( (unsigned char *) ((unsigned int *)reply + THREE) + x));     
      x = x + classParser( ( (unsigned char *)((unsigned int *)reply + THREE) + x));
      x = x + ttlParser( ( (unsigned char *)((unsigned int *)reply + THREE) + x));
      x = x + dataParser( ( (unsigned char *)((unsigned int *)reply + THREE) + x));  
      printf("\n");
   }  
else
   printf("none.\n");
 
/*--------------------------------------------------------------------------*/


 if( argumentFlags[VERBOSE] > ZERO ){
    printf("\nMessages....\n");

    if( argumentFlags[PTR] == ZERO ){
/*
       if(rrTypeStillNotImplemented==(RR_TYPE_REQUEST_FOR_ZONE_TRANSFER + SHORT_LOWER_BYTE_AUGUMENTATION))
          printf("RR_TYPE_REQUEST_FOR_ZONE_TRNSFER still not implemented. Fallen back upon RR_TYPE_ADDRESS.\n");
*/       
       if(rrTypeStillNotImplemented == SHORT_LOWER_BYTE_AUGUMENTATION)
          printf("Unknown RR type. Fallen back upon RR_TYPE_ADDRESS.\n"); 
    }
    
if(ptrArgumentError == ERROR)
  printf("Incomplete IP address(for reverse lookup) used with -p option.\n");  

if( argumentFlags[PTR] > ZERO && argumentFlags[TOR] > ZERO)
   printf("option, -p overrides option, -t.\n");

if( alarmCount < FIVE )
    printf("The option, -c only takes affect when time in seconds is greater than 5.\n");

 
   if(rrTypeStillNotImplemented == ZERO && ptrArgumentError == ZERO && alarmCount >= FIVE )
      printf("none.\n");
 } 

}


