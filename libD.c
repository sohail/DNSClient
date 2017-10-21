/*
libD.c
Written by, Sohail Qayum Malik[sqm@hackers.pk]
*/

#include "cliServ.h"
#include "dnsCli.h"

int flag = ZERO;
int temp = ZERO;

/* ----------------------------------------------------------------- */
extern unsigned char reply[];
/* ----------------------------------------------------------------- */

extern void interprateFlags(unsigned short int *);
/* ----------------------------------------------------------------- */
extern unsigned short int domainParser(void *);
extern unsigned short int typeParser(void *);
extern unsigned short int classParser(void *);
extern unsigned short int ttlParser(void *);
extern unsigned short int dataParser(void *);

static void (* ptrToFunction)(unsigned char *, unsigned short int);
static void dataPTR(unsigned char *, unsigned short int);
static void dataA(unsigned char *, unsigned short int);
static void dataNS(unsigned char *, unsigned short int);
static void dataCNAME(unsigned char *, unsigned short int);
static void dataHINFO(unsigned char *, unsigned short int);
static void dataMX(unsigned char *, unsigned short int);
static void dataAXFR(unsigned char *, unsigned short int);
static void dataSOA(unsigned char *, unsigned short int);
static void dataTXT(unsigned char *, unsigned short int);

static unsigned short int dataType   = ZERO;

/* ----------------------------------------------------------------- */

extern void interprateFlags(unsigned short int * ptrFlags){
 
   printf("(");

   /* QUERY OR REPLY */
   switch( *ptrFlags & 0x8000 ){      
      case 0x0000:
         printf(" ?[QR]");
      break;      
   }
  
  /* OPCODE */
  switch( *ptrFlags & 0x0800 ){
     case 0x0800:
        printf(" PTR");
     break;
  }  

  /* AUTHORITATIVE REPLY */
  switch( *ptrFlags & 0x0400 ){
     case 0x0400:
        printf(" *[AA]");  
     break;
  }

 /* TRUNCATE */ 
 switch( *ptrFlags & 0x0200 ){
    case 0x0200:
       printf(" TC");
    break;
 } 

 /* RECURSION DESIRED */ 
 switch( *ptrFlags & 0x0100){
    case 0x0100:
       printf(" +[RD]");
    break; 
 } 
 
/* RECURSION AVAILABLE */ 
 switch( *ptrFlags & 0x0080 ){
    case 0x0080:
       printf(" -[RA]");
    break;
 }

 printf(" RetrunCode="); 
/* RETURN CODE */
 switch( *ptrFlags & 0x000F ) {
    case 0x0000:
       printf("NOERROR"); 
    break;
    case 0x0001:
       printf("FORMERR");
    break;
    case 0x0002:
       printf("SERVFAIL");
    break;
    case 0x0003:
       printf("NXDOMAIN");
    break;
    case 0x0004:
       printf("NOTIMP"); 
    break;
    case 0x0005:
       printf("REFUSED");
    break;
    case 0x0006:
       printf("YXDOMAIN");
    break;
    case 0x0007:
       printf("YXRRSET");
    break;
    case 0x0008:
       printf("NXRRSET");
    break;
    case 0x0009:
       printf("NOTAUTH");
    break;
    case 0x000A:
       printf("NOTZONE");
    break;    
 }

printf(" )");  
}

extern unsigned short int domainParser(void * domain){

   void * ptr                     = ZERO;
   unsigned short int localCount  = ZERO;
   unsigned short int localIndex  = ZERO;
   unsigned short int domainCount = ZERO;
     
   ptr = domain;
   
   /* 
   If the size of domain is zero, then simply return.
   The value returned should be incremented by one to point to the offset
   of the byte after this byte. So this is why we have....
   return (domainCount + ONE).
   */ 
   while( ((unsigned char *)domain)[ZERO] != ZERO ){     
      /*
      See if the size of the pointer is 2 bytes.  
      if(xx & c0)
      */ 
      if( ((unsigned char *)domain)[ZERO] & TWO_OR_ONE_BYTE){                  
         /*
         See if we are still in the data field of selected RR.
         If yes then increment the pointer by 2, the size of the domain name
         pointer. The actual domain is somewhere in the array reply[].
         */ 
         if( ((unsigned char *)domain + ZERO) == ptr){
            ptr+=TWO;
            domainCount+=TWO;
         }
         /*
         So the size of the pointer is 2 bytes.
         Get the offset of the first byte of the domain. The offset is some
         where in the array reply[]. 
         xx = xx XOR c0
         */ 
         ((unsigned char *)domain)[ZERO] = ((unsigned char *)domain)[ZERO] 
                                                            ^ TWO_OR_ONE_BYTE;
         /* 
         The pointer is in network byte order.
         pointer = xx[0] * 256 + xx[1]         
         */
         localIndex = (((unsigned char *)domain)[ZERO] * 
                                        SHORT_LOWER_BYTE_AUGUMENTATION)
                                          + ((unsigned char *)domain)[ONE];
         domain = &reply[localIndex];
	 
         
      }
      /*
      No, the size of the pointer is not 2 bytes.
      */
      else{
          /*
          Lets go and ptint the domain.
          *(domain + 0) is the size of the domain and the 
          *(domain + 1) is the first byte of the domain.
          say if the size is 6 bytes, the localCount will run for the 6 times
          and in the 6th loop the localCount will incrementd to become 7.
          7 is the byte offset in array domain which points to the size of the 
          next domain in the URL.
          */           
          for(localCount = ONE; localCount <= ((unsigned char *)domain)[ZERO]; 
                                                              localCount++)
             printf("%c",((unsigned char *)domain)[localCount]);

          if(flag == TWO){
             flag = ZERO;
             printf("@");
          }
          else
             printf("."); 
          /*
          See if we are still in the data rnage of the selected RR.
          If yes then increment the ptr by the number of bytes read.
          After this ptr is the address of the size byte of the next domain
          in the URL.
          */          
          if( domain == ptr){
             ptr = ((unsigned char *)domain + localCount);
             domain = ptr;
             domainCount += localCount;                 
          }
          /*
          No we are not in the data area of the selected RR.
          */ 
          else
              domain = ((unsigned char *)domain + localCount);
                    

          
      }/* end of if */         

   } /* end of while */ 
      if(domainCount == TWO)
         return domainCount;
      else                
         return(domainCount + ONE);           
}



extern unsigned short int typeParser(void * type){

   unsigned short int x = ZERO; 
                        
      printf(" Type = %d", *((unsigned short int *)type) / RIGHT_SHIFT);
      dataType = *((unsigned short int *)type) / RIGHT_SHIFT;
 
      switch( *((unsigned short int *)type) ){
         case RR_TYPE_ADDRESS:
            printf("(A)");            
            ptrToFunction = dataA;
         break;    
         case RR_TYPE_NAME_SERVER:
            printf("(NS)");
            ptrToFunction = dataNS;
         break;
         case RR_TYPE_CANONICAL_NAME:
            printf("(CNAME)");
            ptrToFunction = dataCNAME;
         break;  
         case RR_TYPE_HOST_INFO:
            printf("(HINFO)"); 
            ptrToFunction = dataHINFO;
         break;
         case RR_TYPE_MAIL_EXCHANGE:
            printf("(MX)"); 
            ptrToFunction = dataMX;
         break;  
         case RR_TYPE_REQUEST_FOR_ZONE_TRANSFER:
            printf("(AXFR)");
            ptrToFunction = dataAXFR;
         break; 
         case RR_TYPE_ANY:
            printf("(ANY)");
         break;  
         case RR_TYPE_PTR:
            printf("(PTR)");
            ptrToFunction = dataPTR;
         break;
         case RR_TYPE_SOA:
            printf("(SOA)");
            ptrToFunction = dataSOA;
         break;
         case RR_TYPE_TXT:
            printf("(TXT)");
            ptrToFunction = dataTXT;
         break;                    
      }
      
      printf(", "); 
   
   x+=TWO;

   return(x);

}

extern unsigned short int classParser(void * class){

   unsigned short int x = ZERO;
      
   printf(" Class = %d", *((unsigned short int *)class) / RIGHT_SHIFT);

   switch( *((unsigned short int *)class) / RIGHT_SHIFT){
      case ONE:
         printf("(IN)");
      break;
      default:
         printf("(Unknown)");
      break;   
   }
  
   printf(", ");

   x+=TWO;

   return(x);

}

extern unsigned short int ttlParser(void * ttl){

   unsigned int count = ZERO;
   unsigned short int x = ZERO;

   *((unsigned char *)&count + THREE) = *((unsigned char *)ttl + ZERO);
   *((unsigned char *)&count + TWO)   = *((unsigned char *)ttl + ONE);
   *((unsigned char *)&count + ONE)   = *((unsigned char *)ttl + TWO);
   *((unsigned char *)&count + ZERO)  = *((unsigned char *)ttl + THREE); 
  
/*
   printf(" TTL = 0x%x%x%x%x, ", *((unsigned char *)ttl + ZERO), *((unsigned char *)ttl + ONE), *((unsigned char *)ttl + TWO), *((unsigned char *)ttl + THREE) );  
*/

   printf(" TTL = %d, ",count);

   x+=FOUR;
   return(x);
     
}

extern unsigned short int dataParser(void * length){
 
   unsigned short int localCount = ZERO; 
   unsigned short int x          = ZERO;  
       
   x = (*((unsigned char *)length) * SHORT_LOWER_BYTE_AUGUMENTATION) + ((unsigned char *)length)[ONE];

   printf("Data-Length = %d, ", x);

   (*ptrToFunction)( ((unsigned char *)length + TWO), x );   
         
   x+=TWO;
   
   return(x);
 
   
}


static void dataPTR(unsigned char * ptr, unsigned short int size){
   int localCount = ZERO;
   printf("Name = ");
   localCount = domainParser(ptr);  

}


static void dataA(unsigned char * ptr, unsigned short int size){

   printf("IP-ADDRESS = ");
   printf("%d.%d.%d.%d", *ptr, *(ptr + ONE), *(ptr + TWO), *(ptr + THREE) );

}

static void dataNS(unsigned char * ptr, unsigned short int size){
 
   unsigned short int localCount = ZERO;
   printf("Name-Server = ");
   localCount = domainParser(ptr);
    
}

static void dataCNAME(unsigned char * ptr, unsigned short int size){
   
   printf("Canonical-Name = ");
   domainParser(ptr);  
    
}

static void dataHINFO(unsigned char * ptr, unsigned short int size){

    unsigned short int localCount = ZERO;
    printf("\nMachine and OS = ");    
    for(localCount = ZERO; localCount < size; localCount++)
       if( *(ptr + localCount) == '\n')
          ;
       else 
          printf("%c",*(ptr + localCount));      

}

static void dataMX(unsigned char * ptr, unsigned short int size){

   printf("\nPreference-Level = ");
   printf("0x%x%x", *(ptr + ZERO), *(ptr + ONE) );  
   printf("\nMail-Server      = ");
   domainParser( (ptr + TWO) ); 

}

static void dataAXFR(unsigned char * ptr, unsigned short int size){
}

static void dataSOA(unsigned char * ptr, unsigned short int size){
  
   unsigned int count = ZERO; 
   unsigned short int localCount = ZERO;

   printf("\nDomain        = "); 
   localCount = domainParser( ptr );   
   flag=TWO;
   printf("\nEmail         = ");
   localCount = localCount + domainParser( (ptr + localCount) );

   if(temp != ZERO)
      localCount-=ONE;
        
   *((unsigned char *)&count + THREE) = *(ptr + localCount + ZERO);
   *((unsigned char *)&count + TWO)   = *(ptr + localCount + ONE);
   *((unsigned char *)&count + ONE)   = *(ptr + localCount + TWO);
   *((unsigned char *)&count + ZERO)  = *(ptr + localCount + THREE);
   
   printf("\nSerial-Number = %d", count);

/*
   printf("0x%x%x%x%x",*(ptr + localCount + ZERO), *(ptr + localCount + ONE), *(ptr + localCount + TWO), *(ptr + localCount + THREE)); 
*/
   localCount+=FOUR;


   *((unsigned char *)&count + THREE) = *(ptr + localCount + ZERO);
   *((unsigned char *)&count + TWO)   = *(ptr + localCount + ONE);
   *((unsigned char *)&count + ONE)   = *(ptr + localCount + TWO);
   *((unsigned char *)&count + ZERO)  = *(ptr + localCount + THREE);  
   printf("\nRefresh       = %d", count);
/* 
   printf("0x%x%x%x%x", *(ptr + localCount + ZERO), *(ptr + localCount + ONE), *(ptr + localCount + TWO), *(ptr + localCount + THREE)  ); 
*/
   localCount += FOUR;


   *((unsigned char *)&count + THREE) = *(ptr + localCount + ZERO);
   *((unsigned char *)&count + TWO)   = *(ptr + localCount + ONE);
   *((unsigned char *)&count + ONE)   = *(ptr + localCount + TWO);
   *((unsigned char *)&count + ZERO)  = *(ptr + localCount + THREE);

   printf("\nRetry         = %d", count);
/* 
   printf("0x%x%x%x%x", *(ptr + localCount + ZERO), *(ptr + localCount + ONE), *(ptr + localCount + TWO), *(ptr + localCount + THREE) );
*/

   localCount+=FOUR;

   *((unsigned char *)&count + THREE) = *(ptr + localCount + ZERO);
   *((unsigned char *)&count + TWO)   = *(ptr + localCount + ONE);
   *((unsigned char *)&count + ONE)   = *(ptr + localCount + TWO);
   *((unsigned char *)&count + ZERO)  = *(ptr + localCount + THREE);
   
   printf("\nExpire        = %d", count);
/*
   printf("0x%x%x%x%x", *(ptr + localCount + ZERO), *(ptr + localCount + ONE), *(ptr + localCount + TWO), *(ptr + localCount + THREE) );  
*/
   localCount += FOUR;

   *((unsigned char *)&count + THREE) = *(ptr + localCount + ZERO);
   *((unsigned char *)&count + TWO)   = *(ptr + localCount + ONE);
   *((unsigned char *)&count + ONE)   = *(ptr + localCount + TWO);
   *((unsigned char *)&count + ZERO)  = *(ptr + localCount + THREE); 
  
   printf("\nTTL           = %d", count);
/*
   printf("0x%x%x%x%x", *(ptr + localCount + ZERO), *(ptr + localCount + ONE), *(ptr + localCount + TWO), *(ptr + localCount + THREE) );  
*/
      
}

static void dataTXT(unsigned char * ptr, unsigned short int size){

   unsigned short int localCount = ZERO;
   printf("\nText = ");
   for(localCount = ZERO; localCount < size; localCount++)
      printf("%c", *(ptr + localCount));
  
}

