/* 
dnsCli.c,
written by, Sohail Qayum Malik[sqm@hackers.pk]
*/     
   
#include <stdio.h>
#include <string.h>

#include "cliServ.h"
#include "dnsCli.h"

extern short int init(void **); 


static void badArgumentSyntax(char *);
static unsigned short processStringArgument(char **, unsigned short int);
static unsigned short processCharacterArgument(char *);
static unsigned short parseServerIpAddress(char *);
static unsigned short parsePtrIpAddress(char *);
static unsigned short parseDomainName(char *);
static unsigned short determineRrType(unsigned char *); 

static void version(void);
static void help(void);

static unsigned short count      = ZERO;
static unsigned short flag       = ONE;

unsigned char argumentFlags[MAX];
unsigned char ptrIpDotCount[FOUR];
unsigned char firstDomainTag = ZERO;
unsigned short int domainCharCount = ZERO;
unsigned short int rrType  = RR_TYPE_ADDRESS;
unsigned short int rrTypeStillNotImplemented = ZERO;
unsigned short int alarmCount = FIVE;

int main(unsigned short int argumentCount, void ** argumentValue){
    
   if(argumentCount < TWO){
      badArgumentSyntax(*((char **)argumentValue));        
      return(ERROR);
   }

/* 
   really bad Idea, count is important counter, 
   but here still it has not started its work.
*/   
   for(count = ZERO; count < MAX; count++)
      argumentFlags[count] = ZERO;   
   count = ONE;

   do{
      if(*(((char **)argumentValue)[count]) == '-'){

         if( ((char **)argumentValue)[count][ONE] == '-')          
            flag = processStringArgument(((char **)argumentValue + count),argumentCount);
         else
            flag = processCharacterArgument(((char **)argumentValue)[count]);        
            if(flag){
            badArgumentSyntax(*((char **)argumentValue));
            return(ERROR);
         }

      }
      else{
         printf("Use of option without single or double - .\n");
         badArgumentSyntax(*((char **)argumentValue));    
         return(ERROR);
      }

      count++;  
   }while( count < argumentCount );  

/* ----------------------------------------------------------------------- */
/* 
  If rest of the programm does some thing stupid, then I'll not going to
  tell what It was, I'll simply show an alarming message :( 	
*/
 
   if( init(argumentValue) == (short int)LESS_THAN_ZERO )
      printf("Some thing very bad has happend.\n"); 
/* ----------------------------------------------------------------------- */
  
   return(ZERO);
}


static void badArgumentSyntax(char * ptr){
   printf("Incorrect Usage.");
   printf(" For help, %s -[h | H | -help] \n", ptr);   
}

static unsigned short processStringArgument(char ** ptr, unsigned short int argumentCount){
   
   if( strcmp(*ptr, "--version") == ZERO ){
      version();
      exit(ZERO);
   } 
   
   if( strcmp(*ptr, "--help") == ZERO ){
      help();
      exit(ZERO);
   }   
   
   if( strcmp(*ptr, "--verbose") == ZERO ){
      if(argumentFlags[VERBOSE] == ZERO){
         argumentFlags[VERBOSE] = count;
         return(ZERO);  
      }
      else{
         printf("redundant --verbose\n");
         return(ERROR);
      }
   }
 
   if( strcmp(*ptr, "--ptr") == ZERO || strcmp(*ptr, "--pointer") == ZERO ){
      if( argumentFlags[PTR] == ZERO ){
         count++;
         argumentFlags[PTR] = count;
         if(argumentCount > count)
            return(parsePtrIpAddress(ptr[ONE]));
         else{
            printf("IP address is missing for the RR of type PTR\n");
            return(ERROR);
         }
      }
      else{
         printf("redundant %s\n",*ptr);
         return(ERROR);
      }  
   }


   if( strcmp(*ptr, "--domain") == ZERO ){
      if( argumentFlags[DOMAIN] == ZERO ){
         count++;
         argumentFlags[DOMAIN] = count;
         if(argumentCount > count)
            return( parseDomainName(ptr[ONE]) );
         else{
            printf("Domain name is missing\n");
            return(ERROR);
         }
      }
      else{
         printf("redundant %s\n",*ptr);
         return(ERROR);
      }  
   }


   
                
   
   if( strcmp(*ptr, "--server") == ZERO ){
      if(argumentFlags[SERVERIP] == ZERO){
         count++;
         argumentFlags[SERVERIP] = count;         
         if(argumentCount > count)
            return(parseServerIpAddress(ptr[ONE]));
         else{
            printf("server IP address is missing!\n");
            return(ERROR);
         }
      }
      else{
         printf("redundant --server\n"); 
         return(ERROR);
      }
   }
   
   if( strcmp(*ptr, "--type-of-record") == ZERO || strcmp(*ptr, "--type") == ZERO || strcmp(*ptr, "--tor") == ZERO){
      
      if(argumentFlags[TOR] == ZERO){
         count++;
         argumentFlags[TOR] = count;
         if(argumentCount > count)
/* ((unsigned char **)ptr)[1] */
            return( determineRrType(((unsigned char **)ptr)[ONE]) ); 
/*            return(ZERO); */
         else{
            printf("The type of RR is missing\n");
            return(ERROR);
         } 
 
      }
      else{
         printf("redundant %s\n",*ptr);
         return(ERROR);
      }
      
   } 
 
   if( strcmp(*ptr, "--authority") == ZERO){
      if(argumentFlags[AUTHORITY] == ZERO){
         argumentFlags[AUTHORITY] = count;
         return(ZERO);
      }
      else{
         printf("redundant --authority\n");          
         return(ERROR);
      }
   }
   
   if( strcmp(*ptr, "--ID") == ZERO ){

      if(argumentFlags[ID] == ZERO){
         count++;  
         argumentFlags[ID] = count;        
         if( argumentCount > count )
            return(ZERO);
         else{
            printf("ID value is missing!\n");
            return(ERROR);
         }

      }
      else{
         printf("redundant --ID\n");   
         return(ERROR);
      }  
   }
   
   printf("unknown argument %s\n",*ptr); 
   return(ERROR);
}

static unsigned short processCharacterArgument(char * ptr){  
   short int localCount; 

   switch(ptr[ONE]){
   case 'V':
      version();
      exit(ZERO);
   break;

   case 'H':
   case 'h':
      help();
      exit(ZERO);
   break;

   case 'v':
      if( argumentFlags[VERBOSE] == ZERO )
         argumentFlags[VERBOSE] = count; 
      else{
         printf("redundant -v\n");
         return(ERROR);        
      }           
   break;
   
   case 'p':
   case 'P':
   case '*':
      if(argumentFlags[PTR] == ZERO){
         argumentFlags[PTR] = count;
         localCount = LESS_THAN_ZERO;
         do{
            localCount++;
            ptr[localCount] = ptr[localCount + TWO];
         }while(ptr[localCount] != (char)NULL);
         return(parsePtrIpAddress(ptr));
      }
      else{
         printf("redundant -%c\n",ptr[ONE]);
         return(ERROR);
      } 
   break; 
   
/* 
The argument has -s or -S before the IP address, I should make sure that
before connecting to the server the preceding values must be removed, one 
solution would be to replace these values with the NULL or other is  
to move the whole IP number two places to the left. 
*/
   case 's':
   case 'S':
      if( argumentFlags[SERVERIP] == ZERO ){
         argumentFlags[SERVERIP] = count;
/*
Hopefully this patch will take care of the problem, I've gone for the moving
two places to the left option. I'll try to apply the same patch at other places
and hopefully it'll work too. The best solution would've been to put this batch in a function and call it where its need arises, but I think for the time being
I would go for the patch work. 
*/         
         localCount = LESS_THAN_ZERO;
         do{
            localCount++;
            ptr[localCount] = ptr[localCount + TWO];
         }while(ptr[localCount] != (char)NULL);
/* ----------------------------------------------------------------------- */                                     
         return(parseServerIpAddress((ptr + ZERO)));
      }  
      else{
         printf("redundant -%c\n", ptr[ONE]);
         return(ERROR);      
      } 
   break;

   case 'i':
   case 'I':
      if( argumentFlags[ID] == ZERO){
         argumentFlags[ID] = count;         
/*
The same patch is applied here too,ID number is moved 2 places to the left. Lets hope it works.
*/
         localCount = LESS_THAN_ZERO;
         do{
            localCount++;
            ptr[localCount] = ptr[localCount + TWO]; 
         }while(ptr[localCount] != (char)NULL);
          
/* ------------------------------------------------------------------------- */
                  

      }
      else{
         printf("redundant -%c\n",ptr[ONE]);
         return(ERROR);
      }         
   break;

   
   case 'd':
   case 'D':
      if( argumentFlags[DOMAIN] == ZERO){
         argumentFlags[DOMAIN] = count;         
/*
The same patch is applied here too,ID number is moved 2 places to the left. Lets hope it works.
*/
         localCount = LESS_THAN_ZERO;
         do{
            localCount++;
            ptr[localCount] = ptr[localCount + TWO]; 
         }while(ptr[localCount] != (char)NULL);
          
/* ------------------------------------------------------------------------- */
         return( parseDomainName(ptr) );
	  
      }
      else{
         printf("redundant -%c\n",ptr[ONE]);
         return(ERROR);
      }         
   break; 
   

   case 't':
   case 'T':
      if(argumentFlags[TOR] == ZERO){
         argumentFlags[TOR] = count;
/*
Did the same stuff with the same patch, movied -t or -T two places to the 
left.
*/
         localCount = LESS_THAN_ZERO;
         do{
            localCount++;
            ptr[localCount] = ptr[localCount + TWO];
         }while(ptr[localCount] != (char)NULL);
/* ------------------------------------------------------------------------ */ 

         return(  determineRrType(ptr) );       
      }
      else{
         printf("redundant -%c\n",ptr[ONE]);
         return(ERROR);
      }  
   break;

   
   case 'c':
   case 'C':
      if( argumentFlags[ALARM] == ZERO ){
         argumentFlags[ALARM] = count;
         localCount = LESS_THAN_ZERO;
         do{
            localCount++;
            ptr[localCount] = ptr[localCount + TWO];
         }while(ptr[localCount] != (char)NULL);     
/* ---------------------------------------------------------------------*/
/* insted of writing a seperate function just put the code here */
         alarmCount = (unsigned short int)atoi(ptr);              
/* ---------------------------------------------------------------------*/
      }
      else{
         printf("redundant -%c\n", ptr[ONE]); 
         return(ERROR);
      }        
   break; 



 
   case 'A':
   case 'a':
      if( argumentFlags[AUTHORITY] == ZERO )
         argumentFlags[AUTHORITY] = count;
      else{
         printf("redundant -%c\n",ptr[ONE]);
         return(ERROR);
      } 
   break;

   default:
      printf("unknown argument %s\n",ptr); 
      return(ERROR);
   break;
   
   }

   return(ZERO);
}


static unsigned short parseServerIpAddress(char * ptr){
   unsigned short int localCount = ZERO;
   unsigned short int dotCount   = ZERO;
   
   do{ 
     if(ptr[localCount] == DOT)
        dotCount++;
     localCount++; 
   }while(ptr[localCount] != (char)NULL);

   if(dotCount == THREE)   
      return(ZERO);
   else{      
      printf("bad, server IP adress %s?\n",ptr);
      return(ERROR);
   }
}

static unsigned short parsePtrIpAddress(char * ptr){
   unsigned short int localCount = ZERO;
   unsigned short int charCount  = ZERO;
   unsigned short int dotCount   = ZERO;


   while(ptr[localCount] != (char)NULL){
      
      if(ptr[localCount] != DOT){
         charCount++;
         if(dotCount == THREE && charCount > THREE){
            printf("IP address for RR type PTR is incorrect.... %s\n",ptr); 
            return(ERROR);
         }
      }
      else{
         if(charCount > ZERO && charCount <= THREE){
            ptrIpDotCount[dotCount] = charCount;    
            charCount = ZERO;        
         }
         else{
            printf("IP address for RR type PTR is incorrect.... %s\n",ptr);
            return(ERROR);
         }      
         dotCount++;
      }

      localCount++;   
   }

   if(dotCount != THREE){
      printf("IP address for RR type PTR is incorrect.... %s\n",ptr);
      return(ERROR);	
   }
   else
      ptrIpDotCount[dotCount] = charCount;	
   

return(ZERO);
}


static unsigned short parseDomainName(char * ptr){


   unsigned short int dotCount   = ZERO;
   unsigned char charCount  = ZERO;

   while( ptr[domainCharCount] != (unsigned char) NULL ){
         
      if( ptr[domainCharCount] != DOT )
         charCount++;
      
         
      if( ptr[domainCharCount] == DOT ){
         if( dotCount == ZERO )
            firstDomainTag = charCount;
         else
            ptr[domainCharCount - (charCount + ONE)] = charCount; 
         charCount = ZERO;
         dotCount++;

      }
       
      domainCharCount++;
     
   }
   
   ptr[domainCharCount - (charCount + ONE)] = charCount; 
   
   
  
   if( dotCount == ZERO )
      firstDomainTag = charCount;

    
 
return(ZERO);
}


static unsigned short determineRrType(unsigned char * ptr){
   if( strcmp(ptr, "a") == ZERO ){ 
      rrType = RR_TYPE_ADDRESS;  
      return(ZERO);
   }
   if( strcmp(ptr, "ns") == ZERO ){
      rrType = RR_TYPE_NAME_SERVER;
      return(ZERO);
   }
   if( strcmp(ptr, "cname") == ZERO ){
      rrType = RR_TYPE_CANONICAL_NAME;
      return(ZERO);
   }
   if( strcmp(ptr, "hinfo") == ZERO ){
      rrType = RR_TYPE_HOST_INFO;
      return(ZERO);
   }
   if( strcmp(ptr, "mx") == ZERO ){
      rrType = RR_TYPE_MAIL_EXCHANGE;
      return(ZERO);
   }
   if( strcmp(ptr, "soa") == ZERO){
      rrType = RR_TYPE_SOA;
      return(ZERO);         
   }
   if( strcmp(ptr, "txt") == ZERO){
      rrType = RR_TYPE_TXT;
      return(ZERO);
   }
   if( strcmp(ptr, "axfr") == ZERO ){
        rrType = RR_TYPE_REQUEST_FOR_ZONE_TRANSFER;
/*      rrType = RR_TYPE_ADDRESS; */
/*      rrTypeStillNotImplemented = RR_TYPE_REQUEST_FOR_ZONE_TRANSFER + SHORT_LOWER_BYTE_AUGUMENTATION; */
      return(ZERO);
   }
   if( strcmp(ptr, "*") == ZERO || strcmp(ptr, "any") == ZERO){
      rrType = RR_TYPE_ANY;
      return(ZERO);
   }

   rrType = RR_TYPE_ADDRESS;   
   rrTypeStillNotImplemented = SHORT_LOWER_BYTE_AUGUMENTATION;
return(ZERO);
}


static void version(void){
printf("dnsCli, version 0.0.1\n");
printf("written by, Sohail Qayum Malik.\n");
printf("If you find any bugs,or have some suggestions then send them to.....\nsohail@stupidcomputing.com.\n");
printf("For the new version of this programm please visit.....\n");
printf("http://www.stupidcomputing.com/downloads/dns-client/\n");
}

static void help(void){
  printf("The options are....\n");
  printf("-[a | A | -authority] To generate the authoritative or recursive query.\n");     
  printf("-[h | H | -help]      To get help More @....\n"); 
  printf("                      http://www.stupidcomputing.com/downloads/dsn-client/\n");
  printf("-[v | -verbose]       To get messages related to query or reply processing.\n");
  printf("-[V | -version]       To get the version related information.\n");
  printf("\n");
  printf("-[c | C]                                  <request time out, default is 5 sec>\n");
  printf("-[d | D | -domain]                        <domain-name>\n");
  printf("-[i | I | -ID]                            <ID-number>\n");
  printf("-[p | P | * | -pointer | -ptr]            <IP-address>\n");
  printf("-[s | S | -server]                        <IP-address>\n");
  printf("-[t | T | -type-of-record | -type | -tor] <RR>\n"); 
  printf("--------------------------------------------------------->\n\n");       printf("List of supported RR is ....\n");
  printf("*              Any\n");
  printf("a              Address\n");
  printf("axfr           Request For Zone Transfer\n");  
  printf("cname          Cnonical Name\n");
  printf("hinfo          Hardware Info\n");
  printf("mx             Mail Exchange\n");
  printf("ns             Name Server\n");  
  printf("soa            Start of Authority\n"); 
  printf("txt            Text\n");  
  printf("\nFor more help use the man dnsCli(1).\n");
  printf("This programm is distributed under the GPL version 2.\n");
 
}

