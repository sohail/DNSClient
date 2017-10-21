/* 
dnsCli.h
Written by, Sohail Qayum Malik[sqm@hackers.pk]
*/     

#define MAX                            0x0B
#define RIGHT_SHIFT                    0x0100
/* PLEASE NOTE, PLEASE NOTE, PLEASE NOTE, PLEASE NOTE .... */                
/* *********************************************************************** */
/*
IF YOUT SEE THE RUN TIME ERROR "Segmentation fault". THEN
INCREASE THE SIZE OF THE ARRAY reply[].
INCREMENT IN THE UNITS OF 256 BYTES(just a suggestion).
*/
#define REQUEST                        0x0100   /* 0x0100 */
#define REPLY                          0xffff   /* 0x0100 */
/* *********************************************************************** */
#define DOT                            0x2E
#define SHORT_LOWER_BYTE_AUGUMENTATION 0x00FF
#define TWO_OR_ONE_BYTE                0xC0

#define LESS_THAN_ZERO                 0xFFFF
#define ZERO                           0x00000000
#define ONE                            0x00000001
#define TWO                            0x00000002
#define THREE                          0x0000003
#define FOUR                           0x0000004
#define FIVE                           0x0000005
#define SIX                            0x0000006
#define SEVEN                          0x0000007
#define EIGHT                          0x0000008
#define NINE                           0x0000009
#define TEN                            0x000000A
#define ELEVEN                         0x000000B
#define TWELVE                         0x000000C
#define THERTEEN                       0x000000D
#define FOURTEEN                       0x000000E
#define FIFTEEN                        0x000000F

#define SERVERIP                       0x00
#define VERBOSE                        0x01
#define DOMAIN                         0x02
#define PTR                            0x03
#define TOR                            0x04
#define AUTHORITY                      0x05
#define ID                             0x06
#define ALARM                          0x07

#define ERROR                          0x00000001  
