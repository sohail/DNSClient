#Makefile for dnsCli.
#Written by, Sohail Qayum Malik[sqm@hackers.pk]

.PHONY		: clean	help 	
.DEFAULT	: all

all	:  dnsCli

dnsCli : dnsCli.o libA.o libB.o libC.o libD.o libE.o
	gcc -o dnsCli dnsCli.o libA.o libB.o libC.o libD.o libE.o	

dnsCli.o : dnsCli.c dnsCli.h cliServ.h
	gcc -o dnsCli.o dnsCli.c -c 

libA.o : libA.c dnsCli.h cliServ.h
	gcc -o libA.o libA.c -c 

libB.o : libB.c dnsCli.h cliServ.h
	gcc -o libB.o libB.c -c 

libC.o : libC.c dnsCli.h cliServ.h
	gcc -o libC.o libC.c -c 

libD.o : libD.c dnsCli.h cliServ.h
	gcc -o libD.o libD.c -c 

libE.o : libE.c dnsCli.h cliServ.h
	gcc -o libE.o libE.c -c 

#Be very careful, make sure only the object and the binary image get deleted -
#not the C source files.

clean  :
	rm dnsCli -f
	rm dnsCli.o -f
	rm libA.o -f
	rm libB.o -f
	rm libC.o -f
	rm libD.o -f
	rm libE.o -f

help	:
	@echo "help!";
	
