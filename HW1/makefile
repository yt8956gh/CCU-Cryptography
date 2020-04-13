CFLAGS = -Wall -Werror -Wextra
OBJECTS = hw1.o myinterface.o

main: myinterface.o hw1.o
	g++ -g ${CFLAGS} ${OBJECTS} -o hw1 -lssl -lcrypto 
clean:
	rm -f ${OBJECTS} hw1
