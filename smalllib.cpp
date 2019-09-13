extern "C"{
  #include "csapp.h"
}

#include <iostream>
#include <stdint.h>
#include <bitset>
#include <string>
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <sstream>
//#include "smalllib.h"

#define INITBUFSIZE   8

#define SETDEBUG      0
#define GETDEBUG      0
#define DIGDEBUG      0
#define RUNDEBUG      0

#define SET           0
#define SETVARLENSIZE 2
#define SETVARBUFSIZE 16
#define SETVARMAXSIZE 15
#define SETLENMAXSIZE 100
#define SETLENBUFSIZE 2
#define SETVALMAXSIZE 100

#define GET           1
#define GETVARBUFSIZE 16
#define GETVARMAXSIZE 15
#define GETVALMAXSIZE 100

#define DIG           2
#define DIGLENBUFSIZE 2
#define DIGLENMAXSIZE 100
#define DIGRESBUFSIZE 100

#define RUN           3
#define RUNREQBUFSIZE 8
#define RUNRETBUFSIZE 100

#define STATUSBUFSIZE 1

using namespace std;

int getStatus(rio_t rio){
  unsigned char buf[STATUSBUFSIZE];
  Rio_readnb(&rio, buf, STATUSBUFSIZE);
  if(buf[0] == '\0')
    return -1;
  else
    return 0;
}

int getKey(rio_t rio){
  unsigned char buf[STATUSBUFSIZE];
  Rio_readnb(&rio, buf, STATUSBUFSIZE);
  if(buf[0] == '-')
    return -1;
  else
    return 0;
}

void initialBuf(unsigned char (&buf)[INITBUFSIZE], int key, int code){
  // construct key
  buf[0] = (key >> 24) & 0xFF;
  buf[1] = (key >> 16) & 0xFF;
  buf[2] = (key >>  8) & 0xFF;
  buf[3] =  key        & 0xFF;

  // construct code
  buf[4] = (code >> 8) & 0xFF;
  buf[5] = code        & 0xFF;

  // padding
  buf[6] = 0xF;
  buf[7] = 0xF;
}

void fillChar(unsigned char* buf, int bufLen, char* val, int valLen, int maxSize){
  int fillLen = valLen;
  if(valLen > maxSize){
    fillLen = maxSize;
  }
  for(int i = 0; i < bufLen; i++){
    if(i < fillLen)
      buf[i] = val[i];
    else
      buf[i] = '\0';
  }
}

int smallSet(char *MachineName, int port, int secretKey, char *variableName, char *value, int dataLength){
  // Bytes 0-3:   A 4-byte unsigned integer containing SecretKey.
  // Bytes 4-5:   A 2-byte unsigned integer (a short) containing the type of request: set (0)
  // Bytes 6-7:   Two bytes of padding, with arbitrary values.
  // Bytes 8-23:  a null-terminated variable name, no longer than 15 characters.
  // Bytes 24-25: A 2-byte unsigned integer (short) giving the length of the value, which must not exceed 100, including the concluding null (for a string value).
  // Bytes 26 ..: The value itself. The client need not send any more than the number of bytes required.
  int clientfd;
  rio_t rio;

  // Debugging comments
  if(SETDEBUG){
    cout << "Running smallSet()" << endl << endl;
    cout << "MachineName:  " << MachineName << endl;
    cout << "port:         " << port << endl;
    cout << "secretKey:    " << secretKey << endl;
    cout << "variableName: " << variableName << endl;
    cout << "value:        " << value << endl;
    cout << "dataLength:   " << dataLength << endl << endl;
  }

  // Initialize connection
  clientfd = Open_clientfd(MachineName, port);

  Rio_readinitb(&rio, clientfd);

  // Construct and send initial buffer
  unsigned char initBuf[INITBUFSIZE];
  initialBuf(initBuf, secretKey, SET);
  Rio_writen(clientfd, initBuf, INITBUFSIZE);

  // Check key status
  if(getKey(rio) == -1){
    cout << "Read error: connection reset by peer" << endl;
    return -1;
  }

  // Construct and send variable name buffer
  unsigned char varBuf[SETVARBUFSIZE];
  fillChar(varBuf, SETVARBUFSIZE, variableName, strlen(variableName), SETVARMAXSIZE);
  Rio_writen(clientfd, varBuf, SETVARBUFSIZE);

  // Construct and send value length buffer
  unsigned char lenBuf[SETLENBUFSIZE];
  lenBuf[0] = (dataLength >> 8) & 0xFF;
  lenBuf[1] =  dataLength       & 0xFF;
  Rio_writen(clientfd, lenBuf, SETLENBUFSIZE);

  // Check status
  if(getStatus(rio) == -1)
    return -1;

  // Construct and send value buffer
  unsigned char valBuf[dataLength];
  fillChar(valBuf, dataLength, value, strlen(value), SETVALMAXSIZE);
  Rio_writen(clientfd, valBuf, dataLength);

  // Get final status
  if(getStatus(rio) == -1)
    return -1;

  return 0;
}

int smallGet(char *MachineName, int port, int secretKey, char *variableName, char *value, int *resultLength){
  // Bytes 0-3:   A 4-byte unsigned integer containing SecretKey.
  // Bytes 4-5:   A 2-byte unsigned integer (a short) containing the type of request: set (0)
  // Bytes 6-7:   Two bytes of padding, with arbitrary values.
  // Bytes 8-23: a null-terminated variable name, no longer than 15 characters.
  int clientfd;
  rio_t rio;

  // Debugging comments
  if(GETDEBUG){
    cout << "Running smallGet()" << endl << endl;
    cout << "MachineName:  " << MachineName << endl;
    cout << "port:         " << port << endl;
    cout << "secretKey:    " << secretKey << endl;
    cout << "variableName: " << variableName << endl;
  }

  // Initialize connection
  clientfd = Open_clientfd(MachineName, port);
  Rio_readinitb(&rio, clientfd);

  // Construct and send initial buffer
  unsigned char initBuf[INITBUFSIZE];
  initialBuf(initBuf, secretKey, GET);
  Rio_writen(clientfd, initBuf, INITBUFSIZE);

  // Check key status
  if(getKey(rio) == -1){
    cout << "Read error: connection reset by peer" << endl;
    return -1;
  }

  // Construct and send variable name buffer
  unsigned char varBuf[GETVARBUFSIZE];
  fillChar(varBuf, GETVARBUFSIZE, variableName, strlen(variableName), GETVARMAXSIZE);
  Rio_writen(clientfd, varBuf, GETVARBUFSIZE);

  char valBuf[GETVALMAXSIZE];
  Rio_readnb(&rio, valBuf, GETVALMAXSIZE);
  if(valBuf[0] == '\0') // failure
    return -1;
  for(int i = 0; i < GETVALMAXSIZE && valBuf[i] != '\0'; i++){
    value[i] = valBuf[i];
    *resultLength = i + 1;
  }
  return 0; // success
}

int smallDigest(char *MachineName, int port, int secretKey, char *value, int valueLength, char *result, int *resultLength){
  // Bytes 0-3:   A 4-byte unsigned integer containing SecretKey.
  // Bytes 4-5:   A 2-byte unsigned integer (a short) containing the type of request: set (0)
  // Bytes 6-7:   Two bytes of padding, with arbitrary values.
  // Bytes 8-9: a 2-byte unsigned integer (short) giving the length of the value, which must not exceed 100.
  // Bytes 10 ...: The value itself. The client need not send any more than the number of bytes required.
  int clientfd;
  rio_t rio;

  // Debugging comments
  if(DIGDEBUG){
    cout << "Running smallDigest()" << endl << endl;
    cout << "MachineName:  " << MachineName << endl;
    cout << "port:         " << port << endl;
    cout << "secretKey:    " << secretKey << endl;
    cout << "value:        " << value << endl;
    cout << "valueLength:  " << valueLength << endl;
  }

  // Initialize connection
  clientfd = Open_clientfd(MachineName, port);
  Rio_readinitb(&rio, clientfd);

  // Construct and send initial buffer
  unsigned char initBuf[INITBUFSIZE];
  initialBuf(initBuf, secretKey, DIG);
  Rio_writen(clientfd, initBuf, INITBUFSIZE);

  // Check key status
  if(getKey(rio) == -1){
    cout << "Read error: connection reset by peer" << endl;
    return -1;
  }

  // Construct and send value length buffer
  unsigned char lenBuf[DIGLENBUFSIZE];
  if(valueLength > DIGLENMAXSIZE){
    lenBuf[0] = (DIGLENMAXSIZE >> 8) & 0xFF;
    lenBuf[1] =  DIGLENMAXSIZE       & 0xFF;
  } else {
    lenBuf[0] = (valueLength >> 8) & 0xFF;
    lenBuf[1] =  valueLength       & 0xFF;
  }
  Rio_writen(clientfd, lenBuf, DIGLENBUFSIZE);

  // Construct and send value buffer
  unsigned char valBuf[valueLength];
  fillChar(valBuf, valueLength, value, strlen(value), DIGLENMAXSIZE);
  Rio_writen(clientfd, valBuf, valueLength);

  // Check status
  if(getStatus(rio) == -1)
    return -1;

  // Get result
  char resBuf[DIGRESBUFSIZE];
  Rio_readnb(&rio, resBuf, DIGRESBUFSIZE);
  for(int i = 0; i < DIGRESBUFSIZE && resBuf[i] != '\0'; i++){
    result[i] = resBuf[i];
    *resultLength = i + 1;
  }

  return 0;
}

int smallRun(char *MachineName, int port, int secretKey, char *request, char *result, int *resultLength){
  // Bytes 0-3:   A 4-byte unsigned integer containing SecretKey.
  // Bytes 4-5:   A 2-byte unsigned integer (a short) containing the type of request: set (0)
  // Bytes 6-7:   Two bytes of padding, with arbitrary values.
  // Byte 8-15:   an 8-byte string (null terminated) holding one of the valid values.
  int clientfd;
  rio_t rio;

  // Debugging comments
  if(RUNDEBUG){
    cout << "Running runDigest()" << endl << endl;
    cout << "MachineName:  " << MachineName << endl;
    cout << "port:         " << port << endl;
    cout << "secretKey:    " << secretKey << endl;
    cout << "request:      " << request << endl;
  }

  // Initialize connection
  clientfd = Open_clientfd(MachineName, port);
  Rio_readinitb(&rio, clientfd);

  // Construct and send initial buffer
  unsigned char initBuf[INITBUFSIZE];
  initialBuf(initBuf, secretKey, RUN);
  Rio_writen(clientfd, initBuf, INITBUFSIZE);

  // Check key status
  if(getKey(rio) == -1){
    cout << "Read error: connection reset by peer" << endl;
    return -1;
  }

  // Construct and send request
  Rio_writen(clientfd, request, RUNREQBUFSIZE);

  // Get status update
  if(getStatus(rio) == -1)
    return -1;

  // Get result
  char retBuf[RUNRETBUFSIZE];
  Rio_readnb(&rio, retBuf, RUNRETBUFSIZE);
  for(int i = 0; retBuf[i] != '\0' && i < RUNRETBUFSIZE; i++){
    result[i] = retBuf[i];
    *resultLength = i + 1;
  }

  // Get status update
  if(getStatus(rio) == -1)
    return -1;

  return 0;
}
