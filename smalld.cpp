extern "C"{
  #include "csapp.h"
}
#include <string>
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <sstream>
#include <stdint.h>
#include <map>
#include <vector>

#define INITBUFSIZE   8

#define SET           0
#define SETVARBUFSIZE 16
#define SETLENBUFSIZE 2
#define SETLENMAXSIZE 100

#define GET           1
#define GETVARBUFSIZE 16
#define GETVALMAXSIZE 100

#define DIG           2
#define DIGLENBUFSIZE 2
#define DIGRESBUFSIZE 100

#define RUN           3
#define RUNREQBUFSIZE 8
#define RUNRETBUFSIZE 100

#define SETDEBUG      0
#define GETDEBUG      0
#define DIGDEBUG      0
#define RUNDEBUG      0

#define STATUSBUFSIZE 1

using namespace std;

void sendStatus(int connfd, string connection){
  if(connection == "failure"){
    unsigned char buf[STATUSBUFSIZE];
    buf[0] = '\0';
    Rio_writen(connfd, buf, STATUSBUFSIZE);
  } else {
    unsigned char buf[STATUSBUFSIZE];
    buf[0] = ' ';
    Rio_writen(connfd, buf, STATUSBUFSIZE);
  }
}

void badKey(int connfd){
  unsigned char buf[STATUSBUFSIZE];
  buf[0] = '-';
  Rio_writen(connfd, buf, STATUSBUFSIZE);
}

void goodKey(int connfd){
  unsigned char buf[STATUSBUFSIZE];
  buf[0] = '+';
  Rio_writen(connfd, buf, STATUSBUFSIZE);
}

//Basics of server programmed using example in textbook
int main(int argc, char **argv){
  int listenfd, connfd;
  socklen_t clientLen;
  rio_t rio;
  struct sockaddr_storage clientaddr;
  map<string, string> variables;

  unsigned int secretKey, inputSecretKey, port;
  unsigned short reqType;

  //Input argument validation
  if(argc !=3){
    cout << "Usage: " << argv[0] << " <port> <secretkey>" << endl;
    exit(1);
  }

  port = atoi(argv[1]);
  secretKey = atoi(argv[2]);

  listenfd = Open_listenfd(port);

  while(1){
    clientLen = sizeof(clientaddr);
    connfd = Accept(listenfd, (SA *)&clientaddr, &clientLen);
    Rio_readinitb(&rio, connfd);

    // Read initial data
    unsigned char initBuf[INITBUFSIZE];
    Rio_readnb(&rio, initBuf, INITBUFSIZE);
    inputSecretKey = (initBuf[0] << 24) | (initBuf[1] << 16) | (initBuf[2] << 8) | initBuf[3];
    reqType = (initBuf[4] << 8) | initBuf[5];

    //check to see if secretKeys match before continuing
    bool validConnection = true;
    if(secretKey != inputSecretKey){
      cout << "Secret Key:   " << inputSecretKey << endl;
      cout << "-------------------------------" << endl;
      validConnection = false;
      badKey(connfd);
    } else {
      goodKey(connfd);
    }

    if(reqType == SET && validConnection){ //set
      string completion = "success";
      string value = "";

      // Get the variable name
      char varBuf[SETVARBUFSIZE];
      Rio_readnb(&rio, varBuf, SETVARBUFSIZE);
      string variableName = varBuf;

      // Get the value length
      unsigned char lenBuf[SETLENBUFSIZE];
      Rio_readnb(&rio, lenBuf, SETLENBUFSIZE);
      unsigned short valLen = (lenBuf[0] << 8) | lenBuf[1];
      if(valLen > SETLENMAXSIZE)
        completion = "failure";

      // Send status
      sendStatus(connfd, completion);

      // Get the value
      if(completion == "success"){
        char valBuf[valLen];
        Rio_readnb(&rio, valBuf, valLen);
        for(int i = 0; i < valLen; i++)
          value += valBuf[i];

        variables[variableName] = value;
      }

      // Send final status
      sendStatus(connfd, completion);

      // debug info
      if(SETDEBUG){
        cout << "SET DEBUGGING" << endl << endl;
        cout << "inputSecretKey: " << inputSecretKey << endl;
        cout << "reqType:        " << reqType << endl;
        cout << "variableName:   " << variableName << endl;
        cout << "varLen:         " << valLen << endl;
        cout << "value:          " << value << endl << endl;
        cout << "Map contents:" << endl;
        for(map<string, string>::const_iterator i = variables.begin(); i != variables.end(); i++)
          cout << "\t" << i->first << "\t" << i->second << endl;
        cout << endl << endl;
      } else { // Standard out
        cout << "Secret Key:   " << inputSecretKey << endl;
        cout << "Request Type: set" << endl;
        cout << "Detail:       " << variableName << ": " << value << endl;
        cout << "Completion:   " << completion << endl;
        cout << "-------------------------------" << endl;
      }
    }
    else if(reqType == GET && validConnection){ //get
      // Get the variable name
      char varBuf[GETVARBUFSIZE];
      Rio_readnb(&rio, varBuf, GETVARBUFSIZE);
      string variableName = varBuf;
      string completion;

      // Send variable value
      if (variables.find(variableName) == variables.end()){
        completion = "failure";
        // Send NULL for failure
        unsigned char failure[GETVALMAXSIZE];
        failure[0] = '\0';
        Rio_writen(connfd, failure, GETVALMAXSIZE);
      } else {
        completion = "success";
        string temp = variables[variableName];
        if(temp.length() + 1 > GETVALMAXSIZE){
          char res[GETVALMAXSIZE - 1];
          strcpy(res, temp.c_str());
          Rio_writen(connfd, res, GETVALMAXSIZE);
        } else {
          int size = temp.length();
          char res[size];
          strcpy(res, temp.c_str());
          Rio_writen(connfd, res, GETVALMAXSIZE);
        }
      }

      // debug info
      if(GETDEBUG){
        cout << "GET DEBUGGING" << endl << endl;
        cout << "inputSecretKey: " << inputSecretKey << endl;
        cout << "reqType:        " << reqType << endl;
        cout << "variableName:   " << variableName << endl;
      } else { // Standard out
        cout << "Secret Key:   " << inputSecretKey << endl;
        cout << "Request Type: get" << endl;
        cout << "Detail:       " << variableName << endl;
        cout << "Completion:   " << completion << endl;
        cout << "-------------------------------" << endl;
      }
    }
    else if(reqType == DIG && validConnection){ //digest
      // Get size of value
      unsigned char lenBuf[DIGLENBUFSIZE];
      Rio_readnb(&rio, lenBuf, DIGLENBUFSIZE);
      int valLen = (lenBuf[0] << 8) | lenBuf[1];
      string completion = "success";

      // Get the value itself
      char valBuf[valLen];
      Rio_readnb(&rio, valBuf, valLen);
      string value = "";
      for(int i = 0; i < valLen; i++)
        value += valBuf[i];

      // Digest
      FILE *filePointer;
      char resBuf[DIGRESBUFSIZE];
      for(int i = 0; i < DIGRESBUFSIZE; i++)
        resBuf[i] = '\0';
      string command = "/bin/echo " + value +" | /usr/bin/sha256sum";
      const char *convertedCommand = command.c_str();
      filePointer = popen(convertedCommand, "r");
      if(filePointer == NULL){
        completion = "failure";
      }

      // Send final status
      sendStatus(connfd, completion);

      // send result
      if(completion == "success"){
        fgets(resBuf, DIGRESBUFSIZE, filePointer);
        pclose(filePointer);
        Rio_writen(connfd, resBuf, DIGRESBUFSIZE);
      }

      // debug info
      if(DIGDEBUG){
        cout << "DIG DEBUGGING" << endl << endl;
        cout << "valueLength: " << valLen << endl;
        cout << "value:       " << value << endl;
      } else { // Standard out
        cout << "Secret Key:   " << inputSecretKey << endl;
        cout << "Request Type: digest" << endl;
        cout << "Detail:       " << value << endl;
        cout << "Command is [" << command << "]" << endl;
        cout << "Completion:   " << completion << endl;
        cout << "-------------------------------" << endl;
      }
    }
    else if(reqType == RUN && validConnection){ //run
      // Get request
      char reqBuf[RUNREQBUFSIZE];
      Rio_readnb(&rio, reqBuf, RUNREQBUFSIZE);
      string request = "";
      string completion = "success";
      for(int i = 0; reqBuf[i] != '\0' && i < RUNREQBUFSIZE; i++)
        request += reqBuf[i];

      // Execute
      string commandCall;
      if(request == "inet")
        commandCall = "/sbin/ifconfig -a";
      else if(request == "hosts")
        commandCall = "/bin/cat /etc/hosts";
      else if(request == "service")
        commandCall = "/bin/cat /etc/services";
      else //invalid command type
        completion = "failure";

      // Send status update
      sendStatus(connfd, completion);

      if(completion == "success"){
        FILE *filePointer;
        char buf2[RUNRETBUFSIZE];
        vector<char> wholeOutput;
        char returnBuf[RUNRETBUFSIZE];
        for(int i = 0; i < RUNRETBUFSIZE; i++){
          buf2[i] = '\0';
          returnBuf[i] = '\0';
        }
        const char *convertedCommand = commandCall.c_str();
        filePointer = popen(convertedCommand, "r");
        if(filePointer == NULL){
          completion = "failure";
        }

        while(!feof(filePointer)){
          int counter = 0;
          fgets(buf2, RUNRETBUFSIZE  , filePointer);
          while(buf2[counter] != '\0'){
            wholeOutput.push_back(buf2[counter]);
            counter++;
          }
        }

        for(int i = 0; i < RUNRETBUFSIZE - 1; i++)
          returnBuf[i] = wholeOutput[i];
        returnBuf[RUNRETBUFSIZE - 1] = '\0';
        pclose(filePointer);

        // Return result
        Rio_writen(connfd, returnBuf, RUNRETBUFSIZE);
      }

      // Send status update
      sendStatus(connfd, completion);

      if(RUNDEBUG){
        cout << "RUN DEBUGGING" << endl << endl;
        cout << "request: " << request << endl;
      } else { // Standard out
        cout << "Secret Key:   " << inputSecretKey << endl;
        cout << "Request Type: run" << endl;
        cout << "Detail:       " << request << endl;
        cout << "Completion:   " << completion << endl;
        cout << "-------------------------------" << endl;
      }
    }
  } // end while
} // end main
