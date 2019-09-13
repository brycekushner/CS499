#include "smalllib.cpp"
#include <string>
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <sstream>

using namespace std;

#define GETVALMAXSIZE 100

int main(int argc, char ** argv){
  char* machineName;
  char* variableName;
  char value[GETVALMAXSIZE];
  int resultLength;
  int port, variableLength, secretKey;


  if(argc != 5){
    cout << "Usage: " << argv[0] << " <machineName> <port> <secretKey> <variableName> \n";
    exit(1);
  }

  machineName = argv[1];
  port = atoi(argv[2]);
  secretKey = atoi(argv[3]);
  variableName = argv[4];

  if(smallGet(machineName, port, secretKey, variableName, value, &resultLength) == -1)
    cout << "failure" << endl;
  else{
    for(int i = 0; i < resultLength; i++)
      cout << value[i];
    cout << endl;
  }
}
