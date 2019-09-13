#include "smalllib.cpp"
#include <string>
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <sstream>

using namespace std;

int main(int argc, char ** argv){
  char *machineName;
  char *variableName;
  char *value;
  int port, SecretKey, retVal, dataLength;


  if(argc != 6){
    cout << "Usage: " << argv[0] << " <machineName> <port> <secretKey> <variableName> <value> \n";
    exit(1);
  }

  machineName = argv[1];
  port = atoi(argv[2]);
  SecretKey = atoi(argv[3]);
  variableName = argv[4];
  value = argv[5];

  if(smallSet(machineName, port, SecretKey, variableName, value, strlen(value)) == -1){
    cout << "failed" << endl;
    return -1;
  } else {
    return 0;
  }
}
