#include "smalllib.cpp"
#include <string>
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <sstream>

using namespace std;

#define DIGRESMAXSIZE 100

int main(int argc, char ** argv){
  char* machineName;
  char* value;
  char result[DIGRESMAXSIZE];
  int port, SecretKey, resultLength;

  if(argc != 5){
    cout << "Usage: " << argv[0] << " <MachineName> <port> <SecretKey> <value> \n";
    exit(1);
  }

  machineName = argv[1];
  port = atoi(argv[2]);
  SecretKey = atoi(argv[3]);
  value = argv[4];

  if(smallDigest(machineName, port, SecretKey, value, strlen(value), result, &resultLength) == -1){
    cout << "failure" << endl;
    return -1;
  } else
    cout << result << endl;
  return 0;
}
