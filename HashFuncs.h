#ifndef _HASH_FUNCS
#define _HASH_FUNCS

#include <iostream>
using namespace std;

//hash ÇÔ¼ö	
unsigned int SAXHash(char *str);
unsigned int RSHash(char* str);
unsigned int JSHash(char* str);
unsigned int PJWHash(char* str);
unsigned int ELFHash(char* str);
unsigned int BKDRHash(char* str);
unsigned int SDBMHash(char* str);
unsigned int DJBHash(char* str);
unsigned int BPHash(char* str);
unsigned int FNVHash(char* str);
unsigned int APHash(char* str);

#endif