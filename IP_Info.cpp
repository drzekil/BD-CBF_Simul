#include"IP_Info.h"

//////////////////////////////////////////////////////////////////////
//생성자
IP_Info::IP_Info()
{
	this->IP = new char[IP_BUFFER_SIZE];
	this->type = new char[IP_BUFFER_SIZE];
	this->intensity = 0.0;
	this->i_time = 0;
	this ->time = 0.0;
}//Constructor


//////////////////////////////////////////////////////////////////////
//생성자
IP_Info::~IP_Info()
{
	delete this->IP;
}


//////////////////////////////////////////////////////////////////////
//생성자 
//Pre : IP와 time을 전달 받아, 이 값대로 셋팅
IP_Info::IP_Info(char * s, double t, double i)
{
	strcpy_s(this->IP, IP_BUFFER_SIZE, s);
	this->time = t;
	this->intensity = i;
}


//////////////////////////////////////////////////////////////////////
//setIP
//문자열을(s) 전달받아 이 값을 객체의 멤버(IP)에 복사
void  IP_Info::setIP(char * s)
{
	strcpy_s(this->IP, IP_BUFFER_SIZE, s);
}


//////////////////////////////////////////////////////////////////////
//getIP
//IP를 가리키고 있는 포인터를 반환
char * IP_Info::getIP()
{
	return this->IP;
}


//////////////////////////////////////////////////////////////////////
//setTime
//전달받은 실수(t)를 time에 복사
void IP_Info::setTime(double t)
{
	this->time = t;
}


//////////////////////////////////////////////////////////////////////
//getTime
//time을 반환
double IP_Info::getTime()
{
	return this->time;
}


//////////////////////////////////////////////////////////////////////
//setIntensity
//Intensity를 Set
void IP_Info::setIntensity(double i)
{
	this->intensity = i;
}


//////////////////////////////////////////////////////////////////////
//getTime
//time을 반환
double IP_Info::getIntensity()
{
	return this->intensity;
}//end of getInten


//////////////////////////////////////////////////////////////////////
//setType
//Type을 셋팅
void IP_Info :: setType(const char * input)
{
	strcpy_s(type, IP_BUFFER_SIZE, input);
}//setType


//////////////////////////////////////////////////////////////////////
//getType
//Type을 반환
char * IP_Info::getType()
{
	return this->type;
}//GetType


//////////////////////////////////////////////////////////////////////
//setITime
//ITime을 설정
void IP_Info::setITime(int i)
{
	this->i_time = i;
}//setITime


//////////////////////////////////////////////////////////////////////
//getITime
//ITime을 반환
int IP_Info::getITime()
{
	return this->i_time;
}//getITime
