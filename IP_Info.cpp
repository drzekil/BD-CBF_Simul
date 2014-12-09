#include"IP_Info.h"

//////////////////////////////////////////////////////////////////////
//������
IP_Info::IP_Info()
{
	this->IP = new char[IP_BUFFER_SIZE];
	this->type = new char[IP_BUFFER_SIZE];
	this->intensity = 0.0;
	this->i_time = 0;
	this ->time = 0.0;
}//Constructor


//////////////////////////////////////////////////////////////////////
//������
IP_Info::~IP_Info()
{
	delete this->IP;
}


//////////////////////////////////////////////////////////////////////
//������ 
//Pre : IP�� time�� ���� �޾�, �� ����� ����
IP_Info::IP_Info(char * s, double t, double i)
{
	strcpy_s(this->IP, IP_BUFFER_SIZE, s);
	this->time = t;
	this->intensity = i;
}


//////////////////////////////////////////////////////////////////////
//setIP
//���ڿ���(s) ���޹޾� �� ���� ��ü�� ���(IP)�� ����
void  IP_Info::setIP(char * s)
{
	strcpy_s(this->IP, IP_BUFFER_SIZE, s);
}


//////////////////////////////////////////////////////////////////////
//getIP
//IP�� ����Ű�� �ִ� �����͸� ��ȯ
char * IP_Info::getIP()
{
	return this->IP;
}


//////////////////////////////////////////////////////////////////////
//setTime
//���޹��� �Ǽ�(t)�� time�� ����
void IP_Info::setTime(double t)
{
	this->time = t;
}


//////////////////////////////////////////////////////////////////////
//getTime
//time�� ��ȯ
double IP_Info::getTime()
{
	return this->time;
}


//////////////////////////////////////////////////////////////////////
//setIntensity
//Intensity�� Set
void IP_Info::setIntensity(double i)
{
	this->intensity = i;
}


//////////////////////////////////////////////////////////////////////
//getTime
//time�� ��ȯ
double IP_Info::getIntensity()
{
	return this->intensity;
}//end of getInten


//////////////////////////////////////////////////////////////////////
//setType
//Type�� ����
void IP_Info :: setType(const char * input)
{
	strcpy_s(type, IP_BUFFER_SIZE, input);
}//setType


//////////////////////////////////////////////////////////////////////
//getType
//Type�� ��ȯ
char * IP_Info::getType()
{
	return this->type;
}//GetType


//////////////////////////////////////////////////////////////////////
//setITime
//ITime�� ����
void IP_Info::setITime(int i)
{
	this->i_time = i;
}//setITime


//////////////////////////////////////////////////////////////////////
//getITime
//ITime�� ��ȯ
int IP_Info::getITime()
{
	return this->i_time;
}//getITime
