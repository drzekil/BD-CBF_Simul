#ifndef _AD_BCF_LAUNCHER_
#define _AD_BCF_LAUNCHER_
//////////////////////////////////////////////////////////////////////////
//��� ����
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <time.h>
#include <string>
#include <stdlib.h>
#include <time.h>
#include <list>
#include <vector>
#include <map>
#include <numeric>
#include <cmath>
#include <math.h>
#include <WinSock2.h>
#include<Windows.h>
#include <fstream>
#include <iostream>
#include <algorithm>
#include "BloomFilter.h"
#include "HashFuncs.h"
#include "IP_Info.h"
#include "Simul_Params.h"
using namespace std;
//////////////////////////////////////////////////////////////////////////
//���
#define DEFAULT_MEMORY_SIZE 262144
#define MAX_BUFFER_SIZE 128
#define MAX_MEMORY_SIZE 2097152
#define MAX_ARRAY_SIZE 400000000
#define MAXCNT 4
#define DEFAULT_MSIZE 8192
#define DEFAULT_BOTSIZE 2000000
#define DEFAULT_NUMNORMALIP 2000000
#define DEFAULT_INTENSITY_BOT 0.1								// default
#define DEFAULT_NFUNC 4											// default
#define DEFAULT_INTENSITY_NORM 0.0005
#define DEFAULT_NORMIPPERPACKET 5
//////////////////////////////////////////////////////////////////////////
#pragma comment(lib , "Ws2_32.lib")
//////////////////////////////////////////////////////////////////////////
class AD_CBF_Launcher	
{
	private :
		char buffer[1024];
		FILE * traffic_file;
		FILE * log_file;

		BloomFilter * Bloom;			//�ùķ��̼ǿ��� ���� BloomFilter
		BloomFilter * Bloom_BL;			//Bot�� ����Ǵ� �ڷᱸ��

		//IP_Info *normIP_Info;						//normal IP�� ����Ʈ
		//IP_Info *botIP_Info;						//bot IP�� ����Ʈ
		IP_Info * ip;								//���� IP

		//�ùķ��̼��� �Ķ���͵��� �����ص� �༮.
		bool b_flag;
		Simul_Params * sim_params;
			
	public:
		AD_CBF_Launcher();				//Default_������
		~AD_CBF_Launcher();				//�Ҹ���

		void initParams(unsigned long M, int nfuncs, double dabothre, int countthre);
		
		void BloomFilter_Setting();									//BloomFilter��, ����ȯ�氪�� ����
		void IP_Select();										//�α� ���Ϸκ��� IP�� �о�鿩, IP_Info�� ����
		double Simulation_Start();									//���� ��Ŷ�� �м��ϰ�, ������Ϳ� ���� �ְ�, ������ �����Ѵ�
		void clearIPList();											//IP_Info�� �Ҵ�� �޸𸮸� ���� �Ѵ�.
		void clearBloomFilter();									//BloomFilter�� �Ҵ�� �޸𸮸� �����Ѵ�.
		int checkPattern(unsigned long ip, int samplingStep, int patternIdx); //BloomFilter�� ��������� �Ǵ��Ѵ�
};//end of class AD_CBF_Launcher
#endif











/*////////////////////////////////////////////////////////////////////
private:
//�ùķ��̼ǿ� ���� BloomFilter
BloomFilter *Bloom;
BloomFilter *Bloom_BL;

IP_Info * normIP_Info;						//normal IP�� ����Ʈ
IP_Info * botIP_Info;						//bot IP�� ����Ʈ

//�ùķ��̼��� �Ķ���͵��� �����ص� �༮.
bool b_flag;


public:
AD_CBF_Launcher();							//������
~AD_CBF_Launcher();							//�Ҹ���
//void initParams(unsigned long N, unsigned long N_bot,		//Sim_Params�� ���� ȯ�� ������ �����ϱ� ���� �Լ�
//	unsigned long M, double intensityB,
//	double intensityN, int nfuncs, double dabothre,
//	int countthre, int nmin, int index);
void BloomFilter_Setting();									//BloomFilter��, ����ȯ�氪�� ����
void IP_Select(int i);										//�α� ���Ϸκ��� IP�� �о�鿩, IP_Info�� ����
double Simulation_Start();									//���� ��Ŷ�� �м��ϰ�, ������Ϳ� ���� �ְ�, ������ �����Ѵ�
void clearIPList();											//IP_Info�� �Ҵ�� �޸𸮸� ���� �Ѵ�.
void clearBloomFilter();									//BloomFilter�� �Ҵ�� �޸𸮸� �����Ѵ�.
int checkPattern(unsigned long ip, int samplingStep, int patternIdx); //BloomFilter�� ��������� �Ǵ��Ѵ�
/////////////////////////////////////////////////////////////////////*/