#ifndef _AD_BCF_LAUNCHER_
#define _AD_BCF_LAUNCHER_
//////////////////////////////////////////////////////////////////////////
//헤더 파일
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
//상수
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

		BloomFilter * Bloom;			//시뮬레이션에서 사용될 BloomFilter
		BloomFilter * Bloom_BL;			//Bot이 저장되는 자료구조

		//IP_Info *normIP_Info;						//normal IP의 리스트
		//IP_Info *botIP_Info;						//bot IP의 리스트
		IP_Info * ip;								//들어온 IP

		//시뮬레이션의 파라미터들을 저장해둘 녀석.
		bool b_flag;
		Simul_Params * sim_params;
			
	public:
		AD_CBF_Launcher();				//Default_생성자
		~AD_CBF_Launcher();				//소멸자

		void initParams(unsigned long M, int nfuncs, double dabothre, int countthre);
		
		void BloomFilter_Setting();									//BloomFilter에, 실험환경값을 저장
		void IP_Select();										//로그 파일로부터 IP를 읽어들여, IP_Info에 저장
		double Simulation_Start();									//들어온 패킷을 분석하고, 블룸필터에 집어 넣고, 실험을 진행한다
		void clearIPList();											//IP_Info에 할당된 메모리를 해제 한다.
		void clearBloomFilter();									//BloomFilter에 할당된 메모리를 해제한다.
		int checkPattern(unsigned long ip, int samplingStep, int patternIdx); //BloomFilter에 집어넣을지 판단한다
};//end of class AD_CBF_Launcher
#endif











/*////////////////////////////////////////////////////////////////////
private:
//시뮬레이션에 사용될 BloomFilter
BloomFilter *Bloom;
BloomFilter *Bloom_BL;

IP_Info * normIP_Info;						//normal IP의 리스트
IP_Info * botIP_Info;						//bot IP의 리스트

//시뮬레이션의 파라미터들을 저장해둘 녀석.
bool b_flag;


public:
AD_CBF_Launcher();							//생성자
~AD_CBF_Launcher();							//소멸자
//void initParams(unsigned long N, unsigned long N_bot,		//Sim_Params에 실험 환경 변수를 저장하기 위한 함수
//	unsigned long M, double intensityB,
//	double intensityN, int nfuncs, double dabothre,
//	int countthre, int nmin, int index);
void BloomFilter_Setting();									//BloomFilter에, 실험환경값을 저장
void IP_Select(int i);										//로그 파일로부터 IP를 읽어들여, IP_Info에 저장
double Simulation_Start();									//들어온 패킷을 분석하고, 블룸필터에 집어 넣고, 실험을 진행한다
void clearIPList();											//IP_Info에 할당된 메모리를 해제 한다.
void clearBloomFilter();									//BloomFilter에 할당된 메모리를 해제한다.
int checkPattern(unsigned long ip, int samplingStep, int patternIdx); //BloomFilter에 집어넣을지 판단한다
/////////////////////////////////////////////////////////////////////*/