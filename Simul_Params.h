#ifndef _SIMUL_PARAMS_
#define _SIMUL_PARAMS_
////////////////////////////////////////////////////////////////////////////////
#include <iostream>
using namespace std;
////////////////////////////////////////////////////////////////////////////////
#define DEFAULT_NORM_INTENSITY 0.005
////////////////////////////////////////////////////////////////////////////////
class Simul_Params{
private:
	
	unsigned int memorySize;				//메모리 사이즈
	unsigned int numFuncs;					//사용하는 해쉬 함수의 갯수
	double DABOthreshold;					//전체 메모리중에서 Threshold를 넘은 비율
	int Countthreshold;						//Threshold를 넘은 엔트리(필드) 갯수
	
public:
	Simul_Params(unsigned long MSize, int nfuncs, double dabothre,int countthre);					//생성자. 모든 멤버 변수를 초기화
	unsigned int getMSize();											//memorySize반환
	unsigned int getNFuncs();											//사용된 해쉬 함수의 갯수 반환
	double getDABOThreshold();											//DABOthreshold값 반환
	int getCountThreshold();											//Countthreshold값 반환
};//end of class Simul_Params
#endif