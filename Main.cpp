/*//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	MY_DDoS_V3
	Confused_Traffic���� ������ �о�鿩 BD_CBF�� �����ϴ� ������Ʈ
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////*/
#include<iostream>
#include"AD_BCF_Launcher.h"
using namespace std;

int main(void)
{
	AD_CBF_Launcher * launcher = new AD_CBF_Launcher();
	int nFuncs = DEFAULT_NFUNC;
	int Threshold = 4;

	launcher->initParams(DEFAULT_MEMORY_SIZE, nFuncs, 0.5, Threshold); 

	launcher->BloomFilter_Setting();

	launcher->Simulation_Start();

	delete launcher;

	return 0;
}//main





