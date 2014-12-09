#include "Simul_Params.h"
/////////////////////////////////////////////////////////////////////////////////
//Constructor
//시뮬레이션에 사용될 파라미터들을 세팅한다.
Simul_Params::Simul_Params(unsigned long MSize, int nfuncs, double dabothre, int countthre)
{
	memorySize = MSize;
	numFuncs = nfuncs;
	DABOthreshold = dabothre;
	Countthreshold = countthre;

}//end of Constructor


/////////////////////////////////////////////////////////////////////////////////
//getMSize
//memorySize 반환
unsigned int Simul_Params::getMSize(){
	return memorySize;
}//end of getMSize


/////////////////////////////////////////////////////////////////////////////////
//getNFuncs
//numFuncs 반환
unsigned int Simul_Params::getNFuncs()
{
	return numFuncs;
}//end of getNFuncs



/////////////////////////////////////////////////////////////////////////////////
//getDABOThreshold
//DABOthreshold반환
double Simul_Params::getDABOThreshold()
{
	return DABOthreshold;
}//end of getDABOThreshold


/////////////////////////////////////////////////////////////////////////////////
//getCountThreshold
//Countthreshold반환
int Simul_Params::getCountThreshold()
{
	return Countthreshold;
}//end og getCountThreshold


