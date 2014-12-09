#include "Simul_Params.h"
/////////////////////////////////////////////////////////////////////////////////
//Constructor
//�ùķ��̼ǿ� ���� �Ķ���͵��� �����Ѵ�.
Simul_Params::Simul_Params(unsigned long MSize, int nfuncs, double dabothre, int countthre)
{
	memorySize = MSize;
	numFuncs = nfuncs;
	DABOthreshold = dabothre;
	Countthreshold = countthre;

}//end of Constructor


/////////////////////////////////////////////////////////////////////////////////
//getMSize
//memorySize ��ȯ
unsigned int Simul_Params::getMSize(){
	return memorySize;
}//end of getMSize


/////////////////////////////////////////////////////////////////////////////////
//getNFuncs
//numFuncs ��ȯ
unsigned int Simul_Params::getNFuncs()
{
	return numFuncs;
}//end of getNFuncs



/////////////////////////////////////////////////////////////////////////////////
//getDABOThreshold
//DABOthreshold��ȯ
double Simul_Params::getDABOThreshold()
{
	return DABOthreshold;
}//end of getDABOThreshold


/////////////////////////////////////////////////////////////////////////////////
//getCountThreshold
//Countthreshold��ȯ
int Simul_Params::getCountThreshold()
{
	return Countthreshold;
}//end og getCountThreshold


