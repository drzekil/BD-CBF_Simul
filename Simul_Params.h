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
	
	unsigned int memorySize;				//�޸� ������
	unsigned int numFuncs;					//����ϴ� �ؽ� �Լ��� ����
	double DABOthreshold;					//��ü �޸��߿��� Threshold�� ���� ����
	int Countthreshold;						//Threshold�� ���� ��Ʈ��(�ʵ�) ����
	
public:
	Simul_Params(unsigned long MSize, int nfuncs, double dabothre,int countthre);					//������. ��� ��� ������ �ʱ�ȭ
	unsigned int getMSize();											//memorySize��ȯ
	unsigned int getNFuncs();											//���� �ؽ� �Լ��� ���� ��ȯ
	double getDABOThreshold();											//DABOthreshold�� ��ȯ
	int getCountThreshold();											//Countthreshold�� ��ȯ
};//end of class Simul_Params
#endif