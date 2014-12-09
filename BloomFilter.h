#ifndef _BLOOM_FILTER_
#define _BLOOM_FILTER_
///////////////////////////////////////////////////////////////////////////////////
#include<iostream>
#include<string.h>
#include<limits.h>
#include<stdarg.h>
using namespace std;
///////////////////////////////////////////////////////////////////////////////////
//Hash Function Pointer
typedef unsigned int(*hashfunc_t)(const char *); 
///////////////////////////////////////////////////////////////////////////////////
class BloomFilter
{
	private :
		unsigned long array_size;				//BloomFilter Array Size
		int * Array;							//BloomFilter Array
		int maxCount;							//Threshold��
		int nfuncs;								//Hash Function�� ����
		int numThre;							//Threshold�� ������ Entry ����
		hashfunc_t * hash_funcs;				//Hash Function Pointer

	public :
		BloomFilter(unsigned long initSize);		//Constructor
		~BloomFilter();								//�Ҹ���
		void ClearBloomFilter();					//BloomFilter�� ��������� �ʱ�ȭ
		void setParam(unsigned long aSize, 
			          int maxcnt, int nf, ...);		//������ ��������� �ʱ�ȭ
		int bloom_check(const char *s);				//IP�� �ؽ��� ������ ��, n���� ����� �߿��� ���� ���� ���� ��ȯ
		int bloom_add(const char *s);				//���Ϳ� (�ؽ��� �����)IP���� ���� �ִ´�
		int bloom_allDecrease();					//������ ��� ��Ʈ��(�ʵ�)���� 1���� ��Ų��
		int bloom_decrease(const char *s);			//�ش� IP�� �ʵ尪�� 1���� ��Ų��
		int getMaxCount();							//Threshold���� ��ȯ
		int getNumThre();							//�Ӱ����� ���� ��Ʈ���� �� �� �ִ��� ��ȯ�Ѵ�.
		unsigned long getArraySize();				//�޸𸮳� �迭�� ũ�Ⱑ ������ ��ȯ�Ѵ�.
		short getAt(int index);						//�ش��ε����� ���� �������� ��ȯ�Ѵ�.

};//end of BloomFilter

#endif