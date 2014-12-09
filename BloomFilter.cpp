#include"BloomFilter.h"
#include"HashFuncs.h"
//////////////////////////////////////////////////////////////////////////
//Constructor
//������ bloomfilter���� Array�� �������(�ִ� ũ��� �������)
BloomFilter::BloomFilter(unsigned long aSize)
{

	Array = new int[aSize];		//�����ڿ����� ������ �ִ� ������ ��ŭ Bloomfilter Array�� ����� �ش�.(������ ����, ���� alloc, free ����(���� ����))
	memset(Array, 0, sizeof(int)*aSize);
	array_size = 0;					// array size �ʱ�ȭ
	maxCount = 0;					//MAXCNT �ʱ�ȭ
	numThre = 0;
}//end of Constructor


//////////////////////////////////////////////////////////////////////////
//Destroyer
//�Ҹ��� bloomfilter���� ���������Ѱ� ��� ���� ������. ���α׷� �����
BloomFilter::~BloomFilter()
{
	delete[] this->hash_funcs;
	delete[] Array;
}///end of Destroyer


//////////////////////////////////////////////////////////////////////////
//Destroyer
//������͸� �ʱ�ȭ
//(�ѹ� ����Ǹ� ��� ���� �Ұ��̱� ������.)
void BloomFilter::ClearBloomFilter()
{
	for (unsigned int i = 0; i < array_size; i++){	//Array 0���� �ʱ�ȭ
		Array[i] = 0;
	}
	array_size = 0;					// array size �ʱ�ȭ
	maxCount = 0;					//MAXCNT �ʱ�ȭ
	numThre = 0;
}//end of ClearBloomFilter


//////////////////////////////////////////////////////////////////////////
//setParam
// ���⼭ �� �ù� ��Ȳ�� �´� ���ڰ��� �־���
void BloomFilter::setParam(unsigned long aSize, int maxcnt, int nf, ...)
{
	array_size = aSize;			//��ü ������(ó�� �ִ� �Ҵ��� array) �� ����� ��Ʈ�� size ����
	maxCount = maxcnt;			//maxcount, �ù� �� �� ��ġ�� �Ѿ�� Bot���� ó���� ����
	nfuncs = nf;				//function ���� ����

	hash_funcs = new hashfunc_t[nf];	// �̺κ� ���� ... �� �Ѿ�� Function���� function array�� ��´�. 

	va_list list_temp;
	va_start(list_temp, nf);
	for (int n = 0; n < nfuncs; ++n) {
		hash_funcs[n] = va_arg(list_temp, hashfunc_t);
	}
	va_end(list_temp);
}//end of setParam



//////////////////////////////////////////////////////////////////////////
//bloom_add
//�ؽ��� ����� IP�� ������Ϳ� �ִ´�
int BloomFilter::bloom_add(const char *s)
{
	for (int n = 0; n < nfuncs; n++) {
		// hash �Լ� ���� ��ŭ �̸� ������ �ؽ��Լ��� �̿��� �� ���� �����ϴ� Array[�ؽ���]�� ī��Ʈ�� 1 �ø���.
		unsigned long Hash_result = hash_funcs[n](s) % array_size;

		if (Array[Hash_result] < maxCount){
			Array[Hash_result]++;
		}//if

		if (Array[Hash_result] == maxCount){
			numThre++;
		}//if
	}//for

	return 0;
}///end of bloom_add


//////////////////////////////////////////////////////////////////////////
//bloom_check
//���� s �� hash ������� ���� array�� Ȯ���ؼ� �ش� field������ �ּ� ���� �̾Ƴ�.
int BloomFilter::bloom_check(const char *s)
{

	int min_Num = 999;

	for (int n = 0; n < nfuncs; n++) {
		unsigned long Hash_result = hash_funcs[n](s) % array_size;

		if (Array[Hash_result] < min_Num){
			min_Num = Array[Hash_result];
		}//if
	}//for
	// �ּҰ��� �̾� ���� ������, �ϳ��� maxcount�� �������� �ʴ� ��쿣 Bot�� �ƴϱ� ����, 
	// ��, �ּҰ��� maxcount���� �Ѵ��� ���ϱ� �����̴�.
	return min_Num;
}//end of bloom_check


//////////////////////////////////////////////////////////////////////////
//bloom_allDecrease
//��� array�� ���� 1�����
int BloomFilter::bloom_allDecrease()
{
	int result = 0;

	for (unsigned int i = 0; i < array_size; i++){	//�̺κ��� �׳� ������.
		if (Array[i] > 0){
			Array[i]--;
			result++;
		}//if
	}//for
	numThre = 0;
	//��� ��Ʈ��(�ʵ�)�� ���ҵƴ��� ��ȯ
	return result;
}//end of DABO


//////////////////////////////////////////////////////////////////////////
//bloom_decrease
//�ش� filed�� ���� ��Ű�� 0�� �Ǹ� num1s�� 1 ���� ��Ŵ
int BloomFilter::bloom_decrease(const char *s)
{
	for (int n = 0; n < nfuncs; n++) {
		unsigned long Hash_result = hash_funcs[n](s) % array_size;

		if (Array[Hash_result] > 0){
			Array[Hash_result]--;
		}//if
	}//for

	return 0;
}//bloom_decrease


//////////////////////////////////////////////////////////////////////////
//getMaxCount
//MaxCount(�Ӱ�ġ, �� ���� ������ Bot���� ���ֵȴ�)��ȯ
int BloomFilter::getMaxCount()
{
	return maxCount;
}//end of getMaxCount


//////////////////////////////////////////////////////////////////////////
//getNumThre
//numThre(�Ӱ����� ���� �ʵ��� ����)�� ��ȯ�Ѵ�
int BloomFilter::getNumThre()
{
	return numThre;
}//end of getNumThre


//////////////////////////////////////////////////////////////////////////
//getArraySize
//array_Size�� ��ȯ
unsigned long BloomFilter::getArraySize()
{
	return array_size;
}//end of getArraySize


//////////////////////////////////////////////////////////////////////////
//getAt
//���� ���� index�� array�� ��ȯ
short BloomFilter::getAt(int index)
{
	return Array[index];
}//end of getAt
