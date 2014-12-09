#include"BloomFilter.h"
#include"HashFuncs.h"
//////////////////////////////////////////////////////////////////////////
//Constructor
//생성자 bloomfilter에서 Array만 만들어줌(최대 크기로 만들어줌)
BloomFilter::BloomFilter(unsigned long aSize)
{

	Array = new int[aSize];		//생성자에서는 설정한 최대 사이즈 만큼 Bloomfilter Array를 만들어 준다.(재사용을 위함, 잦은 alloc, free 방지(버그 방지))
	memset(Array, 0, sizeof(int)*aSize);
	array_size = 0;					// array size 초기화
	maxCount = 0;					//MAXCNT 초기화
	numThre = 0;
}//end of Constructor


//////////////////////////////////////////////////////////////////////////
//Destroyer
//소멸자 bloomfilter에서 동적생성한건 모든 것을 제거함. 프로그램 종료시
BloomFilter::~BloomFilter()
{
	delete[] this->hash_funcs;
	delete[] Array;
}///end of Destroyer


//////////////////////////////////////////////////////////////////////////
//Destroyer
//블룸필터를 초기화
//(한번 실행되면 계속 재사용 할것이기 때문에.)
void BloomFilter::ClearBloomFilter()
{
	for (unsigned int i = 0; i < array_size; i++){	//Array 0으로 초기화
		Array[i] = 0;
	}
	array_size = 0;					// array size 초기화
	maxCount = 0;					//MAXCNT 초기화
	numThre = 0;
}//end of ClearBloomFilter


//////////////////////////////////////////////////////////////////////////
//setParam
// 여기서 각 시뮬 상황에 맞는 인자값을 넣어줌
void BloomFilter::setParam(unsigned long aSize, int maxcnt, int nf, ...)
{
	array_size = aSize;			//전체 사이즈(처음 최대 할당한 array) 중 사용할 파트의 size 설정
	maxCount = maxcnt;			//maxcount, 시뮬 중 이 수치를 넘어가면 Bot으로 처리될 것임
	nfuncs = nf;				//function 개수 설정

	hash_funcs = new hashfunc_t[nf];	// 이부분 부터 ... 로 넘어온 Function들을 function array에 담는다. 

	va_list list_temp;
	va_start(list_temp, nf);
	for (int n = 0; n < nfuncs; ++n) {
		hash_funcs[n] = va_arg(list_temp, hashfunc_t);
	}
	va_end(list_temp);
}//end of setParam



//////////////////////////////////////////////////////////////////////////
//bloom_add
//해쉬를 통과한 IP를 블룸필터에 넣는다
int BloomFilter::bloom_add(const char *s)
{
	for (int n = 0; n < nfuncs; n++) {
		// hash 함수 개수 만큼 미리 설정된 해쉬함수를 이용해 그 값에 대응하는 Array[해쉬값]의 카운트를 1 올린다.
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
//들어온 s 의 hash 결과값을 내고 array를 확인해서 해당 field들중의 최소 값만 뽑아냄.
int BloomFilter::bloom_check(const char *s)
{

	int min_Num = 999;

	for (int n = 0; n < nfuncs; n++) {
		unsigned long Hash_result = hash_funcs[n](s) % array_size;

		if (Array[Hash_result] < min_Num){
			min_Num = Array[Hash_result];
		}//if
	}//for
	// 최소값만 뽑아 내는 이유는, 하나라도 maxcount에 도달하지 않는 경우엔 Bot이 아니기 때문, 
	// 즉, 최소값이 maxcount값을 넘는지 비교하기 위함이다.
	return min_Num;
}//end of bloom_check


//////////////////////////////////////////////////////////////////////////
//bloom_allDecrease
//모든 array의 값을 1낮춘다
int BloomFilter::bloom_allDecrease()
{
	int result = 0;

	for (unsigned int i = 0; i < array_size; i++){	//이부분은 그냥 간단함.
		if (Array[i] > 0){
			Array[i]--;
			result++;
		}//if
	}//for
	numThre = 0;
	//몇개의 엔트리(필드)가 감소됐는지 반환
	return result;
}//end of DABO


//////////////////////////////////////////////////////////////////////////
//bloom_decrease
//해당 filed를 감소 시키고 0이 되면 num1s를 1 감소 시킴
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
//MaxCount(임계치, 이 값을 넘으면 Bot으로 간주된다)반환
int BloomFilter::getMaxCount()
{
	return maxCount;
}//end of getMaxCount


//////////////////////////////////////////////////////////////////////////
//getNumThre
//numThre(임계점을 넘은 필드의 갯수)를 반환한다
int BloomFilter::getNumThre()
{
	return numThre;
}//end of getNumThre


//////////////////////////////////////////////////////////////////////////
//getArraySize
//array_Size를 반환
unsigned long BloomFilter::getArraySize()
{
	return array_size;
}//end of getArraySize


//////////////////////////////////////////////////////////////////////////
//getAt
//전달 받은 index의 array값 반환
short BloomFilter::getAt(int index)
{
	return Array[index];
}//end of getAt
