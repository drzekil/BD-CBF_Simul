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
		int maxCount;							//Threshold값
		int nfuncs;								//Hash Function의 갯수
		int numThre;							//Threshold에 도달한 Entry 갯수
		hashfunc_t * hash_funcs;				//Hash Function Pointer

	public :
		BloomFilter(unsigned long initSize);		//Constructor
		~BloomFilter();								//소멸자
		void ClearBloomFilter();					//BloomFilter의 멤버값들을 초기화
		void setParam(unsigned long aSize, 
			          int maxcnt, int nf, ...);		//필터의 멤버값들을 초기화
		int bloom_check(const char *s);				//IP가 해쉬를 거쳤을 때, n개의 결과값 중에서 가장 작은 값을 반환
		int bloom_add(const char *s);				//필터에 (해쉬를 통과한)IP값을 집어 넣는다
		int bloom_allDecrease();					//필터의 모든 엔트리(필드)값을 1감소 시킨다
		int bloom_decrease(const char *s);			//해당 IP의 필드값을 1감소 시킨다
		int getMaxCount();							//Threshold값을 반환
		int getNumThre();							//임계점을 넘은 엔트리가 몇 개 있는지 반환한다.
		unsigned long getArraySize();				//메모리내 배열의 크기가 얼마인지 반환한다.
		short getAt(int index);						//해당인덱스의 값이 얼마인지를 반환한다.

};//end of BloomFilter

#endif