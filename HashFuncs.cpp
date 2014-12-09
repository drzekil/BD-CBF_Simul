#include "HashFuncs.h"
////////////////////////////////////////////////////////////////////////////////
unsigned int SAXHash(char *str)
{
	unsigned int hash = 0;

	while (*str) hash ^= (hash << 5) + (hash >> 2) + (unsigned char)*str++;

	return hash;
}//end of SAXHash


unsigned int RSHash(char* str)
{
	unsigned int b = 378551;
	unsigned int a = 63689;
	unsigned int hash = 0;
	unsigned int i = 0;

	for (i = 0; *str; str++, i++)
	{
		hash = hash * a + (*str);
		a = a * b;
	}

	return hash;
}//end of RSHash


unsigned int JSHash(char* str)
{
	unsigned int hash = 1315423911;
	unsigned int i = 0;

	for (i = 0; *str; str++, i++)
	{
		hash ^= ((hash << 5) + (*str) + (hash >> 2));
	}

	return hash;
}//JSHash

unsigned int PJWHash(char* str)
{
	const unsigned int BitsInUnsignedInt = (unsigned int)(sizeof(unsigned int) * 8);
	const unsigned int ThreeQuarters = (unsigned int)((BitsInUnsignedInt * 3) / 4);
	const unsigned int OneEighth = (unsigned int)(BitsInUnsignedInt / 8);
	const unsigned int HighBits = (unsigned int)(0xFFFFFFFF) << (BitsInUnsignedInt - OneEighth);
	unsigned int hash = 0;
	unsigned int test = 0;
	unsigned int i = 0;

	for (i = 0; *str; str++, i++)
	{
		hash = (hash << OneEighth) + (*str);

		if ((test = hash & HighBits) != 0)
		{
			hash = ((hash ^ (test >> ThreeQuarters)) & (~HighBits));
		}
	}

	return hash;
}//PJWHash

unsigned int ELFHash(char* str)
{
	unsigned int hash = 0;
	unsigned int x = 0;
	unsigned int i = 0;

	for (i = 0; *str; str++, i++)
	{
		hash = (hash << 4) + (*str);
		if ((x = hash & 0xF0000000L) != 0)
		{
			hash ^= (x >> 24);
		}
		hash &= ~x;
	}

	return hash;
}//ELFHash

unsigned int BKDRHash(char* str)
{
	unsigned int seed = 131; /* 31 131 1313 13131 131313 etc.. */
	unsigned int hash = 0;
	unsigned int i = 0;

	for (i = 0; *str; str++, i++)
	{
		hash = (hash * seed) + (*str);
	}

	return hash;
}//BKDRHash


unsigned int SDBMHash(char* str)
{
	unsigned int hash = 0;
	unsigned int i = 0;

	for (i = 0; *str; str++, i++)
	{
		hash = (*str) + (hash << 6) + (hash << 16) - hash;
	}

	return hash;
}//SDBMHash


unsigned int DJBHash(char* str)
{
	unsigned int hash = 5381;
	unsigned int i = 0;

	for (i = 0; *str; str++, i++)
	{
		hash = ((hash << 5) + hash) + (*str);
	}

	return hash;
}//DJBHash

unsigned int BPHash(char* str)
{
	unsigned int hash = 0;
	unsigned int i = 0;
	for (i = 0; *str; str++, i++)
	{
		hash = hash << 7 ^ (*str);
	}

	return hash;
}//BPHash

unsigned int FNVHash(char* str)
{
	const unsigned int fnv_prime = 0x811C9DC5;
	unsigned int hash = 0;
	unsigned int i = 0;

	for (i = 0; *str; str++, i++)
	{
		hash *= fnv_prime;
		hash ^= (*str);
	}

	return hash;
}//////////////////////////////////////////////////////////////////////////

unsigned int APHash(char* str)
{
	unsigned int hash = 0xAAAAAAAA;
	unsigned int i = 0;

	for (i = 0; *str; str++, i++)
	{
		hash ^= ((i & 1) == 0) ? ((hash << 7) ^ (*str) * (hash >> 3)) :
			(~((hash << 11) + ((*str) ^ (hash >> 5))));
	}

	return hash;
}//APHash