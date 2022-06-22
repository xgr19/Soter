/**
 *
 *  BloomFilter_x64实现，修改自: https://github.com/upbit/bloomfilter
 *
 *  仿照Cassandra中的BloomFilter实现，Hash选用MurmurHash2，通过双重散列公式生成散列函数
 *    Hash(key, i) = (H1(key) + i * H2(key)) % m
 *
 *  2012.12    完成初始版本
 *  2013.4.10  增加k/m的动态计算功能，参考：http://hur.st/bloomfilter
 **/
#include "bloomfilter.h"
#include "common_data.h"

// 计算BloomFilter的参数m,k
static inline void _CalcBloomFilterParam(uint32_t n, double p, uint64_t *pm, uint32_t *pk) {
	/**
	 *  n - Number of items in the filter
	 *  p - Probability of false positives, float between 0 and 1 or a number indicating 1-in-p
	 *  m - Number of bits in the filter
	 *  k - Number of hash functions
	 *
	 *  f = ln(2) × ln(1/2) × m / n = (0.4805) ^ (m/n)
	 *  m = -1 * ln(p) × n / 0.4805
	 *  k = ln(2) × m / n = 0.6931 * m / n
	 **/

	uint64_t m = n;
	uint32_t k;

	// 计算指定假阳概率下需要的比特数
	m = (uint64_t) ceil(-1 * log(p) * m / 0.4805);
	m = (m - m % 64) + 64;                  // 8字节对齐

	// 计算哈希函数个数
	k = (uint32_t) (log(2) * m / n);
	k++;

	*pm = m;
	*pk = k;
	return;
}

// 根据目标精度和数据个数，初始化BloomFilter结构
int InitBloomFilter(BaseBloomFilter *pstBloomfilter, uint32_t dwSeed, uint32_t dwMaxItems, double dProbFalse) {
	if (pstBloomfilter == NULL){
		return -1;
	}
	if ((dProbFalse <= 0) || (dProbFalse >= 1)){
		return -2;
	}

	// 先检查是否重复Init，释放内存
	if (pstBloomfilter->pstFilter != NULL){
		free(pstBloomfilter->pstFilter);
	}
	if (pstBloomfilter->pdwHashPos != NULL){
		free(pstBloomfilter->pdwHashPos);
	}

	memset(pstBloomfilter, 0, sizeof(BaseBloomFilter));

	// 初始化内存结构，并计算BloomFilter需要的空间
	pstBloomfilter->dwMaxItems = dwMaxItems;
	pstBloomfilter->dProbFalse = dProbFalse;
	pstBloomfilter->dwSeed = dwSeed;

	// 计算 m, k
	_CalcBloomFilterParam(pstBloomfilter->dwMaxItems, pstBloomfilter->dProbFalse, &pstBloomfilter->dwFilterBits, &pstBloomfilter->dwHashFuncs);

	// 分配BloomFilter的存储空间
	pstBloomfilter->dwFilterSize = pstBloomfilter->dwFilterBits / BYTE_BITS;
	pstBloomfilter->pstFilter = (unsigned char*) malloc( pstBloomfilter->dwFilterSize);
	if (NULL == pstBloomfilter->pstFilter) {
		return -100;
	}

	// 哈希结果数组，每个哈希函数一个
	pstBloomfilter->pdwHashPos = (uint64_t*) malloc(pstBloomfilter->dwHashFuncs * sizeof(uint64_t));
	if (NULL == pstBloomfilter->pdwHashPos){
		return -200;
	}

	printf(">>> Init BloomFilter(n=%u, p=%f, m=%ld, k=%d), malloc() size=%.2fMB\n",
			pstBloomfilter->dwMaxItems, pstBloomfilter->dProbFalse,
			pstBloomfilter->dwFilterBits, pstBloomfilter->dwHashFuncs,
			(double) pstBloomfilter->dwFilterSize / 1024 / 1024);

	// 初始化BloomFilter的内存
	memset(pstBloomfilter->pstFilter, 0, pstBloomfilter->dwFilterSize);
	pstBloomfilter->cInitFlag = 1;
	return 0;
}

// 释放BloomFilter
int FreeBloomFilter(BaseBloomFilter *pstBloomfilter) {
	if (pstBloomfilter == NULL){
		return -1;
	}

	pstBloomfilter->cInitFlag = 0;
	pstBloomfilter->dwCount = 0;

	free(pstBloomfilter->pstFilter);
	pstBloomfilter->pstFilter = NULL;
	free(pstBloomfilter->pdwHashPos);
	pstBloomfilter->pdwHashPos = NULL;
	return 0;
}

// 重置BloomFilter
// 注意: Reset()函数不会立即初始化stFilter，而是当一次Add()时去memset
int ResetBloomFilter(BaseBloomFilter *pstBloomfilter) {
	if (pstBloomfilter == NULL){
		return -1;
	}

	pstBloomfilter->cInitFlag = 0;
	pstBloomfilter->dwCount = 0;
	return 0;
}

// 和ResetBloomFilter不同，调用后立即memset内存
int RealResetBloomFilter(BaseBloomFilter *pstBloomfilter) {
	if (pstBloomfilter == NULL){
		return -1;
	}

	memset(pstBloomfilter->pstFilter, 0, pstBloomfilter->dwFilterSize);
	pstBloomfilter->cInitFlag = 1;
	pstBloomfilter->dwCount = 0;
	return 0;
}

///
///  函数FORCE_INLINE，加速执行
///
// MurmurHash2, 64-bit versions, by Austin Appleby
// https://sites.google.com/site/murmurhash/
uint64_t MurmurHash2_x64(const void *key, int len, uint32_t seed) {
	const uint64_t m = 0xc6a4a7935bd1e995;
	const int r = 47;

	uint64_t h = seed ^ (len * m);

	const uint64_t *data = (const uint64_t*) key;
	const uint64_t *end = data + (len / 8);

	while (data != end) {
		uint64_t k = *data++;

		k *= m;
		k ^= k >> r;
		k *= m;

		h ^= k;
		h *= m;
	}

	const uint8_t *data2 = (const uint8_t*) data;

	switch (len & 7) {
	case 7:
		h ^= ((uint64_t) data2[6]) << 48;
	case 6:
		h ^= ((uint64_t) data2[5]) << 40;
	case 5:
		h ^= ((uint64_t) data2[4]) << 32;
	case 4:
		h ^= ((uint64_t) data2[3]) << 24;
	case 3:
		h ^= ((uint64_t) data2[2]) << 16;
	case 2:
		h ^= ((uint64_t) data2[1]) << 8;
	case 1:
		h ^= ((uint64_t) data2[0]);
		h *= m;
	};

	h ^= h >> r;
	h *= m;
	h ^= h >> r;

	return h;
}

// 双重散列封装
void bloom_hash(BaseBloomFilter *pstBloomfilter, const void *key, int len) {
	//if (pstBloomfilter == NULL) return;
	unsigned int i;
	uint64_t dwFilterBits = pstBloomfilter->dwFilterBits;
	uint64_t hash1 = MurmurHash2_x64(key, len, pstBloomfilter->dwSeed);
	uint64_t hash2 = MurmurHash2_x64(key, len, MIX_UINT64(hash1));

	for (i = 0; i < pstBloomfilter->dwHashFuncs; i++) {
		pstBloomfilter->pdwHashPos[i] = (hash1 + i * hash2) % dwFilterBits;
	}

	return;
}

// 向BloomFilter中新增一个元素
// 成功返回0，当添加数据超过限制值时返回1提示用户
int BloomFilter_Add(BaseBloomFilter *pstBloomfilter, const void *key, int len) {
	if ((pstBloomfilter == NULL) || (key == NULL) || (len <= 0)){
		return -1;
	}

	int i;

	if (pstBloomfilter->cInitFlag != 1) {
		// Reset后没有初始化，使用前需要memset
		memset(pstBloomfilter->pstFilter, 0, pstBloomfilter->dwFilterSize);
		pstBloomfilter->cInitFlag = 1;
	}

	// hash key到bloomfilter中
	bloom_hash(pstBloomfilter, key, len);
	for (i = 0; i < (int) pstBloomfilter->dwHashFuncs; i++) {
		SETBIT(pstBloomfilter, pstBloomfilter->pdwHashPos[i]);
	}

	// 增加count数
	pstBloomfilter->dwCount++;
	if (pstBloomfilter->dwCount <= pstBloomfilter->dwMaxItems){
		return 0;
	}
	else{
		return 1;       // 超过N最大值，可能出现准确率下降等情况
	}
}

// 检查一个元素是否在bloomfilter中
// 返回：0-存在，1-不存在，负数表示失败
int BloomFilter_Check(BaseBloomFilter *pstBloomfilter, const void *key, int len) {
	if ((pstBloomfilter == NULL) || (key == NULL) || (len <= 0)){
		return -1;
	}

	int i;

	bloom_hash(pstBloomfilter, key, len);
	for (i = 0; i < (int) pstBloomfilter->dwHashFuncs; i++) {
		// 如果有任意bit不为1，说明key不在bloomfilter中
		// 注意: GETBIT()返回不是0|1，高位可能出现128之类的情况
		if (GETBIT(pstBloomfilter, pstBloomfilter->pdwHashPos[i]) == 0){
			return 1;
		}
	}

	return 0;
}

/* 文件相关封装 */
// 将生成好的BloomFilter写入文件
int SaveBloomFilterToFile(BaseBloomFilter *pstBloomfilter, char *szFileName) {
	if ((pstBloomfilter == NULL) || (szFileName == NULL)){
		return -1;
	}

	int iRet;
	FILE *pFile;
	static BloomFileHead stFileHeader = { 0 };

	pFile = fopen(szFileName, "wb");
	if (pFile == NULL) {
		perror("fopen");
		return -11;
	}

	// 先写入文件头
	stFileHeader.dwMagicCode = __MGAIC_CODE__;
	stFileHeader.dwSeed = pstBloomfilter->dwSeed;
	stFileHeader.dwCount = pstBloomfilter->dwCount;
	stFileHeader.dwMaxItems = pstBloomfilter->dwMaxItems;
	stFileHeader.dProbFalse = pstBloomfilter->dProbFalse;
	stFileHeader.dwFilterBits = pstBloomfilter->dwFilterBits;
	stFileHeader.dwHashFuncs = pstBloomfilter->dwHashFuncs;
	stFileHeader.dwFilterSize = pstBloomfilter->dwFilterSize;

	iRet = fwrite((const void*) &stFileHeader, sizeof(stFileHeader), 1, pFile);
	if (iRet != 1) {
		perror("fwrite(head)");
		return -21;
	}

	// 接着写入BloomFilter的内容
	iRet = fwrite(pstBloomfilter->pstFilter, 1, pstBloomfilter->dwFilterSize, pFile);
	if ((uint32_t) iRet != pstBloomfilter->dwFilterSize) {
		perror("fwrite(data)");
		return -31;
	}

	fclose(pFile);
	return 0;
}

// 从文件读取生成好的BloomFilter
int LoadBloomFilterFromFile(BaseBloomFilter *pstBloomfilter, char *szFileName) {
	if ((pstBloomfilter == NULL) || (szFileName == NULL)){
		return -1;
	}

	unsigned long long iRet;
	FILE *pFile;
	static BloomFileHead stFileHeader = { 0 };

	if (pstBloomfilter->pstFilter != NULL){
		free(pstBloomfilter->pstFilter);
	}
	if (pstBloomfilter->pdwHashPos != NULL){
		free(pstBloomfilter->pdwHashPos);
	}

	//
	pFile = fopen(szFileName, "rb");
	if (pFile == NULL) {
		perror("fopen");
		return -11;
	}

	// 读取并检查文件头
	iRet = fread((void*) &stFileHeader, sizeof(stFileHeader), 1, pFile);
	if (iRet != 1) {
		perror("fread(head)");
		return -21;
	}

	if ((stFileHeader.dwMagicCode != __MGAIC_CODE__)
			|| (stFileHeader.dwFilterBits != stFileHeader.dwFilterSize * BYTE_BITS)){
		return -50;
	}

	// 初始化传入的 BaseBloomFilter 结构
	pstBloomfilter->dwMaxItems = stFileHeader.dwMaxItems;
	pstBloomfilter->dProbFalse = stFileHeader.dProbFalse;
	pstBloomfilter->dwFilterBits = stFileHeader.dwFilterBits;
	pstBloomfilter->dwHashFuncs = stFileHeader.dwHashFuncs;
	pstBloomfilter->dwSeed = stFileHeader.dwSeed;
	pstBloomfilter->dwCount = stFileHeader.dwCount;
	pstBloomfilter->dwFilterSize = stFileHeader.dwFilterSize;

	pstBloomfilter->pstFilter = (unsigned char*) malloc( pstBloomfilter->dwFilterSize);
	if (NULL == pstBloomfilter->pstFilter){
		return -100;
	}
	pstBloomfilter->pdwHashPos = (uint64_t*) malloc( pstBloomfilter->dwHashFuncs * sizeof(uint64_t));
	if (NULL == pstBloomfilter->pdwHashPos){
		return -200;
	}

	// 将后面的Data部分读入 pstFilter
	iRet = fread((void*) (pstBloomfilter->pstFilter), 1, pstBloomfilter->dwFilterSize, pFile);
	if ((uint64_t)iRet != pstBloomfilter->dwFilterSize) {
		perror("fread(data)");
		return -31;
	}
	pstBloomfilter->cInitFlag = 1;

	DEBUGPRINTF( ">>> Load BloomFilter(n=%u, p=%f, m=%u, k=%d), malloc() size=%.2fMB\n",
			pstBloomfilter->dwMaxItems, pstBloomfilter->dProbFalse,
			pstBloomfilter->dwFilterBits, pstBloomfilter->dwHashFuncs,
			(double) pstBloomfilter->dwFilterSize / 1024 / 1024);

	fclose(pFile);
	return 0;
}
