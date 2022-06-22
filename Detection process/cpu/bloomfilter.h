#ifndef __MICRO_BLOOMFILTER_H__
#define __MICRO_BLOOMFILTER_H__

/**
 *  BloomFilter_x64实现，修改自: https://github.com/upbit/bloomfilter
 *
 *  仿照Cassandra中的BloomFilter实现，Hash选用MurmurHash2，通过双重散列公式生成散列函数
 *    Hash(key, i) = (H1(key) + i * H2(key)) % m
 *
 *  2012.12    完成初始版本
 *  2013.4.10  增加k/m的动态计算功能，参考：http://hur.st/bloomfilter
**/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

#define __BLOOMFILTER_VERSION__ "1.1"
#define __MGAIC_CODE__          (0x01464C42)

/**
 *  BloomFilter使用例子：
 *  static BaseBloomFilter stBloomFilter = {0};
 *
 *  初始化BloomFilter(最大100000元素，不超过0.00001的错误率)：
 *      InitBloomFilter(&stBloomFilter, 0, 100000, 0.00001);
 *  重置BloomFilter：
 *      ResetBloomFilter(&stBloomFilter);
 *  释放BloomFilter:
 *      FreeBloomFilter(&stBloomFilter);
 *
 *  向BloomFilter中新增一个数值（0-正常，1-加入数值过多）：
 *      uint32_t dwValue;
 *      iRet = BloomFilter_Add(&stBloomFilter, &dwValue, sizeof(uint32_t));
 *  检查数值是否在BloomFilter内（0-存在，1-不存在）：
 *      iRet = BloomFilter_Check(&stBloomFilter, &dwValue, sizeof(uint32_t));
 *
 *  (1.1新增) 将生成好的BloomFilter写入文件:
 *      iRet = SaveBloomFilterToFile(&stBloomFilter, "dump.bin")
 *  (1.1新增) 从文件读取生成好的BloomFilter:
 *      iRet = LoadBloomFilterFromFile(&stBloomFilter, "dump.bin")
**/

// 注意，要让Add/Check函数内联，必须使用 -O2 或以上的优化等级
#define FORCE_INLINE __attribute__((always_inline))

#define BYTE_BITS           (8)
#define MIX_UINT64(v)       ((uint32_t)((v>>32)^(v)))

#define SETBIT(filter, n)   (filter->pstFilter[n/BYTE_BITS] |= (1 << (n%BYTE_BITS)))
#define GETBIT(filter, n)   (filter->pstFilter[n/BYTE_BITS] & (1 << (n%BYTE_BITS)))

#pragma pack(1)

// BloomFilter结构定义
typedef struct
{
    uint8_t cInitFlag;                              // 初始化标志，为0时的第一次Add()会对stFilter[]做初始化
    uint8_t cResv[3];

    uint32_t dwMaxItems;                            // n - BloomFilter中最大元素个数 (输入量)
    double dProbFalse;                              // p - 假阳概率 (输入量，比如万分之一：0.00001)
    uint64_t dwFilterBits;                          // m = ceil((n * log(p)) / log(1.0 / (pow(2.0, log(2.0))))); - BloomFilter的比特数
    uint32_t dwHashFuncs;                           // k = round(log(2.0) * m / n); - 哈希函数个数
    
    uint32_t dwSeed;                                // MurmurHash的种子偏移量
    uint32_t dwCount;                               // Add()的计数，超过MAX_BLOOMFILTER_N则返回失败

    uint64_t dwFilterSize;                          // dwFilterBits / BYTE_BITS
    unsigned char *pstFilter;                       // BloomFilter存储指针，使用malloc分配
    uint64_t *pdwHashPos;                           // 存储上次hash得到的K个bit位置数组(由bloom_hash填充)
} BaseBloomFilter;

// BloomFilter文件头部定义
typedef struct
{
    uint32_t dwMagicCode;                           // 文件头部标识，填充 __MGAIC_CODE__
    uint32_t dwSeed;
    uint32_t dwCount;

    uint32_t dwMaxItems;                            // n - BloomFilter中最大元素个数 (输入量)
    double dProbFalse;                              // p - 假阳概率 (输入量，比如万分之一：0.00001)
    uint64_t dwFilterBits;                          // m = ceil((n * log(p)) / log(1.0 / (pow(2.0, log(2.0))))); - BloomFilter的比特数
    uint32_t dwHashFuncs;                           // k = round(log(2.0) * m / n); - 哈希函数个数

    uint32_t dwResv[6];
    uint32_t dwFileCrc;                             // (未使用)整个文件的校验和
    uint64_t dwFilterSize;                          // 后面Filter的Buffer长度
} BloomFileHead;

#pragma pack()


// 根据目标精度和数据个数，初始化BloomFilter结构
int InitBloomFilter(BaseBloomFilter *pstBloomfilter, uint32_t dwSeed, uint32_t dwMaxItems, double dProbFalse);

// 释放BloomFilter
int FreeBloomFilter(BaseBloomFilter *pstBloomfilter);

// 重置BloomFilter
// 注意: Reset()函数不会立即初始化stFilter，而是当一次Add()时去memset
int ResetBloomFilter(BaseBloomFilter *pstBloomfilter);

// 和ResetBloomFilter不同，调用后立即memset内存
int RealResetBloomFilter(BaseBloomFilter *pstBloomfilter);

///
///  函数FORCE_INLINE，加速执行
///
// MurmurHash2, 64-bit versions, by Austin Appleby
// https://sites.google.com/site/murmurhash/
uint64_t MurmurHash2_x64 ( const void * key, int len, uint32_t seed );

// 双重散列封装
void bloom_hash(BaseBloomFilter *pstBloomfilter, const void * key, int len);

// 向BloomFilter中新增一个元素
// 成功返回0，当添加数据超过限制值时返回1提示用户
int BloomFilter_Add(BaseBloomFilter *pstBloomfilter, const void * key, int len);

// 检查一个元素是否在bloomfilter中
// 返回：0-存在，1-不存在，负数表示失败
int BloomFilter_Check(BaseBloomFilter *pstBloomfilter, const void * key, int len);


/* 文件相关封装 */
// 将生成好的BloomFilter写入文件
int SaveBloomFilterToFile(BaseBloomFilter *pstBloomfilter, char *szFileName);

// 从文件读取生成好的BloomFilter
int LoadBloomFilterFromFile(BaseBloomFilter *pstBloomfilter, char *szFileName);

#endif
