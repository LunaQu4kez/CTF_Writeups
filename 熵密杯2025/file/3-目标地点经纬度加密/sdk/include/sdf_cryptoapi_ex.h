#ifndef _HEADERS_SDF_CRYPTOAPI_EX_H_
#define _HEADERS_SDF_CRYPTOAPI_EX_H_

#include "sdf_cryptoapi.h"

#ifdef	WIN32
#define WIN_DLL_EXPOERT  __declspec(dllexport) extern 
#else
#define WIN_DLL_EXPOERT extern
#endif


#ifdef __cplusplus
extern "C" {
#endif

/********************************************************************
 * 说明：导出单证书加密公钥，GZW需求    
 *
 * 输入参数:void *hSessionHandle				会话句柄
 *			unsigned int	uiKeyIndex			设备内部存储的ECC密钥对索引值
 *
 * 输出参数:ECCrefPublicKey *	pucPublicKey	ECC公钥结构
 *
 * 返回值:0		成功
 *		非0		失败
*********************************************************************/
WIN_DLL_EXPOERT int SDF_ExportCertPublicKey(void *hSessionHandle,unsigned int uiKeyIndex,ECCrefPublicKey *pucPublicKey);

///////////////////////////////////////////////////////////////////////////////////////////////////
//SYY业务接口
///////////////////////////////////////////////////////////////////////////////////////////////////

 /********************************************************************
 * 说明：数研院新增-获取内部对称密钥句柄  2022/6/17
 *
 *   参数：	hSessionHandle	与设备建立的会话句柄
 *	        uiKeyIndex	密码设备内部存储密钥索引值
 *	        phKeyHandle	返回的密钥句柄
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_GetSymmKeyHandle(
	void * hSessionHandle,
	unsigned int uiKeyIndex,
	void **phKeyHandle
);


/********************************************************************
 * 说明：分散密钥并使用对称密钥加密导出						   	    
 *
 * 输入参数:	void *hSessionHandle			与设备建立的会话句柄	
 *				unsigned int uiAlgID			对称加密算法标识SGD_SM1 SGD_SM4 SGD_SM7
 *				unsigned char *pucRootKey		根密钥
 *				unsigned int  uiRootKeyLen		根密钥长度
 *				unsigned int  uiRootKeyIndex	密码机内部加密根密钥的KEK索引
 *				unsigned char *pucEncKey		加密密钥，用于加密导出子密钥。
 *				unsigned int  uiEncKeyLen		加密密钥长度
 *				unsigned int  uiEncKeyIndex		密码机内部加密加密密钥的KEK索引
 *				unsigned char *pucDispData		分散因子, 16byte*N  (N:分散级数)
 *				unsigned int  uiDispDataLen		分散因子长度 16*N
 * 输出参数：		
 *				unsigned char *pucOutKey		加密密钥加密的子密钥
 *				unsigned int *puiOutKeyLen		返回的密钥密文长度
 *				unsigned char *pucOutCv			加密密钥的校验值
 *				unsigned int *puiOutCvLen		返回的校验值长度
 *					
 * 返回值:	0		成功
 *			非0		失败				
 *******************************************************************/
WIN_DLL_EXPOERT int SDF_DispSymKeyExp(
	void  *hSessionHandle, 
	unsigned int uiAlgID,
	unsigned char *pucRootKey,
	unsigned int uiRootKeyLen,
	unsigned int uiRootKeyIndex,
	unsigned char *pucEncKey,
	unsigned int uiEncKeyLen,
	unsigned int uiEncKeyIndex,
	unsigned char *pucDispData,
	unsigned int uiDispDataLen,
	unsigned char *pucOutKey,
    unsigned int  *puiOutKeyLen,
	unsigned char *pucOutCv,
	unsigned int  *puiOutCvLen
);


/********************************************************************
 * 说明：使用分散密钥加密数据					   	    
 *
 * 输入参数:	void *hSessionHandle			与设备建立的会话句柄	
 *				unsigned int uiAlgID			算法标识，指定对称加密算法 SM1/4/7、ECB/CBC/OFB/CFB的组合eg.SGD_SM1_ECB
				unsigned char *pucIV		    输入+输出：缓冲区指针
 *				unsigned char *pucRootKey		根密钥
 *				unsigned int  uiRootKeyLen		根密钥长度
 *				unsigned int  uiRootKeyIndex	密码机内部加密根密钥的KEK索引
 *				unsigned char *pucDispData		分散因子, 16byte*N  (N:分散级数)
 *				unsigned int  uiDispDataLen		分散因子长度 16*N
 *				unsigned char *pucPlainData		数据明文
 *				unsigned int  uiPlainDataLen	数据明文长度
 *				
 * 输出参数：		
 *				unsigned char *pucCipherData		数据密文
 *				unsigned int *puiCipherDataLen		数据密文长度
 *					
 * 返回值:	0		成功
 *			非0		失败				
 *******************************************************************/
WIN_DLL_EXPOERT int SDF_DispSymKeyEncData(
	void  *hSessionHandle, 
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucRootKey,
	unsigned int uiRootKeyLen,
	unsigned int uiRootKeyIndex,
	unsigned char *pucDispData,
	unsigned int uiDispDataLen,
	unsigned char *pucPlainData,
	unsigned int  uiPlainDataLen,
	unsigned char *pucCipherData,
    unsigned int  *puiCipherDataLen
);

/********************************************************************
 * 说明：使用分散密钥解密数据				   	    
 *
 * 输入参数:	void *hSessionHandle			与设备建立的会话句柄	
 *				unsigned int uiAlgID			算法标识，指定对称加密算法 SM1/4/7、ECB/CBC/OFB/CFB的组合eg.SGD_SM1_ECB
				unsigned char *pucIV		    输入+输出：缓冲区指针
 *				unsigned char *pucRootKey		根密钥
 *				unsigned int  uiRootKeyLen		根密钥长度
 *				unsigned int  uiRootKeyIndex	密码机内部加密根密钥的KEK索引
 *				unsigned char *pucDispData		分散因子, 16byte*N  (N:分散级数)
 *				unsigned int  uiDispDataLen		分散因子长度 16*N
 *				unsigned char *pucCipherData	数据密文
 *				unsigned int  uiCipherDataLen	数据密文长度
 *				
 * 输出参数：		
 *				unsigned char *pucPlainData		数据明文
 *				unsigned int *puiPlainDataLen	数据明文长度
 *					
 * 返回值:	0		成功
 *			非0		失败				
 *******************************************************************/
WIN_DLL_EXPOERT int SDF_DispSymKeyDecData(
	void  *hSessionHandle, 
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucRootKey,
	unsigned int  uiRootKeyLen,
	unsigned int  uiRootKeyIndex,
	unsigned char *pucDispData,
	unsigned int  uiDispDataLen,
	unsigned char *pucCipherData,
    unsigned int  uiCipherDataLen,
	unsigned char *pucPlainData,
	unsigned int  *puiPlainDataLen
);

/********************************************************************
 * 说明：使用分散密钥计算Mac				   	    
 *
 * 输入参数:	void *hSessionHandle			与设备建立的会话句柄	
 *				unsigned int uiAlgID			算法标识，指定MAC加密算法SGD_SM3 
				unsigned char *pucIV		    输入+输出：缓冲区指针
 *				unsigned char *pucRootKey		根密钥
 *				unsigned int  uiRootKeyLen		根密钥长度
 *				unsigned int  uiRootKeyIndex	密码机内部加密根密钥的KEK索引
 *				unsigned char *pucDispData		分散因子, 16byte*N  (N:分散级数)
 *				unsigned int  uiDispDataLen		分散因子长度 16*N
 *				unsigned char *pucData			输入数据
 *				unsigned int  uiDataLength		输入数据长度，16字节整数倍 
 *				
 * 输出参数：		
 *				unsigned char *pucMAC			MAC值
 *				unsigned int *puiMACLength		MAC值长度，8字节
 *					
 * 返回值:	0		成功
 *			非0		失败				
 *******************************************************************/
WIN_DLL_EXPOERT int SDF_DispSymKeyGenMac(
	void  *hSessionHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV, 	
	unsigned char *pucRootKey,
	unsigned int  uiRootKeyLen,
	unsigned int  uiRootKeyIndex,
	unsigned char *pucDispData,
	unsigned int  uiDispDataLen,
	unsigned char  *pucData,
	unsigned int  uiDataLength,
	unsigned char *pucMAC,
	unsigned int  *puiMACLength
);

#ifdef __cplusplus
}
#endif

#endif //__SDCRYPTO_H__
