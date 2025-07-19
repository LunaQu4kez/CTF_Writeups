#ifndef _HEADERS_SDF_CRYPTOAPI_H_
#define _HEADERS_SDF_CRYPTOAPI_H_

#ifdef	WIN32
#define WIN_DLL_EXPOERT  __declspec(dllexport) extern 
#else
#define WIN_DLL_EXPOERT extern
#endif


#ifdef __cplusplus
extern "C" {
#endif


/****算法标识****/

/* block cipher modes */
#define SGD_ECB			0x01
#define SGD_CBC			0x02
#define SGD_CFB			0x04
#define SGD_OFB			0x08
#define SGD_MAC			0x10

	/* ciphrs */
#define SGD_SM1			0x00000100
#define SGD_SM4			0x00000400
#define SGD_SM9		    0x00020803
#define SGD_SM7		    0x00020808
#define SGD_SM7_ECB		0x00020809
#define SGD_SM7_CBC		0x0002080a
#define SGD_SM7_CFB		0x0002080b
#define SGD_SM7_OFB		0x0002080c

#define SGD_AES		    0x00001000
#define SGD_AES_ECB		0x00001001
#define SGD_AES_CBC		0x00001002
#define SGD_AES_CFB		0x00001004
#define SGD_AES_OFB		0x00001008
#define SGD_AES_MAC		0x00001010

#define SGD_DES		    0x00002000
#define SGD_DES_ECB		0x00002001
#define SGD_DES_CBC		0x00002002
#define SGD_DES_CFB		0x00002004
#define SGD_DES_OFB		0x00002008
#define SGD_DES_MAC		0x00002010

#define SGD_2DES		0x00003000
#define SGD_2DES_ECB	0x00003001
#define SGD_2DES_CBC	0x00003002
#define SGD_2DES_CFB	0x00003004
#define SGD_2DES_OFB	0x00003008
#define SGD_2DES_MAC	0x00003010

#define SGD_3DES		0x00004000
#define SGD_3DES_ECB	0x00004001
#define SGD_3DES_CBC	0x00004002
#define SGD_3DES_CFB	0x00004004
#define SGD_3DES_OFB	0x00004008
#define SGD_3DES_MAC	0x00004010


/* ciphers with modes */
#define SGD_SM1_ECB		(SGD_SM1|SGD_ECB)
#define SGD_SM1_CBC		(SGD_SM1|SGD_CBC)
#define SGD_SM1_CFB		(SGD_SM1|SGD_CFB)
#define SGD_SM1_OFB		(SGD_SM1|SGD_OFB)
#define SGD_SM1_MAC		(SGD_SM1|SGD_MAC)
#define SGD_SM4_ECB		(SGD_SM4|SGD_ECB)
#define SGD_SM4_CBC		(SGD_SM4|SGD_CBC)
#define SGD_SM4_CFB		(SGD_SM4|SGD_CFB)
#define SGD_SM4_OFB		(SGD_SM4|SGD_OFB)
#define SGD_SM4_MAC		(SGD_SM4|SGD_MAC)

/* public key types */
#define SGD_RSA			0x00010000 //RSA算法
#define SGD_RSA_1   	0x00010200 //RSA签名算法
#define SGD_RSA_3		0x00010800 //RSA加密算法
#define SGD_SM2			0x00020100 //SM2 椭圆曲线密码算法
#define SGD_SM2_1		0x00020200 //SM2 椭圆曲线签名算法
#define SGD_SM2_2		0x00020400 //SM2 椭圆曲线密钥交换协议
#define SGD_SM2_3		0x00020800 //SM2 椭圆曲线加密算法


/* hash */
#define SGD_SM3			0x00000001  //SM3杂凑算法
#define SGD_SHA1		0x00000002  //SHA_1杂凑算法
#define SGD_SHA256		0x00000004  //SHA_256杂凑算法


/* 签名算法标识 */
#define SGD_SM3_RSA			0x00010001 //基于SM3算法和RSA算法的签名
#define SGD_SHA1_RSA		0x00010002 //基于SHA_1算法和RSA算法的签名
#define SGD_SHA256_RSA		0x00010004 //基于SHA_256算法和RSA算法的签名
#define SGD_SM3_SM2			0x00020201 //基于SM3算法和SM2算法的签名

#define RSAref_MAX_BITS		4096
#define RSAref_MAX_LEN		((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS	((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN		((RSAref_MAX_PBITS + 7) / 8)



/****数据结构****/
#pragma pack(1)
typedef struct DeviceInfo_st {
	unsigned char IssuerName[40];
	unsigned char DeviceName[16];
	unsigned char DeviceSerial[16];	/* 8-char date + 3-char batch num + 5-char serial num */
	unsigned int DeviceVersion;
	unsigned int StandardVersion;
	unsigned int AsymAlgAbility[2];	/* AsymAlgAbility[0] = algors  AsymAlgAbility[1] = modulus lens */
	unsigned int SymAlgAbility;
	unsigned int HashAlgAbility;
	unsigned int BufferSize;
} DEVICEINFO;


#ifndef RSAref_MAX_BITS
#define RSAref_MAX_BITS 4096
#define RSAref_MAX_LEN ((RSAref_MAX_BITS + 7) / 8) //512 256
#define RSAref_MAX_PBITS ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN ((RSAref_MAX_PBITS + 7)/ 8) //256 128
#endif /*  RSAref_MAX_BITS */

#define ECCCipher_MAX_LEN   1440


typedef struct RSArefPublicKey_st{
	unsigned int bits;
	unsigned char m[RSAref_MAX_LEN];
	unsigned char e[RSAref_MAX_LEN];
}RSArefPublicKey;

typedef struct RSArefPrivateKey_st{
	unsigned int bits;
	unsigned char m[RSAref_MAX_LEN];
	unsigned char e[RSAref_MAX_LEN];
	unsigned char d[RSAref_MAX_LEN];
	unsigned char prime[2][RSAref_MAX_PLEN];
	unsigned char pexp[2][RSAref_MAX_PLEN];
	unsigned char coef[RSAref_MAX_PLEN];
}RSArefPrivateKey;

#ifndef ECCref_MAX_BITS 
#define ECCref_MAX_BITS 512
#define ECCref_MAX_LEN ((ECCref_MAX_BITS + 7) / 8)
#endif /*  ECCref_MAX_BITS */

typedef struct ECCrefPublicKey_st{
	unsigned int bits;
	unsigned char x[ECCref_MAX_LEN];
	unsigned char y[ECCref_MAX_LEN];
}ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st{
	unsigned int bits;
	unsigned char K[ECCref_MAX_LEN];
}ECCrefPrivateKey;


typedef struct ECCCipher_st{
	unsigned char x[ECCref_MAX_LEN];
	unsigned char y[ECCref_MAX_LEN];
	unsigned char M[32];
	unsigned int L;
	unsigned char C[ECCCipher_MAX_LEN];
}ECCCipher;


typedef struct ECCSignature_st{
	unsigned char r[ECCref_MAX_LEN];
	unsigned char s[ECCref_MAX_LEN];
}ECCSignature;


typedef struct SDF_ENVELOPEDKEYBLOB {
	unsigned long ulAsymmAlgID;
	unsigned long ulSymmAlgID;
	ECCCipher ECCCipherBlob;
	ECCrefPublicKey PubKey;
	unsigned char cbEncryptedPriKey[64];
} ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;
#pragma pack()

/****错误码****/
#define SDR_OK					0x00					//操作成功
#define SDR_BASE				0x01000000              //操作码基础值
#define SDR_UNKNOWERR			SDR_BASE + 0x00000001   //未知错误
#define SDR_NOTSUPPORT			SDR_BASE + 0x00000002 	//不支持的接口调用
#define SDR_COMMFAIL			SDR_BASE + 0x00000003   //与设备通信失败
#define SDR_HARDFAIL			SDR_BASE + 0x00000004	//运算模块无响应
#define SDR_OPENDEVICE			SDR_BASE + 0x00000005 	//打开设备失败
#define SDR_OPENSESSION			SDR_BASE + 0x00000006 	//创建会话失败
#define SDR_PARDENY				SDR_BASE + 0x00000007 	//无私钥使用权限
#define SDR_ALGNOTSUPPORT		SDR_BASE + 0x00000009 	//不支持的算法调用
#define SDR_KEYNOTEXIST			SDR_BASE + 0x00000008   //不存在的密钥调用
#define SDR_ALGMODNOTSUPPORT	SDR_BASE + 0x0000000A 	//不支持的算法模式调用
#define SDR_PKOPERR				SDR_BASE + 0x0000000B 	//公钥运算失败
#define SDR_SKOPERR				SDR_BASE + 0x0000000C	//私钥运算失败
#define SDR_SIGNERR				SDR_BASE + 0x0000000D 	//签名运算失败
#define SDR_VERIFYERR			SDR_BASE + 0x0000000E 	//验证签名失败
#define SDR_SYMOPERR			SDR_BASE + 0x0000000F	//对称算法运算失败
#define SDR_STEPERR				SDR_BASE + 0x00000010 	//多步运算步骤错误
#define SDR_FILESIZEERR			SDR_BASE + 0x00000011 	//文件长度超出限制
#define SDR_FILENOEXIST			SDR_BASE + 0x00000012 	//指定的文件不存在
#define SDR_FILEOFSERR 			SDR_BASE + 0x00000013	//文件起始位置错误
#define SDR_KEYTYPEERR 			SDR_BASE + 0x00000014	//密钥类型错误
#define SDR_KEYERR 				SDR_BASE + 0x00000015 	//密钥错误
#define SDR_ENCDATAERR			SDR_BASE + 0x00000016 	//ECC加密数据错误
#define SDR_RANDERR				SDR_BASE + 0x00000017 	//随机数产生失败
#define SDR_PRKRERR				SDR_BASE + 0x00000018 	//私钥使用权限获取失败
#define SDR_MACERR 				SDR_BASE + 0x00000019 	//MAC运算失败
#define SDR_FILEEXISTS			SDR_BASE + 0x0000001A 	//指定文件已存在
#define SDR_FILEWERR			SDR_BASE + 0x0000001B 	//文件写入失败
#define SDR_NOBUFFER			SDR_BASE + 0x0000001C	//存储空间不足
#define SDR_INARGERR			SDR_BASE + 0x0000001D 	//输入参数错误
#define SDR_OUTARGERR 			SDR_BASE + 0x0000001E	//输出参数错误
#define SDR_HASHERR 			SDR_BASE + 0x0000001F	//杂凑运算错误
#define	SDR_SESSHANDLE	        SDR_BASE + 0x00000020	//会话句柄错
#define	SDR_KEYHANDLE	        SDR_BASE + 0x00000021	//密钥句柄错
#define	SDR_DEVSTATE	        SDR_BASE + 0x00000022	//设备状态错


/****接口函数****/

///////////////////////////////////////////////////////////////////////////////////////////////////
//设备管理类函数
///////////////////////////////////////////////////////////////////////////////////////////////////
/********************************************************************
 * 说明：打开设备										   	    
 *
 * 参数:	void **phDeviceHandle  返回设备句柄
 *
 * 返回值:	0		成功
 *			非0		失败					
 *******************************************************************/
WIN_DLL_EXPOERT int SDF_OpenDevice(void **phDeviceHandle);
WIN_DLL_EXPOERT int SDF_OpenDevice_ex(void **phDeviceHandle, char *ip, int port);
WIN_DLL_EXPOERT int SDF_OpenDeviceWithPath(char *pInFileName, void **phDeviceHandle);
/********************************************************************
 * 说明：关闭设备
 *	
 * 参数:	void *hDeviceHandle  设备句柄
 *	
 * 返回值:	0		成功
 *			非0		失败
 *******************************************************************/
WIN_DLL_EXPOERT int SDF_CloseDevice(void *hDeviceHandle);

/********************************************************************
 * 说明：创建会话
 *
 * 参数:	void *hDeviceHandle		设备句柄
 *			void **phSessionHandle	返回会话句柄
 *
 * 返回值:	0		成功
 *			非0		失败
 *******************************************************************/
WIN_DLL_EXPOERT int SDF_OpenSession(void *hDeviceHandle,void **phSessionHandle);

/********************************************************************
 * 说明：关闭会话    
 *
 * 参数:	void *hSessionHandle	 会话句柄
 *
 * 返回值:	0		成功
 *			非0		失败
 *******************************************************************/
WIN_DLL_EXPOERT int SDF_CloseSession(void *hSessionHandle);

/********************************************************************
 * 说明：获取设备信息
 *
 * 输入参数:	void *hSessionHandle  		会话句柄
 *							
 * 输出参数:    DEVICEINFO *pstDeviceInfo	设备信息		
 * 返回值:	0		成功
 *			非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_GetDeviceInfo(void *hSessionHandle,DEVICEINFO *pstDeviceInfo);

/********************************************************************
 * 说明：获取随机数	
 *
 * 输入参数:void *hSessionHandle  		会话句柄
 *			unsigned int uiLength		指定生成随机数的长度	
 * 输出参数:unsigned char * pucRandom	生成的随机数	
 *
 * 返回值:	0		成功
 *			非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_GenerateRandom(void *hSessionHandle,unsigned int uiLength,unsigned char *pucRandom);

/********************************************************************
 * 说明：获取私钥使用权限
 *
 * 输入参数:void 			*hSessionHandle 会话句柄
 *			unsigned int	uiKeyIndex		密码设备存储私钥的索引值
 *			unsigned char	*pucPassWord	使用私钥权限的标识码
 *			unsigned int	uiPwdLength		私钥访问控制码长度，不少于8个字节
 * 输出参数:无	
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_GetPrivateKeyAccessRight(void *hSessionHandle,unsigned int uiKeyIndex,unsigned char *pucPassword,unsigned int uiPwdLength);

/********************************************************************
 * 说明：释放私钥使用权限
 *
 * 输入参数:void 			*hSessionHandle	会话句柄
 *			unsigned int	uiKeyIndex		密码设备存储私钥的索引值
 *
 * 输出参数:无	
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_ReleasePrivateKeyAccessRight(void *hSessionHandle,unsigned int uiKeyIndex);

///////////////////////////////////////////////////////////////////////////////////////////////////
//密钥管理类函数
///////////////////////////////////////////////////////////////////////////////////////////////////
/********************************************************************
 * 说明：导出RSA签名公钥	    
 *	
 * 输入参数:void 			*hSessionHandle		会话句柄
 *			unsigned int	uiKeyIndex			设备内部存储的RSA密钥对索引值
 *
 * 输出参数:RSArefPublicKey	*pucPublicKey	RSA公钥结构		
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_ExportSignPublicKey_RSA(void *hSessionHandle, unsigned int uiKeyIndex,RSArefPublicKey * pucPublicKey);

/********************************************************************
 * 说明：导出RSA加密公钥    
 *
 * 输入参数:void *hSessionHandle				会话句柄
 *			unsigned int	uiKeyIndex			设备内部存储的RSA密钥对索引值
 *
 * 输出参数:RSArefPublicKey	*pucPublicKey	RSA公钥结构
 *
 * 返回值:0		成功
 *		非0		失败
*********************************************************************/
WIN_DLL_EXPOERT int SDF_ExportEncPublicKey_RSA(void *hSessionHandle, unsigned int uiKeyIndex,RSArefPublicKey * pucPublicKey);

/********************************************************************
 * 说明：产生RSA密钥对并输出  
 *
 * 输入参数:void 			*hSessionHandle		会话句柄
 *			unsigned int	uiKeyBits			指定的密钥长度
 *
 * 输出参数:RSArefPublicKey 	*pucPublicKey	RSA公钥结构
 *			RSArefPrivateKey	*pucPrivateKey	RSA私钥结构
 *
 * 返回值:0		成功
 *		非0		失败
*********************************************************************/
WIN_DLL_EXPOERT int SDF_GenerateKeyPair_RSA(void *hSessionHandle,unsigned int uiKeyBits,RSArefPublicKey * pucPublicKey,RSArefPrivateKey * pucPrivateKey);

/********************************************************************
 * 说明： 生成会话密钥并用内部RSA公钥加密输出
 *
 * 输入参数:void 			*hSessionHandle		会话句柄
 *			unsigned int	uiIPKIndex			内部公钥索引值
 *			unsigned int	uiKeyBits			指定的密钥长度
 *
 * 输出参数:unsigned char	*pucKey				返回密文
 *			unsigned int	*puiKeyLength		返回密文长度
 *			void			**phKeyHandle			返回密钥句柄
 *
 * 返回值:0		成功
 *		非0		失败
*********************************************************************/
WIN_DLL_EXPOERT int SDF_GenerateKeyWithIPK_RSA(void *hSessionHandle, unsigned int uiIPKIndex,unsigned int uiKeyBits,unsigned char * pucKey,unsigned int * puiKeyLength,void ** phKeyHandle);

/********************************************************************
 * 说明： 生成会话密钥并用外部RSA公钥加密输出
 *
 * 输入参数:void 			*hSessionHandle		会话句柄
 *			unsigned int	uiKeyBits			指定的密钥长度
 *			RSArefPublicKey	*pucPublicKey	RSA公钥结构
 *
 * 输出参数:unsigned char	*pucKey				返回密文
 *			unsigned int	*puiKeyLength		返回密文长度
 *			void			**phKeyHandle			返回密钥句柄
 *
 * 返回值:0		成功
 *		非0		失败
*********************************************************************/
WIN_DLL_EXPOERT int SDF_GenerateKeyWithEPK_RSA(void *hSessionHandle, unsigned int uiKeyBits,RSArefPublicKey * pucPublicKey,unsigned char * pucKey,unsigned int * puiKeyLength,void ** phKeyHandle);

/********************************************************************
 * 说明：导入会话密钥并用内部RSA私钥解密
 *
 * 输入参数:void 			*hSessionHandle		会话句柄
 *			unsigned int	uiISKIndex			密码设备内部存储加密私钥的索引值，对应于加密时的公钥
 *			unsigned char 	*pucKey				密钥密文
 *			unsigned int	puiKeyLength		密文数据长度
 *
 * 输出参数:void 			**phKeyHandle		会话密钥句柄			
 *
 * 返回值:	0		成功
 *			非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_ImportKeyWithISK_RSA(void *hSessionHandle,unsigned int uiISKIndex,unsigned char *pucKey,unsigned int puiKeyLength, void ** phKeyHandle);

/********************************************************************
 * 说明：基于RSA算法的数字信封转换
 *	
 * 输入参数:void 			*hSessionHandle		会话句柄
 *			unsigned int	uiKeyIndex			内部RSA密钥对索引值
 *			RSArefPublicKey	pucPublicKey		外部RSA公钥结构
 *			unsigned char *	pucDEInput			用于存放输入的会话密钥密文
 *			unsigned int	uiDELength			输入的会话密钥密文长度
 *
 * 输出参数:unsigned char *	pucDEOutput			输出的会话密钥密文		
 *			unsigned int *	puiDELength			输出的会话密钥密文长度
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_ExchangeDigitEnvelopeBaseOnRSA(void *hSessionHandle,unsigned int uiKeyIndex,RSArefPublicKey * pucPublicKey, unsigned char * pucDEInput,unsigned int uiDELength,unsigned char * pucDEOutput,unsigned int * puiDELength);

/********************************************************************
 * 说明：导出ECC签名公钥	    
 *	
 * 输入参数:void 			*hSessionHandle		会话句柄
 *			unsigned int	uiKeyIndex			设备内部存储的ECC密钥对索引值
 *
 * 输出参数:ECCrefPublicKey *	pucPublicKey	ECC公钥结构		
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_ExportSignPublicKey_ECC(void *hSessionHandle,unsigned int uiKeyIndex,ECCrefPublicKey *pucPublicKey);

/********************************************************************
 * 说明：导出ECC加密公钥    
 *
 * 输入参数:void *hSessionHandle				会话句柄
 *			unsigned int	uiKeyIndex			设备内部存储的ECC密钥对索引值
 *
 * 输出参数:ECCrefPublicKey *	pucPublicKey	ECC公钥结构
 *
 * 返回值:0		成功
 *		非0		失败
*********************************************************************/
WIN_DLL_EXPOERT int SDF_ExportEncPublicKey_ECC(void *hSessionHandle,unsigned int uiKeyIndex,ECCrefPublicKey *pucPublicKey);

/********************************************************************
 * 说明：产生ECC密钥对并输出  
 *
 * 输入参数:void 			*hSessionHandle		会话句柄
 *			unsigned int	uiAlgID				算法标识
 *			unsigned int	uiKeyBits			指定的密钥长度
 *
 * 输出参数:ECCrefPublicKey 	*pucPublicKey	ECC公钥结构
 *			ECCrefPrivateKey	*pucPrivateKey	ECC私钥结构
 *
 * 返回值:0		成功
 *		非0		失败
*********************************************************************/
WIN_DLL_EXPOERT int SDF_GenerateKeyPair_ECC(void *hSessionHandle,unsigned int uiAlgID,unsigned int uiKeyBits,ECCrefPublicKey *pucPublicKey,ECCrefPrivateKey *pucPrivateKey);

/********************************************************************
 * 说明：产生会话密钥并用内部ECC公钥加密输出
 *	
 * 输入参数:void 			*hSessionHandle		会话句柄
 *			unsigned int	uiIPKIndex			密码设备内部存储的公钥索引
 *			unsigned int	uiKeyBits			指定的会话密钥长度
 *
 * 输出参数:ECCCipher 		*pucKey				会话密钥密文,使用时确保ECCCipher->C已申请内存,下同
 *			void 			**phKeyHandle		会话密钥句柄
 *
 * 返回值:0			成功
 *		非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_GenerateKeyWithIPK_ECC(void *hSessionHandle,unsigned int uiIPKIndex,unsigned int uiKeyBits,ECCCipher *pucKey,void **phKeyHandle);

/********************************************************************
 * 说明：产生会话密钥并用外部ECC公钥加密输出
 *
 * 输入参数:void 				*hSessionHandle	会话句柄
 *			unsigned int		uiKeyBits		指定的会话密钥长度
 *			unsigned int		uiAlgID			算法标识
 *			ECCrefPublicKey 	*pucPublicKey	外部ECC公钥结构
 *
 * 输出参数:ECCCipher 		*pucKey				密钥密文
 *			void 			**phKeyHandle		会话密钥句柄
 *
 * 返回值:	0			成功
 *			非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_GenerateKeyWithEPK_ECC(void *hSessionHandle,unsigned int uiKeyBits,unsigned int uiAlgID,ECCrefPublicKey *pucPublicKey,ECCCipher *pucKey,void **phKeyHandle);

/********************************************************************
 * 说明：导入会话密钥并用内部ECC私钥解密
 *
 * 输入参数:void 			*hSessionHandle		会话句柄
 *			unsigned int	uiISKIndex			密码设备内部存储加密私钥的索引值，对应于加密时的公钥
 *			ECCCipher 		*pucKey				密钥密文
 *
 * 输出参数:void 			**phKeyHandle		会话密钥句柄			
 *
 * 返回值:	0		成功
 *			非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_ImportKeyWithISK_ECC(void * hSessionHandle, unsigned int uiISKIndex,ECCCipher *pucKey,void **phKeyHandle);

/********************************************************************
 * 说明：生成密钥协商参数并输出	
 *	
 * 输入参数:void 			*hSessionHandle				会话句柄
 *			unsigned int	uiISKIndex					设备内部存储的加密私钥索引值，该私钥用于密钥协商
 *			unsigned int	uiKeyBits					指定的会话密钥长度
 *			unsigned char 	*pucSponsorID				发起方ID
 *			unsigned int	uiSponsorIDLength			发起方ID长度
 *
 * 输出参数:ECCrefPublicKey *pucSponsorPublicKey		发起方ECC公钥结构
 *			ECCrefPublicKey *pucSponsorTmpPublicKey		发起方ECC临时公钥结构
 *			void ** phAgreementHandle					协商句柄
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_GenerateAgreementDataWithECC(void *hSessionHandle,unsigned int uiISKIndex,unsigned int uiKeyBits,unsigned char *pucSponsorID,unsigned int uiSponsorIDLength,ECCrefPublicKey *pucSponsorPublicKey,ECCrefPublicKey *pucSponsorTmpPublicKey,void **phAgreementHandle);

/********************************************************************
 * 说明：计算会话密钥  
 *
 * 输入参数:void 			*hSessionHandle				会话句柄
 *			unsigned char 	*pucResponseID				响应方ID
 *			unsigned int	uiResponseIDLength			响应方ID长度
 *			ECCrefPublicKey *pucResponsePublicKey		响应方ECC公钥结构
 *			ECCrefPublicKey *pucResponseTmpPublicKey	响应方临时ECC公钥结构
 *			void 			*phAgreementHandle			协商句柄，用于计算会话密钥
 *
 * 输出参数:void 			**phKeyHandle				会话密钥句柄
 *	
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/		
WIN_DLL_EXPOERT int SDF_GenerateKeyWithECC(void *hSessionHandle,unsigned char *pucResponseID,unsigned int uiResponseIDLength,ECCrefPublicKey *pucResponsePublicKey,ECCrefPublicKey *pucResponseTmpPublicKey,void *hAgreementHandle,void **phKeyHandle);

/********************************************************************
 * 说明：生成协商数据并计算会话密钥
 *
 * 输入参数:void 			*hSessionHandle			会话句柄
 *			unsigned int	uiISKIndex				设备内部存储的加密私钥索引值，该私钥用于密钥协商
 *			unsigned int	uiKeyBits				指定的会话密钥长度
 *			unsigned char	*pucResponseID			响应方ID
 *			unsigned int	uiResponseIDLength		响应方ID长度								
 *			unsigned char 	*pucSponsorID			发起方ID
 *			unsigned int	uiSponsorIDLength		发起方ID长度
 *			ECCrefPublicKey *pucSponsorPublicKey	发起方ECC公钥结构
 *			ECCrefPublicKey *pucSponsorTmpPublicKey	发起方临时ECC公钥结构
 *
 * 输出参数:ECCrefPublicKey *pucResponsePublicKey	响应方ECC公钥结构
 *			ECCrefPublicKey *pucResponseTmpPublicKey响应方临时ECC公钥结构
 *			void ** phKeyHandle						会话密钥句柄
 *
 * 返回值:	0			成功
 *			非0		失败
 ********************************************************************/		
WIN_DLL_EXPOERT int SDF_GenerateAgreementDataAndKeyWithECC(void *hSessionHandle,unsigned int uiISKIndex,unsigned int uiKeyBits,unsigned char *pucResponseID,unsigned int uiResponseIDLength,unsigned char *pucSponsorID,unsigned int uiSponsorIDLength,ECCrefPublicKey *pucSponsorPublicKey,ECCrefPublicKey *pucSponsorTmpPublicKey,ECCrefPublicKey *pucResponsePublicKey,ECCrefPublicKey *pucResponseTmpPublicKey,void **phKeyHandle);

/********************************************************************
 * 说明：基于ECC算法的数字信封转换
 *
 * 输入参数:void 			*hSessionHandle		会话句柄
 *			unsigned int	uiKeyIndex			密码设备内存储的ECC密钥对索引
 *			unsigned int	uiAlgID				外部ECC公钥算法标识
 *			ECCrefPublicKey *pucPublicKey		外部ECC公钥结构
 *			ECCCipher 		*pucEncDataIn		输入的会话密钥密文
 *
 * 输出参数:ECCCipher 		*pucEncDataOut		输出的会话密钥密文
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/				
WIN_DLL_EXPOERT int SDF_ExchangeDigitEnvelopeBaseOnECC(void *hSessionHandle,unsigned int uiKeyIndex,unsigned int uiAlgID,ECCrefPublicKey *pucPublicKey,ECCCipher *pucEncDataIn,ECCCipher *pucEncDataOut);

/********************************************************************
 * 说明：生成会话密钥并用密钥加密密钥加密输出
 *
 * 输入参数:void 			*hSessionHandle	会话句柄
 *			unsigned int	uiKeyBits		指定产生的会话密钥长度
 *			unsigned int	uiAlgID			指定的对称加密算法标识
 *			unsigned int	uiKEKIndex		密码设备内部存储的密钥加密密钥的索引值
 *
 * 输出参数:unsigned char 	*pucKey			密钥密文
 *			unsigned int 	*puiKeyLength	密钥密文长度
 *			void 			**phKeyHANDLE	密钥句柄
 *			
 * 返回值:	0			成功
 *				非0		失败
 ********************************************************************/		
WIN_DLL_EXPOERT int SDF_GenerateKeyWithKEK(void *hSessionHandle,unsigned int uiKeyBits,unsigned int uiAlgID,unsigned int uiKEKIndex,unsigned char *pucKey,unsigned int *puiKeyLength,void **phKeyHandle);

/********************************************************************
 * 说明：导入会话密钥并用密钥加密密钥解密
 *
 * 输入参数:void 			*hSessionHandle		会话句柄
 *			unsigned int	uiAlgID				算法标识
 *			unsigned int	uiKEKIndex			密码设备内部存储的密钥加密密钥的索引值	
 *			unsigned char 	*pucKey				密钥密文
 *			unsigned int	puiKeyLength		密钥密文长度	
 *
 * 输出参数:void 			**phKeyHANDLE		密钥句柄
 *
 * 返回值:	0			成功
 *				非0		失败
 ********************************************************************/			
WIN_DLL_EXPOERT int SDF_ImportKeyWithKEK(void *hSessionHandle,unsigned int uiAlgID,unsigned int uiKEKIndex,unsigned char *pucKey,unsigned int puiKeyLength,void **phKeyHandle);

/********************************************************************
 * 说明：销毁会话密钥
 *
 * 输入参数:void *hSessionHandle	会话句柄
 *			void *hKeyHandle		输入的密钥句柄
 *
 * 输出参数:无			
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/		
WIN_DLL_EXPOERT int SDF_DestroyKey(void *hSessionHandle,void *hKeyHandle);

///////////////////////////////////////////////////////////////////////////////////////////////////
//扩展密钥管理类函数
///////////////////////////////////////////////////////////////////////////////////////////////////
/********************************************************************
 * 说明：导入明文会话密钥											
 *																			
 * 输入参数:		void *hSessionHandle		会话句柄
					unsigned char *pucKey		缓冲区指针，用于存放输入的数据明文
					unsigned int puiKeyLength	输入的数据明文长度

 * 输出参数:		void **phKeyHandle			返回的密钥句柄

 * 返回值:	0			成功
			非0			失败
*********************************************************************/			
WIN_DLL_EXPOERT int SDF_ImportKey(void *hSessionHandle,unsigned char *pucKey,unsigned int puiKeyLength,void **phKeyHandle);

/********************************************************************
* 说明：产生会话密钥		 (非标准接口，暂时不支持)									
*																			
* 输入参数:		void *hSessionHandle			会话句柄
					unsigned int uiKeyBits		指定产生的会话密钥长度
					unsigned int uiAlgID		指定算法标识

* 输出参数:		void **phKeyHandle			返回的密钥句柄

* 返回值:	0			成功
			非0			失败
*********************************************************************/		
WIN_DLL_EXPOERT int SDF_GenerateKey(void *hSessionHandle,unsigned int uiKeyBits,unsigned int uiAlgID,void **phKeyHandle);

/********************************************************************
* 说明：外部ECC公钥加密输出指定的会话密钥 (非标准接口，暂时不支持)
*																			
* 输入参数:		void *hSessionHandle					会话句柄
					void *hKeyHandle					指定的会话密钥句柄
					unsigned int uiAlgID				指定算法标识
					ECCrefPublicKey *pucPublicKey		输入的外部ECC公钥结构

* 输出参数:		ECCCipher *pucKey						缓冲区指针，用于存放返回的密钥密文

* 返回值:	0			成功
			非0			失败
*********************************************************************/	
WIN_DLL_EXPOERT int SDF_ExternalPublicKeyEncrypt_ECC(void *hSessionHandle,void *hKeyHandle,unsigned int uiAlgID,ECCrefPublicKey *pucPublicKey,ECCCipher *pucKey);

/********************************************************************
* 说明：内部KEK加密输出指定的会话密钥	 (非标准接口，暂时不支持)
*																			
* 输入参数:		void *hSessionHandle					会话句柄
					void *hKeyHandle					指定的会话密钥句柄
					unsigned int uiAlgID				指定算法标识
					unsigned int uiKEKIndex				密码设备内部存储密钥加密密钥的索引值

* 输出参数:		unsigend char *pucEncKey				缓冲区指针，用于存放返回的密钥密文
				unsigned int *puiEncKeyLength		    返回的密钥密文长度

* 返回值:	0			成功
			非0			失败
*********************************************************************/	
WIN_DLL_EXPOERT int SDF_InternalKeyEncrypt_KEK(void *hSessionHandle,void *hKeyHandle,unsigned int uiAlgID,unsigned char *pucIV,unsigned int uiKEKIndex,unsigned char *pucEncKey,unsigned int *puiEncKeyLength);

///////////////////////////////////////////////////////////////////////////////////////////////////
//非对称算法运算类函数		
///////////////////////////////////////////////////////////////////////////////////////////////////

/********************************************************************
 * 说明：外部公钥RSA运算
 *
 * 输入参数:void 				*hSessionHandle		会话句柄
 *			RSArefPublicKey		*pucPublicKey		外部RSA公钥
 *			unsigned char	    *pucDataInput		输入数据
 *			unsigned int 		uiInputLength		输入数据长度
 *		
 * 输出参数:unsigned char	    *pucDataOutput		输出数据
 *			unsigned int 		*uiOutputLength		输出数据长度
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/

WIN_DLL_EXPOERT int SDF_ExternalPublicKeyOperation_RSA(void *hSessionHandle, RSArefPublicKey *pucPublicKey,unsigned char *pucDataInput,unsigned int uiInputLength,unsigned char *pucDataOutput,unsigned int *uiOutputLength);

/********************************************************************
 * 说明：外部私钥RSA运算
 *
 * 输入参数:void 				*hSessionHandle		会话句柄
 *			RSArefPrivateKey	*pucPrivateKey		外部RSA私钥
 *			unsigned char	    *pucDataInput		输入数据
 *			unsigned int 		uiInputLength		输入数据长度
 *		
 * 输出参数:unsigned char	    *pucDataOutput		输出数据
 *			unsigned int 		*uiOutputLength		输出数据长度
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/

WIN_DLL_EXPOERT int SDF_ExternalPrivateKeyOperation_RSA(void *hSessionHandle,RSArefPrivateKey *pucPrivateKey,unsigned char *pucDataInput,unsigned int uiInputLength,unsigned char *pucDataOutput,unsigned int *uiOutputLength);


/********************************************************************
 * 说明：内部公钥RSA运算
 *
 * 输入参数:void 				*hSessionHandle		会话句柄
 *			unsigned int	    uiKeyIndex		    设备内公钥索引值
 *			unsigned char	    *pucDataInput		输入数据
 *			unsigned int 		uiInputLength		输入数据长度
 *		
 * 输出参数:unsigned char	    *pucDataOutput		输出数据
 *			unsigned int 		*uiOutputLength		输出数据长度
 *		
 * 输出参数:ECCSignature 	*pucSignature			输出的数据签名值
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/

WIN_DLL_EXPOERT int SDF_InternalPublicKeyOperation_RSA(void *hSessionHandle,unsigned int uiKeyIndex,unsigned char *pucDataInput,unsigned int uiInputLength,unsigned char *pucDataOutput,unsigned int *uiOutputLength);

/********************************************************************
 * 说明：内部私钥RSA运算
 *
 * 输入参数:void 				*hSessionHandle		会话句柄
 *			unsigned int	    uiKeyIndex		    设备内私钥钥索引值
 *			unsigned char	    *pucDataInput		输入数据
 *			unsigned int 		uiInputLength		输入数据长度
 *		
 * 输出参数:unsigned char	    *pucDataOutput		输出数据
 *			unsigned int 		*uiOutputLength		输出数据长度
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/

WIN_DLL_EXPOERT int SDF_InternalPrivateKeyOperation_RSA(void *hSessionHandle,unsigned int uiKeyIndex,unsigned char *pucDataInput,unsigned int uiInputLength,unsigned char *pucDataOutput,unsigned int *uiOutputLength);

/********************************************************************
 * 说明：外部密钥ECC签名
 *
 * 输入参数:void 				*hSessionHandle		会话句柄
 *			unsigned int		uiAlgID				算法标识
 *			ECCrefPrivateKey	*pucPrivateKey		外部ECC私钥数据
 *			unsigned char 		*pucData			输入数据
 *			unsigned int		uiDataLength		输入数据长度
 *		
 * 输出参数:ECCSignature 	*pucSignature			输出的数据签名值
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/

WIN_DLL_EXPOERT int SDF_ExternalSign_ECC(void *hSessionHandle,unsigned int uiAlgID,ECCrefPrivateKey *pucPrivateKey,unsigned char *pucData,unsigned int uiDataLength,ECCSignature *pucSignature);

/********************************************************************
 * 说明：外部密钥ECC验证
 *
 * 输入参数:void 			*hSessionHandle		会话句柄
 *			unsigned int		uiAlgID			算法标识
 *			ECCrefPublicKey		*pucPublicKey	外部ECC公钥结构
 *			unsigned char		*pucDataInput	输入数据
 *			unsigned int		uiInputLength	输入数据长度
 *			ECCSignature		*pucSignature	输入签名值
 *
 * 输出参数:无
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_ExternalVerify_ECC(void *hSessionHandle,unsigned int uiAlgID,ECCrefPublicKey *pucPublicKey,unsigned char *pucDataInput,unsigned int uiInputLength,ECCSignature *pucSignature);

/********************************************************************
 * 说明：内部密钥ECC签名
 *
 * 输入参数:void 			*hSessionHandle		会话句柄
 *			unsigned int	uiISKIndex			签名私钥索引					
 *			unsigned char 	*pucData			输入数据
 *			unsigned int	uiDataLength		输入数据长度
 *		
 * 输出参数:ECCSignature 	*pucSignature		输出的数据签名值
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_InternalSign_ECC(void *hSessionHandle,unsigned int uiISKIndex,unsigned char *pucData,unsigned int uiDataLength,ECCSignature *pucSignature);

/********************************************************************
 * 说明：内部密钥ECC验证
 *
 * 输入参数:void 			*hSessionHandle	会话句柄
 *			unsigned int	uiISKIndex		签名公钥索引
 *			unsigned char 	*pucData		输入数据
 *			unsigned int	uiDataLength	输入数据长度
 *			ECCSignature 	*pucSignature	输入数据的签名值
 *
 * 输出参数:无		
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_InternalVerify_ECC(void *hSessionHandle,unsigned int uiISKIndex,unsigned char *pucData,unsigned int uiDataLength,ECCSignature *pucSignature);

/********************************************************************
 * 说明：外部密钥ECC公钥加密
 *
 * 输入参数:void 			*hSessionHandle		会话句柄
 *			unsigned int	uiAlgID				算法标识
 *			ECCrefPublicKey *pucPublicKey		外部ECC公钥结构
 *			unsigned char 	*pucData			输入数据
 *			unsigned int	uiDataLength		输入数据长度
 *					
 * 输出参数:ECCCipher 		*pucEncData			输出数据的密文

 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_ExternalEncrypt_ECC(void *hSessionHandle,unsigned int uiAlgID,ECCrefPublicKey *pucPublicKey,unsigned char *pucData,unsigned int uiDataLength,ECCCipher *pucEncData);

/********************************************************************
 * 说明：外部密钥ECC私钥解密
 *
 * 输入参数:void 				*hSessionHandle		会话句柄
 *			unsigned int		uiAlgID				算法标识
 *			ECCrefPrivateKey	*pucPrivateKey		外部ECC私钥结构
 *			ECCCipher 			*pucEncData				输入密文
 *					
 * 输出参数:unsigned char 		*pucData			输出数据缓冲区
 *			unsigned int		*puiDataLength		输出数据长度
 *
 * 返回值:0		成功
 *		非0		失败
********************************************************************/
WIN_DLL_EXPOERT int SDF_ExternalDecrypt_ECC(void * hSessionHandle,unsigned int uiAlgID,ECCrefPrivateKey *pucPrivateKey,ECCCipher *pucEncData,unsigned char *pucData,unsigned int *puiDataLength);

/********************************************************************
 * 说明：内部公钥ECC加密 (非标准接口)
 *
 * 输入参数:void 				*hSessionHandle		会话句柄
 *			unsigned int	uiISKIndex			内部私钥索引
 *			unsigned int 	uiAlgID				算法标识，取值SGD_SM2或SGD_SM2_3
 *			unsigned char	*pucData			输入明文缓冲区
 *			unsigned int	*uiDataLength		输出数据
 *
 * 输出参数:
 *			ECCCipher		*pucEncData			输入密文数据
 *		
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_InternalEncrypt_ECC(void* hSessionHandle,unsigned int uiAlgID,unsigned int uiISKIndex,unsigned char *pucData,unsigned int uiDataLength, ECCCipher *pucEncData);


/********************************************************************
 * 说明：内部私钥ECC解密 (非标准接口)
 *
 * 输入参数:void 				*hSessionHandle		会话句柄
 *			unsigned int	uiISKIndex			内部私钥索引
 *			unsigned int 	uiAlgID				算法标识，取值SGD_SM2或SGD_SM2_3
 *			ECCCipher 		*pucEncData			输入密文数据
 *
 * 输出参数:unsigned char		*pucData			输出数据缓冲区
 *			unsigned int 	*puiDataLength		输出数据长度
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_InternalDecrypt_ECC(void* hSessionHandle,unsigned int uiAlgID,unsigned int uiISKIndex,ECCCipher *pucEncData,unsigned char *pucData,unsigned int *puiDataLength);

///////////////////////////////////////////////////////////////////////////////////////////////////
//对称算法运算类函数		
///////////////////////////////////////////////////////////////////////////////////////////////////
/********************************************************************
 * 说明：对称加密
 *
 * 输入参数:void 			*hSessionHandle		会话句柄
 *			void 			*hKeyHandle			指定的密钥句柄
 *			unsigned int	uiAlgID				算法标识
 *			unsigned char	*pucIV				缓冲区指针用来存放输入和返回的IV数据
 *			unsigned char	*pucData			输入数据明文
 *			unsigned int	uiDataLength		输入明文数据长度
 *					
 * 输出参数:ECCCipher		*pucEncData			输出数据的密文
 *			unsigned int	*puiEncDataLength	输出数据的密文长度
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_Encrypt(void *hSessionHandle,void *hKeyHandle,unsigned int uiAlgID,unsigned char *pucIV,unsigned char *pucData,unsigned int uiDataLength,unsigned char *pucEncData,unsigned int *puiEncDataLength);

/********************************************************************
 * 说明：对称解密
 *
 * 输入参数:void 			*hSessionHandle		会话句柄
 *			void			*hKeyHandle			指定的密句柄
 *			unsigned int	uiAlgID				算法标识
 *			unsigned char	*pucIV				缓冲区指针用来存放输入和返回的IV数据
 *			unsigned char	*pucEncData			输入的数据密文
 *			unsigned int	uiEncDataLength		输入密文数据长度
 *					
 * 输出参数:unsigned char	*pucData			输出数据的明文
 *			unsigned int	*puiDataLength		输出数据的明文长度
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_Decrypt(void *hSessionHandle,void *hKeyHandle,unsigned int uiAlgID,unsigned char *pucIV,unsigned char *pucEncData,unsigned int uiEncDataLength,unsigned char *pucData,unsigned int *puiDataLength);

/********************************************************************
 * 说明：计算MAC
 *
 * 输入参数:void			*hSessionHandle		会话句柄
 *			void			*hKeyHandle			指定的密句柄
 *			unsigned int	uiAlgID				算法标识
 *			unsigned char	*pucIV				缓冲区指针用来存放输入和返回的IV数据
 *			unsigned char	*pucData			输入的数据明文
 *			unsigned int	uiDataLength		输入明文数据长度
 *					
 * 输出参数:unsigned char	*pucMAC			输出数据的MAC
 *			unsigned int 	*puiMACLength		输出数据的MAC长度
 *
 * 返回值:0			成功
 *		非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_CalculateMAC(void *hSessionHandle,void *hKeyHandle,unsigned int uiAlgID,unsigned char *pucIV,unsigned char *pucData,unsigned int uiDataLength,unsigned char *pucMAC,unsigned int *puiMACLength);

///////////////////////////////////////////////////////////////////////////////////////////////////
//Hash运算类函数
///////////////////////////////////////////////////////////////////////////////////////////////////
/********************************************************************
 * 说明：杂凑运算初始化，杂凑运算第一步
 *
 * 输入参数:void 			*hSessionHandle		会话句柄
 *			unsigned int	uiAlgID				算法标识
 *			ECCrefPublicKey	*pucPublicKey		签名者公钥
 *			unsigned char	*pucID				签名者ID
 *			unsigned int	uiIDLength			签名者ID长度
 *	
 * 输出参数:无
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_HashInit(void *hSessionHandle,unsigned int uiAlgID,ECCrefPublicKey *pucPublicKey,unsigned char *pucID,unsigned int uiIDLength);

/********************************************************************
 * 说明：多包杂凑运算，杂凑运算第二步
 *
 * 输入参数:void			*hSessionHandle		会话句柄
 *			unsigned char	*pucData			待签名数据明文
 *			unsigned int	uiDataLength		待签名数据长度
 *					
 * 输出参数:无
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_HashUpdate(void *hSessionHandle,unsigned char *pucData,unsigned int uiDataLength);

/********************************************************************
 * 说明：杂凑运算结束
 *
 * 输入参数:void 			*hSessionHandle		会话句柄
 *					
 * 输出参数:unsigned char	*pucHash			返回的杂凑数据
 *			unsigned int	uiHashLength		杂凑数据长度
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_HashFinal(void *hSessionHandle,unsigned char *pucHash,unsigned int *puiHashLength);

///////////////////////////////////////////////////////////////////////////////////////////////////
//文件管理类函数
///////////////////////////////////////////////////////////////////////////////////////////////////
/********************************************************************
 * 说明：创建文件
 *
 * 输入参数:void 			*hSessionHandle		会话句柄
 *			unsigned char	*pucFileName		文件名称
 *			unsigned int	uiNameLen			文件名称长度
 *			unsigned int	uiFileSize			文件占用存储空间长度
 *	
 * 输出参数:无
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_CreateFile(void *hSessionHandle,unsigned char *pucFileName,unsigned int uiNameLen,unsigned int uiFileSize);
 
 /********************************************************************
 * 说明：读取文件
 *
 * 输入参数:void 			*hSessionHandle		会话句柄
 *			unsigned char	 *pucFileName		文件名
 *			unsigned int 	uiNameLen			文件名长度
 *			unsigned int	 uiOffset			读取文件偏移
 *			unsigned int	 *puiFileLength		需要读取文件长度
 *	
 * 输出参数:unsigned int *puiFileLength		实际读取文件长度
 *			unsigned char *pucBuffer		读取数据
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_ReadFile(void *hSessionHandle, unsigned char *pucFileName,unsigned int uiNameLen,unsigned int uiOffset,unsigned int *puiFileLength,unsigned char *pucBuffer);

 
 /********************************************************************
 * 说明：写入文件
 *
 * 输入参数:void 			*hSessionHandle		会话句柄
 *			unsigned char	*pucFileName		文件名
 *			unsigned int	uiNameLen			文件名长度
 *			unsigned int	uiOffset			写入文件偏移
 *			unsigned int	uiFileLength		写入数据长度
 *			unsigned char	*pucBuffer			写入数据
 *	
 * 输出参数:无
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_WriteFile(void *hSessionHandle,unsigned char *pucFileName,unsigned int uiNameLen,unsigned int uiOffset,unsigned int uiFileLength,unsigned char *pucBuffer);
 
 /********************************************************************
 * 说明：删除文件
 *
 * 输入参数:void 			*hSessionHandle		会话句柄
 *			unsigned char	*pucFileName		文件名
 *			unsigned int	uiNameLen			文件名长度
 *	
 * 输出参数:无
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_DeleteFile(void *hSessionHandle,unsigned char *pucFileName,unsigned int uiNameLen);



 /********************************************************************
 * 说明：业务保活接口，用于长时间无业务通信时可能被迫中断的场景，调用此接口用于维护通信正常,建议5分钟调用一次
 *
 * 输入参数:void 			*hSessionHandle		会话句柄
 *	
 * 输出参数:无
 *
 * 返回值:0		成功
 *		非0		失败
 ********************************************************************/
WIN_DLL_EXPOERT int SDF_LoopBack(void *hSessionHandle);





#ifdef __cplusplus
}
#endif

#endif //__SDCRYPTO_H__
