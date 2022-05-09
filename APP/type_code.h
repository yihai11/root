#ifndef __TYPE_CODE_H__
#define	__TYPE_CODE_H__


//-----------密钥管理-----------//
#define	MCUCMD_START		0x1000

#define	SD_TASK_GETDEVINFO						0x1001	//	获取设备信息
#define	SD_TASK_GETKEYACCRINGHT				0x1002	//	获取私钥权限
#define	SD_TASK_EXPSIGNPUB_RSA				0x1003	//	导出RSA签名公钥
#define	SD_TASK_EXPENCPUB_RSA					0x1004	//	导出RSA加密公钥
#define	SD_TASK_GENKEYPAIREXPORT_RSA	0x1005	//	产生RSA密钥对并输出
#define	SD_TASK_GENKEYWIHTIPK_RSA			0x1006	//	生成会话密钥并用内部RSA公钥加密输出
#define	SD_TASK_GENKEYWITHEPK_RSA			0x1007	//	生成会话密钥并用外部RSA公钥加密输出
#define	SD_TASK_IMPORTKEYWITHISK_RSA	0x1008	//	导入会话秘钥并用内部RSA私钥解密
#define	SD_TASK_EXPSIGNPUB_ECC				0x1009	//	导出ECC签名公钥
#define	SD_TASK_EXPENCPUB_ECC					0x100A	//	导出ECC加密公钥
#define	SD_TASK_GENKEYPAIREXPORT_ECC	0x100B	//	产生ECC非对称秘钥对并输出
#define	SD_TASK_GENKEYWIHTIPK_ECC			0x100C	//	生成会话密钥并用内部ECC公钥加密输出
#define	SD_TASK_GENKEYWITHEPK_ECC			0x100D	//	生成会话密钥并用外部ECC公钥加密输出
#define	SD_TASK_IMPORTKEYWITHISK_ECC	0x100E	//	导入会话秘钥并用内部ECC私钥解密
#define	SD_TASK_GENAGREEDATAWITHECC		0x100F	//	生成秘钥协商参数并输出
#define	SD_TASK_GENKEYWITHECC					0x1010	//	计算会话秘钥
#define	SD_TASK_GENAGREEANDKEYWITHECC	0x1011	//	产生协商参数并计算会话秘钥
#define	SD_TASK_GENKEYWIHTKEK					0x1012	//	生成会话秘钥并用秘钥加密秘钥加密输出
#define	SD_TASK_IMPORTKEYWITHKEK			0x1013	//	导入会话秘钥并用秘钥加密秘钥解密KEK
#define	SD_TASK_IMPORTSESSIONKEY			0x1014	//	明文导入/导出会话秘钥
#define	SD_TASK_DESTORYKEY						0x1015	//	销毁会话秘钥
#define	SD_TASK_EXTPUBKEYOPER_RSA			0x1016	//	外部公钥RSA运算
#define	SD_TASK_EXTPRIKEYOPER_RSA			0x1017	//	外部私钥RSA运算
#define	SD_TASK_INTPUBKEYOPER_RSA			0x1018	//	内部公钥RSA运算
#define	SD_TASK_INTPRIKEYOPER_RSA			0x1019	//	内部私钥RSA运算
#define	SD_TASK_INTSYMENC_AES					0x101A	//	AES内部秘钥加密
#define	SD_TASK_EXTSYMENC_AES					0x101B	//	AES外部秘钥加密
#define	SD_TASK_INTSYMENC_DES					0x101C	//	DES内部秘钥加密
#define	SD_TASK_EXTSYMENC_DES					0x101D	//	DES外部秘钥加密
#define	SD_TASK_INTSYMDEC_AES					0x101E	//	AES内部秘钥解密
#define	SD_TASK_EXTSYMDEC_AES					0x101F	//	AES外部秘钥解密
#define	SD_TASK_INTSYMDEC_DES					0x1020	//	DES内部秘钥解密
#define	SD_TASK_EXTSYMDEC_DES					0x1021	//	DES外部秘钥解密
#define	SD_TASK_CREATEFILE						0x1022	//	创建文件
#define	SD_TASK_READFILE							0x1023	//	读取文件
#define	SD_TASK_WRITEFILE							0x1024	//	写入文件
#define	SD_TASK_DELETEFILE						0x1025	//	删除文件
#define	SD_TASK_CLEARFILE							0x1026	//	清空文件区
#define	SD_TASK_ENUMFILE							0x1027	//	枚举文件
#define	SD_TASK_ADDUSER								0x1028	//	添加用户
#define	SD_TASK_USERLOGIN							0x1029	//	用户登录
#define	SD_TASK_USERLOGOUT						0x102A	//	用户登出
#define	SD_TASK_RESETPWD							0x102B	//	重置用户密码NULLNULLNULL
#define	SD_TASK_DELUSER								0x102C	//	删除操作员
#define	SD_TASK_RESETOPERATORPWD			0x102D	//	操作员口令重置（需要管理态）
#define	SD_TASK_GETLOGINSTATUS				0x102E	//	获取登录状态
#define	SD_TASK_CHGOCURPWD						0x102F	//	修改当前用户密码（不需要管理态）
#define	SD_TASK_CONFIGFILE						0x1030	//	设置最大单个文件大小和文件总数
#define	SD_TASK_BACKUPADMININFO				0x1031	//	备份管理员信息
#define	SD_TASK_RECOVERYADMININFO			0x1032	//	恢复管理员信息
#define	SD_TASK_BACKUPOPERATOR				0x1033	//	备份操作员（全部）
#define	SD_TASK_BACKUPKEY							0x1034	//	备份秘钥
#define	SD_TASK_BACKUPADMINLOGIN			0x1035	//	备份管理员登录
#define	SD_TASK_BACKUPADMINQUIT				0x1036	//	备份管理员登出
#define	SD_TASK_GETDEVICESTATE				0x1037	//	获取设备状态
#define	SD_TASK_RECOVEROPERATOR				0x1038	//	恢复操作员（所有）
#define	SD_TASK_CHECKSELF							0x1039	//	设备自检
#define	SD_TASK_CYCLECHECKSELF				0x103A	//	周期自检
#define	SD_TASK_GENDEVKEY							0x103B	//	生成设备秘钥
#define	SD_TASK_EXPORTDEVPUBKEY				0x103C	//	导出设备秘钥公钥
#define	SD_TASK_GENKEYUSERKEYPAIR			0x103D	//	生成用户密钥对
#define	SD_TASK_CHGKEYKEYPAIRPWD			0x103E	//	用户秘钥私钥访问口令修改
#define	SD_TASK_GENKEK								0x103F	//	生成秘钥保护密钥
#define	SD_TASK_DELKEK								0x1040	//	删除秘钥保护密钥
#define	SD_TASK_RECOVERKEY						0x1041	//	恢复秘钥
#define	SD_TASK_IMPORTKEYPAIR					0x1042	//	导入秘钥对
#define	SD_TASK_DESKEYPAIR						0x1043	//	销毁密钥对
#define	SD_TASK_GETKEYPAIRNUM					0x1044	//	查询密钥对数量
#define	SD_TASK_GETKEYPAIRSTAT				0x1045	//	查询密钥对状态
#define	SD_TASK_EXPORTKEYPAIR					0x1046	//	导出密钥对
#define	SD_TASK_GETUSERKEYCHK					0x1047	//	计算用户秘钥校验值
#define	SD_TASK_GETKEKCHK							0x1048	//	计算KEK校验值
#define	SD_TASK_IMPORTENCKEY					0x1049	//	导入加密秘钥
#define	SD_TASK_IMPORTKEK							0x104A	//	导入KEK
#define	SD_TASK_DEVKEKENC							0x104B	//	设备秘钥加密
#define	SD_TASK_DEVKEKDEC							0x104C	//	设备秘钥解密
#define	SD_TASK_DEVKEKSIGN						0x104D	//	设备秘钥签名
#define	SD_TASK_DEVKEKVERIFY					0x104E	//	设备秘钥验签
#define	SD_TASK_DESTORYDEV						0x104F	//	设备销毁
#define	SD_TASK_CLEARUKEY							0x1050	//	清空Ukey信息
#define	SD_MANU_UPDATEDEV							0x1051	//	设备升级
#define	SD_MANU_CLEARMCU							0x1052	//	擦除MCU
#define	SD_MANU_SETDEVINFO						0x1053	//	设置加密卡信息
#define	SD_MANU_CLEARUKEY							0x1054	//	清除UKEY
#define SD_TASK_HASHSHA1							0x1055	//	SHA1
#define SD_TASK_HASHSHA256						0x1056	//	SHA256
#define SD_TASK_EXCHDIGENVELOP_RSA		0x1057	//	基于RSA的数字信封
#define SD_TASK_EXCHDIGENVELOP_ECC		0x1058	//	基于SM2的数字信封
#define	SD_TASK_EXTPUBKEYENC_ECC			0x1059	//	外部公钥ECC加密运算
#define	SD_TASK_EXTPRIKEYDEC_ECC			0x105A	//	外部私钥ECC解密运算
#define	SD_TASK_INTPUBKEYENC_ECC			0x105B	//	内部公钥ECC加密运算
#define	SD_TASK_INTPRIKEYDEC_ECC			0x105C	//	内部私钥ECC解密运算
#define	SD_TASK_GOTOFACTORY						0x105D	//	恢复出厂态
#define	SD_TASK_INTPRIKEYSIGN_ECC			0x105E	//	内部私钥ECC签名
#define	SD_TASK_INTPUBKEYVERI_ECC			0x105F	//	内部公钥ECC验签
#define	SD_TASK_EXTPRIKEYSIGN_ECC			0x1060	//	外部私钥ECC签名
#define	SD_TASK_EXTPUBKEYVERI_ECC			0x1061	//	外部公钥ECC验签
#define	SD_TASK_SHA384								0x1062	//	SHA384
#define	SD_TASK_SHA512								0x1063	//	SHA512
#define	SD_TASK_INTSYMENC_SM1					0x1064	//	SM1内部秘钥加密
#define	SD_TASK_INTSYMDEC_SM1					0x1065	//	SM1内部秘钥解密
#define	SD_TASK_EXTSYMENC_SM1					0x1066	//	SM1外部秘钥加密
#define	SD_TASK_EXTSYMDEC_SM1					0x1067	//	SM1外部秘钥解密
#define	SD_TASK_GETMUCVERSION					0x1068	//	获取MCU版本
#define	SD_TASK_GOTOFACTORY_NOADMIN		0x1069	//	恢复出厂态无管理员
#define	MCUCMD_END		0x1070


//#define SDR_UNKNOWERR					0x0001						//未知错误
//#define SDR_NOTSUPPORT				0x0002						//不支持的接口调用
//#define SDR_COMMFAIL					0x0003						//与设备通信失败
//#define SDR_HARDFAIL					0x0004						//运算模块无响应
//#define SDR_OPENDEVICE				0x0005						//打开设备失败
//#define SDR_OPENSESSION				0x0006						//创建会话失败
//#define SDR_PARDENY						0x0007						//无私钥使用权陿
#define SDR_ALGNOTSUPPORT			0x0009						//不支持的算法调用
#define SDR_KEYNOTEXIST				0x0008							//不存在的密钥调用
//#define SDR_ALGMODNOTSUPPORT	0x000A						//不支持的算法模式调用
#define SDR_PKOPERR						0x000B						//公钥运算失败
#define SDR_SKOPERR						0x000C						//私钥运算失败
#define SDR_SIGNERR						0x000D						//签名运算失败
#define SDR_VERIFYERR					0x000E						//验证签名失败
//#define SDR_SYMOPERR					0x000F						//对称算法运算失败
//#define SDR_STEPERR						0x0010						//多步运算步骤错误
#define SDR_FILESIZEERR				0x0011						//文件长度超出限制
#define SDR_FILENOEXIST				0x0012						//指定的文件不存在
#define SDR_FILEOFSERR 				0x0013						//文件起始位置错误
#define SDR_KEYTYPEERR 				0x0014						//密钥类型错误
#define SDR_KEYERR 						0x0015						//密钥对错误
#define SDR_ENCDATAERR				0x0016						//ECC加密数据错误
#define SDR_RANDERR						0x0017						//随机数产生失败
//#define SDR_PRKRERR						0x0018						//私钥使用权限获取失败
//#define SDR_MACERR 						0x0019						//MAC运算失败
//#define SDR_FILEEXISTS				0x001A						//指定文件已存在
#define SDR_FILEWERR					0x001B						//文件写入失败
#define SDR_NOBUFFER					0x001C						//存储空间不足
#define SDR_INARGERR					0x001D						//输入参数错误
//#define SDR_OUTARGERR 				0x001E						//输出参数错误


//错误码
#define ERR_UKEY   0X1000        //Ukey类错误
#define ERR_DVES   0X2000        //加密卡类错误
#define ERR_MANG   0X3000        //管理类错误
#define ERR_CIPH   0X4000        //密码类错误
#define ERR_COMM   0X5000        //常规错误
#define ERR_TEST 	 0X0500        //自检类错误
//0X1000  //Ukey类错误
#define ERR_UKEY_CONNECT        ERR_UKEY + 0X01    //连接Ukey失败
#define ERR_UKEY_DEVAUTH        ERR_UKEY + 0X02    //非法Ukey，非制定类型Ukey
#define ERR_UKEY_NOFREE         ERR_UKEY + 0X03    //当前Ukey不是空白Ukey，无法创建指定Ukey
#define ERR_UKEY_APP            ERR_UKEY + 0X04    //Ukey应用操作失败，管理操作员和备份应用
#define ERR_UKEY_FILE           ERR_UKEY + 0X05    //Ukey文件操作错误
//#define ERR_UKEY_SERKEY         ERR_UKEY + 0X06    //Ukey 序列号获取错误
#define ERR_UKEY_PIN            ERR_UKEY + 0X07    //Ukey PIN 校验错误
#define ERR_UKEY_CHANGEPIN      ERR_UKEY + 0X08    //修改 Ukey PIN 错误
//#define ERR_UKEY_DECDATA        ERR_UKEY + 0X09    //Ukey数据解密失败
#define ERR_UKEY_KIND           ERR_UKEY + 0X0a    //Ukey类型错误，当前Ukey非所要的身份类型
#define ERR_UKEY_FIELD          ERR_UKEY + 0X0b    //Ukey域错误，非当前管理域的Ukey
//#define	ERR_UKEY_TIMEOUT			  ERR_UKEY + 0X0c		 //Ukey超时
#define	ERR_UKEY_LOCK			  		ERR_UKEY + 0X0d		 //Ukey锁定
#define	ERR_UKEY_VOID			  		ERR_UKEY + 0X0e		 //Ukey未识别或为空


//0X2000	//加密卡设备状态错误
#define ERR_DVES_INIT           ERR_DVES + 0X01     //创建管理员时，设备状态错
#define ERR_DVES_INIT_BACKUP    ERR_DVES + 0X02     //恢复数据时,该数据已存在
#define ERR_DVES_OPER           ERR_DVES + 0X03     //创建删除操作员时，设备状态非管理态
#define ERR_DVES_USERLOGIN      ERR_DVES + 0X04     //用户登录时，设备状态错误
//#define ERR_DVES_BADMLOGIN      ERR_DVES + 0X05     //备份管理员登录，设备状态错误
//#define ERR_DVES_BACKUPUKEY     ERR_DVES + 0X06     //备份数据时，设备状态非管理态
//#define ERR_DVES_RECOVERUKEY    ERR_DVES + 0X07     //恢复备份数据时，设备状态错误
//#define ERR_DVES_CLEANUP        ERR_DVES + 0X08     //擦除管理数据时，设备状态错误
//#define ERR_DVES_DESTORY        ERR_DVES + 0X09     //销毁管理数据时，设备状态错误
#define ERR_DVES_USERLOGOUT     ERR_DVES + 0X0a     //退出用户登录时，设备状态错误
//#define ERR_DVES_USERPOLICY     ERR_DVES + 0X0b     //用户管理策略时，设备状态错误
//#define ERR_DVES_ERTUKEY        ERR_DVES + 0X0C     //重置Ukey时，设备状态错误,主密钥为NULL
//#define	ERR_DVES_BACKUPUSR			ERR_DVES + 0x0D			//备份用户数据时，设备非管理态
#define	ERR_DVES_WORKSTATE			ERR_DVES + 0x0E			//设备非工作态，权限错误
#define	ERR_DVES_MANGSTATE			ERR_DVES + 0x0F			//设备非管理态，权限错误
#define	ERR_DVES_FACTYSTATE			ERR_DVES + 0x10			//设备非出厂态，权限错误
#define	ERR_DVES_STATETODO			ERR_DVES + 0x11			//设备状态，不允许该操作
#define	ERR_DVES_ENSHIELD				ERR_DVES + 0x12			//设备开盖保护设置重复，开盖保护已经开启
#define	ERR_DVES_DISSHIELD			ERR_DVES + 0x13			//设备开盖保护设置重复，开盖保护已经关闭


//0X3000    //管理类错误
#define ERR_MANG_PINLEN		      ERR_MANG + 0X01     //PIN 口令长度错误
#define ERR_MANG_PINCHECK		    ERR_MANG + 0X02     //PIN 口令校验错误
#define ERR_MANG_ADMNUM 	    	ERR_MANG + 0X03     //创建管理员，超过策略上限
#define ERR_MANG_RELOGIN	    	ERR_MANG + 0X04     //管理员UKEY，重复登录。该Ukey已经登录过了
//#define ERR_MANG_AUTHKEY 	    	ERR_MANG + 0X05     //设备认证错误
#define ERR_MANG_BACKLOGIN   		ERR_MANG + 0X06     //登录的备份管理员与第一次登录的非同一管理域
//#define ERR_MANG_BAUKEYANT	    ERR_MANG + 0X07     //备份Ukey认证错误
//#define ERR_MANG_NUM 	        	ERR_MANG + 0X08     //创建管理员，超过策略上限
//#define ERR_MANG_USERPOLICY 	  ERR_MANG + 0X09     //设置管理策略时，策略值不符合规定
//#define ERR_UPFI_SERNU 	        ERR_MANG + 0X0A     //在线更新固件，包序号错误
//#define ERR_UPFI_FPGAFL	        ERR_MANG + 0X0B     //在线更新固件，写FPGA FLASH错误
//#define ERR_UPFI_ARMFL 	        ERR_MANG + 0X0C     //在线更新固件，写ARM FLASH错误
//#define ERR_DELE_UKEYNULL 	    ERR_MANG + 0X0D     //Ukey为空白Ukey，不需要初始化。
//#define ERR_STAU_MANG 	        ERR_MANG + 0X0E     //设置成管理态出错，主密钥为空。
//#define ERR_STAU_READY 	        ERR_MANG + 0X0f     //设置成就绪态出错，主密钥为空。
//#define ERR_STAU_MANGDECKEY 	  ERR_MANG + 0X11     //设置成管理态出错，解密设备密钥对私钥错误。
#define	ERR_MANG_RE_ADD					ERR_MANG + 0x12			//创建用户时该用户序列号已存在
#define ERR_MANG_ERROR_USR			ERR_MANG + 0x13		  //登录或删除不存在的用户
#define ERR_MANG_DEL_ADMIN			ERR_MANG + 0x14			//删除管理员错误
#define ERR_MANG_RECOVER_LEN		ERR_MANG + 0x15			//恢复备份时，数据或长度异常
#define ERR_MANG_AUTHUSR 	    	ERR_MANG + 0X16     //用户认证错误
#define ERR_MANG_CHECKCODE 	    ERR_MANG + 0X17     //完整性校验码错误
#define ERR_MANG_BACKAUTH 	    ERR_MANG + 0X18     //备份管理员登录少于两个

//0X4000    //密码类错误
#define ERR_CIPN_SKEYFULL     	ERR_CIPH + 0X01    //会话密钥已满
#define ERR_CIPN_SKEYINFPGA    	ERR_CIPH + 0X02    //会话写入FPGA失败
#define ERR_CIPN_SKEYINDEXERR   ERR_CIPH + 0X03    //会话密钥句柄对应索引值非法
#define ERR_CIPN_SKEYINDEXNULL  ERR_CIPH + 0X04    //会话密钥句柄对应索引值无密钥
#define ERR_CIPN_SKEYLEN    	ERR_CIPH + 0X05    //会话密钥数据长度错误
//0X0000
#define ERR_CIPN_INDEXLEN       SDR_INARGERR	//ERR_CIPH + 0X06    //参数大小长度错误
#define ERR_CIPN_GENRANDOM      SDR_RANDERR		//ERR_CIPH + 0X07    //生成随机数错误
#define ERR_CIPN_FPGASM2ENCIN   SDR_ENCDATAERR//ERR_CIPH + 0X08    //FPGAsm2内部加密错误
#define ERR_CIPN_FPGASM2DECIN   SDR_ENCDATAERR//ERR_CIPH + 0X09    //FPGAsm2内部加密错误
//#define ERR_CIPN_FPGASM2ENCIN   ERR_CIPH + 0X08    //FPGAsm2内部加密错误
//#define ERR_CIPN_FPGASM2DECIN   ERR_CIPH + 0X09    //FPGAsm2内部解密错误
#define ERR_CIPN_RSAPUBKEYOP    SDR_PKOPERR//ERR_CIPH + 0X11    //RSA公钥操作错误
#define ERR_CIPN_RSAPRIKEYOP    SDR_SKOPERR//ERR_CIPH + 0X12    //RSA私钥操作错误

//#define ERR_CIPN_FPGASM4        ERR_CIPH + 0X0a    //FPGAsm4内部运算错误
#define ERR_CIPN_GENSM2KEY   		ERR_CIPH + 0X0b    //生成SM2密钥对
#define ERR_CIPN_GETSM2KEY   		ERR_CIPH + 0X0c    //获取SM2密钥错误
#define ERR_CIPN_GENRSAKEY   		ERR_CIPH + 0X0d    //生成RSA密钥对MCU算法失败
#define ERR_CIPN_GETRSAKEY      ERR_CIPH + 0X0e    //读取RSA密钥失败
#define ERR_CIPN_EXPRSAPUBKEY   ERR_CIPH + 0X0f    //导出RSA公钥失败
#define ERR_CIPN_RSAINLEN       ERR_CIPH + 0X10    //RSA长度输入错误

#define ERR_CIPH_DECMAIN 	      ERR_CIPH + 0X1f    //解密主密钥分量错误,或主密钥解密失败。
//#define	ERR_CIPN_ERR_AUTH			  ERR_CIPH + 0x20		 //UKEY认证密钥错误
#define	ERR_CIPN_RANDOM 			  ERR_CIPH + 0x21		 //获取随机数错误
#define	ERR_CIPN_DECDATA 			  ERR_CIPH + 0x22		 //解密数据错误
#define	ERR_CIPN_CREATEFILE 	  ERR_CIPH + 0x23		 //创建（密钥）文件错误
#define	ERR_CIPN_OPENKEYFILE 		ERR_CIPH + 0x24		 //打开（密钥）文件错误
#define	ERR_CIPN_DELKEYFILE 		ERR_CIPH + 0x25		 //删除（密钥）文件错误
#define	ERR_CIPN_READKEYFILE 		ERR_CIPH + 0x26		 //读  （密钥）文件错误
#define	ERR_CIPN_WRITKEYFILE 		ERR_CIPH + 0x27		 //写  （密钥）文件错误
#define	ERR_CIPN_DECKEYFILE 		ERR_CIPH + 0x28		 //解密（密钥）文件错误
#define	ERR_CIPN_ENCKEYFILE 		ERR_CIPH + 0x29		 //加密（密钥）文件错误
#define	ERR_CIPN_USRKEYEXIT 		ERR_CIPH + 0x30		 //密钥索引已经存在错误
#define	ERR_CIPN_USRKEYNOEXIT 	ERR_CIPH + 0x31		 //密钥索引不存在错误
#define	ERR_CIPN_USRKEYERR 		  ERR_CIPH + 0x32		 //密钥索引非法
#define	ERR_CIPN_SM2ARGENKEY 	  ERR_CIPH + 0x33	   //sm2协商计算密钥错误
#define	ERR_CIPN_SM2ARGEEXCHE 	ERR_CIPH + 0x34	   //FPGA协商交换函数错误

//0X5000  //常规通用错误
//0X0000
#define	ERR_COMM_MALLOC         SDR_NOBUFFER//ERR_COMM + 0x01    //内存申请失败
#define	ERR_COMM_INPUT          SDR_INARGERR//ERR_COMM + 0x02    //参数数据错误
#define	ERR_COMM_INDATA         ERR_COMM + 0x03    //内部数据异常
#define	ERR_COMM_INPUTLEN       ERR_COMM + 0x04    //长度数据错误
#define	ERR_COMM_OUTTIME        ERR_COMM + 0x05    //超时

//0X0500  //自检类错误
#define	ERR_TEST_RANDOM       ERR_TEST + 0x01    //随机数自检失败
#define	ERR_TEST_SM1          ERR_TEST + 0x02    //SM1算法自检失败
#define	ERR_TEST_SM2         	ERR_TEST + 0x03    //SM2算法自检失败
#define	ERR_TEST_SM3       		ERR_TEST + 0x04    //SM3算法自检失败
#define	ERR_TEST_SM4        	ERR_TEST + 0x05    //SM4算法自检失败
#define	ERR_TEST_RSA        	ERR_TEST + 0x06    //RSA算法自检失败
#define	ERR_TEST_FWAREDATA    ERR_TEST + 0x07    //固件完整性检测
#define	ERR_TEST_USRDATA    	ERR_TEST + 0x08    //用户数据完整性检测
#define	ERR_TEST_KEYDATA    	ERR_TEST + 0x09    //密钥完整性测试失败
#define	ERR_TEST_ELSE   		ERR_TEST + 0x0A    //其他自检错误
#endif
