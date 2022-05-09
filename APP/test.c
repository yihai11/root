#include "test.h"
#include "pwm.h"
#include "config.h"
#include "common.h"
extern FlashData eFlash;
uint8_t ArgFlag = 0;
#define PRINT_TEST 2
void StrToHex(unsigned char *hex,char *str)
{
	unsigned int i, n, len = strlen(str);

	for(i = 0; i < len; i+=2)
	{
		sscanf(str + i, "%2X", &n);
		hex[i / 2] = n;
	}
	//hex[i/2] = '\0';
}

#define ERR_ST  "!!!!!!!!!!!!!"
#define NOR_ST  "-------------"
#define TAG_ST  "*************"

void printTag(uint8_t state,uint8_t error,const char * str)
{
	if(error && END == state){
		print(PRINT_TEST,ERR_ST);
	}
	else{
		print(PRINT_TEST,NOR_ST);
	}
	print(PRINT_TEST,"%-16s",str);
	switch(state){
		case START:
			print(PRINT_TEST,"测试开始");
			print(PRINT_TEST,NOR_ST);
			break;
		case RETRY:
			print(PRINT_TEST,"测试等待");
			print(PRINT_TEST,NOR_ST);
			break;
		case INVALID:
			print(PRINT_TEST,"  不支持");
			print(PRINT_TEST,NOR_ST);
			break;
		case END:
			if(error){
				print(PRINT_TEST,"测试失败");
				print(PRINT_TEST,ERR_ST);
			}
			else{
				print(PRINT_TEST,"测试成功");
				print(PRINT_TEST,NOR_ST);
			}
			break;
	}
	
	print(PRINT_TEST,"\r\n");
}
int eeprom_task()
{
	uint8_t error=0;
//	BaseType_t er=pdFALSE;
	error = i2c_test();
	if(error){
		print(PRINT_TEST,"错误代码：%d \r\n",error);
		return error;
	} 
	return 0;
}

//注意eflash存储数据擦写时避开程序段
#define EFlashTestAddr         (EFLASH_BASE_ADDR + 0x0007EE00) //EFLASH_DATA_ADDR			0x7F000		//存储设备信息的地址 前一页
int eflash_task()
{
	uint8_t error=0;
//	BaseType_t er=pdFALSE;

	error=eflash_page_erase_test(EFlashTestAddr);

	if(error){
		print(PRINT_TEST,"错误代码：%d \r\n",error);
		return error;
	}
	return 0;
}
	
int spiflash_task()
{
	uint8_t error=0;
//	BaseType_t er=pdFALSE;

	error=spim_nflash_all_x1();

	if(error){
		return error;
	}
	return 0;
}
int MIM_task()
{
	uint8_t error=0;
//	BaseType_t er=pdFALSE;

	error = mem_test();

	if(error){
		return error;
	}
		return 0;
}

int USB_enum_task()
{
//	uint8_t usbstate=0;
	uint8_t error=0;
//	BaseType_t er=pdFALSE;
	sl811_os_init();
	for(uint8_t i=0;i<5;i++)
	{
		
		if(!Slave_Detach()){
			error=sl811_disk_init();
			if(error){
				printTag(RETRY,error,"USB");
				vTaskDelay(1000);
				continue;
			}
			break;
		}
		else{
			printTag(RETRY,error,"USB");
			vTaskDelay(1000);
			//return 1;
		}
	}
	
	return error;
}
int SL811_task()
{
//	uint8_t usbstate=0;
	uint8_t error=0;
//	BaseType_t er=pdFALSE;

	error=SL811_MemTest();

	if(error){
		return error;
	}
	return 0;
}	

int FPGA_task()
{
//	uint8_t usbstate=0;
	uint8_t error=0;
//	BaseType_t er=pdFALSE;

	error=fpga_check_reg();

	if(error){
		return error;
	}
	return 0;
}	
void spiflash_erase(uint16_t sector_num )
{
	uint16_t i = 0;
	for(;i<sector_num;i++)
		flash_erase_sector(i);
}
uint32_t mem_test(void)
{
	UINT32 i, result=0;
	UINT32 wdata[8];
	UINT32 rdata[8];
	UINT8  *buff8;
	UINT16 *buff16;
	UINT32 *buff32;

	for(i = 0; i < 8; i++)
	{
		wdata[i] = 0x01234567;
		rdata[i] = 0;
	}
	
	//printfS("write(16bit) test\r\n");
	buff16 = (UINT16 *)wdata;
	for(i = 0; i < 16; i++)
	{
		MEM0_PORT16(2 * i) = buff16[i];
	}
	
	//printfS("read(16bit) test \r\n");
	buff16 = (UINT16 *)rdata;
	for(i = 0; i < 16; i++)
	{
		buff16[i] = MEM0_PORT16(2 * i);
	}

	for(i = 0; i < 8; i++)
	{
		if(rdata[i] != wdata[i])
		{
			return -1;
			//printfS("error, rdata[%d]=0x%x, wdata[%d]=0x%x\r\n", i, rdata[i], i, wdata[i]);
		}
	}
	return 0;
}
//static void test_eflahs_WR(void)
//{
//	int i=0;
//	//*(uint32_t *)eFlash.MAINKEY_MCU=0x12345678;
//	for(;i<16;i++)
//		eFlash.MAINKEY_MCU[i]=0x15;
//	WriteFlashData();
//	ReadeFlashData(&eFlash);
//}


FRESULT fatfs_write_test(	FIL* fp)
{
	FRESULT res;
	unsigned char  i=0;
	unsigned char buff[10];
	for(;i<10;i++)
		buff[i]=0x12;
	UINT btw=10;
	UINT bw=0;
	res = f_write (fp,buff,btw,&bw);
	return res;
}
FRESULT fatfs_read_test(FIL* fp,void* buff)
{
	FRESULT res;
	UINT btw=10;
	UINT bw=0;
	res = f_read(fp,buff,btw,&bw);
	return res;
}
//FRESULT fatfs_test(FIL* fp,void* buff)
//{
////	FRESULT res;
////	res=f_open(fp,"1:testspiflash.txt",FA_OPEN_EXISTING|FA_WRITE);
////	print(PRINT_TEST,"open state is %d\r\n",res);
////	res = fatfs_write_test(fp);
////	print(PRINT_TEST,"write state is %d\r\n",res);
////	res= f_close(fp);
////	print(PRINT_TEST,"close state is %d\r\n",res);
////	
////	res=f_open(fp,"1:testspiflash.txt",FA_OPEN_EXISTING|FA_READ);
////	print(PRINT_TEST,"open state is %d\r\n",res);
////	res = fatfs_read_test(fp,buff);
////	print(PRINT_TEST,"read state is %d\r\n",res);
////	res= f_close(fp);
////	print(PRINT_TEST,"close state is %d\r\n",res);
//	return 0;
//}


int gwd_test_memcpy(void){
	
	uint32_t len = 4096;
	
	uint32_t fornum = 1024;
	uint8_t to[4096] = {0};
	uint32_t t_cont = 0;
	uint32_t t_cont1 = 0;
	uint32_t t_cont0 = xTaskGetTickCount();
	for(int c=0;c<fornum;c++){
		memcpy(to, (unsigned char *)0x60802000,len);
		//memcpy(to, (unsigned char *)0x60000000,len);
		memcpy((unsigned char *)0x60802000,to, len);
	}
	t_cont1 = xTaskGetTickCount();
	t_cont = t_cont1-t_cont0;
	
//	print(PRINT_TEST,"TickCount is %d\r\n",t_cont);
//	print(PRINT_TEST,"len is %d\r\n",len);
//	print(PRINT_TEST,"fornum is %d\r\n",fornum);
//	print(PRINT_TEST,"memcpy is %u KB/s\r\n",(len*fornum)/t_cont);
	return 0;
}

int power_on_testspiflash(void){
	return spi_testid();
}

int power_on_testsram(void){
//	uint8_t read,write;
//	uint32_t SRAMADDBEGIN = 0x60000000;
//	uint32_t SRAMADDEND 	= 0x60100000;
//	uint32_t SRAMlen = SRAMADDEND-SRAMADDBEGIN;
//	for(int i=0;i<SRAMlen;i++){
//		write = i;
//		*(uint8_t*)(SRAMADDBEGIN+i) = write;
//		read = *(uint8_t*)(SRAMADDBEGIN+i);
//		if(write != read){
//			return -1;
//		}
//	}
	return 0;	
}

//FPGA密钥设置
int FPGAsetgetkey(void){
	int ret;
	SM2PublicKey pkA;
	SM2PrivateKey skA;
	SM2PublicKey pkB;
	SM2PrivateKey skB;
	//私钥 "\x17\xB3\x7F\xA4\xB0\x9B\x4D\x5A\xC2\xE0\xFE\xE9\xF4\x0F\x3B\x8D\x47\x5D\xE3\xB4\xBC\x39\xF1\xFB\xF4\x6A\x6F\x37\x33\xB7\xC2\xF1"		
	memcpy(skA.K,	"\x17\xB3\x7F\xA4\xB0\x9B\x4D\x5A\xC2\xE0\xFE\xE9\xF4\x0F\x3B\x8D\x47\x5D\xE3\xB4\xBC\x39\xF1\xFB\xF4\x6A\x6F\x37\x33\xB7\xC2\xF1",32);
	//公X  "\x14\xD3\xEE\x92\x17\xEE\x17\x38\x2C\xB0\x68\x0B\x21\x3A\x44\xCA\xC9\xF2\x43\xE8\x35\xDD\x33\xC7\x7D\x75\xB8\xF9\x82\xDE\xC4\x68"			
	memcpy(pkA.x,	"\x14\xD3\xEE\x92\x17\xEE\x17\x38\x2C\xB0\x68\x0B\x21\x3A\x44\xCA\xC9\xF2\x43\xE8\x35\xDD\x33\xC7\x7D\x75\xB8\xF9\x82\xDE\xC4\x68",32);
	//公Y  "\x46\x24\x0A\x6E\xAB\xDB\x6D\xBA\xED\x3A\x19\x75\xCA\x56\x4B\xCD\xA1\x43\x62\xCD\xF9\xC4\x5A\xC2\x77\x29\xB0\x23\x25\x0E\x75\x37"
	memcpy(pkA.y,	"\x46\x24\x0A\x6E\xAB\xDB\x6D\xBA\xED\x3A\x19\x75\xCA\x56\x4B\xCD\xA1\x43\x62\xCD\xF9\xC4\x5A\xC2\x77\x29\xB0\x23\x25\x0E\x75\x37",32);

	ret = fpga_sm2_setkey(3, &skA, &pkA);
	memset(&skB,0,32);
	memset(&pkB,0,64);
	//ret = fpga_sm2_1510_getkey(3, &skA, &pkA);
	
	fpga_sm2_setkey(256, &skA, &pkA);
	fpga_sm2_delkey(256);
	fpga_sm2_setkey(256, &skA, &pkA);
	memset(&skB,0,32);
	memset(&pkB,0,64);
	fpga_sm2_getkey(256, &skB, &pkB);
//	printf("1\n");
//	printf_buff_byte((uint8_t *)&skB,32);
//	printf_buff_byte((uint8_t *)&pkB,64);
	fpga_sm2_getkey(256, &skB, &pkB);
//	printf("2\n");
//	printf_buff_byte((uint8_t *)&skB,32);
//	printf_buff_byte((uint8_t *)&pkB,64);
return ret;
}


//sm2加密测试
int	mcu_testsm2enc(void){
	int ret = 0;
	SM2PublicKey pkA;
	SM2PrivateKey skA;
	//私钥 "\x17\xB3\x7F\xA4\xB0\x9B\x4D\x5A\xC2\xE0\xFE\xE9\xF4\x0F\x3B\x8D\x47\x5D\xE3\xB4\xBC\x39\xF1\xFB\xF4\x6A\x6F\x37\x33\xB7\xC2\xF1"		
	memcpy(skA.K,"\x17\xB3\x7F\xA4\xB0\x9B\x4D\x5A\xC2\xE0\xFE\xE9\xF4\x0F\x3B\x8D\x47\x5D\xE3\xB4\xBC\x39\xF1\xFB\xF4\x6A\x6F\x37\x33\xB7\xC2\xF1",32);
	//公X  "\x14\xD3\xEE\x92\x17\xEE\x17\x38\x2C\xB0\x68\x0B\x21\x3A\x44\xCA\xC9\xF2\x43\xE8\x35\xDD\x33\xC7\x7D\x75\xB8\xF9\x82\xDE\xC4\x68"			
	memcpy(pkA.x,"\x14\xD3\xEE\x92\x17\xEE\x17\x38\x2C\xB0\x68\x0B\x21\x3A\x44\xCA\xC9\xF2\x43\xE8\x35\xDD\x33\xC7\x7D\x75\xB8\xF9\x82\xDE\xC4\x68",32);
	//公Y  "\x46\x24\x0A\x6E\xAB\xDB\x6D\xBA\xED\x3A\x19\x75\xCA\x56\x4B\xCD\xA1\x43\x62\xCD\xF9\xC4\x5A\xC2\x77\x29\xB0\x23\x25\x0E\x75\x37"
	memcpy(pkA.y,"\x46\x24\x0A\x6E\xAB\xDB\x6D\xBA\xED\x3A\x19\x75\xCA\x56\x4B\xCD\xA1\x43\x62\xCD\xF9\xC4\x5A\xC2\x77\x29\xB0\x23\x25\x0E\x75\x37",32);
	//标准明文  
	unsigned char M0[16] = {0};
	memcpy(M0,"\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10",16);
	//标准密文  
	unsigned char C0[SM2_CIPHER_LEN(16)];
	memcpy(C0,"\x7E\xF1\x9A\xFC\x17\xE0\x56\xBD\x7A\xD1\xA4\x65\x16\x32\x29\x55\x63\xBE\x0C\xE1\x5F\x7F\x56\xCD\x4B\xD4\x00\xEF\xA5\x5B\x9B\x73\xC7\xF0\x33\x3E\x30\x70\x39\x2A\x48\x48\xBC\xA6\xC3\x33\x34\xF2\xC1\x89\x9E\x11\x20\x00\x5B\xD1\x21\x52\x27\x65\x4F\x9D\x4D\x5F\x29\x2F\x09\xAF\x69\xCD\xA0\xD8\x36\x6E\xE5\xA3\xA7\x0F\xCB\x19\x5B\x07\x61\x19\x9E\x79\x8E\x5A\x0F\x2E\x28\x03\x1D\xF2\xB1\x72\x19\xCC\x35\xF9\x76\x78\x17\xA2\x79\xC8\xA1\x51\x2E\xDC\x3C\xD0"
	,SM2_CIPHER_LEN(16));
	//密文
	unsigned char C[SM2_CIPHER_LEN(16)] = {0};
	unsigned int CL = 0;
	//明文
	unsigned char M[SM2_CIPHER_LEN(16)] = {0};
	unsigned int ML = 0;
	//解密明文
	unsigned char M1[SM2_CIPHER_LEN(16)] = {0};
	unsigned int ML1 = 0;
	
	//标准数据解密验证
	ret = mcu_sm2_decrypt_external(&skA,C0,SM2_CIPHER_LEN(16),M1,&ML1);
	if ((0 != ret) || (memcmp(M0,M1,16))) {
			print(PRINT_TEST,"SM2 dec 0 err\r\n");
			return -1;
	}
	//加密
	memcpy(M,M0,16);
	//ret = fpga_sm2_encrypt_internal(1, M, 16, C, &CL);
	ret = mcu_sm2_encrypt_external(&pkA, M, 16, C, &CL);
	if ((0 != ret) || !(memcmp(C,M,16))) { //密文与明文对比需不相同
			print(PRINT_TEST,"SM2 enc err\r\n");
			return -1;
	}
	//解密
	memset(M1,0,16);
	//ret = fpga_sm2_encrypt_internal(1,C,SM2_CIPHER_LEN(16),M1,&ML1);
	ret = mcu_sm2_decrypt_external(&skA,C,SM2_CIPHER_LEN(16),M1,&ML1);
	if ((0 != ret) || (memcmp(M,M1,16))) {
			print(PRINT_TEST,"SM2 dec err\r\n");
			return -1;
	}
	return 0;
}

//sm2加密测试，去除标准数据解密验证
int	mcu_testsm2_pair(SM2PublicKey *pkA, SM2PrivateKey *skA){
	int ret = 0;

	//标准明文  
	unsigned char M0[16] = {0};
	memcpy(M0,"\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10",16);
	//标准密文  
	unsigned char C0[SM2_CIPHER_LEN(16)];
	memcpy(C0,"\x7E\xF1\x9A\xFC\x17\xE0\x56\xBD\x7A\xD1\xA4\x65\x16\x32\x29\x55\x63\xBE\x0C\xE1\x5F\x7F\x56\xCD\x4B\xD4\x00\xEF\xA5\x5B\x9B\x73\xC7\xF0\x33\x3E\x30\x70\x39\x2A\x48\x48\xBC\xA6\xC3\x33\x34\xF2\xC1\x89\x9E\x11\x20\x00\x5B\xD1\x21\x52\x27\x65\x4F\x9D\x4D\x5F\x29\x2F\x09\xAF\x69\xCD\xA0\xD8\x36\x6E\xE5\xA3\xA7\x0F\xCB\x19\x5B\x07\x61\x19\x9E\x79\x8E\x5A\x0F\x2E\x28\x03\x1D\xF2\xB1\x72\x19\xCC\x35\xF9\x76\x78\x17\xA2\x79\xC8\xA1\x51\x2E\xDC\x3C\xD0"
	,SM2_CIPHER_LEN(16));
	//密文
	unsigned char C[SM2_CIPHER_LEN(16)] = {0};
	unsigned int CL = 0;
	//明文
	unsigned char M[SM2_CIPHER_LEN(16)] = {0};
	unsigned int ML = 0;
	//解密明文
	unsigned char M1[SM2_CIPHER_LEN(16)] = {0};
	unsigned int ML1 = 0;
	
	//加密
	memcpy(M,M0,16);
	//ret = fpga_sm2_encrypt_internal(1, M, 16, C, &CL);
	ret = mcu_sm2_encrypt_external(pkA, M, 16, C, &CL);
	if ((0 != ret) || !(memcmp(C,M,16))) { //密文与明文对比需不相同
			print(PRINT_TEST,"SM2 enc err\r\n");
			return -1;
	}
	//解密
	memset(M1,0,16);
	//ret = fpga_sm2_encrypt_internal(1,C,SM2_CIPHER_LEN(16),M1,&ML1);
	ret = mcu_sm2_decrypt_external(skA,C,SM2_CIPHER_LEN(16),M1,&ML1);
	if ((0 != ret) || (memcmp(M,M1,16))) {
			print(PRINT_TEST,"SM2 dec err\r\n");
			return -1;
	}
	return 0;
}

//sm2签名测试
int	mcu_testsm2ver(void){
	int ret = 0;
	SM2PublicKey pkA;
	SM2PrivateKey skA;
	SM2Signature sign0;
	SM2Signature sign1;
	//私钥 "\x17\xB3\x7F\xA4\xB0\x9B\x4D\x5A\xC2\xE0\xFE\xE9\xF4\x0F\x3B\x8D\x47\x5D\xE3\xB4\xBC\x39\xF1\xFB\xF4\x6A\x6F\x37\x33\xB7\xC2\xF1"		
	memcpy(skA.K,	 "\x17\xB3\x7F\xA4\xB0\x9B\x4D\x5A\xC2\xE0\xFE\xE9\xF4\x0F\x3B\x8D\x47\x5D\xE3\xB4\xBC\x39\xF1\xFB\xF4\x6A\x6F\x37\x33\xB7\xC2\xF1",32);
	//公X  "\x14\xD3\xEE\x92\x17\xEE\x17\x38\x2C\xB0\x68\x0B\x21\x3A\x44\xCA\xC9\xF2\x43\xE8\x35\xDD\x33\xC7\x7D\x75\xB8\xF9\x82\xDE\xC4\x68"			
	memcpy(pkA.x,	 "\x14\xD3\xEE\x92\x17\xEE\x17\x38\x2C\xB0\x68\x0B\x21\x3A\x44\xCA\xC9\xF2\x43\xE8\x35\xDD\x33\xC7\x7D\x75\xB8\xF9\x82\xDE\xC4\x68",32);
	//公Y  "\x46\x24\x0A\x6E\xAB\xDB\x6D\xBA\xED\x3A\x19\x75\xCA\x56\x4B\xCD\xA1\x43\x62\xCD\xF9\xC4\x5A\xC2\x77\x29\xB0\x23\x25\x0E\x75\x37"
	memcpy(pkA.y,	 "\x46\x24\x0A\x6E\xAB\xDB\x6D\xBA\xED\x3A\x19\x75\xCA\x56\x4B\xCD\xA1\x43\x62\xCD\xF9\xC4\x5A\xC2\x77\x29\xB0\x23\x25\x0E\x75\x37",32);
	//签名消息Hash值
	unsigned char H[64] = {0};
	memcpy(H,			 "\x66\xC7\xF0\xF4\x62\xEE\xED\xD9\xD1\xF2\xD4\x6B\xDC\x10\xE4\xE2\x41\x67\xC4\x87\x5C\xF2\xF7\xA2\x29\x7D\xA0\x2B\x8F\x4B\xA8\xE0",32);
	//标准签名值  
	memcpy(sign0.r,"\xC7\x1E\x4F\x76\xA3\xD9\xE5\xE7\xD0\xE0\x9C\xAF\xF0\x3D\xC7\x96\x92\x00\x39\x22\x51\xE5\x68\x2A\x9D\x36\x59\x5A\x3A\xDA\x68\xF0",32);
	memcpy(sign0.s,"\xF6\xE5\xF6\x40\x96\x2E\x78\xC0\x8F\xA5\x1D\xC4\xD2\xF8\xCD\x09\xBC\xCB\x25\xFF\x2F\xAD\xBC\x87\xB3\xA5\x38\x17\xC6\xB2\x56\xEF",32);
	
	//标准值验签
	ret = mcu_sm2_verify_external(&pkA, sign0.r, sign0.s, H);
	if(0 != ret){
		print(PRINT_TEST,"SM2 ver0 err\r\n");
		return -1;
	}
	//签名
	ret = mcu_sm2_sign_external(&skA, H, sign1.r, sign1.s);
	if(0 != ret){
		print(PRINT_TEST,"SM2 sig err\r\n");
		return -1;
	}
	//验签
	ret = mcu_sm2_verify_external(&pkA, sign1.r, sign1.s, H);
	if(0 != ret){
		print(PRINT_TEST,"SM2 ver err\r\n");
		return -1;
	}
	return 0;
}

//sm2密钥交换测试
int	mcu_testsm2exchange(void){
	int ret = 0;
	SM2PublicKey pkA;
	SM2PrivateKey skA;
	SM2PublicKey pkB;
	SM2PrivateKey skB;
	SM2PublicKey tmppkA;
	SM2PublicKey tmppkB;
	unsigned char keyA[16];
	unsigned char keyB[16];
	unsigned short keyL;
	
	//私钥 "\x17\xB3\x7F\xA4\xB0\x9B\x4D\x5A\xC2\xE0\xFE\xE9\xF4\x0F\x3B\x8D\x47\x5D\xE3\xB4\xBC\x39\xF1\xFB\xF4\x6A\x6F\x37\x33\xB7\xC2\xF1"		
	memcpy(skA.K,	"\x17\xB3\x7F\xA4\xB0\x9B\x4D\x5A\xC2\xE0\xFE\xE9\xF4\x0F\x3B\x8D\x47\x5D\xE3\xB4\xBC\x39\xF1\xFB\xF4\x6A\x6F\x37\x33\xB7\xC2\xF1",32);
	//公X  "\x14\xD3\xEE\x92\x17\xEE\x17\x38\x2C\xB0\x68\x0B\x21\x3A\x44\xCA\xC9\xF2\x43\xE8\x35\xDD\x33\xC7\x7D\x75\xB8\xF9\x82\xDE\xC4\x68"			
	memcpy(pkA.x,	"\x14\xD3\xEE\x92\x17\xEE\x17\x38\x2C\xB0\x68\x0B\x21\x3A\x44\xCA\xC9\xF2\x43\xE8\x35\xDD\x33\xC7\x7D\x75\xB8\xF9\x82\xDE\xC4\x68",32);
	//公Y  "\x46\x24\x0A\x6E\xAB\xDB\x6D\xBA\xED\x3A\x19\x75\xCA\x56\x4B\xCD\xA1\x43\x62\xCD\xF9\xC4\x5A\xC2\x77\x29\xB0\x23\x25\x0E\x75\x37"
	memcpy(pkA.y,	"\x46\x24\x0A\x6E\xAB\xDB\x6D\xBA\xED\x3A\x19\x75\xCA\x56\x4B\xCD\xA1\x43\x62\xCD\xF9\xC4\x5A\xC2\x77\x29\xB0\x23\x25\x0E\x75\x37",32);
	
	//私钥 "\x43\x90\x4F\xA7\x74\xAD\x86\xCA\x58\xF1\xED\x5A\x2C\x68\xDC\xE9\x6A\x50\x6F\xD0\x27\x95\xE3\xDD\xE4\xD2\x9B\x64\x80\x02\xFD\x84"
	memcpy(skB.K,	"\x43\x90\x4F\xA7\x74\xAD\x86\xCA\x58\xF1\xED\x5A\x2C\x68\xDC\xE9\x6A\x50\x6F\xD0\x27\x95\xE3\xDD\xE4\xD2\x9B\x64\x80\x02\xFD\x84",32);
	//公X  "\x6A\x73\x24\xE5\xA8\xDF\xFA\x66\xA5\xF6\x1C\x5C\x6C\x4D\x71\x56\xC8\x73\x32\xAB\x50\xE6\x01\xF0\x6A\x8E\x01\xC0\x38\x36\x88\x8D"
	memcpy(pkB.x,	"\x6A\x73\x24\xE5\xA8\xDF\xFA\x66\xA5\xF6\x1C\x5C\x6C\x4D\x71\x56\xC8\x73\x32\xAB\x50\xE6\x01\xF0\x6A\x8E\x01\xC0\x38\x36\x88\x8D",32);
	//公Y  "\x22\x50\x0B\xF1\x1F\x83\xD3\xA8\xD3\xB9\xB3\xCE\xE6\x87\x30\xFF\xB7\x47\x01\x51\xBC\x56\x1C\x4F\xA3\x67\x96\x6D\x72\xA3\x9A\x8F"
	memcpy(pkB.y,	"\x22\x50\x0B\xF1\x1F\x83\xD3\xA8\xD3\xB9\xB3\xCE\xE6\x87\x30\xFF\xB7\x47\x01\x51\xBC\x56\x1C\x4F\xA3\x67\x96\x6D\x72\xA3\x9A\x8F",32);
	
	uint8_t *id_a = (uint8_t *)"ALICE123@YAHOO.COM";
	uint8_t *id_b = (uint8_t *)"BILL456@YAHOO.COM";
	void *agree_handle = NULL;
	unsigned int index_a;
	unsigned int index_b;
	unsigned short dindex_a;
	unsigned short dindex_b;
	
	ret = mcu_sm2_setkey(2, &skA, &pkA);
	if (ret)
	{
		print(PRINT_TEST,"sm2_f_skey err\r\n");
	}
	delay_ms(100);
	ret = mcu_sm2_setkey(4, &skB, &pkB);
	if (ret)
	{
		print(PRINT_TEST,"sm2_f_skey err\r\n");
	}
	
	memset(keyA, 0, 16);
	memset(keyB, 1, 16);

	ret = mcu_sm2_agreement_generate_data(1, 128, id_a, strlen((const char *)id_a), &pkA, &tmppkA, &agree_handle);
	if (ret)
	{
		print(PRINT_TEST,"f_sm2_ag_gen_data err %d!!!\r\n", ret);
		return -1;
	}
	//rtval = fpga_sm2_agreement_generate_data_key(&pri_key_b, &pub_key_b, 128, id_b, strlen((const char *)id_b), id_a, strlen((const char *)id_a), &pub_key_gen_a, &pub_key_temp_a, &pub_key_gen_b, &pub_key_gen_b, &index_b);
	ret = mcu_sm2_agreement_generate_data_key(2, 128, id_b, strlen((const char *)id_b), id_a, strlen((const char *)id_a), &pkA, &tmppkA, &pkB, &tmppkB, &index_b);
	if (ret)
	{
		print(PRINT_TEST,"f_sm2_ag_gen_data_key err %d!!!\r\n", ret);
		return -1;
	}
	ret = mcu_sm2_agreement_generate_key(id_b, strlen((const char *)id_b), &pkB, &tmppkB, agree_handle, &index_a);
	if (ret)
	{
		print(PRINT_TEST,"f_sm2_ag_gen_key err %d!!!\r\n", ret);
		return -1;
	}
	ret = read_sessionkey_mcu(&keyL,keyA,index_a);
	if ((0 != ret)) {
			print(PRINT_TEST,"RD sess key err\r\n");
			return -1;
	}
	ret = read_sessionkey_mcu(&keyL,keyB,index_b);
	if ((0 != ret) || (memcmp(keyA,keyB,16))) {
			print(PRINT_TEST,"memcmp err!\r\n");
			return -1;
	}
	mcu_sm2_delkey(2);
	mcu_sm2_delkey(4);
	dindex_a=index_a;
	dindex_b=index_b;
	destory_sessionkey_mcufpga(1, (unsigned char *)&dindex_a);
	destory_sessionkey_mcufpga(1, (unsigned char *)&dindex_b);
	return 0;
}

//sm2 mcu 加密1 签名2 交换3
int	power_on_testsm2mcu(void){
	if(mcu_testsm2enc()){
		return 1;
	}
	if(mcu_testsm2ver()){
		return 2;
	}
	if(mcu_testsm2exchange()){
		return 3;
	}
	return 0;
}
//sm2加密测试
int	power_on_testsm2enc(void){
	int ret = 0;
	SM2PublicKey pkA;
	SM2PrivateKey skA;
	//私钥 "\x17\xB3\x7F\xA4\xB0\x9B\x4D\x5A\xC2\xE0\xFE\xE9\xF4\x0F\x3B\x8D\x47\x5D\xE3\xB4\xBC\x39\xF1\xFB\xF4\x6A\x6F\x37\x33\xB7\xC2\xF1"		
	memcpy(skA.K,"\x17\xB3\x7F\xA4\xB0\x9B\x4D\x5A\xC2\xE0\xFE\xE9\xF4\x0F\x3B\x8D\x47\x5D\xE3\xB4\xBC\x39\xF1\xFB\xF4\x6A\x6F\x37\x33\xB7\xC2\xF1",32);
	//公X  "\x14\xD3\xEE\x92\x17\xEE\x17\x38\x2C\xB0\x68\x0B\x21\x3A\x44\xCA\xC9\xF2\x43\xE8\x35\xDD\x33\xC7\x7D\x75\xB8\xF9\x82\xDE\xC4\x68"			
	memcpy(pkA.x,"\x14\xD3\xEE\x92\x17\xEE\x17\x38\x2C\xB0\x68\x0B\x21\x3A\x44\xCA\xC9\xF2\x43\xE8\x35\xDD\x33\xC7\x7D\x75\xB8\xF9\x82\xDE\xC4\x68",32);
	//公Y  "\x46\x24\x0A\x6E\xAB\xDB\x6D\xBA\xED\x3A\x19\x75\xCA\x56\x4B\xCD\xA1\x43\x62\xCD\xF9\xC4\x5A\xC2\x77\x29\xB0\x23\x25\x0E\x75\x37"
	memcpy(pkA.y,"\x46\x24\x0A\x6E\xAB\xDB\x6D\xBA\xED\x3A\x19\x75\xCA\x56\x4B\xCD\xA1\x43\x62\xCD\xF9\xC4\x5A\xC2\x77\x29\xB0\x23\x25\x0E\x75\x37",32);
	//标准明文  
	unsigned char M0[16] = {0};
	memcpy(M0,"\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10",16);
	//标准密文  
	unsigned char C0[SM2_CIPHER_LEN(16)];
	memcpy(C0,"\x7E\xF1\x9A\xFC\x17\xE0\x56\xBD\x7A\xD1\xA4\x65\x16\x32\x29\x55\x63\xBE\x0C\xE1\x5F\x7F\x56\xCD\x4B\xD4\x00\xEF\xA5\x5B\x9B\x73\xC7\xF0\x33\x3E\x30\x70\x39\x2A\x48\x48\xBC\xA6\xC3\x33\x34\xF2\xC1\x89\x9E\x11\x20\x00\x5B\xD1\x21\x52\x27\x65\x4F\x9D\x4D\x5F\x29\x2F\x09\xAF\x69\xCD\xA0\xD8\x36\x6E\xE5\xA3\xA7\x0F\xCB\x19\x5B\x07\x61\x19\x9E\x79\x8E\x5A\x0F\x2E\x28\x03\x1D\xF2\xB1\x72\x19\xCC\x35\xF9\x76\x78\x17\xA2\x79\xC8\xA1\x51\x2E\xDC\x3C\xD0"
	,SM2_CIPHER_LEN(16));
	//密文
	unsigned char C[SM2_CIPHER_LEN(16)] = {0};
	unsigned int CL = 0;
	//明文
	unsigned char M[SM2_CIPHER_LEN(16)] = {0};
	unsigned int ML = 0;
	//解密明文
	unsigned char M1[SM2_CIPHER_LEN(16)] = {0};
	unsigned int ML1 = 0;
	
	//标准数据解密验证
	ret = fpga_sm2_decrypt_external(&skA,C0,SM2_CIPHER_LEN(16),M1,&ML1);
	if ((0 != ret) || (memcmp(M0,M1,16))) {
			print(PRINT_TEST,"SM2 dec 0 err\r\n");
			return -1;
	}
	//加密
	memcpy(M,M0,16);
	ret = fpga_sm2_encrypt_external(&pkA, M, 16, C, &CL);
	if ((0 != ret) || !(memcmp(C,M,16))) { //密文与明文对比需不相同
			print(PRINT_TEST,"SM2 enc err\r\n");
			return -1;
	}
	//解密
	memset(M1,0,16);
	ret = fpga_sm2_decrypt_external(&skA,C,SM2_CIPHER_LEN(16),M1,&ML1);
	if ((0 != ret) || (memcmp(M,M1,16))) {
			print(PRINT_TEST,"SM2 dec err\r\n");
			return -1;
	}
	return 0;
}
//sm2签名测试
int	power_on_testsm2ver(void){
	int ret = 0;
	SM2PublicKey pkA;
	SM2PrivateKey skA;
	SM2Signature sign0;
	SM2Signature sign1;
	//私钥 "\x17\xB3\x7F\xA4\xB0\x9B\x4D\x5A\xC2\xE0\xFE\xE9\xF4\x0F\x3B\x8D\x47\x5D\xE3\xB4\xBC\x39\xF1\xFB\xF4\x6A\x6F\x37\x33\xB7\xC2\xF1"		
	memcpy(skA.K,	 "\x17\xB3\x7F\xA4\xB0\x9B\x4D\x5A\xC2\xE0\xFE\xE9\xF4\x0F\x3B\x8D\x47\x5D\xE3\xB4\xBC\x39\xF1\xFB\xF4\x6A\x6F\x37\x33\xB7\xC2\xF1",32);
	//公X  "\x14\xD3\xEE\x92\x17\xEE\x17\x38\x2C\xB0\x68\x0B\x21\x3A\x44\xCA\xC9\xF2\x43\xE8\x35\xDD\x33\xC7\x7D\x75\xB8\xF9\x82\xDE\xC4\x68"			
	memcpy(pkA.x,	 "\x14\xD3\xEE\x92\x17\xEE\x17\x38\x2C\xB0\x68\x0B\x21\x3A\x44\xCA\xC9\xF2\x43\xE8\x35\xDD\x33\xC7\x7D\x75\xB8\xF9\x82\xDE\xC4\x68",32);
	//公Y  "\x46\x24\x0A\x6E\xAB\xDB\x6D\xBA\xED\x3A\x19\x75\xCA\x56\x4B\xCD\xA1\x43\x62\xCD\xF9\xC4\x5A\xC2\x77\x29\xB0\x23\x25\x0E\x75\x37"
	memcpy(pkA.y,	 "\x46\x24\x0A\x6E\xAB\xDB\x6D\xBA\xED\x3A\x19\x75\xCA\x56\x4B\xCD\xA1\x43\x62\xCD\xF9\xC4\x5A\xC2\x77\x29\xB0\x23\x25\x0E\x75\x37",32);
	//签名消息Hash值
	unsigned char H[64] = {0};
	memcpy(H,			 "\x66\xC7\xF0\xF4\x62\xEE\xED\xD9\xD1\xF2\xD4\x6B\xDC\x10\xE4\xE2\x41\x67\xC4\x87\x5C\xF2\xF7\xA2\x29\x7D\xA0\x2B\x8F\x4B\xA8\xE0",32);
	//标准签名值  
	memcpy(sign0.r,"\xC7\x1E\x4F\x76\xA3\xD9\xE5\xE7\xD0\xE0\x9C\xAF\xF0\x3D\xC7\x96\x92\x00\x39\x22\x51\xE5\x68\x2A\x9D\x36\x59\x5A\x3A\xDA\x68\xF0",32);
	memcpy(sign0.s,"\xF6\xE5\xF6\x40\x96\x2E\x78\xC0\x8F\xA5\x1D\xC4\xD2\xF8\xCD\x09\xBC\xCB\x25\xFF\x2F\xAD\xBC\x87\xB3\xA5\x38\x17\xC6\xB2\x56\xEF",32);
	
	//标准值验签
	ret = fpga_sm2_verify_external(&pkA, sign0.r, sign0.s, H);
	if(0 != ret){
		print(PRINT_TEST,"SM2 ver0 err\r\n");
		return -1;
	}
	//签名
	ret = fpga_sm2_sign_external(&skA, H, sign1.r, sign1.s);
	if(0 != ret){
		print(PRINT_TEST,"SM2 sig err\r\n");
		return -1;
	}
	//验签
	ret = fpga_sm2_verify_external(&pkA, sign1.r, sign1.s, H);
	if(0 != ret){
		print(PRINT_TEST,"SM2 ver err\r\n");
		return -1;
	}
	return 0;
}


//sm2密钥交换测试
int power_on_testsm2exchange(void){
	int ret = 0;
	SM2PublicKey pkA;
	SM2PrivateKey skA;
	SM2PublicKey pkB;
	SM2PrivateKey skB;
	SM2PublicKey tmppkA;
	SM2PublicKey tmppkB;
	unsigned char keyA[16];
	unsigned char keyB[16];
	unsigned short keyL;
	
	//私钥 "\x17\xB3\x7F\xA4\xB0\x9B\x4D\x5A\xC2\xE0\xFE\xE9\xF4\x0F\x3B\x8D\x47\x5D\xE3\xB4\xBC\x39\xF1\xFB\xF4\x6A\x6F\x37\x33\xB7\xC2\xF1"		
	memcpy(skA.K,	"\x17\xB3\x7F\xA4\xB0\x9B\x4D\x5A\xC2\xE0\xFE\xE9\xF4\x0F\x3B\x8D\x47\x5D\xE3\xB4\xBC\x39\xF1\xFB\xF4\x6A\x6F\x37\x33\xB7\xC2\xF1",32);
	//公X  "\x14\xD3\xEE\x92\x17\xEE\x17\x38\x2C\xB0\x68\x0B\x21\x3A\x44\xCA\xC9\xF2\x43\xE8\x35\xDD\x33\xC7\x7D\x75\xB8\xF9\x82\xDE\xC4\x68"			
	memcpy(pkA.x,	"\x14\xD3\xEE\x92\x17\xEE\x17\x38\x2C\xB0\x68\x0B\x21\x3A\x44\xCA\xC9\xF2\x43\xE8\x35\xDD\x33\xC7\x7D\x75\xB8\xF9\x82\xDE\xC4\x68",32);
	//公Y  "\x46\x24\x0A\x6E\xAB\xDB\x6D\xBA\xED\x3A\x19\x75\xCA\x56\x4B\xCD\xA1\x43\x62\xCD\xF9\xC4\x5A\xC2\x77\x29\xB0\x23\x25\x0E\x75\x37"
	memcpy(pkA.y,	"\x46\x24\x0A\x6E\xAB\xDB\x6D\xBA\xED\x3A\x19\x75\xCA\x56\x4B\xCD\xA1\x43\x62\xCD\xF9\xC4\x5A\xC2\x77\x29\xB0\x23\x25\x0E\x75\x37",32);
	
	//私钥 "\x43\x90\x4F\xA7\x74\xAD\x86\xCA\x58\xF1\xED\x5A\x2C\x68\xDC\xE9\x6A\x50\x6F\xD0\x27\x95\xE3\xDD\xE4\xD2\x9B\x64\x80\x02\xFD\x84"
	memcpy(skB.K,	"\x43\x90\x4F\xA7\x74\xAD\x86\xCA\x58\xF1\xED\x5A\x2C\x68\xDC\xE9\x6A\x50\x6F\xD0\x27\x95\xE3\xDD\xE4\xD2\x9B\x64\x80\x02\xFD\x84",32);
	//公X  "\x6A\x73\x24\xE5\xA8\xDF\xFA\x66\xA5\xF6\x1C\x5C\x6C\x4D\x71\x56\xC8\x73\x32\xAB\x50\xE6\x01\xF0\x6A\x8E\x01\xC0\x38\x36\x88\x8D"
	memcpy(pkB.x,	"\x6A\x73\x24\xE5\xA8\xDF\xFA\x66\xA5\xF6\x1C\x5C\x6C\x4D\x71\x56\xC8\x73\x32\xAB\x50\xE6\x01\xF0\x6A\x8E\x01\xC0\x38\x36\x88\x8D",32);
	//公Y  "\x22\x50\x0B\xF1\x1F\x83\xD3\xA8\xD3\xB9\xB3\xCE\xE6\x87\x30\xFF\xB7\x47\x01\x51\xBC\x56\x1C\x4F\xA3\x67\x96\x6D\x72\xA3\x9A\x8F"
	memcpy(pkB.y,	"\x22\x50\x0B\xF1\x1F\x83\xD3\xA8\xD3\xB9\xB3\xCE\xE6\x87\x30\xFF\xB7\x47\x01\x51\xBC\x56\x1C\x4F\xA3\x67\x96\x6D\x72\xA3\x9A\x8F",32);
	
	uint8_t *id_a = (uint8_t *)"ALICE123@YAHOO.COM";
	uint8_t *id_b = (uint8_t *)"BILL456@YAHOO.COM";
	void *agree_handle = NULL;
	unsigned int index_a;
	unsigned int index_b;
	unsigned short dindex_a;
	unsigned short dindex_b;
	
	memset(keyA, 0, 16);
	memset(keyB, 1, 16);

	ret = fpga_sm2_setkey(2, &skA, &pkA);
	if (ret)
	{
		print(PRINT_TEST,"sm2_f_skey err\r\n");
	}
	delay_ms(100);
	ret = fpga_sm2_setkey(4, &skB, &pkB);
	if (ret)
	{
		print(PRINT_TEST,"sm2_f_skey err\r\n");
	}
	ret = fpga_sm2_agreement_generate_data(1, 128, id_a, strlen((const char *)id_a), &pkA, &tmppkA, &agree_handle);
	if (ret)
	{
		print(PRINT_TEST,"f_sm2_ag_gen_data err %d!!!\r\n", ret);
		return -1;
	}
	
	//rtval = fpga_sm2_agreement_generate_data_key(&pri_key_b, &pub_key_b, 128, id_b, strlen((const char *)id_b), id_a, strlen((const char *)id_a), &pub_key_gen_a, &pub_key_temp_a, &pub_key_gen_b, &pub_key_gen_b, &index_b);
	ret = fpga_sm2_agreement_generate_data_key(2, 128, id_b, strlen((const char *)id_b), id_a, strlen((const char *)id_a), &pkA, &tmppkA, &pkB, &tmppkB, &index_b);
	if (ret)
	{
		print(PRINT_TEST,"f_sm2_ag_gen_data_key err %d!!!\r\n", ret);
		return -1;
	}
	ret = fpga_sm2_agreement_generate_key(id_b, strlen((const char *)id_b), &pkB, &tmppkB, agree_handle, &index_a);
	if (ret)
	{
		print(PRINT_TEST,"f_sm2_ag_gen_key err %d!!!\r\n", ret);
		return -1;
	}
	ret = read_sessionkey_mcu(&keyL,keyA,index_a);
	if ((0 != ret)) {
			print(PRINT_TEST,"RD sess key err\r\n");
			return -1;
	}
	ret = read_sessionkey_mcu(&keyL,keyB,index_b);
	if ((0 != ret) || (memcmp(keyA,keyB,16))) {
			print(PRINT_TEST,"memcmp err!\r\n");
			return -1;
	}
	dindex_a=index_a;
	dindex_b=index_b;
	destory_sessionkey_mcufpga(1, (unsigned char *)&dindex_a);
	destory_sessionkey_mcufpga(1, (unsigned char *)&dindex_b);
	fpga_sm2_delkey(2);
	fpga_sm2_delkey(4);
	return 0;
}

//sm4测试
int	power_on_testsm4FPGA(void){
	int ret = 0;
	//0123456789ABCDEFFEDCBA9876543210
	unsigned char key[16]= {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};
	//标准明文ECB  
	unsigned char M0[16] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};
	//标准密文ECB  
	unsigned char C0[16] = {0x68,0x1E,0xDF,0x34,0xD2,0x06,0x96,0x5E,0x86,0xB3,0xE9,0x4F,0x53,0x6E,0x42,0x46};
	//标准明文CBC  
	unsigned char M1[32] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10,
													0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};
	//标准密文CBC  
	unsigned char C1[32] = {0x26,0x77,0xF4,0x6B,0x09,0xC1,0x22,0xCC,0x97,0x55,0x33,0x10,0x5B,0xD4,0xA2,0x2A,
													0xF6,0x12,0x5F,0x72,0x75,0xCE,0x55,0x2C,0x3A,0x2B,0xBC,0xF5,0x33,0xDE,0x8A,0x3B};
	//IV
	unsigned char IV[16] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};
	//密文
	unsigned char C[64] =  {0};
	unsigned int CL = 0;
	//明文
	unsigned char M[64] =  {0};
	unsigned int ML = 0;


	//SM4-ECB加密
	memset(C,0,16);
	ret = FPGA_SYM_Encrypt(FPGA_DATA_SM4,FPGA_ECB_MODE,key,NULL,M0,16,C);
	if ((0 != ret) || (memcmp(C,C0,16))) {
			print(PRINT_TEST,"SM4-ECB enc err\r\n");
			return -1;
	}
	//SM4-ECB解密
	memset(M,0,16);
	ret = FPGA_SYM_Decrypt(FPGA_DATA_SM4,FPGA_ECB_MODE,key,0,C,16,M);
	if ((0 != ret) || (memcmp(M,M0,16))) {
		  print(PRINT_TEST,"SM4-ECB dec err\r\n");
			return -1;
	}	
	
	//SM4-CBC加密
	memset(C,0,32);
	ret = FPGA_SYM_Encrypt(FPGA_DATA_SM4,FPGA_CBC_MODE,key,IV,M1,32,C);
	if ((0 != ret) || (memcmp(C,C1,32))) {
			print(PRINT_TEST,"SM4-CBC enc err\r\n");
			return -1;
	}
	//SM4-CBC解密
	memset(M,0,32);
	ret = FPGA_SYM_Decrypt(FPGA_DATA_SM4,FPGA_CBC_MODE,key,IV,C1,32,M);
	if ((0 != ret) || (memcmp(M,M1,32))) {
		  print(PRINT_TEST,"SM4-CBC dec err\r\n");
			return -1;
	}	
	return 0;
}
//sm4测试
int	power_on_testsm4(void){
	int ret = 0;
	//0123456789ABCDEFFEDCBA9876543210
	unsigned char key[16]={0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};
	//标准明文ECB  
	unsigned char M0[16] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};
	//标准密文ECB  
	unsigned char C0[16] = {0x68,0x1E,0xDF,0x34,0xD2,0x06,0x96,0x5E,0x86,0xB3,0xE9,0x4F,0x53,0x6E,0x42,0x46};
	//标准明文CBC  
	unsigned char M1[32] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10,
													0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};
	//标准密文CBC  
	unsigned char C1[32] = {0x26,0x77,0xF4,0x6B,0x09,0xC1,0x22,0xCC,0x97,0x55,0x33,0x10,0x5B,0xD4,0xA2,0x2A,
													0xF6,0x12,0x5F,0x72,0x75,0xCE,0x55,0x2C,0x3A,0x2B,0xBC,0xF5,0x33,0xDE,0x8A,0x3B};
	//IV
	unsigned char IV[16] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};
	//密文
	unsigned char C[64] = {0};
	unsigned int CL = 0;
	//明文
	unsigned char M[64] = {0};
	unsigned int ML = 0;


	//SM4-ECB加密
	memset(C,0,16);
	ret = Sym_Crypt_WithKey(M0,16,key,16,NULL,0,SYM_ALG_SM4,SYM_ENCRYPTION,SYM_ECB_MODE,C);
	//ret = FPGA_SYM_Encrypt(FPGA_DATA_SM4,SM4_ECB_MODE,key,NULL,M0,16,C);
	if ((0 != ret) || (memcmp(C,C0,16))) {
			print(PRINT_TEST,"SM4-ECB enc err\r\n");
			return -1;
	}
	//SM4-ECB解密
	memset(M,0,16);
	ret = Sym_Crypt_WithKey(C,16,key,16,NULL,0,SYM_ALG_SM4,SYM_DECRYPTION,SYM_ECB_MODE,M);
	//ret = FPGA_SYM_Decrypt(FPGA_DATA_SM4,SM4_ECB_MODE,key,0,C,16,M);
	if ((0 != ret) || (memcmp(M,M0,16))) {
		  print(PRINT_TEST,"SM4-ECB dec err\r\n");
			return -1;
	}	
	
	//SM4-CBC加密
	memset(C,0,32);
	ret = Sym_Crypt_WithKey(M1,32,key,16,IV,16,SYM_ALG_SM4,SYM_ENCRYPTION,SYM_CBC_MODE,C);
	//ret = FPGA_SYM_Encrypt(FPGA_DATA_SM4,SM4_CBC_MODE,key,IV,M1,32,C);
	if ((0 != ret) || (memcmp(C,C1,32))) {
			print(PRINT_TEST,"SM4-CBC enc err\r\n");
			return -1;
	}
	//SM4-CBC解密
	memset(M,0,32);
	ret = Sym_Crypt_WithKey(C1,32,key,16,IV,16,SYM_ALG_SM4,SYM_DECRYPTION,SYM_CBC_MODE,M);
	//ret = FPGA_SYM_Decrypt(FPGA_DATA_SM4,SM4_CBC_MODE,key,IV,C1,32,M);
	if ((0 != ret) || (memcmp(M,M1,32))) {
		  print(PRINT_TEST,"SM4-CBC dec err\r\n");
			return -1;
	}	
	return 0;
}
//sm1测试
int	power_on_testsm1FPGA(void){
	int ret = 0;
	unsigned char key0[16]= {0}; StrToHex(key0,"67902ECC9EC60D35400D5C311D2D4E78");
	//标准明文ECB
	unsigned char M0[16] = {0};  StrToHex(M0,	 "8D8EA611110AF4C499CD577195701F9B");
	//标准密文ECB  
	unsigned char C0[16] = {0};  StrToHex(C0,	 "462713836C9737BE068B0B3FDF61D2B6");
	
	
//	unsigned char key0[16]= {0xe8,0x5f,0x07,0x2e,0x5c,0xad,0x0d,0x3f,0x4a,0x1e,0x62,0xed,0x5a,0xcb,0x7f,0xe2}; //StrToHex(key0,"67902ECC9EC60D35400D5C311D2D4E78");
//	//标准明文ECB
//	unsigned char M0[64] =  {0xc3,0xbc,0xc2,0x12,0x70,0x1b,0xb9,0x30,0x46,0x40,0x8f,0x20,0x64,0x66,0xe1,0x18,0xc3,0xbc,0xc2,0x12,0x70,0x1b,0xb9,0x30,0x46,0x40,0x8f,0x20,0x64,0x66,0xe1,0x18,0xc3,0xbc,0xc2,0x12,0x70,0x1b,0xb9,0x30,0x46,0x40,0x8f,0x20,0x64,0x66,0xe1,0x18,0xc3,0xbc,0xc2,0x12,0x70,0x1b,0xb9,0x30,0x46,0x40,0x8f,0x20,0x64,0x66,0xe1,0x18};  //StrToHex(M0,	 "8D8EA611110AF4C499CD577195701F9B");
//	//标准密文ECB  
//	unsigned char C0[64] = {0};  //StrToHex(C0,	 "462713836C9737BE068B0B3FDF61D2B6");
	
	
	unsigned char key1[16]= {0}; StrToHex(key1,"31EA428F7FC1A7704CC004139173FF56");
	//标准明文CBC  
	unsigned char M1[32] = {0};  StrToHex(M1,"4749F43401CDF211A12EBC62F0BA6D9C539D80946EE2201972B1853DF9935434");
	//标准密文CBC  
	unsigned char C1[32] = {0};  StrToHex(C1,"8A5303139B1CC2E0C405522DFD655EC800C4B587913D86EE897AC63A904AA0FA");
	//IV
	unsigned char IV[16] = {0};  StrToHex(IV,"78ED19E06BB666AB8A20D60745C4E172");
	//密文
	unsigned char C[64] = {0};
	unsigned int CL = 0;
	//明文
	unsigned char M[64] = {0};
	unsigned int ML = 0;

	//SM1-ECB加密
	memset(C,0,16);
	ret = FPGA_SYM_Encrypt(FPGA_DATA_SM1,FPGA_ECB_MODE,key0,NULL,M0,16,C);
	if ((0 != ret) || (memcmp(C,C0,16))) {
			print(PRINT_TEST,"SM1-ECB enc err\r\n");
			return -1;
	}
	//SM4-ECB解密
	memset(M,0,16);
	ret = FPGA_SYM_Decrypt(FPGA_DATA_SM1,FPGA_ECB_MODE,key0,NULL,C,16,M);
	if ((0 != ret) || (memcmp(M,M0,16))) {
		  print(PRINT_TEST,"SM1-ECB dec err\r\n");
			return -1;
	}
	//SM1-CBC加密
	memset(C,0,32);
	ret = FPGA_SYM_Encrypt(FPGA_DATA_SM1,FPGA_CBC_MODE,key1,IV,M1,32,C);
	if ((0 != ret) || (memcmp(C,C1,32))) {
			print(PRINT_TEST,"SM1-CBC enc err\r\n");
			return -1;
	}
	//SM4-CBC解密
	memset(M,0,32);
	ret = FPGA_SYM_Decrypt(FPGA_DATA_SM1,FPGA_CBC_MODE,key1,IV,C1,32,M);
	if ((0 != ret) || (memcmp(M,M1,32))) {
		  print(PRINT_TEST,"SM1-CBC dec err\r\n");
			return -1;
	}	
	return 0;
}
int	power_on_testsm1(void){
	int ret = 0;
	unsigned char key0[16]= {0}; StrToHex(key0,"67902ECC9EC60D35400D5C311D2D4E78");
	//标准明文ECB
	unsigned char M0[16] = {0};  StrToHex(M0,	 "8D8EA611110AF4C499CD577195701F9B");
	//标准密文ECB  
	unsigned char C0[16] = {0};  StrToHex(C0,	 "462713836C9737BE068B0B3FDF61D2B6");
	
	unsigned char key1[16]= {0}; StrToHex(key1,"31EA428F7FC1A7704CC004139173FF56");
	//标准明文CBC  
	unsigned char M1[32] = {0};  StrToHex(M1,"4749F43401CDF211A12EBC62F0BA6D9C539D80946EE2201972B1853DF9935434");
	//标准密文CBC  
	unsigned char C1[32] = {0};  StrToHex(C1,"8A5303139B1CC2E0C405522DFD655EC800C4B587913D86EE897AC63A904AA0FA");
	//IV
	unsigned char IV[16] = {0};  StrToHex(IV,"78ED19E06BB666AB8A20D60745C4E172");
	//密文
	unsigned char C[64] = {0};
	unsigned int CL = 0;
	//明文
	unsigned char M[64] = {0};
	unsigned int ML = 0;

	//SM1-ECB加密
	memset(C,0,16);
	ret = Sym_Crypt_WithKey(M0,16,key0,16,NULL,0,SYM_ALG_SM1,SYM_ENCRYPTION,SYM_ECB_MODE,C);
	if ((0 != ret) || (memcmp(C,C0,16))) {
			print(PRINT_TEST,"SM1-ECB enc err\r\n");
			return -1;
	}
	//SM4-ECB解密
	memset(M,0,16);
	ret = Sym_Crypt_WithKey(C,16,key0,16,NULL,0,SYM_ALG_SM1,SYM_DECRYPTION,SYM_ECB_MODE,M);
	if ((0 != ret) || (memcmp(M,M0,16))) {
		  print(PRINT_TEST,"SM1-ECB dec err\r\n");
			return -1;
	}
	//SM1-CBC加密
	memset(C,0,32);
	ret = Sym_Crypt_WithKey(M1,32,key1,16,IV,16,SYM_ALG_SM1,SYM_ENCRYPTION,SYM_CBC_MODE,C);
	if ((0 != ret) || (memcmp(C,C1,32))) {
			print(PRINT_TEST,"SM1-CBC enc err\r\n");
			return -1;
	}
	//SM4-CBC解密
	memset(M,0,32);
	ret = Sym_Crypt_WithKey(C1,32,key1,16,IV,16,SYM_ALG_SM1,SYM_DECRYPTION,SYM_CBC_MODE,M);
	if ((0 != ret) || (memcmp(M,M1,32))) {
		  print(PRINT_TEST,"SM1-CBC dec err\r\n");
			return -1;
	}
	return 0;
}
//ras
int power_on_testras(void){
	int ret = 0;
	uint8_t rsa_key[RSA2048_BUFFLEN]={0};
	uint8_t *pto = rsa_key;
	RSA_KEYGEN_G_STR rsakey;
	
	uint8_t M[256]={0};
	uint8_t C[256]={0};
	uint32_t OutL = 0;
	uint8_t M0[256]={0};StrToHex(M0,"0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210");
	uint8_t C0[256]={0};StrToHex(C0,"353541475F2E3AA7B475C2FCE75D73C80A6702BCF135665B115FB0C9A00CDE16C9C7E437B0FCF5A6BBE366518D83BE49787C8E0D2BC010C7E596A600786D26EB157F17F4E5C4EDBDBD269D02EC5B9D0ABEF098AA1A96EEFF26333F2F25153D45138089FEFF6248B9B5F4D8BC4778A2960072A410BE186EFC31B61605DB12F92DAD78DC801F2EBD753DA23073FF5E0816C3CF3CC1667CEB5DB8E1AC88B50026B445761B3EBE632FD301FF8519295E70FF787ADEE935E60B69A81BA675CCAF63BF135D0A5CCEA82998CF265A821D957D17715810D489C717B03C01577E2B248FF38858CE1D8286BB8A2C6F3FE02D9BC95E77F7E3390BA8D8D800489B187610D996");
	uint8_t M1[128]={0};StrToHex(M1,"0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210");
	uint8_t C1[128]={0};StrToHex(C1,"2DBE641D145181D4A1CCF3EB26D13489962D5AC8D2587D367F0C677905C67353076F2368EFD74E470CAF02272EA7C5FDEF3CB4BEB08B17ADB1372229D7AB967CF3FB22A64DC3D9305116457459D37FBDA05F637DFBFF09E81A3020B09B84655C735F26D1CF6D4E6E36DAB520A3AA0146F8020564E5A7413A9F47DD5BD10348B7");
	//rsa2048
	memset(rsa_key,0,RSA2048_BUFFLEN);
	pto=rsa_key;  //N
	StrToHex(pto,"9163D2A12734EBD8CEBB768AB44DBEA8D737012717535E24FE5FE5CBC832EDB5D0A05AA1D226EB0A9405DBA4BF579AAEA23DC42D823D3E28EC8C54E4357E3C2865A7925EB18FC8C88105E81E19FC3013042A13DEBDCCE03B50A86322C048FE63CD3E708D6DF8B5C369C07E926004559A99A559F314BEA43BA19DCF3896473F44F48B6B6882EBDBFD0B7B1FF5384E5C05BE74AB65C0D241281434434BB71D0667CAACB05E650E50AE95900D0DC99F6B76204024B085A4990F93665C995E2D15B2ACE7945FD1717BE7F73B93F1EF56DFA7FB158B89291627AF5A82C07B2F048FE144B18F0CD1F455BE2282CD9441F14A90D640CD2B0FD8750F6B60E7EA64267FED");
	pto+=256+253; //E
	StrToHex(pto,"010001");
	pto+=3;				//D
	StrToHex(pto,"22A6EC18C4C37442E46301C9E557724DC39DB484A0A69A15AF1B242601BD41B2C7DAB03F495B4541EC2DC93FE6EAF64F11142FA1B91CE7A7D1595112633D871109C97AB55F14AA023FDE2C88A020DF446905AE5EB456144B8ED9D36700F564CC5CAAB920BC493EE928575CD37E570A2022E6AA1DA9A0167CAFF470E347CE0B6203A46F2BF0BB8A37A34E2E18E667BADC0D92A64AF2F31178B00FAD71DF29CBA09409D0E3618ACEEAD2602E4765C96574BD2EA0919A7112AE2F506DB783F18A37C3A35BF7EEC4BD80887398EA1E23AF5D897648741B25D7D388D043A8FCDA80FE17CBC32A2545C9EF655FB362F98970A86FBCA811DD63F745E2D6531AB3038401");
	pto+=256;			//P
	StrToHex(pto,"B09FBEC293E6602B34D96CE45BDD2528849665A9AE2C84EFE7BE87F216268BF90AED72B4C28FCE96FDF20C770423E469B55200D8D20EE9E88BC338094873FCDEBAB3684F23E8C0EAE3C1858145F6DE008A41488D359C7FE598BBAEF49ECBD5B5D96A794BCEE8915F7EBFAEBB364F6B269ADD1780EECDA020A61DC16B302370C1");
	pto+=128;			//Q
	StrToHex(pto,"D2BAA83FEDB80335543581E9C7E99F2B3B54EEC7A7F400DC90C18E7BD6EBF182BFD6C2B94355CA2D99242FCC00AADF40D1EE3E0FC4D90EF180AD9D7368C434CCA38CBEFD6CC0B62E9AEA55477118FBCCA9DDDDFCBE89EE2C79AB115FBEC67F28965175C37EF32170F100CC12322C4B075D97A248AFFDF8C31334C2F6F0E92E2D");
	pto+=128;			//dP
	StrToHex(pto,"0C691D2154FD2212C722E3F8E3CF9535D4A330BF8C828A50C52AE928848FEED3F005A142BC4D188A198BF17E4767323C8F4614D327676EDE2D3BE96B159138DA79A9F39164078DCEB3743CAA49BD3FFA2FBCC8994B8414A49067D7B24E9A2A091E1ED229167FD6FF2BCBD23E4B61A738CE36ECD8DD6ECB6A9FE1855EBFC22DC1");
	pto+=128;			//dQ
	StrToHex(pto,"B4F93EA3606966BFF6E8D900480298028DBADC323548353137543324A1A811CA632C72209EF65F6297A15F3708DFB649B9C0AC25E8BD2CBB34F26545071571EEC90A87BFA7153DA07AC482A68F37908FECD630DDED591165BABBB27912A2EFF3905CB71144C652D2E6F6F34B31319EE1DD7BEB1017ACBA65F5E99B026E5523A5");
	pto+=128;			//Qinv
	StrToHex(pto,"8373F3FBA1840DF4E12AD7EE089BCAC007FDBCF3AAE37BB7D60A43DA7A0BAD0B70A556E0A63EF9CFAA6BACA29D924BE7D5BE5C2182B2EF6C413BEF7C467AA2BE929C2A8848AA29E2CC47977762A2C93E554C3DB43A7EA74ACE999A2BB20ACD80B8B4C847989063481DE9CA51DC70634C7400D3A64D3788ACABF81B49BEEFAB01");
	
	RSA_Keygen_init(&rsakey, 2048, rsa_key);
	//rsa2048 公钥运算
	memset(C,0,256);
	//memset(M0,1,256);
	ret=RSA_Pubkey_Operation(M0, 256, rsakey.RSA_e, 1, rsakey.RSA_n, 64, C, &OutL);
	if ((0 != ret) || (memcmp(C0,C,256))) {
		  print(PRINT_TEST,"RSA2048_Pub_OP err\r\n");
			return -1;
	}	
	//rsa2048 私钥运算
	memset(M,0,256);
	ret=RSA_Prikey_Operation(C,256,rsakey.RSA_e,1,rsakey.RSA_p,32,rsakey.RSA_q,32,rsakey.RSA_dp,32,rsakey.RSA_dq,32,rsakey.RSA_qInv,32,M,&OutL);
	if ((0 != ret) || (memcmp(M0,M,256))){
		  print(PRINT_TEST,"RSA2048_Pri_OP err\r\n");
			return -1;
	}
	//rsa1024 
	memset(rsa_key,0,RSA2048_BUFFLEN);
	pto=rsa_key;  //N
	StrToHex(pto,"CE7EB3D5DF0239B73B6C815EBE54D564D9DA0777C292A1AA8246D8E4847675D0D99B25E23A3420D3F2142F86C2ECFC1F49E728B7E2D5667BA45E5AC614F44DA6F658DEA95D7E058368CF05D325CA8FBA1BBB5E188A9A7E27202E87C3EC80F3EF8C768605AB8D9E74B87AC010CE20F0B174B2419CA795E03BE4A836D15E522D99");
	pto+=128+125; //E
	StrToHex(pto,"010001");
	pto+=3;				//D
	StrToHex(pto,"6B6FBCBD7FE436874121B945C41D7B51978F3AE77292BC0E6CEDD39741DC287C5B5BBFA02ECC447041B982E8C8AE689716EA70630C601F8C20FEFE97A4FB5F1299205C2B44F730E82D43FB6F82ECBF888B41AA89AE7F213CDE0794B3E4FB9493DC81141AD71C0DD99A99AFB67EDE3B1DDB52055B1DAB23DD61FF9EE6F5B29B29");
	pto+=128;			//P
	StrToHex(pto,"D07FE38FFE06EF00009C127BA237CAE794D83DF43F9732C2E8EB51D6093E9E3DEEAF32008D283AC9AAA234D529B6661CB567A1BE912D36AFBC4438A44A35F2F7");
	pto+=64;			//Q
	StrToHex(pto,"FD89E6371C3505400BC6F418AFAC095BCEDEC1F06BEBBCB2E346F95C48CC54B4FC983FF9900ABF90DD14A9EC62C71CBDDF1C405C32053F7570B682F4452F2FEF");
	pto+=64;			//dP
	StrToHex(pto,"4EE1335C948457032F37DC9E3D7ED21ACEEB087551618868C8E9CE2A25913518C5262ECA9A9CAFB1000721E9CB40205D981BBECB73ED2115572A902B4790257D");
	pto+=64;			//dQ
	StrToHex(pto,"DB956B459FB06BF3A43F93792DEC99CE61C49BC35634BD2151A64EA1968B2171FEB2FDF56EC360565EA35EE7D4450EA7836C3C719D00DE8D202972118D39E911");
	pto+=64;			//Qinv
	StrToHex(pto,"C1ED8EB99D95417A0B5CD531FED97FA0D385CA35B6F0B4984694AC6AC4C622C9769349C457ED1235E18B880A0B72C0B3662D2512F185D30538929C5AA8E4BC8A");
	RSA_Keygen_init(&rsakey, 1024, rsa_key);
	//rsa1024 公钥运算
	memset(C,0,128);
	ret=RSA_Pubkey_Operation(M1, 128, rsakey.RSA_e, 1, rsakey.RSA_n, 32, C, &OutL);
	if ((0 != ret) || (memcmp(C1,C,128))) {
		  print(PRINT_TEST,"RSA2048_Pub_OP err\r\n");
			return -1;
	}
	//rsa1024 私钥运算
	memset(M,0,128);
	ret=RSA_Prikey_Operation(C,128,rsakey.RSA_e,1,rsakey.RSA_p,16,rsakey.RSA_q,16,rsakey.RSA_dp,16,rsakey.RSA_dq,16,rsakey.RSA_qInv,16,M,&OutL);
	if ((0 != ret) || (memcmp(M1,M,128))) {
		  print(PRINT_TEST,"RSA2048_Pri_OP err\r\n");
			return -1;
	}
	return 0;
}
//sha1_sha256
int	power_on_testshaX(void){
	
	int ret = 0;
	UINT32 padding_size = 0;
	//原文
	unsigned char M[128] = {"abc"};
	unsigned int ML = 3;
	//标准哈希值 sha1
	unsigned char H0[64] = {0xA9,0x99,0x3E,0x36,0x47,0x06,0x81,0x6A,0xBA,0x3E,0x25,0x71,0x78,0x50,0xC2,0x6C,0x9C,0xD0,0xD8,0x9D};
	unsigned int HL0 = 20;
	//标准哈希值 sha256
	unsigned char H1[64] = {0xBA,0x78,0x16,0xBF,0x8F,0x01,0xCF,0xEA,0x41,0x41,0x40,0xDE,0x5D,0xAE,0x22,0x23,0xB0,0x03,0x61,0xA3,0x96,0x17,0x7A,0x9C,0xB4,0x10,0xFF,0x61,0xF2,0x00,0x15,0xAD};
	unsigned int HL1 = 32;
	//标准哈希值 sha384
	unsigned char H2[64] = {0xCB,0x00,0x75,0x3F,0x45,0xA3,0x5E,0x8B,0xB5,0xA0,0x3D,0x69,0x9A,0xC6,0x50,0x07,0x27,0x2C,0x32,0xAB,0x0E,0xDE,0xD1,0x63,0x1A,0x8B,0x60,0x5A,0x43,0xFF,0x5B,0xED,
													0x80,0x86,0x07,0x2B,0xA1,0xE7,0xCC,0x23,0x58,0xBA,0xEC,0xA1,0x34,0xC8,0x25,0xA7};
	unsigned int HL2 = 48;
	//标准哈希值 sha512
	unsigned char H3[64] = {0xDD,0xAF,0x35,0xA1,0x93,0x61,0x7A,0xBA,0xCC,0x41,0x73,0x49,0xAE,0x20,0x41,0x31,0x12,0xE6,0xFA,0x4E,0x89,0xA9,0x7E,0xA2,0x0A,0x9E,0xEE,0xE6,0x4B,0x55,0xD3,0x9A,
													0x21,0x92,0x99,0x2A,0x27,0x4F,0xC1,0xA8,0x36,0xBA,0x3C,0x23,0xA3,0xFE,0xEB,0xBD,0x45,0x4D,0x44,0x23,0x64,0x3C,0xE8,0x0E,0x2A,0x9A,0xC9,0x4F,0xA5,0x4C,0xA4,0x9F};
	unsigned int HL3 = 64;		
	//哈希值
	unsigned char H[64] = {0};
	unsigned int HL = 0;
	fill_hash_padding(HASH_BLOCK_LEN,ML, M+ML, &padding_size);
	ML+=padding_size;
  memset(H,0,64);
	ret = sha1_with_iv(NULL,0,M,ML,H,&HL);
	if(ret){
		print(PRINT_TEST,"SM3 test err\r\n");
		return ret;
	}
	if((memcmp(H0,H,HL0))){
		print(PRINT_TEST,"SM3 HL0 mem err\r\n");
		return -1;
	}
	memset(H,0,64);
	ret = sha256_with_iv(NULL,0,M,ML,H,&HL);
	if(ret){
		print(PRINT_TEST,"SM3 test iv err\r\n");
		return ret;
	}
	if((memcmp(H1,H,HL1))){
		print(PRINT_TEST,"SM3 HL1 mem err\r\n");
		return -1;
	}
	ML = 3;
	fill_hash_padding(SHA3_BLOCK_LEN,ML, M+ML, &padding_size);
	ML+=padding_size;
	memset(H,0,64);
	ret = sha384_with_iv(NULL,0,M,ML,H,&HL);
	if(ret){
		print(PRINT_TEST,"SM3 test iv err\r\n");
		return ret;
	}
	if((memcmp(H2,H,HL2))){
		print(PRINT_TEST,"SM3 HL2 mem err\r\n");
		return -1;
	}
	memset(H,0,64);
	ret = sha512_with_iv(NULL,0,M,ML,H,&HL);
	if(ret){
		print(PRINT_TEST,"SM3 test iv err\r\n");
		return ret;
	}
	if((memcmp(H3,H,HL3))){
		print(PRINT_TEST,"SM3 HL3 mem err\r\n");
		return -1;
	}
	return 0;
}
//aes
int	power_on_testaes(void){
	int ret = 0;
	unsigned char key128[16]= {0};  StrToHex(key128,"0123456789ABCDEFFEDCBA9876543210");
	unsigned char key192[24]= {0};  StrToHex(key192,"0123456789ABCDEFFEDCBA98765432100123456789ABCDEF");
	unsigned char key256[32]= {0};  StrToHex(key256,"0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210");
	//标准明文ECB  
	unsigned char M0[16] = {0};     StrToHex(M0,"0123456789ABCDEFFEDCBA9876543210");
	//标准密文ECB  
	unsigned char C0128[16] = {0};  StrToHex(C0128,"A674F5A389253565260D08DCBED5C971");
	unsigned char C0192[16] = {0};  StrToHex(C0192,"4B40B6F939CF3CC95487797FF3169F78");
	unsigned char C0256[16] = {0};  StrToHex(C0256,"65561E88A83C44DBB99C18D9A63E5620");
	//标准明文CBC  
	unsigned char M1[32] = {0};     StrToHex(M1,"0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210");
	//标准密文CBC  
	unsigned char C1128[32] = {0};  StrToHex(C1128,"D5C825A21F04643B43E2DF3278A762F7A831225EEB167A72D6609A5828FBEB87");
	unsigned char C1192[32] = {0};  StrToHex(C1192,"582CDD2529E125CA63892BB2D96591BFD0515D42B608F609D8B4D21A34ABE8DD");
	unsigned char C1256[32] = {0};  StrToHex(C1256,"B631748F9FC0BEAC9DEF2C2CFDCE8E72AB262519EE2925BD2AA02F9D1FB25D86");	
	//IV
	unsigned char IV[16] = {0}; 	  StrToHex(IV,"0123456789ABCDEFFEDCBA9876543210");
	//密文
	unsigned char C[64] = {0};
	unsigned int CL = 0;
	//明文
	unsigned char M[64] = {0};
	unsigned int ML = 0;


	//AES128-ECB加密
	memset(C,0,16);
	ret = Sym_Crypt_WithKey(M0,16,key128,16,IV,16,SYM_ALG_AES,SYM_ENCRYPTION,SYM_ECB_MODE,C);
	if ((0 != ret) || (memcmp(C,C0128,16))) {
			print(PRINT_TEST,"AES128-ECB enc err\r\n");
			return -1;
	}
	//AES128-ECB解密
	memset(M,0,16);
	ret = Sym_Crypt_WithKey(C,16,key128,16,IV,16,SYM_ALG_AES,SYM_DECRYPTION,SYM_ECB_MODE,M);
	if ((0 != ret) || (memcmp(M,M0,16))) {
		  print(PRINT_TEST,"AES128-ECB dec err\r\n");
			return -1;
	}	
	//AES128-CBC加密
	memset(C,0,32);
	ret = Sym_Crypt_WithKey(M1,32,key128,16,IV,16,SYM_ALG_AES,SYM_ENCRYPTION,SYM_CBC_MODE,C);
	if ((0 != ret) || (memcmp(C,C1128,32))) {
			print(PRINT_TEST,"AES128-CBC enc err\r\n");
			return -1;
	}
	//AES128-CBC解密
	memset(M,0,32);
	ret = Sym_Crypt_WithKey(C,32,key128,16,IV,16,SYM_ALG_AES,SYM_DECRYPTION,SYM_CBC_MODE,M);
	if ((0 != ret) || (memcmp(M,M1,32))) {
		  print(PRINT_TEST,"AES128-CBC dec err\r\n");
			return -1;
	}	
	
	
	//AES192-ECB加密
	memset(C,0,16);
	ret = Sym_Crypt_WithKey(M0,16,key192,24,IV,16,SYM_ALG_AES,SYM_ENCRYPTION,SYM_ECB_MODE,C);
	if ((0 != ret) || (memcmp(C,C0192,16))) {
			print(PRINT_TEST,"AES192-ECB enc err\r\n");
			return -1;
	}
	//AES192-ECB解密
	memset(M,0,16);
	ret = Sym_Crypt_WithKey(C,16,key192,24,IV,16,SYM_ALG_AES,SYM_DECRYPTION,SYM_ECB_MODE,M);
	if ((0 != ret) || (memcmp(M,M0,16))) {
		  print(PRINT_TEST,"AES192-ECB dec err\r\n");
			return -1;
	}	
	//AES192-CBC加密
	memset(C,0,32);
	ret = Sym_Crypt_WithKey(M1,32,key192,24,IV,16,SYM_ALG_AES,SYM_ENCRYPTION,SYM_CBC_MODE,C);
	if ((0 != ret) || (memcmp(C,C1192,32))) {
			print(PRINT_TEST,"AES192-CBC enc err\r\n");
			return -1;
	}
	//AES192-CBC解密
	memset(M,0,32);
	ret = Sym_Crypt_WithKey(C,32,key192,24,IV,16,SYM_ALG_AES,SYM_DECRYPTION,SYM_CBC_MODE,M);
	if ((0 != ret) || (memcmp(M,M1,32))) {
		  print(PRINT_TEST,"AES192-CBC dec err\r\n");
			return -1;
	}
	//AES256-ECB加密
	memset(C,0,16);
	ret = Sym_Crypt_WithKey(M0,16,key256,32,IV,16,SYM_ALG_AES,SYM_ENCRYPTION,SYM_ECB_MODE,C);
	if ((0 != ret) || (memcmp(C,C0256,16))) {
			print(PRINT_TEST,"AES256-ECB enc err\r\n");
			return -1;
	}
	//AES256-ECB解密
	memset(M,0,16);
	ret = Sym_Crypt_WithKey(C,16,key256,32,IV,16,SYM_ALG_AES,SYM_DECRYPTION,SYM_ECB_MODE,M);
	if ((0 != ret) || (memcmp(M,M0,16))) {
		  print(PRINT_TEST,"AES256-ECB dec err\r\n");
			return -1;
	}	
	//AES256-CBC加密
	memset(C,0,32);
	ret = Sym_Crypt_WithKey(M1,32,key256,32,IV,16,SYM_ALG_AES,SYM_ENCRYPTION,SYM_CBC_MODE,C);
	if ((0 != ret) || (memcmp(C,C1256,32))) {
			print(PRINT_TEST,"AES256-CBC enc err\r\n");
			return -1;
	}
	//AES256-CBC解密
	memset(M,0,32);
	ret = Sym_Crypt_WithKey(C,32,key256,32,IV,16,SYM_ALG_AES,SYM_DECRYPTION,SYM_CBC_MODE,M);
	if ((0 != ret) || (memcmp(M,M1,32))) {
		  print(PRINT_TEST,"AES256-CBC dec err\r\n");
			return -1;
	}
	return 0;
}

//aes
int	power_on_testdes(void){
	int ret = 0;
	unsigned char keydes[8]= {0};    StrToHex(keydes, "0123456789ABCDEF");
	unsigned char key3des[24]= {0};  StrToHex(key3des,"0123456789ABCDEFFEDCBA98765432100123456789ABCDEF");
	//标准明文ECB  
	unsigned char M0[8] = {0};      StrToHex(M0,"0123456789ABCDEF");
	//标准密文ECB  
	unsigned char C0des[8] = {0};   StrToHex(C0des, "56CC09E7CFDC4CEF");
	unsigned char C03des[8] = {0};  StrToHex(C03des,"1A4D672DCA6CB335");

	//标准明文CBC  
	unsigned char M1[16] = {0};     StrToHex(M1,"0123456789ABCDEFFEDCBA9876543210");
	//标准密文CBC  
	unsigned char C1des[16] = {0};  StrToHex(C1des, "D5D44FF720683D0D323C4190D2212752");
	unsigned char C13des[16]= {0};  StrToHex(C13des,"08D7B4FB629D0885D46DA5432A6C0CE8");
	//IV
	unsigned char IV[8] = {0}; 	    StrToHex(IV,"0123456789ABCDEF");
	//密文
	unsigned char C[16] = {0};
	unsigned int CL = 0;
	//明文
	unsigned char M[16] = {0};
	unsigned int ML = 0;


	//DES-ECB加密
	memset(C,0,8);
	ret = Sym_Crypt_WithKey(M0,8,keydes,8,IV,8,SYM_ALG_DES,SYM_ENCRYPTION,SYM_ECB_MODE,C);
	if ((0 != ret) || (memcmp(C,C0des,8))) {
			print(PRINT_TEST,"DES-ECB enc err\r\n");
			return -1;
	}
	//DES-ECB解密
	memset(M,0,8);
	ret = Sym_Crypt_WithKey(C,8,keydes,8,IV,8,SYM_ALG_DES,SYM_DECRYPTION,SYM_ECB_MODE,M);
	if ((0 != ret) || (memcmp(M,M0,8))) {
		  print(PRINT_TEST,"DES-ECB dec err\r\n");
			return -1;
	}	
	//DES-CBC加密
	memset(C,0,16);
	ret = Sym_Crypt_WithKey(M1,16,keydes,8,IV,8,SYM_ALG_DES,SYM_ENCRYPTION,SYM_CBC_MODE,C);
	if ((0 != ret) || (memcmp(C,C1des,16))) {
			print(PRINT_TEST,"DES-CBC enc err\r\n");
			return -1;
	}
	//DES-CBC解密
	memset(M,0,16);
	ret = Sym_Crypt_WithKey(C,16,keydes,8,IV,8,SYM_ALG_DES,SYM_DECRYPTION,SYM_CBC_MODE,M);
	if ((0 != ret) || (memcmp(M,M1,16))) {
		  print(PRINT_TEST,"DES-CBC dec err\r\n");
			return -1;
	}	

	//3DES-ECB加密
	memset(C,0,8);
	ret = Sym_Crypt_WithKey(M0,8,key3des,24,IV,8,SYM_ALG_3DES,SYM_ENCRYPTION,SYM_ECB_MODE,C);
	if ((0 != ret) || (memcmp(C,C03des,8))) {
			print(PRINT_TEST,"3DES-ECB enc err\r\n");
			return -1;
	}
	//3DES-ECB解密
	memset(M,0,8);
	ret = Sym_Crypt_WithKey(C,8,key3des,24,IV,8,SYM_ALG_3DES,SYM_DECRYPTION,SYM_ECB_MODE,M);
	if ((0 != ret) || (memcmp(M,M0,8))) {
		  print(PRINT_TEST,"3DES-ECB dec err\r\n");
			return -1;
	}	
	//3DES-CBC加密
	memset(C,0,16);
	ret = Sym_Crypt_WithKey(M1,16,key3des,24,IV,8,SYM_ALG_3DES,SYM_ENCRYPTION,SYM_CBC_MODE,C);
	if ((0 != ret) || (memcmp(C,C13des,16))) {
			print(PRINT_TEST,"3DES-CBC enc err\r\n");
			return -1;
	}
	//3DES-CBC解密
	memset(M,0,16);
	ret = Sym_Crypt_WithKey(C,16,key3des,24,IV,8,SYM_ALG_3DES,SYM_DECRYPTION,SYM_CBC_MODE,M);
	if ((0 != ret) || (memcmp(M,M1,16))) {
		  print(PRINT_TEST,"3DES-CBC dec err\r\n");
			return -1;
	}
	return 0;
}

//sm3
int	power_on_testsm3(void){
	int ret = 0;
	UINT32 padding_size = 0;
	//原文
	unsigned char M[64] = {"abc"};
	unsigned int ML = 3;
	//标准哈希值
	unsigned char H0[64] = {0x66,0xC7,0xF0,0xF4,0x62,0xEE,0xED,0xD9,0xD1,0xF2,0xD4,0x6B,0xDC,0x10,0xE4,0xE2,0x41,0x67,0xC4,0x87,0x5C,0xF2,0xF7,0xA2,0x29,0x7D,0xA0,0x2B,0x8F,0x4B,0xA8,0xE0};
	unsigned int HL0 = 32;
	//哈希值
	unsigned char H[64] = {0};
	unsigned int HL = 0;	
//	ret = FPGA_SM3_test();
//	if(ret){
//		print(PRINT_TEST,"SM3 power on test FPGA err\r\n");
//		return ret;
//	}
	fill_hash_padding(HASH_BLOCK_LEN,ML, M+ML, &padding_size);
	ML+=padding_size;
	memset(H,0,64);
	ret = sm3_with_iv(NULL,0,M,ML,H,&HL);
	if(ret){
		print(PRINT_TEST,"SM3 iv err\r\n");
		return ret;
	}
	if((memcmp(H0,H,HL0))){
		print(PRINT_TEST,"SM3 HL0 mem err\r\n");
		return -1;
	}
	return ret;
}

//用户数据完整性校验
int usr_data_check(void){
	uint32_t btr=0;
	uint8_t *usrdata=(uint8_t *)&eFlash;
	if(GetUserKeyCheck(usrdata,sizeof(FlashData),&btr)){
		print(PRINT_TEST,"usr key err\r\n");
		return -1;
	}
	else{
		print(PRINT_TEST,"usr key ok\r\n");
	}
	return 0;
}
//用户密钥完整性校验
int usr_key_check(void){
	if(chip_check_keypin()){
		print(PRINT_TEST,"keypin err\r\n");
		return -1;
	}
	else{
		print(PRINT_TEST,"keypin ok\r\n");
	}
	
	if(chip_check_keypair()){
		print(PRINT_TEST,"keypair err\r\n");
		return -1;
	}
	else{
		print(PRINT_TEST,"keypair ok!\r\n");
	}
	if(chip_check_kek()){
		print(PRINT_TEST,"kek err\r\n");
		return -1;
	}
	else{
		print(PRINT_TEST,"kek ok\r\n");
	}
	return 0;
}
//上电测试算法
void power_on_test(MCUSelfCheck* test_result){
	int ret = 0;
	//FPGA算法状态寄存器
	//ArgFlag = *(uint8_t *)FPGA_ARG_REG_ADDR;
	memset(test_result,0,sizeof(MCUSelfCheck));
	/********  硬件测试  ********/
	//spiflash测试
//	FPGAsetgetkey();
	ret = power_on_testspiflash();
	if(ret){
		test_result->spiflash = 1;
		print(PRINT_TEST,"spi err ");
	}
	else{
		print(PRINT_TEST,"spi ok ");
	}
	//SRAM测试
	ret = power_on_testsram();
	if(ret){
		test_result->sram = 1;
		print(PRINT_TEST,"sram err ");
	}
	else{
		print(PRINT_TEST,"sram ok ");
	}
	/********  算法测试  ********/
	//查看SM1算法
	if((ArgFlag&0x04) == 0){
		test_result->sm1FPGA = 2;
	}
	else{
		//sm1测试FPGA
		ret = power_on_testsm1FPGA();
		if(ret){
			test_result->sm1FPGA = 1;
			print(PRINT_TEST,"sm1_F err ");
		}
		else{
			print(PRINT_TEST,"sm1_F ok ");
		}
	}
	//sm1测试MCU
	ret = power_on_testsm1();
	if(ret){
		test_result->sm1MCU = 1;
		print(PRINT_TEST,"sm1_M err ");
	}
	else{
		print(PRINT_TEST,"sm1_M ok ");
	}
	//sm2测试 mcu
	ret = power_on_testsm2mcu();
	if(ret){
		test_result->sm2mcu = 1;
		print(PRINT_TEST,"sm2_M err ");
	}
	else{
		print(PRINT_TEST,"sm2_M ok ");
	}
	//查看SM2算法
 	if((ArgFlag&0x01) == 0){
		test_result->sm2enc = 2;
		test_result->sm2ver = 2;
		test_result->sm2exchange = 2;
	}
	else{
		//sm2加密测试
		ret = power_on_testsm2enc();
		if(ret){
			test_result->sm2enc = 1;
		print(PRINT_TEST,"sm2_enc_F err ");
		}
		else{
			print(PRINT_TEST,"sm2_enc_F ok ");
		}
		//sm2签名测试
		ret = power_on_testsm2ver();
		if(ret){
			test_result->sm2ver = 1;
			print(PRINT_TEST,"sm2_ver_F err ");
		}
		else{
			print(PRINT_TEST,"sm2_ver_F ok ");
		}
		//sm2密钥交换测试
	if(!HSMD1){
			ret = power_on_testsm2exchange();
			if(ret){
				test_result->sm2exchange = 1;
				print(PRINT_TEST,"sm2_ex err ");
			}
			else{
				print(PRINT_TEST,"sm2_ex ok ");
			}
		}
	}

	//查看SM3算法
	if((ArgFlag&0x08) == 0){
		test_result->sm3FPGA = 2;
	}
	else{

		//sm3 FPGA
		ret = FPGA_SM3_test();
		if(ret){
			test_result->sm3FPGA = 1;
			print(PRINT_TEST,"sm3_F err\r\n");
		}
		else{
			print(PRINT_TEST,"sm3_F ok\r\n");
		}
	}

	//sm3 MCU
	ret = power_on_testsm3();
	if(ret){
		test_result->sm3MCU = 1;
		print(PRINT_TEST,"sm3_M err ");
	}
	else{
		print(PRINT_TEST,"sm3_M ok ");
	}
	
	//查看SM4算法
	if((ArgFlag&0x10) == 0){
		test_result->sm4FPGA = 2;
	}
	else{

		//sm4测试 FPGA
		ret = power_on_testsm4FPGA();
		if(ret){
			test_result->sm4FPGA = 1;
			print(PRINT_TEST,"sm4_F err ");
		}
		else{
			print(PRINT_TEST,"sm4_F ok ");
		}
	}

	//sm4测试 MCU
	ret = power_on_testsm4();
	if(ret){
		test_result-> sm4MCU = 1;
		print(PRINT_TEST,"sm4_M err ");
	}
	else{
		print(PRINT_TEST,"sm4_M ok ");
	}

	//ras
	ret = power_on_testras();
	if(ret){
		test_result->ras = 1;
		print(PRINT_TEST,"ras err ");
	}
	else{
		print(PRINT_TEST,"ras ok ");
	}

	//sha1_sha256
	ret = power_on_testshaX();
	if(ret){
		test_result->sha = 1;
		print(PRINT_TEST,"shaX err ");
	}
	else{
		print(PRINT_TEST,"shaX ok ");
	}

	//aes
	ret = power_on_testaes();
	if(ret){
		test_result->aes = 1;
		print(PRINT_TEST,"aes err ");
	}
	else{
		print(PRINT_TEST,"aes ok ");
	}

	//des
	ret = power_on_testdes();
	if(ret){
		test_result->des = 1;
		print(PRINT_TEST,"des err ");
	}
	else{
		print(PRINT_TEST,"des ok ");
	}

}
extern MCUSelfCheck DevSelfCheck;
void Run_Test_task(void){
	uint8_t * pTest = NULL;
	uint16_t Ti = 0;
	//	gwd_test();
	//	clear_filedir_file("1:/kek");   		//清除KEK密钥文件
	//	clear_filedir_file("1:/cipher");   	//清除用户密钥对密钥文件
	//自检开始绿灯LED_1亮
	//led_display(LED_1,HZ_1,LED_ON);
	//上电算法自检
	power_on_test(&DevSelfCheck);
	//上电随机性检测
	if(RandomCyclicalTest())
	{
		print(PRINT_TEST,"ran err");
		DevSelfCheck.Randomcheck = 1;
	}else{
		print(PRINT_TEST,"ran ok ");
		DevSelfCheck.Randomcheck = 0x00;
	}
	//用户数据完整性校验
/****************************************     ~~~  **/
	if(usr_data_check()){
		DevSelfCheck.usrcheck = 0x01;
	}else{
		DevSelfCheck.usrcheck = 0x00;
	}
	//用户密钥完整性校验
	if(usr_key_check()){
		DevSelfCheck.usrcheck = 1;
	}else{
		DevSelfCheck.usrcheck = 0x00;
	}

	/************************************/
	//go_to_factory();
#ifdef DG_login
	mcu_debug_set(ManagementStatus);//ManagementStatus WorkStatus FactoryStatus ReadyStatus
	mcutodriver_LOGINSTATUS();
#endif	
	//自检检查
	pTest = (uint8_t *)&DevSelfCheck;
	for(Ti=0;Ti<sizeof(MCUSelfCheck);Ti++){
		if(pTest[Ti] == 1){ 
			led_display(LED_0,HZ_2,LED_BL); //自检出现失败
			led_display(LED_1,HZ_1,LED_OFF);//自检出现失败
			break;
		}
	}
	//print(PRINT_TEST,"Ti = %d\r\n",Ti);
	if(Ti == sizeof(MCUSelfCheck))
		led_display(LED_0,HZ_1,LED_OFF);//自检成功，红灯熄灭
	/*****usb 重新枚举*****/
//	at24cxx_read_bytes(UKEY_DATA_ADDR,(uint8_t*)&DevSelfCheck.des, 4);
//	if(DevSelfCheck.des>3){
//		Ti = 0;
//		at24cxx_write_bytes(UKEY_DATA_ADDR,(uint8_t*)&Ti, 4);
//	}
}

void testonebyte(void){
	unsigned short tmpL = 0;
	
//	unsigned short ii=0;
//	unsigned short jj=0;
//	while(1){
//		ii++;
//		*(unsigned short *)0x60800018 = ii;
//		jj = *(unsigned short *)0x6080001A;
//		tmpL = jj;
//	}
	
	unsigned short ii=0;
	unsigned char jj=0;
	ii = 0x1234;
	while(1){
		//ii++;
		*(unsigned short *)0x60800004 = ii;
		jj = *(unsigned char *)0x60800004;
		jj = *(unsigned char *)0x60800005;
		tmpL = jj;
	}
}


int test60801000(void){
	
	uint16_t read,write;
	uint32_t SRAMADDBEGIN = 0x60801000;
//	uint32_t SRAMADDEND 	= 0x60100000;
	uint32_t SRAMlen = 4096;//SRAMADDEND-SRAMADDBEGIN;
	for(int i=0;i<SRAMlen;i+=2){
		write = i;
		*(uint16_t*)(SRAMADDBEGIN+i) = write;
		read = *(uint16_t*)(SRAMADDBEGIN+i);
		if(write != read){
			return -1;
		}
	}
	return 0;	

//	unsigned char ii=0;
//  unsigned char jj=0;
//	*(unsigned char *)0x60801000 = 0xac;
//  jj = *(unsigned char *)0x60801000;
//	*(unsigned char *)0x60801001 = 0xcd;
//	jj = *(unsigned char *)0x60801001;
//	*(unsigned char *)0x60801002 = 0x67;
//	jj = *(unsigned char *)0x60801002;
//	*(unsigned char *)0x60801003 = 0x89;
//	jj = *(unsigned char *)0x60801003;
//	ii = jj;
//reverse_memory((unsigned char *)0x60801000,4);
	
//	*(unsigned short *)0x60801000 = 0x1234;
//	//*(unsigned char *)0x60801001 = 0x34;
//	*(unsigned short *)0x60801002 = 0x5678;
//	//*(unsigned char *)0x60801003 = 0x78;
//	reverse_memory((unsigned char *)0x60801000,4);	

}

void gwd_test(void){
	//testonebyte();
	//test60801000();
	//power_on_test(0);
	//gwd_test_memcpy();
	//FPGAsetgetkey();
	//power_on_testsm2exchange();
	while(1){
			//test60801000();
	}
}

int sram_test_new(){
 FPGAHeader *header;
 unsigned int sram_addr = 0x60000000 + 0x300;
 unsigned char test_array[16] = {
  0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08, 
  0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10
 };
 unsigned char *tmp_ptr;
 unsigned char check_byte;
 unsigned char dummy_byte;
 
 header = (FPGAHeader *)sram_addr;
 memcpy(header, test_array, 16);
 
 tmp_ptr = (unsigned char *)header;
 check_byte = *tmp_ptr;
 dummy_byte = check_byte;
 
 check_byte = *(tmp_ptr + 1);
 dummy_byte = check_byte;
 
 check_byte = header->dst;
 dummy_byte = check_byte;
 
 check_byte = header->src;
 dummy_byte = check_byte;

 return 0;
}
void ciph_test(void){
	uint32_t br;
	uint16_t index =257;
	uint16_t type =2;
	char pin[16]="123458";
	uint8_t data[1408];
		DelUsrCiph(257);
	//uint8_t src_temp[2]={0x04,0x01};
	GenUsrCiph(index,type,pin,6);
	//test_eflahs_WR();
	read_cipher(257,1408,&br,data);
//	print(PRINT_TEST," read sm2 ciph is\n");
//	printf_byte((uint8_t *)data,1408);
	
	read_cipher(0xF101,1408,&br,data);
//	print(PRINT_TEST,"read sm2 sign is\n");
//	printf_byte((uint8_t *)data,1408);
	check_cipher_access(257,6,pin);
		
//	print(PRINT_TEST,"sm2 pin is\n");
//	printf_byte((uint8_t *)pin,6);
	//DelUsrCiph(1);
}
//自检 扑克检测
//随机数周期扑克检查，检查 RAN_CHIP_NUM组10000bits的随机数
int RandomCyclicalTest(void)
{

	int i,j,Count;
	int M = 2;

	unsigned char buff[(10000/8-2)] = {0}; 
	unsigned int len = (10000/8-2);
	//扑克检查不合格的组数
	Count = 0;

	//丢弃128KB，10组无效数据
#ifndef CHECK
		for(j=0;j<(10*128);j++)
	{
		for(i=1;i<=RAN_CHIP_NUM;i++)
		{
			memset(buff,0,len);
			//GetRandfromchip(buff, len);
			FPGA_ApplyRandomData(buff,len,i);
//			if(j>10)
//				delay_ms(1);
		}
	}
#endif

	//第一次扑克检查
	for(j=0;j<5;j++)
	{
		for(i=0;i<=RAN_CHIP_NUM;i++)
		{
			memset(buff,0,len);
			//GetRandfromchip(buff, len);
			FPGA_ApplyRandomData(buff,len,i);
			//扑克检查
			if( 0 != poker_test(M, buff, len))
			{
				//返回值不为0，改组不合格
				print(PRINT_TEST,"1st data[%d]\r\n",i);
				//printf_buff_byte(buff,len);
				Count++;
			}
		}
	}
	if(Count < 1)//检查合格
		return 0;
	
	//第二次扑克检查
	Count = 0;
	for(j=0;j<5;j++)
	{
		for(i=0;i<=RAN_CHIP_NUM;i++)
		{
			memset(buff,0,len);
			FPGA_ApplyRandomData(buff,len,i);
			//扑克检查
			if( 0 != poker_test(M, buff, len))
			{
				//返回值不为0，改组不合格
				print(PRINT_TEST,"2nd data[%d]\r\n",i);
				//printf_buff_byte(buff,len);
				Count++;
			}
		}
	}
	if(Count <= 3)//检查合格
		return 0;
	else{
		//print(PRINT_TEST,"Rand ck err!\r\n");
		return -1;
	}
	return 0;
}

//随机数单次扑克检查，检查长度大于256bits
int RandomSigleTest(unsigned char *data, unsigned int len)
{
//	int i,Count;
	int M = 2;
	 //扑克检查
	if( 0 != poker_test(M,data,len))
	{
			//返回值不为0，改组不合格
			return -1;
	}
	return 0;
}	


