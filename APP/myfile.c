#include "myfile.h"
#include "fpga.h"
#include "gd25q256b.h"

#define FPGA_PRO_FILE	"0:HSCM.BIT"
static char path[512]="0:";
static char fpga_pro_fn[32]="HSCM.BIT";

static char config_txt[20]="config.txt";
static const uint32_t FILESIZE=0xAE9E05;		//0-0xAE9E04

FATFS fs; 
FIL fsrc;         /* file objects */   
FRESULT res;
UINT br;

FRESULT FATFS_init(	BYTE drv)
{    
	
	if(f_mount(drv,&fs)==FR_OK){

		return FR_OK;
	}
	else
		return 1;
}

FRESULT FAT_init(USHORT mkfs_permission)
{
	DIR dir;
	sl811_disk_init();
	delay_ms(500);
	if(f_mount(0,&fs)==FR_OK){
#ifdef FF_DEBUG
		printf("U盘挂载成功\r\n");
#endif 
	}
	else
		printf("U盘挂载失败\r\n");
		delay_ms(500);
	if(mkfs_permission){					//格式化U盘 状态系统
		res=f_opendir(&dir, path);
		if(res==FR_NO_FILESYSTEM){
			printf("\r\n no file system\r\n");
			res=f_mkfs(0,0,0);
#ifdef	FF_DEBUG
		printf("U盘格式化完成，mkfs state is %d \r\n",res);
#endif
		}
		else {
			res=f_opendir(&dir, path);
			printf("opendir code is %d",res);
			return res;
		}
	}
	else{
		res=f_opendir(&dir, path);
		if(res!=FR_OK){
#ifdef	FF_DEBUG
			printf("opendir error,error code is %d",res);
#endif
			return res;
		}
	}
}

FRESULT scan_files (char* path)
{
    FILINFO fno;
		uint8_t error=FR_NO_FILE;
    DIR dir;
    int i;
    char *fn;
#if _USE_LFN
    static char lfn[_MAX_LFN * (_DF1S ? 2 : 1) + 1];
    fno.lfname = lfn;
    fno.lfsize = sizeof(lfn);
#endif

    res = f_opendir(&dir, path);
    if (res == FR_OK) {
        i = strlen(path);
        for (;;) {
            res = f_readdir(&dir, &fno);
            if (res != FR_OK || fno.fname[0] == 0) break;
            if (fno.fname[0] == '.') continue;
#if _USE_LFN
            fn = *fno.lfname ? fno.lfname : fno.fname;
#else
            fn = fno.fname;
#endif
						printf(  " \r\n 文件名为: %s \r\n",fno.fname );
						if(!strcmp(fn,fpga_pro_fn))		//找到目标文件
							{
								printf("get the file: %s/%s \r\n", path, fn);
								error=FR_OK;
								return error;
							}
					/*
            if (fno.fattrib & AM_DIR) {
                sprintf(&path[i], "/%s", fn);
                res = scan_files(path);
                if (res != FR_OK) break;
                path[i] = 0;
            } else {
							if(!strcmp(fn,fpga_pro_fn))		//找到目标文件
							{
								printf("get the file: %s/%s \r\n", path, fn);
								error=FR_OK;
								return error;
							}
							else
								printf("%s/%s \r\n", path, fn);
            }
						*/
        }
				return error;
    }

    return res;
}
/***********************************************************************
 * fpga_pro_fromflash
 * 输入参数 ：无
 * 返回值   ：无
 * 函数功能 ：从SPIFLASH读取固件并加载固件至FPGA中
 ***********************************************************************/
void fpga_pro_fromflash(void)
{
	uint8_t databuff[256]={0};
	uint32_t dataRW=0,datanum=0;
	if(!fpga_pro_start())
		printf("加载固件握手成功\r\n");
	else
		printf("加载固件握手失败\r\n");
	printf("开始加载固件\r\n");
	for(datanum=0;datanum<FILESIZE;){
		if((FILESIZE-datanum) >= 256){
			dataRW=256;
			flash_page_read_X1(databuff,datanum,dataRW);
			datanum+=256;
		}
		else if (((FILESIZE-datanum)>0) && ((FILESIZE-datanum)<256)){
			dataRW=FILESIZE-datanum;
			flash_page_read_X1(databuff,datanum,dataRW);
			datanum=FILESIZE;
		}
		else if(datanum == FILESIZE){
			printf("固件读取结束\r\n");
			break;
		}
		fpga_pro_write(databuff,dataRW);
	}
	printf("固件加载结束\r\n等待done信号\r\n");
	if(fpga_wait_done(30))
			printf("wait done signal timeout\r\n");
	else
			printf("download firmware success\r\n");
}

/***********************************************************************
 * fpga_pro_fromusb
 * 输入参数 ：无
 * 返回值   ：无
 * 函数功能 ：从USB读取固件并加载固件至FPGA中
 ***********************************************************************/
void fpga_pro_fromusb(void)
{
	FIL pro_fil;
	FRESULT res;
	UINT br;
	uint8_t buff[512]={0x00};		//FAT 的buff为512，所以此处必须小于等于512
	uint16_t i=0,sign=0;
	//fpga_init();
	if(scan_files(path) == FR_OK){
		f_open(&pro_fil,FPGA_PRO_FILE,FA_READ);
		if(!fpga_pro_start())
			printf("加载固件握手成功\r\n");
		else
			printf("加载固件握手失败\r\n");
		printf("file data is \r\n");
		for(;;){
			res=f_read(&pro_fil,buff,sizeof(buff),&br);
			if(res||br==0){
				printf("文件结束\r\n");
				break;
			}
		//else{
		//	printf("res is %d ,br is %d\r\n",res,br);
		//}
		//if(!sign){
		//	sign=1;
		//	for(i=0;i<512;i++)
		//		printf("0x%2x ",buff[i]);
		//}
		 fpga_pro_write(buff,br);
		}
		f_close(&pro_fil);
		if(fpga_wait_done(20))
			printf("wait done timeout\r\n");
		else
			printf("download done\r\n");
	}
	else
		printf("scan file fail\r\n");
	
}
/***********************************************************************
 * SaveDataFromUsb
 * 输入参数 ：无
 * 返回值   ：无
 * 函数功能 ：从usb中读取固件文件并保存到spiflash中
 ***********************************************************************/
void SaveDataFromUsb(void)
{
	FIL pro_fil;
	FRESULT res;
	UINT br;
	uint8_t buff[256]={0};		//FAT 的buff为512，所以此处必须小于等于512
	uint8_t buff2[256]={0};
	uint16_t i=0,sign=0;
	uint32_t addr=0,sec=0;
	if(scan_files(path) == FR_OK){
		if(f_open(&pro_fil,FPGA_PRO_FILE,FA_READ) ==FR_OK)
			printf("file open success\r\n");
		else
			printf("file open fail \r\n");
	/*	f_read(&pro_fil,buff,sizeof(buff),&br);
		for(i=0;i<512;i++)
					printf("0x%2x ",buff[i]);
		printf("\r\n\r\n 擦除flash\r\n");
		flash_erase_sector(addr);
		printf("写入flash\r\n");
		flash_page_program(buff, addr, 256);
		printf("读取写入结果:\r\n");
		flash_page_read_X1(buff2,0,256);
		for(i=0;i<512;i++)
			printf("0x%2x ",*(buff2+i));
	*/	
		printf("开始读写数据\r\n");
		for(;;){
			res=f_read(&pro_fil,buff,sizeof(buff),&br);
			if(res||br==0){
				printf("文件结束\r\n");
				break;
			}
		//	else{
		//		printf("res is %d ,br is %d\r\n",res,br);
		//	}
		/*	if(!sign){
				sign=1;
				for(i=0;i<512;i++)
					printf("0x%2x ",buff[i]);
			}*/
			if(!(sec++%16))
				flash_erase_sector(addr);
			flash_page_program(buff, addr, br);
			flash_page_read_X1(buff2,addr,br);
			for(i=0;i<256;i++){
				if(buff[i]!=buff2[i])
					printf("地址为 %d 的第 %d 个数据不正确\r\n",addr,i);
			}
			addr+=256;
		}
		f_close(&pro_fil);
		printf("写入flash结束\r\n");
	}
	else
		printf("scan file fail\r\n");
	
}




void testfatfs(void)
{
		FRESULT res,res2;
		FILINFO fno;
    DIR dir;
		FIL fsrc;
		UINT br, bw; 
    int i;
		char buffer[8];
    char *fn;
		res=f_opendir(&dir, path);
		if(res==FR_NO_FILESYSTEM){
			res2=f_mkfs(0,0,0);
			printf("mkfs state is %d \r\n",res2);
		}
		res=f_opendir(&dir, path);
		if(res== FR_OK){
		//while(f_opendir(&dir, path) == FR_OK){
			printf("打开根目录成功\r\n");
			while( (f_readdir(&dir, &fno)    == FR_OK)){
				if( !fno.fname[0] )				              /* 文件名为空即到达了目录的末尾，退出 */
          break; 
				printf(  " \r\n 文件名为: %s \r\n",fno.fname );
				if(fno.fname=="TEST.TXT")
					break;
				memset(fno.fname,0,13*sizeof(char));
			}
			res = f_open( &fsrc, fno.fname, FA_OPEN_EXISTING | FA_READ ); /* 以只读方式打开 */					

    	res = f_read( &fsrc, buffer, sizeof(buffer), &br );
			printf("%s is %s",fno.fname,buffer);
			f_close(&fsrc);
		}
		else
			printf("opendir fail code is :%d \r\n",res);
		while(1);
}
