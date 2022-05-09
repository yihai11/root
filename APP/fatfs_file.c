/***********************************************************************
 * Copyright (c)  2020, beijing shudun Co.,Ltd .
 * All rights reserved.
 * Filename    : Abstract.txt
 * Description : log file
 * Author(s)   : jaime  
 * version     : V1.0
 * Modify date : 2020-10
 ***********************************************************************/
#include "fatfs_file.h"
#include "ff.h"
#include "internal_alg.h"
#include "fpga_sm4.h"
#include "type_code.h"

//文件系统分配：
//file 		文件夹下存放所有用户自定义文件 
//					(注：此文件夹下不可再建文件夹,否则需要自行更新清除文件区函数)
//cipher 	文件夹下存放所有密钥及相应密钥的认证码
//				cipher/pinxxx	为xxx密钥号的认证码
//				cipher/xxx		为xxx密钥文件			例：cipher/pin0		--	设备密钥(0号密钥)认证标识码
//																						cipher/0			--	设备密钥

#define ENUM_COUNT_MAX	30
#define	ENUM_NAME_SIZE	128				//索引文件名时，每个文件名所占用的空间

#define ENC_BYTE_LEN		16				//加密所需要的字节对齐数
#define PRINT_FATS 2
extern FATFS fs[_VOLUMES];//逻辑磁盘工作区.	

char cipherdir[10]="1:/cipher";
//char cipher_pin_dir[11]="1:cipherpin";
char kekdir[7]="1:/kek";				//存放kek密钥文件夹
char filedir[8]="1:/file";		  //存放用户文件文件夹
char filename_buff[136]="1:file/";		//128 +5 + 2 + 1 (文件长度128+盘符2+文件夹5+字符串结束符1)

extern unsigned char main_key[16];

//创建文件系统
void	mkFS(void)
{
	uint8_t res;
	res=f_mount(&fs[1],"1:",1);
	res=f_mkfs("1:",0,0);			//创建文件系统(只需要出厂态下创建)
	//print(PRINT_FATS,"mkfs state is %d\r\n",res);
	if(res!=FR_OK)
	{
		print(PRINT_FATS,"make fatfs err %d\r\n",res);
		while(1);
	}
	print(PRINT_FATS,"make file ok \r\n");
}
//创建文件系统内必须的文件夹cipher and file
//如果创建不成功则系统停止运行
//只在板卡首次上电或者刷机后才能运行,否则认为芯片被篡改
//
void mkFSdir(void)
{
	uint8_t res;
	res = f_mkdir(filedir);
	if(res!=FR_OK){
		if(res==FR_EXIST){
			print(PRINT_FATS,"data in eflash or spiflash chip was illegal changed\r\n");
			print(PRINT_FATS,"need manufactor to restore the error\r\n");
		}
		else{
			print(PRINT_FATS,"make cipher dir error ,error code is %d\r\n",res);
			print(PRINT_FATS,"restart to restore the error\r\n");
		}
		while(1);
	}
	res = f_mkdir(cipherdir);
	if(res!=FR_OK){
		if(res==FR_EXIST){
			print(PRINT_FATS,"data in eflash or spiflash chip was illegal changed\r\n");
			//print(PRINT_FATS,"need manufactor to restore the error\r\n");
		}
		else{
			print(PRINT_FATS,"make cipher dir error ,error code is %d\r\n",res);
			//print(PRINT_FATS,"restart to restore the error\r\n");
		}
		while(1);
	}
	res = f_mkdir(kekdir);
	if(res!=FR_OK){
		if(res==FR_EXIST){
			print(PRINT_FATS,"data in eflash or spiflash chip was illegal changed\r\n");
			//print(PRINT_FATS,"need manufactor to restore the error\r\n");
		}
		else{
			print(PRINT_FATS,"make kekdir error ,error code is %d\r\n",res);
			//print(PRINT_FATS,"restart to restore the error\r\n");
		}
		while(1);
	}
		print(PRINT_FATS,"make dir ok\r\n");
}

//初始化文件系统
//1.创建并格式化文件系统	
//2.创建必须的两个文件夹
void FS_config(void)
{
	mkFS();
	mkFSdir();
}

//保存设备密钥pin码
// 输入 pin:口令
//			pinlen：口令长度 8——16
//			*cipher:密钥指针
//			cipher_len：密钥长度
int write_usr_key( char *pin, uint8_t pinlen,uint8_t *cipher,uint8_t cipher_len)
{
	uint8_t res;
	DIR dir_p;
	FIL fp;
	UINT32 bw;
	char pin_file[14]="1:cipher/pin0";
	char cipher_file[14]="1:cipher/0";
	//创建密钥pin文件
	res = f_open(&fp,pin_file,FA_CREATE_NEW|FA_WRITE);
	if(res)
		return res;
	//写入密钥至pin文件
	res = f_write(&fp,cipher,pinlen,&bw);
	if(res)
		return res;
	f_close(&fp);
	//创建用户密钥文件
	res = f_open(&fp,cipher_file,FA_CREATE_NEW|FA_WRITE);
	if(res)
		return res;
	//写入密钥至文件中
	res = f_write(&fp,cipher,cipher_len,&bw);
	if(res)
		return res;
	f_close(&fp);
	//f_closedir(&dir_p);
	return 0;
}
/***********************************************************
*file_encrypt
*input: *message 要加密的数据指针
*				*encrymess 加密后的数据指针
*output:  0  		成功
*					1			失败
************************************************************/
int file_encrypt(uint8_t * message,uint8_t *encrymess,uint32_t data_len)
{
	int res;
	res = Sym_Crypt_WithKey(message,data_len,main_key,16,0, 0, \
					 SYM_ALG_SM4, SYM_ENCRYPTION , SYM_ECB_MODE,encrymess);
	return res;
}
/***********************************************************
*file_decrypt
*input: *message 要解密的数据指针
*				*encrymess 解密后的数据指针
*output:  0  		成功
*					1			失败
************************************************************/
int file_decrypt(uint8_t *decrymess,uint8_t *encrymess,uint32_t data_len)
{
	int res;
	res = Sym_Crypt_WithKey(encrymess,data_len,main_key,16,0, 0, \
					 SYM_ALG_SM4, SYM_DECRYPTION , SYM_ECB_MODE,decrymess);
	return res;
}

void set_file_name(char *file_name_complete,char *file_name,uint16_t name_length)
{
	memset(file_name_complete+7,0,129);
	memcpy(file_name_complete+7,file_name,name_length);
	memset(file_name_complete+7+name_length,'\0',1);
}

uint16_t create_fs_file(char *filename, uint16_t name_length, uint32_t filesize)
{
	FRESULT res;
	FIL file_c;
	uint32_t real_size;
	uint32_t write_size;
	
	real_size = (filesize + SM4_BLOCK_LEN - 1) / SM4_BLOCK_LEN * SM4_BLOCK_LEN;
	set_file_name(filename_buff, filename, name_length);
	res = f_open (&file_c, filename_buff, FA_CREATE_NEW | FA_WRITE);
	if (res != FR_OK)
	{
		return res;
	}
	else
	{
		res = f_write(&file_c, &filesize, REAL_SIZE_LEN, &write_size);
		if (res != FR_OK || write_size != REAL_SIZE_LEN)
		{
			f_close(&file_c);
			f_unlink(filename_buff);
			return res;
		}
		res = f_lseek(&file_c, real_size + REAL_SIZE_LEN);		//扩展文件尺寸
		print(PRINT_FATS,"CR fsize %ld\r\n",file_c.fsize);
		if (res != FR_OK)
		{
			f_close(&file_c);
			f_unlink(filename_buff);
			return res;
		}
	}
	f_close(&file_c);
	return 0;
}

uint8_t read_fs_file(char *filename ,uint8_t name_length, uint32_t file_offset,
						uint8_t *filebuff, uint32_t read_len, uint32_t *br)
{
	FRESULT res;
	FIL  file_c;
	uint32_t br_temp = 0;
	uint32_t len_temp = 0;
	uint16_t read_once = 0;
	
	set_file_name(filename_buff, filename, name_length);
	res = f_open(&file_c, filename_buff, FA_OPEN_EXISTING | FA_READ);
	if(res == FR_OK)
	{
		memset(filebuff, 0, read_len);
		f_lseek(&file_c, file_offset);		//偏移读取指针
		for(;read_len > 0; read_len -= br_temp)
		{
			read_once = read_len > _MAX_SS ? _MAX_SS : read_len;
			res = f_read(&file_c, filebuff+len_temp, read_once, &br_temp);
			if(br_temp == 0){
				break;
			}
			len_temp += br_temp;
			*br += br_temp;
		}
		f_close(&file_c);
	}
	
	return res;
}

uint8_t write_fs_file(char *filename,uint8_t name_length,uint32_t file_offset,\
																		 uint32_t write_len,uint8_t *filebuff){
	FRESULT res;
	FIL  file_c;
	uint32_t w_offset =0;
	set_file_name(filename_buff,filename,name_length);
	
	res = f_open(&file_c,filename_buff,FA_OPEN_EXISTING|FA_WRITE);			
	if(res==FR_OK){
//		if(file_c.fsize < file_offset)
//			return FR_EX_OVERSIZE;
		res = f_lseek(&file_c,file_offset);
		res = f_write(&file_c,filebuff,write_len,&w_offset);
	  f_close(&file_c);
		return res;
	}
	return res;
}


//delete_fs_file
//函数功能：删除指定文件
uint16_t delete_fs_file(char *filename,uint16_t name_length)
{
	FRESULT res;
	set_file_name(filename_buff,filename,name_length);
	res = f_unlink (filename_buff);
	return res;
}


//函数功能：删除指定目录中的密钥文件
uint16_t clear_filedir_file(char* filedirchar)
{
	uint16_t  j=0;
	char filename_buff0[128]={0};
	uint16_t fileL = strlen(filedirchar);
	if(fileL ==  6){ //"1:kek/"  "1:cipher/"
		strcpy(filename_buff0,"1:kek/");
	}else{
		strcpy(filename_buff0,"1:cipher/");
	}
	FRESULT res;
	DIR dir;
	FILINFO fno;
	unsigned char  *fn;
  fno.lfname = 0;
	res = f_opendir(&dir,filedirchar);
	fno.lfsize=136;		//128+1+7
	fno.lfname=pvPortMalloc(fno.lfsize);
	if(fno.lfname==NULL){
		f_closedir(&dir);
		return FR_MALLOC_ERROR;	
	}
	if (res == FR_OK ){
		for(;;){
			res = f_readdir(&dir,&fno);
			if (res != FR_OK ) break;	//读取文件夹信息失败
			fn=(unsigned char *)(*fno.lfname?fno.lfname:fno.fname);
			if(*fn==0) break;			//未读到有效文件名
			if (*fn == '.') continue;		//系统文件跳过
			j = 0;
			do
				filename_buff0[fileL+j] = *(fn+j);//未使能相对路径,使用绝对路径
			while (*(fn+j++));
			res = f_unlink(filename_buff0);
			if (res != FR_OK){ 					//&& (res != FR_DENIED)) break;
				print(PRINT_FATS,"DL file err %d\r\n",res);
			}
		}
	}
	vPortFree(fno.lfname);
	f_closedir(&dir);
	return res;
}
//clear_fs_file
//函数功能：删除所有用户文件
uint8_t clear_fs_file(void)
{
	uint16_t  j=0;
	FRESULT res;
	DIR dir;
	FILINFO fno;
	unsigned char  *fn;
  fno.lfname = 0;
	res = f_opendir(&dir,filedir);
	fno.lfsize=136;		//128+1+7
	fno.lfname=pvPortMalloc(fno.lfsize);
	if(fno.lfname==NULL){
		f_closedir(&dir);
		return FR_MALLOC_ERROR;	
	}
	if (res == FR_OK ){
		for(;;){
			res = f_readdir(&dir,&fno);
			if (res != FR_OK ) break;	//读取文件夹信息失败
			fn=(unsigned char *)(*fno.lfname?fno.lfname:fno.fname);
			if(*fn==0) break;			//未读到有效文件名
			if (*fn == '.') continue;		//系统文件跳过
			j = 0;
			do
				filename_buff[7+j] = *(fn+j);//未使能相对路径,使用绝对路径
			while (*(fn+j++));
			res = f_unlink(filename_buff);
			if (res != FR_OK){ 					//&& (res != FR_DENIED)) break;
				print(PRINT_FATS,"DL file err %d\r\n",res);
			}
		}
	}
	vPortFree(fno.lfname);
	f_closedir(&dir);
	return res;
}

//enum_usr_file
//函数功能：枚举用户文件
//输入：		file_num_start	--		起始枚举地址
//					file_count			--		读取文件数
//输出：		*enmu_file 	-- 实际读出的文件数指针
//					*outdata		--	文件名缓冲区指针
uint16_t enum_usr_file(uint16_t file_num_start,uint16_t file_count,uint8_t *enum_file,uint8_t *outdata)
{

	FRESULT res;
	DIR dir;
	FILINFO fno;
//	uint8_t *fn;
	uint16_t i=0;
	uint32_t name_point=0;
  fno.lfname = 0;
	res = f_opendir(&dir,filedir);
	fno.lfsize=136;		//128+1+7
	fno.lfname=pvPortMalloc(fno.lfsize);
	memset(fno.lfname,0,fno.lfsize);
	memset(fno.fname,0,13);
	if(fno.lfname==NULL){
		f_closedir(&dir);
		return FR_MALLOC_ERROR;
	}		
	if (res == FR_OK ){
		//读文件信息偏移
		for(;i<file_num_start;i++){
			res = f_readdir(&dir,&fno);
			if(res!=FR_OK || (fno.fname[0]==0 && fno.lfname[0]==0) )
			{
				vPortFree(fno.lfname);
				f_closedir(&dir);
				return 1;			//读文件夹下文件信息失败 或者文件数低于起始枚举数
			}
		}
		for(;;){
			res = f_readdir(&dir,&fno);
			if (res != FR_OK ) break;	//读取文件夹信息失败
			if(*fno.lfname){				//长文件名
				if(*fno.lfname =='.')
					continue;
				memcpy(outdata+name_point,fno.lfname,fno.lfsize);
				memset(fno.lfname,0,fno.lfsize);
			}else{									//短文件名
				if(*fno.fname =='.')
					continue;
				if(*fno.fname == 0)	//文件名为空
					break;
				memcpy(outdata+name_point,fno.fname,13);
				memset(fno.fname,0,13);
			}
			(*enum_file)++;
			name_point+=ENUM_NAME_SIZE;
		}
	}
	vPortFree(fno.lfname);
	f_closedir(&dir);
	return res;
}


uint8_t clear_fs(void)
{
	FRESULT res;
	res=f_mount(&fs[1],"1:",1);
	res = f_mkfs("1:",0,0);		//格式化文件系统
	return res;
	
}

//缺少补16字节的情况
void SM4_padding(uint8_t *data,uint8_t datalen)
{
	memset(data+datalen,SM4_PADDING_LEN(datalen),SM4_PADDING_LEN(datalen));
}

uint8_t SM4_depadding(uint8_t *data)
{
	uint8_t i;
	uint8_t pad=0;
	pad = *data+15;
	if(pad > 16)
		return 16;
	for(i=0;i<pad;i++)
		if(*(data+15-i) != pad)
			return 0;
	return (16-pad);
}

uint16_t CheckPara(char *filename,uint8_t name_length,uint32_t file_offset,uint32_t *oper_size)
{
	uint8_t res=0;
	FIL fil_check;
	uint32_t file_size,len;
	set_file_name(filename_buff,filename,name_length);
	res = f_open(&fil_check,filename_buff,FA_READ);
	if(res)
		return SDR_FILENOEXIST;
	
	res = f_read(&fil_check, &file_size, 4, &len);
	if(res)
		return ERR_CIPN_READKEYFILE;
	
	if((fil_check.fsize - 4)< file_offset||file_size< file_offset){
		//print(PRINT_FATS,"CK file_c.fsize offset %ld %d\r\n",fil_check.fsize,file_offset);
		f_close(&fil_check);
		return SDR_FILEOFSERR;
	}
	if((fil_check.fsize - 4) < (file_offset + *oper_size)||file_size< (file_offset + *oper_size)){
		print(PRINT_FATS,"fsize of size %ld %d %d %d\r\n",fil_check.fsize,file_size,file_offset,*oper_size);
		//print(PRINT_FATS,"check file_c.fsize offset size %d %d \r\n",(fil_check.fsize - 4),(file_offset + oper_size));
		*oper_size = file_size - file_offset;
		f_close(&fil_check);
		return SDR_FILESIZEERR;
	}
	f_close(&fil_check);
	return 0;
	
}

uint16_t read_file(char *filename, uint8_t name_length, uint32_t file_offset, uint8_t *filebuff, uint32_t *read_size)
{
	uint8_t res=0;
	uint8_t head_remain=0;
	uint8_t	tail_remain=0;	
	uint32_t head_addr=0;
	uint32_t buff_len=0;
	uint32_t br=0;
	uint8_t *enc_data, *dec_data;
	FIL fil_check;
	head_remain = file_offset % ENC_BYTE_LEN ;  	//sm4 16字节对齐
	head_addr = file_offset - head_remain + REAL_SIZE_LEN;
	//tail_remain = (ENC_BYTE_LEN - (*read_size + head_remain) % ENC_BYTE_LEN) % ENC_BYTE_LEN;
	//buff_len = *read_size + head_remain + tail_remain;
	
	res = CheckPara(filename, name_length, file_offset, read_size);	//检查参数是否合法
	if(0 != res){
		if(SDR_FILESIZEERR != res){
			return res;
		}
	}
	tail_remain = (ENC_BYTE_LEN - (*read_size + head_remain) % ENC_BYTE_LEN) % ENC_BYTE_LEN;
	buff_len = *read_size + head_remain + tail_remain;
	if(0 == buff_len)return 0;
	enc_data = pvPortMalloc(buff_len);
	if(enc_data == NULL)
		return ERR_COMM_MALLOC;
	dec_data = pvPortMalloc(buff_len);
	if(dec_data == NULL){
		vPortFree(enc_data);
		return ERR_COMM_MALLOC;}
	//读取fs中的密文数据
	res = read_fs_file(filename, name_length, head_addr, enc_data, buff_len, &br);
	//解密数据
	file_decrypt(dec_data, enc_data, buff_len);
	memcpy(filebuff, dec_data + head_remain, *read_size);
	
	vPortFree(enc_data);
	vPortFree(dec_data);
	if(res){
		return ERR_CIPN_READKEYFILE;
	}
	return 0;
}

//write_file
//input:		*filename		-	file name point
//				name_length	-	file name length
//				file_offset	-	offset of file write
//				*filebuff		-	file buff point
//				write_size	-	the size of data that write in FS 
uint16_t write_file(char *filename,uint8_t name_length,uint32_t file_offset, \
																 uint8_t *filebuff,uint32_t write_size)
{
	uint8_t res = 0;
	uint8_t head_remain = 0;
	uint8_t	tail_remain = 0;
	uint8_t data_temp[16] = {0};
	uint8_t paddinglen = 0;						//最后16字节有效数据长度
	uint32_t br = 0;
	uint32_t head_addr, tail_addr, buff_len;
	uint8_t *enc_data, *dec_data;
	
	head_remain = file_offset % ENC_BYTE_LEN;  	//sm4 16字节对齐
	head_addr = file_offset - head_remain + REAL_SIZE_LEN;
	tail_remain = (ENC_BYTE_LEN - (write_size + head_remain) % ENC_BYTE_LEN) % ENC_BYTE_LEN;
	buff_len = write_size + head_remain + tail_remain;
	
	res = CheckPara(filename, name_length, file_offset, &write_size);	//检查参数是否合法
	if(res)
	{
		return res;
	}
	
	enc_data = pvPortMalloc(buff_len);
	if(enc_data == NULL)
		return ERR_COMM_MALLOC;
	dec_data = pvPortMalloc(buff_len);
	if(dec_data == NULL){
		vPortFree(enc_data);
		return ERR_COMM_MALLOC;
	}
	
	res = read_fs_file(filename, name_length, head_addr, enc_data, buff_len, &br);
	if (res != FR_OK)
	{
		return ERR_CIPN_OPENKEYFILE;
	}
	file_decrypt(dec_data, enc_data, buff_len);
	memcpy(dec_data + head_remain, filebuff, write_size);
	
#if 0
	if((head_remain + write_size) > ENC_BYTE_LEN)
	{	//跨页(16字节)写
	tail_addr = file_offset+write_size+tail_remain-ENC_BYTE_LEN;
	//读出首页(16B)数据																																																																												
		res = read_fs_file(filename,name_length,head_addr,enc_data,ENC_BYTE_LEN,&br);
		file_decrypt(dec_data,enc_data,ENC_BYTE_LEN);

		memcpy(dec_data+head_remain,filebuff,ENC_BYTE_LEN-head_remain);
		
		//更新中间部分明文数据
		if((write_size+head_remain-ENC_BYTE_LEN) >= ENC_BYTE_LEN)
			memcpy(dec_data+ENC_BYTE_LEN,filebuff+ENC_BYTE_LEN, \
						 write_size+head_remain+tail_remain-2*ENC_BYTE_LEN);
		
		//读出末16字节加密数据
		if(tail_remain!=0){
			res = read_fs_file(filename,name_length,tail_addr,enc_data,ENC_BYTE_LEN,&br);
			file_decrypt(data_temp,enc_data,ENC_BYTE_LEN);	
			
			memcpy(data_temp,filebuff+write_size+tail_remain-ENC_BYTE_LEN,ENC_BYTE_LEN-tail_remain);
			memcpy(dec_data+buff_len-ENC_BYTE_LEN,data_temp,ENC_BYTE_LEN);
		}
	}
	else
	{	//单页(16B)写
		res = read_fs_file(filename,name_length,head_addr,enc_data,ENC_BYTE_LEN,&br);
		file_decrypt(dec_data,enc_data,ENC_BYTE_LEN);
		
		memcpy(dec_data+head_remain,filebuff,write_size);
	}
#endif
	
	//加密更新后的明文数据
	file_encrypt(dec_data, enc_data, buff_len);
	//写加密数据到文件中
	res = write_fs_file(filename, name_length, head_addr, buff_len, enc_data);
	
	vPortFree(enc_data); 
	vPortFree(dec_data);
	if(res){
		return ERR_CIPN_WRITKEYFILE;
	}
	return 0;
}
