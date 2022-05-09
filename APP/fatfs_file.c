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

//�ļ�ϵͳ���䣺
//file 		�ļ����´�������û��Զ����ļ� 
//					(ע�����ļ����²����ٽ��ļ���,������Ҫ���и�������ļ�������)
//cipher 	�ļ����´��������Կ����Ӧ��Կ����֤��
//				cipher/pinxxx	Ϊxxx��Կ�ŵ���֤��
//				cipher/xxx		Ϊxxx��Կ�ļ�			����cipher/pin0		--	�豸��Կ(0����Կ)��֤��ʶ��
//																						cipher/0			--	�豸��Կ

#define ENUM_COUNT_MAX	30
#define	ENUM_NAME_SIZE	128				//�����ļ���ʱ��ÿ���ļ�����ռ�õĿռ�

#define ENC_BYTE_LEN		16				//��������Ҫ���ֽڶ�����
#define PRINT_FATS 2
extern FATFS fs[_VOLUMES];//�߼����̹�����.	

char cipherdir[10]="1:/cipher";
//char cipher_pin_dir[11]="1:cipherpin";
char kekdir[7]="1:/kek";				//���kek��Կ�ļ���
char filedir[8]="1:/file";		  //����û��ļ��ļ���
char filename_buff[136]="1:file/";		//128 +5 + 2 + 1 (�ļ�����128+�̷�2+�ļ���5+�ַ���������1)

extern unsigned char main_key[16];

//�����ļ�ϵͳ
void	mkFS(void)
{
	uint8_t res;
	res=f_mount(&fs[1],"1:",1);
	res=f_mkfs("1:",0,0);			//�����ļ�ϵͳ(ֻ��Ҫ����̬�´���)
	//print(PRINT_FATS,"mkfs state is %d\r\n",res);
	if(res!=FR_OK)
	{
		print(PRINT_FATS,"make fatfs err %d\r\n",res);
		while(1);
	}
	print(PRINT_FATS,"make file ok \r\n");
}
//�����ļ�ϵͳ�ڱ�����ļ���cipher and file
//����������ɹ���ϵͳֹͣ����
//ֻ�ڰ忨�״��ϵ����ˢ�����������,������ΪоƬ���۸�
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

//��ʼ���ļ�ϵͳ
//1.��������ʽ���ļ�ϵͳ	
//2.��������������ļ���
void FS_config(void)
{
	mkFS();
	mkFSdir();
}

//�����豸��Կpin��
// ���� pin:����
//			pinlen������� 8����16
//			*cipher:��Կָ��
//			cipher_len����Կ����
int write_usr_key( char *pin, uint8_t pinlen,uint8_t *cipher,uint8_t cipher_len)
{
	uint8_t res;
	DIR dir_p;
	FIL fp;
	UINT32 bw;
	char pin_file[14]="1:cipher/pin0";
	char cipher_file[14]="1:cipher/0";
	//������Կpin�ļ�
	res = f_open(&fp,pin_file,FA_CREATE_NEW|FA_WRITE);
	if(res)
		return res;
	//д����Կ��pin�ļ�
	res = f_write(&fp,cipher,pinlen,&bw);
	if(res)
		return res;
	f_close(&fp);
	//�����û���Կ�ļ�
	res = f_open(&fp,cipher_file,FA_CREATE_NEW|FA_WRITE);
	if(res)
		return res;
	//д����Կ���ļ���
	res = f_write(&fp,cipher,cipher_len,&bw);
	if(res)
		return res;
	f_close(&fp);
	//f_closedir(&dir_p);
	return 0;
}
/***********************************************************
*file_encrypt
*input: *message Ҫ���ܵ�����ָ��
*				*encrymess ���ܺ������ָ��
*output:  0  		�ɹ�
*					1			ʧ��
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
*input: *message Ҫ���ܵ�����ָ��
*				*encrymess ���ܺ������ָ��
*output:  0  		�ɹ�
*					1			ʧ��
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
		res = f_lseek(&file_c, real_size + REAL_SIZE_LEN);		//��չ�ļ��ߴ�
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
		f_lseek(&file_c, file_offset);		//ƫ�ƶ�ȡָ��
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
//�������ܣ�ɾ��ָ���ļ�
uint16_t delete_fs_file(char *filename,uint16_t name_length)
{
	FRESULT res;
	set_file_name(filename_buff,filename,name_length);
	res = f_unlink (filename_buff);
	return res;
}


//�������ܣ�ɾ��ָ��Ŀ¼�е���Կ�ļ�
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
			if (res != FR_OK ) break;	//��ȡ�ļ�����Ϣʧ��
			fn=(unsigned char *)(*fno.lfname?fno.lfname:fno.fname);
			if(*fn==0) break;			//δ������Ч�ļ���
			if (*fn == '.') continue;		//ϵͳ�ļ�����
			j = 0;
			do
				filename_buff0[fileL+j] = *(fn+j);//δʹ�����·��,ʹ�þ���·��
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
//�������ܣ�ɾ�������û��ļ�
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
			if (res != FR_OK ) break;	//��ȡ�ļ�����Ϣʧ��
			fn=(unsigned char *)(*fno.lfname?fno.lfname:fno.fname);
			if(*fn==0) break;			//δ������Ч�ļ���
			if (*fn == '.') continue;		//ϵͳ�ļ�����
			j = 0;
			do
				filename_buff[7+j] = *(fn+j);//δʹ�����·��,ʹ�þ���·��
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
//�������ܣ�ö���û��ļ�
//���룺		file_num_start	--		��ʼö�ٵ�ַ
//					file_count			--		��ȡ�ļ���
//�����		*enmu_file 	-- ʵ�ʶ������ļ���ָ��
//					*outdata		--	�ļ���������ָ��
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
		//���ļ���Ϣƫ��
		for(;i<file_num_start;i++){
			res = f_readdir(&dir,&fno);
			if(res!=FR_OK || (fno.fname[0]==0 && fno.lfname[0]==0) )
			{
				vPortFree(fno.lfname);
				f_closedir(&dir);
				return 1;			//���ļ������ļ���Ϣʧ�� �����ļ���������ʼö����
			}
		}
		for(;;){
			res = f_readdir(&dir,&fno);
			if (res != FR_OK ) break;	//��ȡ�ļ�����Ϣʧ��
			if(*fno.lfname){				//���ļ���
				if(*fno.lfname =='.')
					continue;
				memcpy(outdata+name_point,fno.lfname,fno.lfsize);
				memset(fno.lfname,0,fno.lfsize);
			}else{									//���ļ���
				if(*fno.fname =='.')
					continue;
				if(*fno.fname == 0)	//�ļ���Ϊ��
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
	res = f_mkfs("1:",0,0);		//��ʽ���ļ�ϵͳ
	return res;
	
}

//ȱ�ٲ�16�ֽڵ����
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
	head_remain = file_offset % ENC_BYTE_LEN ;  	//sm4 16�ֽڶ���
	head_addr = file_offset - head_remain + REAL_SIZE_LEN;
	//tail_remain = (ENC_BYTE_LEN - (*read_size + head_remain) % ENC_BYTE_LEN) % ENC_BYTE_LEN;
	//buff_len = *read_size + head_remain + tail_remain;
	
	res = CheckPara(filename, name_length, file_offset, read_size);	//�������Ƿ�Ϸ�
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
	//��ȡfs�е���������
	res = read_fs_file(filename, name_length, head_addr, enc_data, buff_len, &br);
	//��������
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
	uint8_t paddinglen = 0;						//���16�ֽ���Ч���ݳ���
	uint32_t br = 0;
	uint32_t head_addr, tail_addr, buff_len;
	uint8_t *enc_data, *dec_data;
	
	head_remain = file_offset % ENC_BYTE_LEN;  	//sm4 16�ֽڶ���
	head_addr = file_offset - head_remain + REAL_SIZE_LEN;
	tail_remain = (ENC_BYTE_LEN - (write_size + head_remain) % ENC_BYTE_LEN) % ENC_BYTE_LEN;
	buff_len = write_size + head_remain + tail_remain;
	
	res = CheckPara(filename, name_length, file_offset, &write_size);	//�������Ƿ�Ϸ�
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
	{	//��ҳ(16�ֽ�)д
	tail_addr = file_offset+write_size+tail_remain-ENC_BYTE_LEN;
	//������ҳ(16B)����																																																																												
		res = read_fs_file(filename,name_length,head_addr,enc_data,ENC_BYTE_LEN,&br);
		file_decrypt(dec_data,enc_data,ENC_BYTE_LEN);

		memcpy(dec_data+head_remain,filebuff,ENC_BYTE_LEN-head_remain);
		
		//�����м䲿����������
		if((write_size+head_remain-ENC_BYTE_LEN) >= ENC_BYTE_LEN)
			memcpy(dec_data+ENC_BYTE_LEN,filebuff+ENC_BYTE_LEN, \
						 write_size+head_remain+tail_remain-2*ENC_BYTE_LEN);
		
		//����ĩ16�ֽڼ�������
		if(tail_remain!=0){
			res = read_fs_file(filename,name_length,tail_addr,enc_data,ENC_BYTE_LEN,&br);
			file_decrypt(data_temp,enc_data,ENC_BYTE_LEN);	
			
			memcpy(data_temp,filebuff+write_size+tail_remain-ENC_BYTE_LEN,ENC_BYTE_LEN-tail_remain);
			memcpy(dec_data+buff_len-ENC_BYTE_LEN,data_temp,ENC_BYTE_LEN);
		}
	}
	else
	{	//��ҳ(16B)д
		res = read_fs_file(filename,name_length,head_addr,enc_data,ENC_BYTE_LEN,&br);
		file_decrypt(dec_data,enc_data,ENC_BYTE_LEN);
		
		memcpy(dec_data+head_remain,filebuff,write_size);
	}
#endif
	
	//���ܸ��º����������
	file_encrypt(dec_data, enc_data, buff_len);
	//д�������ݵ��ļ���
	res = write_fs_file(filename, name_length, head_addr, buff_len, enc_data);
	
	vPortFree(enc_data); 
	vPortFree(dec_data);
	if(res){
		return ERR_CIPN_WRITKEYFILE;
	}
	return 0;
}
