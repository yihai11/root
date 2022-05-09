#ifndef 	__DEVICE_H__
#define		__DEVICE_H__

#define		DEVICEVERSION			1
typedef struct DeviceInfo_str{
	unsigned	char	IssuerName[40];
	unsigned	char	DeviceName[16];
	unsigned	char 	DeviceSerial[16];
	unsigned	int		DeviceVersion;
	unsigned	int		StandardVersion;
	unsigned	int		AsymAlgAbility[2];
	unsigned	int		SymAlgAbility;
	unsigned	int 	HashAlgAbility;
	unsigned	int		BufferSize;
}	DEVICEINFO

DEVICEIONFO  MyDevice={
	
};
#endif