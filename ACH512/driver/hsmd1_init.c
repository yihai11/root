#include "sram.h"
#include "fpga.h"
#include "hsmd1_init.h"
#include "config.h"
#if !NEW

const static uint32_t smd1_init0_data[220] = 
{
	0x00000200, 0x04002000, 0x28000000, 0x00030000, 0x31212000, 0x0a212100, 0x03212115,
	0x07302100, 0x03222215, 0x07312200, 0x30000000, 0x00000200, 0x04002200, 0x28000000,
	0x00030000, 0x31232200, 0x0a232300, 0x03232315, 0x07232300, 0x0b000000, 0x28000000,
	0x28000000, 0x30000000, 0x00000200, 0x04002300, 0x28000000, 0x00030000, 0x31262400,
	0x03212106, 0x322a2521, 0x0926262a, 0x0a262600, 0x03262615, 0x03272715, 0x07262600,
	0x00000200, 0x01262620, 0x07262600, 0x04002623, 0x29000000, 0x30000000, 0x00000200,
	0x04002000, 0x00030000, 0x03212106, 0x03222206, 0x08012100, 0x28000000, 0x31232000,
	0x32262021, 0x0a232300, 0x03232315, 0x07302300, 0x03242415, 0x07312400, 0x30000000,
	0x00000200, 0x01262015, 0x04012600, 0x00000200, 0x04002000, 0x28000000, 0x00030000,
	0x32232021, 0x0a232300, 0x03232315, 0x07302300, 0x03242415, 0x07312400, 0x30000000,
	0x00000200, 0x04002000, 0x28000000, 0x0d2a2116, 0x0f2a2a17, 0x032c2a20, 0x032c2c02,
	0x012c2c23, 0x072c2c00, 0x00030000, 0x03242406, 0x03252506, 0x322d2b24, 0x092d2d26,
	0x0a262d00, 0x322d2c26, 0x0a2d2d00, 0x08002d00, 0x28000000, 0x032d2d15, 0x07302d00,
	0x30000000, 0x00000200, 0x04002000, 0x28000000, 0x07302000, 0x03202002, 0x06252000,
	0x03252515, 0x07252500, 0x00030000, 0x31212500, 0x0a212100, 0x03212115, 0x07312100,
	0x03222215, 0x07322200, 0x30000000, 0x00000200, 0x04002000, 0x28000000, 0x07302000,
	0x03202002, 0x06262000, 0x03262615, 0x07262600, 0x00030000, 0x32232621, 0x07280900,
	0x0229030a, 0x072a0500, 0x09282823, 0x0a282800, 0x03282815, 0x07312800, 0x03292915,
	0x07322900, 0x30000000, 0x00000200, 0x04002000, 0x00030000, 0x03232306, 0x03242406,
	0x08032300, 0x28000000, 0x31262100, 0x32292223, 0x09262629, 0x0a262600, 0x03262615,
	0x07262600, 0x00000200, 0x012c2625, 0x012e2c21, 0x032e2e02, 0x032e2e20, 0x07302c00,
	0x07322e00, 0x30000000, 0x00000200, 0x04002000, 0x28000000, 0x07302400, 0x03202002,
	0x03222202, 0x03202021, 0x03202022, 0x0b000000, 0x30000000, 0x00030000, 0x02210321,
	0x00030000, 0x03242006, 0x03252106, 0x08002400, 0x28000000, 0x0b000000, 0x30000000,
	0x00000200, 0x04002000, 0x28000000, 0x03202002, 0x06262000, 0x03262615, 0x07262600,
	0x00030000, 0x32232621, 0x0a232300, 0x03232315, 0x07302300, 0x03242415, 0x07312400,
	0x30000000, 0x00000200, 0x01222021, 0x07302200, 0x30000000, 0x00000200, 0x02222021,
	0x07302200, 0x30000000, 0x00000200, 0x03202002, 0x03222021, 0x07302200, 0x30000000,
	0x00000200, 0x03202002, 0x05222021, 0x03222215, 0x07302200, 0x30000000, 0x00000200,
	0x04002000, 0x28000000, 0x03202002, 0x06212000, 0x03212115, 0x07302100, 0x30000000,
	0x30000000, 0x28000000, 0x30000000, 0x30000000, 0x30000000, 0x30000000, 0xffffffff,
	0xffffffff, 0xffffffff, 0xffffffff
};

const static uint32_t smd1_init1_data[168] = 
{
	0x00000200, 0x01252015, 0x04012500, 0x28000000, 0x00030000, 0x31212000, 0x30000000,
	0x00000200, 0x04012100, 0x01272115, 0x04022700, 0x28000000, 0x00030000, 0x31232200,
	0x00000200, 0x03272702, 0x06282700, 0x0c000000, 0x01302023, 0x07303000, 0x04003000,
	0x01233022, 0x07232300, 0x04012300, 0x28000000, 0x03243021, 0x03242402, 0x02232224,
	0x03312328, 0x07313100, 0x04003100, 0x28000000, 0x30000000, 0x00000200, 0x04012400,
	0x01252324, 0x07252500, 0x04022500, 0x28000000, 0x00030000, 0x31262400, 0x03222206,
	0x322a2521, 0x29000000, 0x30000000, 0x00030000, 0x28000000, 0x31232000, 0x32262021,
	0x0a262600, 0x03262615, 0x07322600, 0x03272715, 0x07332700, 0x30000000, 0x00030000,
	0x03212106, 0x03222206, 0x08022100, 0x28000000, 0x32232021, 0x30000000, 0x00000200,
	0x04012300, 0x01292315, 0x04022900, 0x28000000, 0x0d2b2416, 0x0f2b2b17, 0x00030000,
	0x03262606, 0x03272706, 0x02280503, 0x322d2b24, 0x322d2c26, 0x28000000, 0x032e2e15,
	0x07312e00, 0x30000000, 0x28000000, 0x00030000, 0x31212500, 0x30000000, 0x00030000,
	0x03212106, 0x03222206, 0x08012100, 0x28000000, 0x32232621, 0x30000000, 0x00000200,
	0x04012100, 0x04022200, 0x00030000, 0x28000000, 0x31262100, 0x32292223, 0x00000200,
	0x03222202, 0x032d2022, 0x07312d00, 0x30000000, 0x28000000, 0x00000200, 0x03232302,
	0x03232321, 0x0c000000, 0x01232320, 0x02232324, 0x07312300, 0x30000000, 0x00030000,
	0x03272206, 0x03282306, 0x08012700, 0x28000000, 0x07260500, 0x07290500, 0x0c000000,
	0x09242427, 0x0a242400, 0x03242415, 0x07302400, 0x03252515, 0x07312500, 0x30000000,
	0x00030000, 0x03212106, 0x03222206, 0x08012100, 0x28000000, 0x32232621, 0x30000000,
	0x30000000, 0x30000000, 0x30000000, 0x30000000, 0x28000000, 0x30000000, 0x00030000,
	0x03202006, 0x05222021, 0x03222215, 0x07302200, 0x30000000, 0x00030000, 0x04002003,
	0x28000000, 0x03202006, 0x06212000, 0x03212115, 0x07302100, 0x30000000, 0x00030000,
	0x01222021, 0x07302200, 0x30000000, 0x00030000, 0x02222021, 0x07302200, 0x30000000,
	0x00030000, 0x03202006, 0x03222021, 0x07302200, 0x30000000, 0xffffffff, 0xffffffff
};

const static uint32_t smd1_init2_data[192] = 
{
	0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0x7203df6b, 0x21c6052b, 0x53bbf409, 
	0x39d54123, 0x6f39132f, 0x82e4c7bc, 0x2b0068d3, 0xb08941d4, 0xdf1e8d34, 0xfc8319a5, 
	0x327f9e88, 0x72350975, 0xeb5e412b, 0x22b3d3b6, 0x20fc84c3, 0xaffe0d43, 0xd4412542, 
	0xc5342a7d, 0xad5d36ee, 0x873fb0dd, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 
	0xffffffff, 0x00000000, 0xffffffff, 0xffffffff, 0xfffffffc, 0x00000001, 0xfffffffe, 
	0x00000000, 0xffffffff, 0x00000001, 0x00000000, 0x00000001, 0x00000004, 0x00000000, 
	0x00000000, 0x00000000, 0x00000003, 0xfffffffc, 0x00000000, 0x00000004, 0x00000040, 
	0x00000020, 0x00000010, 0x00000010, 0x0000002f, 0xfffffff0, 0x00000020, 0x00000030, 
	0xfffffff2, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffff3, 0x0000000c, 0xffffffff, 
	0xfffffff3, 0x903f8622, 0xe8838b21, 0x49e60541, 0x7a9470f1, 0xc73cde6b, 0xa6d4deae, 
	0x4348c18c, 0xaf037508, 0x4459e97d, 0x8704ec17, 0x5a87b666, 0xb0930f0c, 0xf9e607b9, 
	0x729b013f, 0x84ca2643, 0xd0600a7a, 0x8f359753, 0x075cd6f6, 0x3533ec19, 0xb8a923e3, 
	0x07d795e3, 0x34ca57ea, 0x04d53964, 0xf0b43775, 0xc09e1fe1, 0x4aa8a4fb, 0x34381262, 
	0xf203b2c1, 0x70407e79, 0x6437fecd, 0x2ccf8082, 0xeb60c348, 0x2c25a5c8, 0xf788c9e7, 
	0x700e80e2, 0x244ec4a3, 0x3d73af83, 0xf83b8ddd, 0xff5933b4, 0x883e3f21, 0x4471a7c5, 
	0x4cca7d66, 0x5d96c92f, 0x533ccf43, 0xdf48a731, 0x187b7e95, 0xd3ba1388, 0xe6836771, 
	0xec7a0511, 0x12d090e9, 0x18910872, 0x6609f928, 0xe91943c5, 0xe1fc3968, 0x04256ede, 
	0x81eb8c59, 0x27994104, 0x5a2d3159, 0xa003da59, 0x466d30d4, 0xafdc4c3d, 0x45534dda, 
	0xee7d586a, 0x2a452d43, 0x8d5b3d1b, 0x30599d1c, 0x7ffe78f5, 0x0158b97d, 0xe0684bdc, 
	0x88473877, 0xc1c1b801, 0xb6628cc5, 0x54910ad4, 0xff79f940, 0x2d59190a, 0x1dc49448, 
	0x9527d593, 0xf5aeae60, 0xece64a90, 0x80af78e7, 0xe8242565, 0x095c3079, 0xb6c3b762, 
	0x41b7b231, 0x6c653c2c, 0x20eca6f5, 0x9b3bf422, 0x8f4f85b9, 0xc5db0be9, 0x0d2e255f, 
	0xcc849156, 0x8ce4163b, 0x82b475e7, 0x16b51c1e, 0xc95379ba, 0x017c3b63, 0x103aaf68, 
	0x6f39dedb, 0x99816aa0, 0x36995785, 0xebcdead9, 0xaa98a39f, 0xa90a9a4a, 0x458bfe12, 
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
	0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xffffffff, 0xffffffff, 
	0xffffffff, 0xffffffff, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000, 
	0x00000000, 0x00000000, 0x00000000
};

#endif

#if NEW

const static uint32_t smd1_init0_data[244] = 
{
0x00000200, 0x04002000, 0x28000000, 0x00030000, 0x31212000, 0x0a212100, 0x08022100, 
0x28000000, 0x00000200, 0x07322000, 0x30000000, 0x28000000, 0x00000200, 0x04032200, 
0x07381800, 0x28000000, 0x00030000, 0x31232200, 0x0a232300, 0x08042300, 0x03232315, 
0x07232300, 0x28000000, 0x28000000, 0x28000000, 0x30000000, 0x00000200, 0x04002300, 
0x28000000, 0x00030000, 0x31262400, 0x03212106, 0x322a2521, 0x0926262a, 0x0a262600, 
0x071d1a00, 0x071e1b00, 0x071f1c00, 0x04032703, 0x28000000, 0x08042600, 0x00000200, 
0x01383815, 0x07383800, 0x28000000, 0x00030000, 0x03262615, 0x03272715, 0x07262600, 
0x00000200, 0x01262620, 0x07262600, 0x04052623, 0x02383815, 0x07383800, 0x29050000, 
0x30000000, 0x00000200, 0x04002000, 0x07381800, 0x28000000, 0x02383815, 0x07383800, 
0x00030000, 0x03212106, 0x03222206, 0x08012100, 0x28000000, 0x31232000, 0x32262021, 
0x0a232300, 0x08012300, 0x071d1a00, 0x071e1b00, 0x071f1c00, 0x28000000, 0x03232315, 
0x07302300, 0x03242415, 0x07312400, 0x30000000, 0x00000200, 0x04002000, 0x01262015, 
0x04012600, 0x07381500, 0x28000000, 0x28000000, 0x01381919, 0x07383800, 0x00030000, 
0x32232021, 0x0a232300, 0x071d1a00, 0x071e1b00, 0x071f1c00, 0x08032300, 0x28000000, 
0x03232315, 0x07302300, 0x03242415, 0x07312400, 0x30000000, 0x28000000, 0x00000200, 
0x04002000, 0x01383819, 0x07383800, 0x28000000, 0x0d2a2116, 0x0f2a2a17, 0x032c2a20, 
0x032c2c02, 0x012c2c23, 0x072c2c00, 0x00030000, 0x03242406, 0x03252506, 0x032d2106, 
0x032e2206, 0x08032400, 0x01381819, 0x07383800, 0x28000000, 0x28000000, 0x28000000, 
0x322d2b24, 0x092d2d26, 0x0a262d00, 0x322d2c26, 0x0a2d2d00, 0x08002d00, 0x071d1a00, 
0x071e1b00, 0x071f1c00, 0x01381919, 0x07383800, 0x28000000, 0x032d2d15, 0x07302d00, 
0x02383838, 0x07383800, 0x30000000, 0x00000200, 0x01252324, 0x07252500, 0x01292425, 
0x02290029, 0x07292900, 0x00030000, 0x02260903, 0x02270a03, 0x02280503, 0x0926261d, 
0x0a262600, 0x32262426, 0x322a252a, 0x322d292d, 0x0926262a, 0x0926262d, 0x0a262600, 
0x08002600, 0x28000000, 0x29000000, 0x30000000, 0x00000200, 0x022c0020, 0x072c2c00, 
0x00030000, 0x03262106, 0x03272206, 0x02280503, 0x0926261d, 0x0a262600, 0x32232023, 
0x32262026, 0x32292c29, 0x09232329, 0x0a232300, 0x08012300, 0x091d1d1d, 0x01381919, 
0x07383800, 0x28000000, 0x03232315, 0x07302300, 0x03242415, 0x07312400, 0x02383838, 
0x07383800, 0x30000000, 0x00030000, 0x03232106, 0x03242206, 0x02250503, 0x0923231d, 
0x0a232300, 0x32232023, 0x32262026, 0x02270327, 0x09232326, 0x0a232300, 0x08032300, 
0x28000000, 0x03232315, 0x07302300, 0x03242415, 0x07312400, 0x02383838, 0x07383800, 
0x30000000, 0x00000200, 0x0d2a2116, 0x0f2a2a17, 0x032c2a20, 0x032c2c02, 0x012c2c23, 
0x072c2c00, 0x0d2b2416, 0x0f2b2b17, 0x03202b2c, 0x03202002, 0x02200020, 0x07202000, 
0x00030000, 0x322d2b2d, 0x092d2d26, 0x0a2d2d00, 0x0a261d00, 0x322d2c2d, 0x32262026, 
0x092d2d26, 0x0a2d2d00, 0x08002d00, 0x01381919, 0x07383800, 0x28000000, 0x032d2d15, 
0x07302d00, 0x02383838, 0x07383800, 0x30000000, 0xffffffff, 0xffffffff
};

const static uint32_t smd1_init1_data[200] = 
{
0x00000200, 0x01252015, 0x04012500, 0x07381500, 0x28000000, 0x00030000, 0x31212000, 
0x01381919, 0x07383800, 0x28000000, 0x02383838, 0x07383800, 0x03212115, 0x07302100, 
0x03222215, 0x07312200, 0x30000000, 0x00000200, 0x04012100, 0x01272115, 0x04022700, 
0x07381500, 0x28000000, 0x28000000, 0x00030000, 0x31232200, 0x00000200, 0x03272702, 
0x06282700, 0x01381919, 0x07383800, 0x28000000, 0x01302023, 0x07303000, 0x04003000, 
0x01233022, 0x07232300, 0x04012300, 0x07381800, 0x28000000, 0x03243021, 0x03242402, 
0x02232224, 0x03312328, 0x07313100, 0x04063100, 0x28000000, 0x02383838, 0x07383800, 
0x30000000, 0x00000200, 0x04012400, 0x01252324, 0x07252500, 0x04022500, 0x01381815, 
0x07383800, 0x28000000, 0x01383819, 0x07383800, 0x00030000, 0x31262400, 0x03222206, 
0x322a2521, 0x28000000, 0x28000000, 0x29050000, 0x02383838, 0x07383800, 0x30000000, 
0x28000000, 0x00030000, 0x28000000, 0x31232000, 0x32262021, 0x0a262600, 0x08022600, 
0x01381919, 0x07383800, 0x28000000, 0x03262615, 0x07322600, 0x03272715, 0x07332700, 
0x02383838, 0x07383800, 0x30000000, 0x28000000, 0x00030000, 0x03212106, 0x03222206, 
0x08022100, 0x07381900, 0x28000000, 0x32232021, 0x28000000, 0x02383838, 0x07383800, 
0x30000000, 0x00000200, 0x04012300, 0x01292315, 0x04022900, 0x07381500, 0x28000000, 
0x28000000, 0x0d2b2416, 0x0f2b2b17, 0x00030000, 0x03262606, 0x03272706, 0x02280503, 
0x28000000, 0x08042600, 0x02381815, 0x07383800, 0x28000000, 0x08052d00, 0x01383819, 
0x07383800, 0x28000000, 0x322d2b24, 0x322d2c26, 0x28000000, 0x032e2e15, 0x07312e00, 
0x30000000, 0x00030000, 0x032a2106, 0x032b2206, 0x022c0503, 0x092a2a1d, 0x0a2a2a00, 
0x0a2d1d00, 0x32262426, 0x322a252a, 0x322d292d, 0x01381919, 0x07383800, 0x28000000, 
0x03262615, 0x03272715, 0x07262600, 0x00000200, 0x01262620, 0x07262600, 0x04002623, 
0x02383815, 0x07383800, 0x29000000, 0x02383838, 0x07383800, 0x30000000, 0x00030000, 
0x02230903, 0x02240a03, 0x02250503, 0x0923231d, 0x0a232300, 0x0a291d00, 0x32232023, 
0x32262026, 0x32292c29, 0x09262629, 0x0a262600, 0x08002600, 0x28000000, 0x03262615, 
0x07322600, 0x03272715, 0x07332700, 0x30000000, 0x00030000, 0x0a261d00, 0x32232023, 
0x32262026, 0x091d1d1d, 0x01381919, 0x07383800, 0x28000000, 0x30000000, 0x00030000, 
0x03262606, 0x03272706, 0x02280503, 0x032d2406, 0x032e2506, 0x022f0503, 0x092d2d1d, 
0x0a2d2d00, 0x322d2b2d, 0x322d2c2d, 0x32262026, 0x091d1d1d, 0x28000000, 0x032e2e15, 
0x07312e00, 0x30000000, 0xffffffff, 0xffffffff
};

const static uint32_t smd1_init2_data[256] = 
{
0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0x7203df6b, 0x21c6052b, 0x53bbf409, 
0x39d54123, 0x6f39132f, 0x82e4c7bc, 0x2b0068d3, 0xb08941d4, 0xdf1e8d34, 0xfc8319a5, 
0x327f9e88, 0x72350975, 0xeb5e412b, 0x22b3d3b6, 0x20fc84c3, 0xaffe0d43, 0xd4412542, 
0xc5342a7d, 0xad5d36ee, 0x873fb0dd, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 
0xffffffff, 0x00000000, 0xffffffff, 0xffffffff, 0xfffffffc, 0x00000001, 0xfffffffe, 
0x00000000, 0xffffffff, 0x00000001, 0x00000000, 0x00000001, 0x00000004, 0x00000000, 
0x00000000, 0x00000000, 0x00000003, 0xfffffffc, 0x00000000, 0x00000004, 0x00000040, 
0x00000020, 0x00000010, 0x00000010, 0x0000002f, 0xfffffff0, 0x00000020, 0x00000030, 
0xfffffff2, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffff3, 0x0000000c, 0xffffffff, 
0xfffffff3, 0x903f8622, 0xe8838b21, 0x49e60541, 0x7a9470f1, 0xc73cde6b, 0xa6d4deae, 
0x4348c18c, 0xaf037508, 0x4459e97d, 0x8704ec17, 0x5a87b666, 0xb0930f0c, 0xf9e607b9, 
0x729b013f, 0x84ca2643, 0xd0600a7a, 0x8f359753, 0x075cd6f6, 0x3533ec19, 0xb8a923e3, 
0x07d795e3, 0x34ca57ea, 0x04d53964, 0xf0b43775, 0xc09e1fe1, 0x4aa8a4fb, 0x34381262, 
0xf203b2c1, 0x70407e79, 0x6437fecd, 0x2ccf8082, 0xeb60c348, 0x2c25a5c8, 0xf788c9e7, 
0x700e80e2, 0x244ec4a3, 0x3d73af83, 0xf83b8ddd, 0xff5933b4, 0x883e3f21, 0x4471a7c5, 
0x4cca7d66, 0x5d96c92f, 0x533ccf43, 0xdf48a731, 0x187b7e95, 0xd3ba1388, 0xe6836771, 
0xec7a0511, 0x12d090e9, 0x18910872, 0x6609f928, 0xe91943c5, 0xe1fc3968, 0x04256ede, 
0x81eb8c59, 0x27994104, 0x5a2d3159, 0xa003da59, 0x466d30d4, 0xafdc4c3d, 0x45534dda, 
0xee7d586a, 0x2a452d43, 0x8d5b3d1b, 0x30599d1c, 0x7ffe78f5, 0x0158b97d, 0xe0684bdc, 
0x88473877, 0xc1c1b801, 0xb6628cc5, 0x54910ad4, 0xff79f940, 0x2d59190a, 0x1dc49448, 
0x9527d593, 0xf5aeae60, 0xece64a90, 0x80af78e7, 0xe8242565, 0x095c3079, 0xb6c3b762, 
0x41b7b231, 0x6c653c2c, 0x20eca6f5, 0x9b3bf422, 0x8f4f85b9, 0xc5db0be9, 0x0d2e255f, 
0xcc849156, 0x8ce4163b, 0x82b475e7, 0x16b51c1e, 0xc95379ba, 0x017c3b63, 0x103aaf68, 
0x6f39dedb, 0x99816aa0, 0x36995785, 0xebcdead9, 0xaa98a39f, 0xa90a9a4a, 0x458bfe12, 
0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xffffffff, 0xffffffff, 
0xffffffff, 0xffffffff, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000, 
0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
0x00000000, 0x00000000, 0x00000000, 0x00000003, 0x00000000, 0x00000000, 0x00000000, 
0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000005, 0x4459e97d, 0x8704ec17, 
0x5a87b666, 0xb0930f0c, 0xf9e607b9, 0x729b013f, 0x84ca2643, 0xd0600a7a, 0x8f359753, 
0x075cd6f6, 0x3533ec19, 0xb8a923e3, 0x07d795e3, 0x34ca57ea, 0x04d53964, 0xf0b43775, 
0x00000004, 0x00000000, 0x00000000, 0x00000000, 0x00000003, 0xfffffffc, 0x00000000, 
0x00000004, 0x4459e97d, 0x8704ec17, 0x5a87b666, 0xb0930f0c, 0xf9e607b9, 0x729b013f, 
0x84ca2643, 0xd0600a7a, 0x8f359753, 0x075cd6f6, 0x3533ec19, 0xb8a923e3, 0x07d795e3, 
0x34ca57ea, 0x04d53964, 0xf0b43775, 0x00000004, 0x00000000, 0x00000000, 0x00000000, 
0x00000003, 0xfffffffc, 0x00000000, 0x00000004
};

#endif



void print_byte(uint8_t *buff, uint32_t len);

void fpga_hsmd1_cmd(uint32_t addr, const uint32_t *data, uint16_t len, uint16_t cmd, uint8_t i)
{
	FPGAHeader fpga_header;
	HSMD1CMD Hsmd_cmd;
	uint8_t *alg_hdr;
	uint8_t *data_ptr;
	uint32_t buff[500];
	memcpy(buff, data,len);
	memset(&fpga_header, 0, sizeof(FPGAHeader));

	while(fpga_write_start()==REG_REST) {
		fpga_reset_mcu();
		delay_ms(5);
	}
	fpga_header.mark = FPGA_HEAD_MARK;
	fpga_header.src = FPGA_DATA_ARM;
	fpga_header.dst = FPGA_DATA_SM2_HSM2+i;
	fpga_header.channel = FPGA_CHANNEL_DEF;
	fpga_header.sm2_cmd = cmd;
	fpga_header.pkglen = FPGA_DATAHEAD_LEN + FPGA_ALGHEAD_LEN + FPGA_HSMD1_LEN + FPGA_DATA_LEN(len);
	//print(PRINT_FPGA,"fpga_header.pkglen=%d",fpga_header.pkglen);
	
	Hsmd_cmd.length = len;
	Hsmd_cmd.addr = addr;
	alg_hdr = set_fpga_header((uint8_t *)FPGA_DATA_WRITE_ADDR, &fpga_header);
	data_ptr = alg_header(alg_hdr, 0, FPGA_ALGHEAD_LEN + FPGA_DATA_LEN(len), ENCRYPT_MODE, FPGA_ECB_MODE, FPGA_DISABLE, 0, FPGA_DISABLE, 0);
	memcpy(data_ptr, &Hsmd_cmd, sizeof(HSMD1CMD));
	data_ptr += sizeof(HSMD1CMD);
	if(len == sizeof(uint32_t)){
		reverse_memory((uint8_t*)buff,len);
	}
	else if(len > sizeof(uint32_t)){
		for(uint16_t i=0; i<len; i+=4){
		reverse_memory((uint8_t*)buff+i,sizeof(uint32_t));
		}
	}
	//print(PRINT_FPGA,"datalen=%d",len);
	//printf_buff_byte((uint8_t*)data,len);
	memcpy(data_ptr, buff, len);
	fpga_write_finish(fpga_header.pkglen);
	
	//��ȡ
//	if(CMD_SM2_MD1RD == cmd){
//		data_ptr=fpga_read_start_ex();
//		if( data_ptr == NULL){
//			print(PRINT_FPGA,"fpga no data return!\r\n");
//			return;
//		}
//		get_fpga_header(&fpga_header, data_ptr);
//		data_ptr = (uint8_t *)(data_ptr + FPGA_DATAHEAD_LEN);
//		memcpy((uint8_t*)data, data_ptr, 32);
//		printf_buff_byte((uint8_t*)data,32);
//	}
}

void fpga_hsmd1_init(void)
{
	uint32_t data;
	uint8_t num = 0,times = 0,i,ret;
	num = (FPGA_REG(FPGA_CARD_TYPE_ADDR) & 0x3f);
	
	//smd1 reset all
	FPGA_REG(FPGA_HSMD1_STATUS_ADDR) = 0;
	//print(PRINT_FPGA,"FPGA_HSMD1_STATUS_ADDR is %x\r\n",FPGA_REG(FPGA_HSMD1_STATUS_ADDR));
	delay_ms(5);
	FPGA_REG(FPGA_HSMD1_STATUS_ADDR) = 0xff;
	//print(PRINT_FPGA,"FPGA_HSMD1_STATUS_ADDR is %x\r\n",FPGA_REG(FPGA_HSMD1_STATUS_ADDR));

	for(uint8_t i = 0; i < HSM2_NUM; i++){
		if(!(HSMD1 & (0x01U << i))){					//bit0:HSMD1_CHIP1; bit1:HSMD1_CHIP2; bit2:HSMD1_CHIP3; bit3:HSMD1_CHIP4;
			continue;
		}
		times = 0;
		do
		{
			//FPGA_REG(FPGA_HSMD1_STATUS_ADDR) = 0;
			FPGA_REG(FPGA_HSMD1_STATUS_ADDR) &= ~((0x01U) << (i+4));
			print(PRINT_FPGA,"F_HSMD1_STAT_ADDR %x\r\n",FPGA_REG(FPGA_HSMD1_STATUS_ADDR));
			delay_ms(5);
			//FPGA_REG(FPGA_HSMD1_STATUS_ADDR) = 0xff;
			FPGA_REG(FPGA_HSMD1_STATUS_ADDR) |= (0x01U) << (i+4);
			print(PRINT_FPGA,"F_HSMD1_STAT_ADDR %x\r\n",FPGA_REG(FPGA_HSMD1_STATUS_ADDR));
			delay_ms(500);
			/*****1.��ʼ���ϵ�*****/
			print(PRINT_FPGA,"INIT HSMD1 ch %x\r\n",(FPGA_DATA_SM2_HSM2+i));

			FPGA_REG(FPGA_HSMD1_SELECT_ADDR) |= (0x01U) << (i);
			data = 0x0000000f;
			fpga_hsmd1_cmd(0x50, &data, sizeof(uint32_t), CMD_SM2_MD1WR,i); //1.���� ʱ��ģ����ƼĴ�������ַ��101-0000 ����0x0000_000F

			/*****2.���� PLL��Ƶ��*****/

			data = 0x00000004;
			fpga_hsmd1_cmd(0x51, &data, sizeof(uint32_t), CMD_SM2_MD1WR,i); //2.1 д PLL����״̬�Ĵ�������ַ��101-0001��=> 0x0000_0004;
			delay_ms(5);  //2.2 wait for 50ns;
			data = 0x00000005;
			fpga_hsmd1_cmd(0x51, &data, sizeof(uint32_t), CMD_SM2_MD1WR,i); //2.3 д PLL����״̬�Ĵ�������ַ��101-0001��=> 0x0000_0005;
			data = HSMD1_HZ; //�ⲿ����25MHz������Ƶ��350MHz��1010010��ַд��0x0000101C
			fpga_hsmd1_cmd(0x52, &data, sizeof(uint32_t), CMD_SM2_MD1WR,i); //2.4 д PLL����״̬�Ĵ�������ַ��101-0010��=> ��Ƶ����;
			//fpga_hsmd1_cmd(0x52, &data, sizeof(uint32_t), CMD_SM2_MD1RD,i); //2.4 д PLL����״̬�Ĵ�������ַ��101-0010��=> ��Ƶ����;
			times++;
			if(times > 3) break;
			delay_ms(1);
			ret = (FPGA_REG(FPGA_HSMD1_STATUS_ADDR) & ((0x01U)<<i));  //���Ե�һ�ζ�ȡ����״̬
			if(!ret) delay_ms(500);
			ret = (FPGA_REG(FPGA_HSMD1_STATUS_ADDR) & ((0x01U)<<i));  //���Եڶ��ζ�ȡ����״̬
		}while(ret == 0); //2.5 �� PLL����״̬�Ĵ�����MCU�Ĵ���0x0012
		data = 0x00000009;
		fpga_hsmd1_cmd(0x51, &data, sizeof(uint32_t), CMD_SM2_MD1WR,i); //2.6 д PLL����״̬�Ĵ�������ַ��101-0001��=> 0x0000_0009;

		/*******3.���ó�ʼ������*******/

		fpga_hsmd1_cmd(0x16, smd1_init0_data, sizeof(smd1_init0_data), CMD_SM2_MD1WR,i); //3.1 ��SM2�������û�����1(001-0110)д�븽¼1��220*4Byte = 880 byte
		//delay_ms(1);
		fpga_hsmd1_cmd(0x17, smd1_init1_data, sizeof(smd1_init1_data), CMD_SM2_MD1WR,i); //3.2 ��SM2�������û�����2(001-0111)д�븽¼2��24*7*4Byte = 672 byte
	//	print_byte((uint8_t *)FPGA_DATA_WRITE_ADDR, fpga_header.pkglen);
		//delay_ms(1);
		fpga_hsmd1_cmd(0x18, smd1_init2_data, sizeof(smd1_init2_data), CMD_SM2_MD1WR,i); //3.3 ��SM2�������ݻ�����0(001-1000)д�븽¼3��192 * 4 byte = 768 byte 
		//delay_ms(1);
		//print_byte((uint8_t *)FPGA_DATA_WRITE_ADDR, fpga_header.pkglen);
		}
}

