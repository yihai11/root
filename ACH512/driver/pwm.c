/***********************************************************************
 * Filename    : pwm.c
 * Description : pwm driver source file
 * Author(s)   : 
 * version     : V1.0
 * Modify date : 2021.1.26
 ***********************************************************************/
#include  "pwm.h"

void (*TimerFunc[4])(void) = { 0 };

//仅Timer0,Timer2的Capture有效
volatile UINT8 flag_capture_int[4] = { 0 };
volatile UINT32 CaptureCounter[4] = { 0 };

volatile UINT8 flag_timer_int[4] = { 0 };


void CCPWM_IRQHandler(void)
{
    UINT8 i;
//PWM
    for(i = 0; i < 4; i++)
    {
        if(REG_TIMER_CPIF & (0x01 << i))
        {
            REG_TIMER_CPIF = 0x01 << i; //清PWM中断,写1清中断
        }
    }
//CC
    if(REG_TIMER_CCIF & 0x01)
    {
        REG_TIMER_CCIF = 0x01; //清CC0中断，写1清中断
        CaptureCounter[TIMER0] = REG_TIMER_C0_CR;
        flag_capture_int[TIMER0] = 1;
    }
    if((REG_TIMER_CCIF & 0x02))
    {

        REG_TIMER_CCIF = 0x02; //清CC2中断，写1清中断
        CaptureCounter[TIMER2] = REG_TIMER_C2_CR;
        flag_capture_int[TIMER2] = 1;
    }
}

/************************************************************************
 * function   : timer_start
 * Description: timer start
 * input :
 *         UINT8 num: TIMER0,1,2,3
 * return:
 ************************************************************************/
void timer_start(uint8_t num)
{
    REG_TIMER_CR(num) |= 0x01;      //enable timer
}
/************************************************************************
 * function   : timer_stop
 * Description: timer stop
 * input :
 *         UINT8 num: TIMER0,1,2,3
 * return:
 ************************************************************************/

void timer_stop(uint8_t num)
{
    REG_TIMER_CR(num) &= ~0x01;    //close timer
    REG_TIMER_CIF(num) = 0xff; //清中断timer
}



/************************************************************************
 * function   : pwm_start
 * Description: pwm start
 * input :
 *         UINT8 num: TIMER0,1,2,3
 * return: none
 ************************************************************************/
void pwm_start(uint8_t num)
{
    REG_TIMER_PCR |= 1 << 2 * num;  //使能
}

/************************************************************************
 * function   : pwm_stop
 * Description: pwm stop
 * input :
 *         UINT8 num: TIMER0,1,2,3
 * return: none
 ************************************************************************/
void pwm_stop(uint8_t num)
{
    REG_TIMER_PCR &= ~(1 << 2 * num);
}

/************************************************************************
 * function   : pwm_output_wave
 * Description: pwm output wave --hz
 * input :
 *         UINT8 num: TIMER0,1,2,3
 *         UINT32 freq_hz: 输出的频率
 *         UINT32 duty:占空比  0~~10
 * return: none
 ************************************************************************/
void pwm_output_wave(uint8_t num, uint32_t freq_01hz, uint8_t duty)
{
    UINT32 frep;
    //NVIC_ClearPendingIRQ(CCPWM_IRQn); //CCPWM
    //NVIC_EnableIRQ(CCPWM_IRQn);
    if(num == TIMER0)
    {
        REG_SCU_MUXCTRLD = (REG_SCU_MUXCTRLD & ~(0x03 << 2)) | (0x02 << 2); //PWM0
    }
    else if(num == TIMER1)
    {
        REG_SCU_MUXCTRLD = (REG_SCU_MUXCTRLD & ~(0x03 << 22)) | (0x02 << 22); //PWM1
    }
    else if(num == TIMER2)
    {
        REG_SCU_MUXCTRLD = (REG_SCU_MUXCTRLD & ~(0x03 << 0)) | (0x01 << 0); //PWM2
    }
    else
    {
        REG_SCU_MUXCTRLA = (REG_SCU_MUXCTRLA & ~(0x03 << 18)) | (0x02 << 18); //PWM3
    }

    REG_TIMER_PSC = (REG_TIMER_PSC & ~(0x07 << (3 * num))) | (0x00 << (3 * num)); //不分频
    REG_TIMER_CR(num) = 0x01 << 4 | 0x01 << 3 | 0x02 << 1; //down counter,interrupt masked,Cyclic mode,close
    REG_TIMER_ICMODE |= 1 << num;

    frep = ( PClock / freq_01hz * 10  - 1);

    REG_TIMER_ARR(num) = frep;
    REG_TIMER_CX_PR(num) = (frep * duty) / 10;

    REG_TIMER_PCR |= 1 << (2 * num + 1);  //disable pwm interrupt
		//REG_TIMER_PCR &= ~(1 << (2 * num + 1));
    timer_start(num); //enable timer0
    pwm_start(num);
}
/************************************************************************
 * function   : led_display
 * Description: led state display
 * input :
 *         UINT8 num: LED_0:RED,LED_1:GREEN
 *         UINT32 freq_hz: freq setting  (HZ_2,HZ_1,HZ_05)
 *				 UINT8 state: led state  (LED_ON,LED_OFF,LED_BL)
 * return: none
 ************************************************************************/
void led_display(uint8_t led_num,uint32_t freq_10hz,uint8_t state)
{
		if (freq_10hz <= 0)
		{
				freq_10hz = 1;
		}

		if(led_num == LED_0)
		{
				pwm_output_wave(TIMER0, freq_10hz, state);
		}
		else if(led_num == LED_1)
		{
				pwm_output_wave(TIMER1, freq_10hz, state);
		}
}
/*
void timer_output_stop(UINT8 num)
{
    timer_stop(num); //enable timer0
    pwm_stop(num);
}
*/

