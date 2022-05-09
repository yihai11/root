/***********************************************************************
 * Filename    : pwm.h
 * Description : pwm driver header file
 * Author(s)   : 
 * version     : V1.0
 * Modify date : 
 ***********************************************************************/

#ifndef __TIMER_H__
#define __TIMER_H__

#include  "common.h"

/*----------------------TIMER BIT------------------------*/
#define VAL_TIMER_CONTROL_MOD_FREE     0
#define VAL_TIMER_CONTROL_MOD_CYC      2
#define VAL_TIMER_CONTROL_MOD_SINGLE   3

#define VAL_TIMER_PRES_DIVISOR_1       0
#define VAL_TIMER_PRES_DIVISOR_2       1
#define VAL_TIMER_PRES_DIVISOR_4       2
#define VAL_TIMER_PRES_DIVISOR_8       3
#define VAL_TIMER_PRES_DIVISOR_16      4
#define VAL_TIMER_PRES_DIVISOR_32      5
#define VAL_TIMER_PRES_DIVISOR_64      6
#define VAL_TIMER_PRES_DIVISOR_128     7

#define CAPTURE_TRIGGER_RISING         0
#define CAPTURE_TRIGGER_FALLING        1

extern volatile UINT8 flag_capture_int[];
extern volatile UINT32 CaptureCounter[];
extern volatile UINT8 flag_timer_int[];

#define LED_0         0
#define LED_1         1

#define HZ_2        	20
#define HZ_1        	10
#define HZ_05         5

#define LED_ON        10
#define LED_OFF       0
#define LED_BL        5

/************************************************************************
 * function   : led_display
 * Description: led state display
 * input :
 *         UINT8 num: LED_0,LED_1
 *         UINT32 freq_hz: freq setting  (HZ_2,HZ_1,HZ_05)
 *				 UINT8 state: led state  (LED_ON,LED_OFF,LED_BL)
 * return: none
 ************************************************************************/
void led_display(UINT8 led_num,UINT32 freq_10hz,UINT8 state);

#endif

