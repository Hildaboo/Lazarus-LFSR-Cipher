#ifndef __NKLFSR_CIPHER__
#define __NKLFSR_CIPHER__

#include <stdint.h>

/////////////////////////////////////////////////////////////////////////////////////////////
/// Song I listened to while working on this: https://www.youtube.com/watch?v=3X1raMnuoks ///
/////////////////////////////////////////////////////////////////////////////////////////////

struct LFSR_ctx
{
	uint32_t KeyState[4];
};

void LFSR_init(struct LFSR_ctx *ctx, const uint8_t *zeKey);
void LFSR_encryptdecrypt(struct LFSR_ctx *ctx, uint8_t *data, uint32_t data_len);
void LFSR_processkey(struct LFSR_ctx *ctx, uint32_t data_len);
void LFSR_clock_1(struct LFSR_ctx *ctx);
void LFSR_clock_2(struct LFSR_ctx *ctx);
void LFSR_clock_3(struct LFSR_ctx *ctx);
void LFSR_clock_4(struct LFSR_ctx *ctx);
uint8_t LFSR_getbyte(struct LFSR_ctx *ctx);

#endif