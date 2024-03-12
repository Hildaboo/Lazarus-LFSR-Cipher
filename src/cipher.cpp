#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#include "cipher.h"

//////////////////////////////////////////////////////////////////////////////
/// Reference: https://www.cisa.gov/news-events/analysis-reports/ar19-304a ///
//////////////////////////////////////////////////////////////////////////////

void LFSR_init(struct LFSR_ctx *ctx, const uint8_t *zeKey)
{
	memset(ctx->KeyState, 0x00, sizeof(ctx->KeyState));
	
	ctx->KeyState[0] = 0x00000000;
	ctx->KeyState[1] = *(uint32_t*)(zeKey);
	ctx->KeyState[2] = *(uint32_t*)(&zeKey[4]);
	ctx->KeyState[3] = *(uint32_t*)(&zeKey[8]);
}

void LFSR_encryptdecrypt(struct LFSR_ctx *ctx, uint8_t *data, uint32_t data_len)
{
	LFSR_processkey(ctx, data_len);
	
	for(uint32_t i = 0; i < data_len; i++)
	{
		uint8_t xor_byte = LFSR_getbyte(ctx);
		data[i] ^= xor_byte;
	}
}

void LFSR_processkey(struct LFSR_ctx *ctx, uint32_t data_len)
{
	for(uint32_t i = 0; i < (data_len / 3); i++)
	{
		ctx->KeyState[1] ^= ctx->KeyState[2];
		ctx->KeyState[2] ^= ctx->KeyState[3];
		ctx->KeyState[3] ^= ctx->KeyState[1];
	}
	
	for(uint32_t i = 0; i < (data_len % 3); i++)
	{
		ctx->KeyState[1] |= ctx->KeyState[2];
		ctx->KeyState[2] |= ctx->KeyState[3];
		ctx->KeyState[3] |= ctx->KeyState[1];
	}
}

void LFSR_clock_1(struct LFSR_ctx *ctx)
{
	uint8_t bit_chk = 0;
	
	if((ctx->KeyState[1] & 0x200) == 0x200)
	{
		bit_chk += 1;
	}
	
	if((ctx->KeyState[2] & 0x800) == 0x800)
	{
		bit_chk += 1;
	}
	
	if((ctx->KeyState[3] & 0x800) == 0x800)
	{
		bit_chk += 1;
	}
	
	if(bit_chk <= 1)
	{
		ctx->KeyState[0] = 0x00000001;
	}
	else
	{
		ctx->KeyState[0] = 0x00000000;
	}
}

void LFSR_clock_2(struct LFSR_ctx *ctx)
{
	uint32_t v1 = ctx->KeyState[1];
	uint32_t r  = (ctx->KeyState[1] >> 9) & 1;
	uint32_t v3 = r == ctx->KeyState[0];
	uint32_t v4 = 0;
	ctx->KeyState[0] ^= r;
	
	if(!v3)
	{
		r = (v1 ^ ((v1 ^ (( v1 ^ (v1 >> 1)) >> 1)) >> 3)) >> 13;
		v4 = 2 * (v1 & 0x3FFFF);
		ctx->KeyState[1] = v4;
		
		if(r & 1)
		{
			ctx->KeyState[1] = v4 ^ 1;
		}
	}
}

void LFSR_clock_3(struct LFSR_ctx *ctx)
{
	uint32_t v1 = ctx->KeyState[2];
	uint32_t r  = (ctx->KeyState[2] >> 11) & 1;
	uint32_t v3 = r == ctx->KeyState[0];
	uint32_t v4 = 0;
	ctx->KeyState[0] ^= r;
	
	if(!v3)
	{
		r = (v1 ^ ((v1 ^ ((v1 ^ (v1 >> 1)) >> 4)) >> 4)) >> 12;
		v4 = 2 * (v1 & 0x1FFFFF);
		ctx->KeyState[2] = v4;
		
		if(r & 1)
		{
			ctx->KeyState[2] = v4 ^ 1;
		}
	}
}

void LFSR_clock_4(struct LFSR_ctx *ctx)
{
	uint32_t v1 = ctx->KeyState[3];
	uint32_t r  = (ctx->KeyState[3] >> 11) & 1;
	uint32_t v3 = r == ctx->KeyState[0];
	uint32_t v4 = 0;
	ctx->KeyState[0] ^= r;
	
	if(!v3)
	{
		r = (v1 ^ ((v1 ^ ((v1 ^ (v1 >> 1)) >> 3)) >> 1)) >> 17;
		v4 = 2 * (v1 & 0x3FFFFF);
		ctx->KeyState[3] = v4;
		
		if(r & 1)
		{
			ctx->KeyState[3] = v4 ^ 1;
		}
	}
}

uint8_t LFSR_getbyte(struct LFSR_ctx *ctx)
{
	LFSR_clock_1(ctx);
	LFSR_clock_2(ctx);
	LFSR_clock_3(ctx);
	LFSR_clock_4(ctx);
	
	uint32_t v2 = ctx->KeyState[1] ^ ctx->KeyState[2] ^ ctx->KeyState[3];
	
	return ((v2 >> 0x18) ^ (v2 >> 0x10) ^ (v2 >> 0x8) ^ v2) & 0xFF;
}