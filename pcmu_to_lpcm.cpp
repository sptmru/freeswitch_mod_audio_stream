#include "pcmu_to_lpcm.h"
#include <cmath>

std::array<int16_t, 256> pcmu_to_lpcm;

void init_pcmu_to_lpcm()
{
  for (int i = 0; i < 256; ++i)
  {
    int mu = 255;
    int sign = (i & 0x80) ? -1 : 1;
    int exponent = (i >> 4) & 0x07;
    int mantissa = i & 0x0F;
    int magnitude = ((mantissa << 1) + 33) << (exponent + 2);
    pcmu_to_lpcm[i] = sign * (magnitude - 132);
  }
}

void pcmu_to_lpcm_convert_buffer(const uint8_t *pcmu_buffer, int16_t *lpcm_buffer, size_t len)
{
  for (size_t i = 0; i < len; ++i)
  {
    lpcm_buffer[i] = pcmu_to_lpcm_convert(pcmu_buffer[i]);
  }
}
