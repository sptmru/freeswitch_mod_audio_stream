#ifndef PCMU_TO_LPCM_H
#define PCMU_TO_LPCM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

  void pcmu_to_lpcm_convert_buffer(const unsigned char *pcmu_buffer, short *lpcm_buffer, size_t len);
  short pcmu_to_lpcm(unsigned char pcmu_byte);

#ifdef __cplusplus
}
#endif

#endif // PCMU_TO_LPCM_H
