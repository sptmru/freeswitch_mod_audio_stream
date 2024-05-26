#ifndef PCMU_TO_LPCM_H
#define PCMU_TO_LPCM_H

#include <cstdint>
#include <array>

extern std::array<int16_t, 256> pcmu_to_lpcm;

// Function to initialize the lookup table
void init_pcmu_to_lpcm();

// Function to convert a single PCMU byte to LPCM
inline int16_t pcmu_to_lpcm_convert(uint8_t pcmu_byte)
{
  return pcmu_to_lpcm[pcmu_byte];
}

// Function to convert an array of PCMU bytes to LPCM
void pcmu_to_lpcm_convert_buffer(const uint8_t *pcmu_buffer, int16_t *lpcm_buffer, size_t len);

#endif // PCMU_TO_LPCM_H
