// Application to test unpack utilities
// PackLab - CS213 - Northwestern University

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unpack-utilities.h"


int test_parse_header(void) {

  uint8_t fullHeader[] = {0x02, 0x13, 0x01, 0xE0, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x09, 0xF1};
  packlab_config_t config1;
  parse_header(fullHeader, 22, &config1);
  if (!((config1.is_valid) && (config1.is_compressed) && (config1.is_encrypted) && (config1.is_checksummed))) {
    return 1;
    // this means 1 = failed first test
  }
  if (sizeof(config1.dictionary_data) != 16) {
    return 1;
  }
  for (int i = 4; i < 20; i++) {
    if (((config1.dictionary_data[i - 4]) ^ (fullHeader[i])) != 0) {
      return 1;
    }
  }
  uint16_t properCS = ((fullHeader[20]) << 8) | (fullHeader[21]);
  if (properCS != config1.checksum_value) {
    return 1;
  }



  return 0;
}

int inv_header(void) {

  uint8_t badMagic[] = {0x02, 0x83, 0x01, 0xE0, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x09, 0xF1};
  packlab_config_t config1;
  parse_header(badMagic, 22, &config1);
  if (config1.is_valid) {
    return 1;
  }


  uint8_t badVersion[] = {0x02, 0x13, 0x02, 0xE0, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x09, 0xF1};
  packlab_config_t config2;
  parse_header(badVersion, 22, &config2);
  if (config2.is_valid) {
    return 2;
  }

  uint8_t tooShort[] = {0x02, 0x13, 0x01};
  packlab_config_t config3;
  parse_header(tooShort, 3, &config3);
  if (config3.is_valid) {
    return 3;
  }

  uint8_t notComped[] = {0x02, 0x13, 0x01, 0x60, 0x09, 0xF1};
  packlab_config_t config4;
  parse_header(notComped, 6, &config4);
  if ((config4.is_compressed) || !(config4.is_checksummed)) {
    return 4;
  }



  return 0;
}

int test_lfsr_step(void) {
  // A properly created LFSR should do two things
  //  1. It should generate specific new state based on a known initial state
  //  2. It should iterate through all 2^16 integers, once each (except 0)

  // Create an array to track if the LFSR hit each integer (except 0)
  // 2^16 (65536) possibilities
  bool* lfsr_states = malloc_and_check(65536);
  memset(lfsr_states, 0, 65536);

  // Initial 16 LFSR states
  uint16_t correct_lfsr_states[16] = {0x1337, 0x899B, 0x44CD, 0x2266,
                                      0x9133, 0xC899, 0xE44C, 0x7226,
                                      0x3913, 0x9C89, 0x4E44, 0x2722,
                                      0x9391, 0xC9C8, 0x64E4, 0x3272};

  // Step the LFSR until a state repeats
  bool repeat = false;
  size_t steps = 0;
  uint16_t new_state = 0x1337; // known initial state
  while (!repeat) {

    // Iterate LFSR
    steps++;
    new_state = lfsr_step(new_state);

    // Check if this state has already been reached
    repeat = lfsr_states[new_state];
    lfsr_states[new_state] = true;

    // Check first 16 LFSR steps
    if(steps < 16) {
      if (new_state != correct_lfsr_states[steps]) {
        printf("ERROR: at step %lu, expected state 0x%04X but received state 0x%04X\n",
            steps, correct_lfsr_states[steps], new_state);
        free(lfsr_states);
        return 1;
      }
    }
  }

  // Check that all integers were hit. Should take 2^16 (65536) steps (2^16-1 integers, plus a repeat)
  if (steps != 65536) {
    printf("ERROR: expected %d iterations before a repeat, but ended after %lu steps\n", 65536, steps);
    free(lfsr_states);
    return 1;
  }

  // Cleanup
  free(lfsr_states);
  return 0;
}

// Here's an example testcase
// It's written for the `calculate_checksum()` function, but the same ideas
//  would work for any function you want to test
// Feel free to copy it and adapt it to create your own tests
int example_test(void) {
  // Create input data to test with
  // If you wanted to test a header, these would be bytes of the header with
  //    meaningful bytes in appropriate places
  // If you want to test one of the other functions, they can be any bytes
  uint8_t input_data[] = {0x01, 0x03, 0x04,};

  // Create an "expected" result to compare against
  // If you're testing header parsing, you will likely need one of these for
  //    each config field. If you're testing decryption or decompression, this
  //    should be an array of expected output_data bytes
  uint16_t expected_checksum_value = 0x0008;

  // Actually run your code
  // Note that `sizeof(input_data)` actually returns the number of bytes for the
  //    array because it's a local variable (`sizeof()` generally doesn't return
  //    buffer lengths in C for arrays that are passed in as arguments)
  uint16_t calculated_checksum_value = calculate_checksum(input_data, sizeof(input_data));

  // Compare the results
  // This might need to be multiple comparisons or even a loop that compares many bytes
  // `memcmp()` in the C standard libary might be a useful function here!
  // Note, you don't _need_ the CHECK() functions like we used in CS211, you
  //    can just return 1 then print that there was an error
  if (calculated_checksum_value != expected_checksum_value) {
    // Test failed! Return 1 to signify failure
    return 1;
  }

  // Test succeeded! Return 0 to signify success
  return 0;
}

int test_decompress(void) {
    uint8_t fullFileHeader[] = {0x02, 0x13, 0x01, 0xE0, 
                          0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                          0x09, 0xF1};


    uint8_t fullData[] = {0x07, 0x70, 0xF2, 0x07, 0x52, 0xFE, 0x07, 0x8F};

  // RULES RE: COMPRESSION DICT
  // 0x07 - esc -- 0x00 = 0x07
  // 0x07 -- 0xXY -- write dict[y] X times

  uint8_t unpackedFile[] = {0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 
                            0xF2,
                            0x34, 0x34, 0x34, 0x34, 0x34, 
                            0xFE,
                            0x47, 0x47, 0x47, 0x47, 0x47, 0x47, 0x47, 0x47};

  packlab_config_t config2;

  parse_header(fullFileHeader, 22, &config2);
  if (!config2.is_compressed) {
    return 3;
  }

  uint8_t uncompressed[22];

  decompress_data(fullData, 8, uncompressed, 22, config2.dictionary_data);

  for (int i = 0; i < 22; i++) {

    printf("%x: %x \n", unpackedFile[i], uncompressed[i]);

    if (unpackedFile[i] != uncompressed[i]) {
      return 2;
    }
  }


return 0;

}



int main(void) {

  // Test the LFSR implementation
  int result = test_lfsr_step();
  if (result != 0) {
    printf("Error when testing LFSR implementation\n");
    return 1;
  }

  // TODO - add tests here for other functionality
  // You can craft arbitrary array data as inputs to the functions
  // Parsing headers, checksumming, decryption, and decompressing are all testable

  // Here's an example test
  // Note that it's going to fail until you implement the `calculate_checksum()` function
  result = example_test();
  if (result != 0) {
    // Make sure to print the name of which test failed, so you can go find it and figure out why
    printf("ERROR: example_test_setup failed\n");
    return 1;
  }


  result = test_parse_header();
  if (result != 0) {
    if (result == 1) {
      printf("ERROR: error in test 1 of test_parse_header\n");
      return 1;
    }
  }


  result = test_decompress();
  if (result != 0) {
    if (result == 2) {
      printf("ERROR: error in test 1 of test_decompress\n");
      return 1;
    } else if (result == 3) {
      printf("ERROR: error in parse header");
      return 1;
    }
  }

  result = inv_header();
  if (result != 0) {
    if (result == 1) {
      printf("ERROR: error in test 1 of inv_header\n");
      return 1;
    } else if (result == 2) {
      printf("ERROR: error in test 2 of inv header");
      return 1;
    } else if (result == 3) {
      printf("ERROR: error in test 3 of inv header");
      return 1;
    } else if (result == 4) {
      printf("ERROR: error in test 4 of inv header");
      return 1;
    }
  }

  printf("All tests passed successfully!\n");
  return 0;
}

