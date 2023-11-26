// Utilities for unpacking files
// PackLab - CS213 - Northwestern University

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unpack-utilities.h"

// --- public functions ---

void error_and_exit(const char *message)
{
  fprintf(stderr, "%s", message);
  exit(1);
}

void *malloc_and_check(size_t size)
{
  void *pointer = malloc(size);
  if (pointer == NULL)
  {
    error_and_exit("ERROR: malloc failed\n");
  }
  return pointer;
}

void parse_header(uint8_t *input_data, size_t input_len, packlab_config_t *config)
{

  // TODO
  // Validate the header and set configurations based on it
  // Look at unpack-utilities.h to see what the fields of config are
  // Set the is_valid field of config to false if the header is invalid
  // or input_len (length of the input_data) is shorter than expected
  if (input_len < 4)
  {
    config->is_valid = false;
    return;
  }


  // checking for the 'magic' two initial bytes, should be 0x0213
  short magic;
  magic = 0x0213;
  size_t byteNum = 0;

  // short read_magic ={input_data[byteNum], input_data[byteNum + 1]}; <<<< idk if this would work
  unsigned short int read_magic = (input_data[byteNum] << 8) | input_data[byteNum + 1];
  byteNum += 2;

  if ((magic ^ read_magic) != 0)
  {
    config->is_valid = false;
    return;
  }

  // checking for the version code, which should always be one byte: 0x01

  char version = 0x01;
  char readVersion = input_data[byteNum];
  byteNum++;

  if ((version ^ readVersion) != 0)
  {
    config->is_valid = false;
    return;
  }

  // now we analyze the flags to see whether the data is compressed, checksummed, encrypted, or a combination
  char importantFlagDigits = (input_data[byteNum]) >> 5;
  byteNum++; // byteNum should be at 4 now
  // char compressed = 0b100;
  // char encrypted = 0b010;
  // char checksummed = 0b001;
  // and then I could check each one this way OR
  
  char compressed = importantFlagDigits & 0x04;
  char encrypted = importantFlagDigits & 0x02;
  char checksum = importantFlagDigits & 0x01;
  if (compressed != 0)
  {
    if ((byteNum + 15) <= input_len) {
    config->is_compressed = true;
    } else {
      config->is_valid = false;
    }
  }
  else
  {
    config->is_compressed = false;
  }

  if (encrypted != 0)
  {
    config->is_encrypted = true;
  }
  else
  {
    config->is_encrypted = false;
  }
  if (checksum != 0)
  {
    if (config->is_compressed && (byteNum + 17) <= input_len) {
      config->is_checksummed = true;
    } else if ((!config->is_compressed) && (byteNum + 1 <= input_len)) {
      config->is_checksummed = true;
    } else {
      config->is_valid = false;
    }
    
  }
  else
  {
    config->is_checksummed = false;
  }

  // after this point, the header could have either a 16-byte compression dictionary, indicating the file was compressed
  // a 2-byte checksum, or both of these things

  /// need to make sure that the bytes are actually a number that works whenever we think it is checksummed and compressed!!!!!

  if (config->is_compressed)
  {
    int i = 0;
    while (i < 16)
    {
      (config->dictionary_data)[i] = input_data[byteNum];
      byteNum++;
      i++;
    }
  }

  if (config->is_checksummed)
  {
    config->checksum_value = ((input_data[byteNum] << 8) | input_data[byteNum + 1]);
    byteNum+= 2;
  }

  config->header_len = byteNum;

  config->is_valid = true;
}

uint16_t calculate_checksum(uint8_t* input_data, size_t input_len) {


  // TODO
  // Calculate a checksum over input_data
  // Return the checksum value
  uint16_t checkvalue = 0;
  size_t i = 0;
 
  while (i < input_len) {
    //printf("\n \n %x \n \n", input_data[i]);
    checkvalue = checkvalue + input_data[i];
    i++;
  }


  return checkvalue;
}


uint16_t lfsr_step(uint16_t oldstate) {


  // TODO
  // Calculate the new LFSR state given previous state
  // Return the new LFSR state


  //xor b0 and b11
  int b0_mask = oldstate & 0x0001;
  int b11_mask = ((oldstate & 0x0800) >> 11);
  int b0b11_mask = b0_mask ^ b11_mask;


  //xor b0b11 and b13
  int b13_mask = ((oldstate & 0x2000) >> 13);
  int b0b11b13_mask = b0b11_mask ^ b13_mask;


  //xor b0b11b13 and b14
  int b14_mask = ((oldstate & 0x4000) >> 14);
  int b0b11b13b14_mask = b0b11b13_mask ^ b14_mask;


  //make result into 16 bit with most sig bit at the front
  uint16_t newsigbit = b0b11b13b14_mask;
  newsigbit = newsigbit << 15;


  //shift oldstate right 1 and add new mostsignificant bit
  uint16_t new_state = (oldstate >> 1) ^ newsigbit;


  return new_state;
}


void decrypt_data(uint8_t* input_data, size_t input_len,
                  uint8_t* output_data, size_t output_len,
                  uint16_t encryption_key) {


  // TODO
  // Decrypt input_data and write result to output_data
  // Uses lfsr_step() to calculate psuedorandom numbers, initialized with encryption_key
  // Step the LFSR once before encrypting data
  // Apply psuedorandom number with an XOR in big-endian order
  // Beware: input_data may be an odd number of bytes


  //initializing lfsr
  uint16_t previous_state = lfsr_step(encryption_key);


  //creating masks
  uint16_t mask_1 = 0x00FF;
  uint16_t mask_2 = 0xFF00;
  uint8_t first;
  uint8_t second;


  int i = 0;
  int j = 0;


  while (i < input_len && j < output_len) {
    //creating first byte
    first = input_data[i] ^ (previous_state & mask_1);
    output_data[j] = first;
    i++;
    j++;
    if (i == input_len || j ==output_len) {
      break;
    }
    else {
      second = input_data[i] ^ ((previous_state & mask_2)>>8);
      output_data[j] = second;
      i++;
      j++;
      previous_state = lfsr_step(previous_state);
    }
  }


}



size_t decompress_data(uint8_t *input_data, size_t input_len,
                       uint8_t *output_data, size_t output_len,
                       uint8_t *dictionary_data)
{

  // TODO
  // Decompress input_data and write result to output_data
  // Return the length of the decompressed data
  char esc = 0x07;


  int j = 0;
  // j tracks the output data index
  for (int i = 0; i < input_len; i++)
  {
    // if we have hit our output capacity get tf outta here
    if (j == output_len)
    {
      break;
    }

    if ((input_data[i] == esc))
    {
      // if we get the escape character, one of two things
      // if next char is 0x00, fuck it add esc char to new file
      // if next char is anything else (save a byte beginning in 0000, which we won't have),
      // then add dictionary_data[LS4b] to file MS4b times
      if (i == (input_len - 1)) {
        if (j == output_len) {
          break;
        }
        output_data[j] = esc;
      } 
      else if ((input_data[i + 1] ==0))
      {
        if (j == output_len)
        {
          break;
        }
        output_data[j] = esc;
        i++;
        j++;
      }
      else
      {
        uint8_t numRep = input_data[i+1] >> 4;
        char compdByte = dictionary_data[input_data[i+1] & 0x0F];
        for (int h = 0; h < numRep; h++)
        {
          if (j == output_len)
          {
            // this break should get us to the top of the next loop, where it will break again
            break;
          }
          output_data[j] = compdByte;
          j++;
        }

        // account for the fact that we essentially added i+1 to the output without i catching up
        i++;
      }
    }
    else
    {
      if (j == output_len)
      {
        break;
      }
      output_data[j] = input_data[i];
      j++;
    }
  }

  return j;
}