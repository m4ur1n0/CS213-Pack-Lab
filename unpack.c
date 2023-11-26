// Application to unpack files
// PackLab - CS213 - Northwestern University

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "unpack-utilities.h"


int main(int argc, char* argv[]) {
  // Parse app flags
  // No flags for unpack, just input and output filenames
  if (argc != 3) {
    printf("usage: %s inputfilename outputfilename\n", argv[0]);
    error_and_exit("\n");
  }
  char* input_filename = argv[1];
  char* output_filename = argv[2];

  // Validate input data
  if (strcmp(input_filename, output_filename) == 0) {
    // This check is for safety to make sure we don't overwrite a file
    error_and_exit("ERROR: input and output filename match\n");
  }

  // Open input file
  FILE* input_fd = fopen(input_filename, "r");
  if (input_fd == NULL) {
    error_and_exit("ERROR: input file likely does not exist\n");
  }

  // Determine size of input file
  struct stat st;
  int result = stat(input_filename, &st);
  if (result != 0) {
    error_and_exit("ERROR: input file likely does not exist\n");
  }
  size_t input_len = st.st_size;

  // Read entire input file contents
  uint8_t* input_data = malloc_and_check(input_len);
  size_t read_len = fread(input_data, sizeof(uint8_t), input_len, input_fd);
  if (read_len != input_len) {
    error_and_exit("ERROR: fread failed on input\n");
  }
  fclose(input_fd);

  // Create a zero'd out configuration
  packlab_config_t config = {0};

  // Parse the header to determine the packed file's configuration
  parse_header(input_data, input_len, &config);

  // Check if header is valid
  if (!config.is_valid) {
    error_and_exit("ERROR: header is invalid\n");
  }

  // Create a buffer containing the file data only
  if (config.header_len > input_len) {
    error_and_exit("ERROR: input file is shorter than expected\n");
  }
  size_t data_len = input_len - config.header_len;
  uint8_t* data = malloc_and_check(data_len);
  memcpy(data, &(input_data[config.header_len]), data_len);

  // Done with the raw input data
  free(input_data);

  // Handle checksumming
  if (config.is_checksummed) {

    // Calculate checksum of data
    uint16_t calc_checksum = calculate_checksum(data, data_len);

    // Validate checksum
    if (calc_checksum != config.checksum_value) {
      // printf("Looking for: %u \n", config.checksum_value);
      // printf("got: %u", calc_checksum);
      error_and_exit("ERROR: checksum is invalid\n");
    }
  }

  // Handle decryption
  if (config.is_encrypted) {
    // Get a password from the user
    char password[80];
    printf("Type the file password and hit enter: ");
    int match_count = scanf("%79s", password);
    if (match_count != 1) {
      error_and_exit("ERROR: invalid password entered\n");
    }

    // Use a checksum as a lazy method for "hashing" the password
    // This isn't ideal as it will have many collisions (password "ab" equals password "ba")
    uint16_t encryption_key = calculate_checksum((uint8_t*)password, strlen(password));

    // Decrypt the data
    size_t output_len = data_len;
    uint8_t* output_data = malloc_and_check(output_len);
    decrypt_data(data, data_len, output_data, output_len, encryption_key);

    // Replace data with new output
    free(data);
    data = output_data;
    data_len = output_len;
  }

  // Handle decompression
  if (config.is_compressed) {
    // Decompress the data
    size_t output_len = (MAX_RUN_LENGTH*input_len)/2; // worst-case output could be MAX_RUN_LENGTH bytes for every two bytes
    uint8_t* output_data = malloc_and_check(output_len);
    output_len = decompress_data(data, data_len, output_data, output_len, config.dictionary_data);

    // Replace data with new output
    free(data);
    data = output_data;
    data_len = output_len;
  }

  // Create output file
  // This is done late in the process in case the input was invalid
  FILE* output_fd = fopen(output_filename, "w");
  if (output_fd == NULL) {
    error_and_exit("ERROR: could not open output file\n");
  }

  // Write data to output file
  size_t write_len = fwrite(data, sizeof(uint8_t), data_len, output_fd);
  if (write_len != data_len) {
    error_and_exit("ERROR: could not write output file data\n");
  }
  fclose(output_fd);
  free(data);

  return 0;
}

