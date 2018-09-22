# -*- coding: utf-8 -*-
"""
Created on Fri Sep 21 17:05:32 2018

@author: Miika
"""

def test():
    
    testkey = b'\x13\x34\x57\x79\x9B\xBC\xDF\xF1'
    testdata = b'\x0A\x0B\x0C\x0D\x0E\x0F\x0F\x0F'
    
    des = DESCipher()
    
    cipher_text = des.encrypt([testdata], testkey)
    
    clear_text = des.decrypt([cipher_text], testkey)
    
    print(cipher_text)
    print(clear_text)
    


""" This is a simple implementation of a DES algorithm simply for practice.
 
    The class encapsulates all DES Cipher functionality and offers two easy client side functions (encrypt and decrypt)
"""
class DESCipher:

    """The constructor. Also intializes all the required tables for cipher functionality
    """
    def __init__(self):
        
        self._pc_table1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]
        self._pc_table2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]
        self._expansion = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
        self._roundkey_shift = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
        
        self._expansion = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
        
        self._initial_permutation = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
        
        self._permutation_final = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]
        
        self._permutation = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
        
        self._substitution_boxes = [   [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
                                        [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
                                        [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
                                        [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
                                        
                                       [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
                                        [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
                                        [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
                                        [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
                                        
                                       [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
                                        [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
                                        [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
                                        [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
                                        
                                       [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
                                        [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
                                        [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
                                        [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
                                       
                                       [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
                                        [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
                                        [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
                                        [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
                                       
                                       [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
                                        [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
                                        [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
                                        [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
                                      
                                       [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
                                        [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
                                        [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
                                        [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
                                      
                                       [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
                                        [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
                                        [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
                                        [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]]

    
    """ Function to perform encryption on a number of 64 bit blocks of data.
      @param list_of_64bit_blocks a list containing blocks bytes to be encrypted. Each member expected to be 64 bit in length
      @param the DES key (64 bit). Expected type BYTES
      @return a cipher text in BYTES format
    """
    def encrypt(self, list_of_64bit_blocks, key_64bit):
        #Error checking
        if type(key_64bit) !=bytes:
            return 1
        if len(key_64bit) != 8:
            return 1
        if type(list_of_64bit_blocks) != list:
            return 1

        cipher_text_arr = list()

        #Create round keys
        round_keys = self._createRoundkeys(self._byteArrayToInt(key_64bit));
        
        for i in range(0, len(list_of_64bit_blocks)):
            cipher_text = self._encryptBlock(self._byteArrayToInt(list_of_64bit_blocks[i]), round_keys)
            
            cipher_bytes = self._intIntoByteArray(cipher_text)
            
            for y in range(0, len(cipher_bytes)):
                cipher_text_arr.append(cipher_bytes[y])
                            
        return bytes(cipher_text_arr)
    
    """ Function to perform decryption on a number of 64 bit blocks of data.
      @param list_of_64bit_blocks a list containing blocks bytes to be decrypted. Each member expected to be 64 bit in length
      @param the DES key (64 bit). Expected type BYTES
      @return a clear text in BYTES format
    """
    def decrypt(self, list_of_64bit_ciphertxt_blocks, key_64bit):
        #Error checking
        if type(key_64bit) !=bytes:
            return 1
        if len(key_64bit) != 8:
            return 1
        if type(list_of_64bit_ciphertxt_blocks) != list:
            return 1
        
        clear_text_arr = list()

        #Create round keys
        round_keys = self._createRoundkeys(self._byteArrayToInt(key_64bit));
        round_keys.reverse()
        
        #Decrypt each block & add it into an array
        for i in range(0, len(list_of_64bit_ciphertxt_blocks)):
            clear_text = self._decryptBlock(self._byteArrayToInt(list_of_64bit_ciphertxt_blocks[i]), round_keys)
            
            clear_bytes = self._intIntoByteArray(clear_text)
            
            for y in range(0, len(clear_bytes)):
                clear_text_arr.append(clear_bytes[y])
                            
        return bytes(clear_text_arr)
    
    
    """A private function to be used in decryption of a single block. 
      @param data_64bit the data to be decrypted
      @param round_keys_reversed a list of round keys
      @return decrypted data in form of INT 64 bit
    """
    def _decryptBlock(self, data_64bit, round_keys_reversed):
        return self._encryptBlock(data_64bit, round_keys_reversed)
    
    """ A private function to be used in encryption of a single block. 
     @param data_64bit the data to be encrypted
     @param round_keys a list of round keys
     @return encrypted data in form of INT 64 bit
    """
    def _encryptBlock(self, data_64bit, round_keys):
        data_64bit = self._permute(data_64bit, self._initial_permutation, 64)
                
        #Split the data
        left_side = (data_64bit & 0xFFFFFFFF00000000) >> 32
        right_side = (data_64bit & 0x00000000FFFFFFFF)
        
        for i in range(0,16):
            cipher_round_output = self._cipherRound(left_side, right_side, round_keys[i])
            
            left_side = cipher_round_output[0]
            right_side = cipher_round_output[1]
                        
        return self._permute((left_side | (right_side << 32)),self._permutation_final, 64)
    
    """ A private function to perform a single cipher round
         @param left0_32bit initial left side bits (32) for operation
         @param right0_32bit initial right side bits (32) for operation
         @return
    """ 
    def _cipherRound(self, left0_32bit, right0_32bit, round_key):
        
        left1_32bit = right0_32bit
       
        right1_32bit = (self._cipherFunction(right0_32bit, round_key) ^ left0_32bit)
        
        return left1_32bit, right1_32bit
        
    """ A private function to perform a cipher function on the right side bits during a round (expansion, xor with key, substitution, permutation)
        @param data32_bit the right side bits to be operated on
        @param round_key the round_key of corresponding iteration
        @return the output of function (32 bit integer)
    """
    def _cipherFunction(self, data_32bit, round_key):
        #perform expansion permutation (32bit to 48bit)
        data_48bit = self._permute(data_32bit, self._expansion, 32)
        #Xor value with the round key of iteration
        xor_value = data_48bit ^ round_key
        #perform substitution
        substitution = self._substitute(xor_value)
        #Permutation
        return self._permute(substitution, self._permutation, 32)
    
    """ A private function to perform substitute operation within the cipher function.
        @param xor_value of key and right side bits
        @return the output of the operation (32bit int)
    """
    def _substitute(self, xor_value):        
        output_data = 0
                
        #break 48bit xor value into 8 x 6 bit blocks        
        for i in range(0, 8):
            shift_amount = 42 - (i * 6)
            
            block = ((xor_value & (0b111111 << shift_amount)) >> shift_amount)
           
            block_outer_bits = block & 0b100001
            
            if self._getNthBit(block_outer_bits, 5):
                block_outer_bits = (block_outer_bits | 2) & 0b11 #Shift the MSb to index 1 to get a proper index in substitution table (row)
            
            block_inner_bits = (block & 0b011110) >> 1  #shifted left to get directly the correct index in substitution table (column)
            
            substituted_block = self._substitution_boxes[i][block_outer_bits][block_inner_bits]
            #Put the substituted block back into the original place in the input
            output_data = output_data | ((substituted_block) << (28 - (i * 4)))
            
        return output_data
            
    """ A private function to build a set of (16) round keys needed during the encryption and decryption operations
        @param key_64bit the original 64 bit key
        @return a list of round keys (int 48 bit)
    """
    def _createRoundkeys(self, key_64bit ):        
        #FIRST PERMUTATION        
        key_64bit = self._permute(key_64bit, self._pc_table1, 64)

        left_side =     key_64bit >> 28
        right_side =    (key_64bit & 0xFFFFFFF)
        
        round_keys = list()
        
        for i in range(0,16):
            #Shift for both of the sides
            left_side = self._leftShift(left_side, 28, self._roundkey_shift[i])
            right_side = self._leftShift(right_side, 28, self._roundkey_shift[i])
            
            #Combine sides
            combined_sides = ((left_side << 28) | right_side)
                        
            #Perform the second permutation
            round_keys.append(
                    self._permute(combined_sides, self._pc_table2, 56))

        return round_keys
    
    """ A private function to simply convert a byte array into an integer
        @param byte_arr the input array
        @return an integer representation of byte array
    """
    def _byteArrayToInt(self, byte_arr):
        value = 0
        
        for i in range(0, len(byte_arr)):
            value = value | (byte_arr[len(byte_arr) - (i + 1)] << 8 * i)
            
        return value
    
    """ A private function to convert a 64 bit integer into a byte array
        @param int64_bit the input integer
        @return a bytes representing the integer
    """
    def _intIntoByteArray(self, int_64bit):
        byte_arr = list()
        
        for i in range (0,8):
            
            byte_arr.append( int_64bit &(0xFF << i * 8  ))
            byte_arr[i] = byte_arr[i] >> (i * 8)
            
        byte_arr.reverse()
        return bytes(byte_arr)
    
    """ A private function to perform a permutation operation typical to DES algorithm on input
        @param value_n_bits a value of N bits in size
        @param table the permutation table
        @param var_size the size of input variable
        @return permutated value (int). Size corresponding to the length of permutation table
    """
    def _permute(self, value_n_bits, table, var_size):
        permutated_value = 0
        
        #Relovate the bit in a new value according to the table instruction
        for i in range(0,len(table)):
            bit_index = var_size - table[i]

            permutated_value = (permutated_value | (self._getNthBit(value_n_bits, bit_index) << ((len(table) - 1) - i)))
            
        return permutated_value
    
    """ A private function to get the bit value of a N:th bit in a variable
        @param value the target variable value
        @bit_index the index of the bit to be retrieved from the value
        @return 1 or 0 
    """
    def _getNthBit(self, value, bit_index):
        if ((value & (1 << bit_index)) != 0):
            return 1
        else:
            return 0
            
    """ A private function to perform left shift operation during round key creation.
        @param value to be operated on
        @param size_bits the value size in bits
        @num_shifts the number of shifts (by 1) to be performed on the value
        @return the shifted value (int)
    """
    def _leftShift(self, value, size_bits, num_shifts):
        #No reason to shift more than once around 
        num_shifts = num_shifts % size_bits
        
        #The mask to catch the overflowing bits after each shift
        overflow_mask = 1 << (size_bits - 1)
        #The mask to catch only the relevant bits (none of the overflow)
        var_size_mask = 0
        
        #Value after the shift
        shifted_value = value
        
        #Create variable size mask
        for i in range(0, size_bits):
            var_size_mask = var_size_mask << 1
            var_size_mask = var_size_mask | 1
        
        #Time to get SHIFTYYYYY
        for i in range(0, num_shifts):
            #Check overflow
            overflow = (shifted_value & overflow_mask) >> (size_bits - 1)
            #Cause the overflow & clean it up
            shifted_value = (shifted_value << 1) & var_size_mask
            #Move the overflow to the beginning of the value
            shifted_value = shifted_value | overflow
        
        return shifted_value
        
        
                                               
        
            
            
            
            
            

            
        
        