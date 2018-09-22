# -*- coding: utf-8 -*-
"""
Created on Fri Sep 21 17:05:32 2018

@author: Miika
"""

def test():
    
    des = DES()
    
    key_int = des._byteArrayToInt(testkey)
    data_int = des._byteArrayToInt(testdata)
    
    des._createRoundkeys(key_int)

    print("Starting a test\n")
    print("Data: " + str(data_int))
    print("Key: " + str(key_int))
    print("Round keys: ")
    print(des._round_keys)
    print("")
        
    
    print(des._encryptBlock(data_int, des._round_keys))

testkey = b'\x13\x34\x57\x79\x9B\xBC\xDF\xF1'
testdata = b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'



class DES:

    def __init__(self):
        self._pc_table1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]
        self._pc_table2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]
        self._expansion = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
        self._roundkey_shift = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
        
        self._expansion = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
        
        self._initial_permutation = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
        
        self._permutation_final = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]
        
        self._permutation = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
        
        self._round_keys = list()
        
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

    
    
    
    def _encryptBlock(self, data_64bit, round_keys):
        data_64bit = self._permute(data_64bit, self._initial_permutation, 64)
        
        print("IP: " + str(data_64bit))
        
        #Split the data
        left_side = (data_64bit & 0xFFFFFFFF00000000) >> 32
        right_side = (data_64bit & 0x00000000FFFFFFFF)
        
        for i in range(0,16):
            print("Cipher round " + str(i))
            cipher_round_output = self._cipherRound(left_side, right_side, round_keys[i])
            
            left_side = cipher_round_output[0]
            right_side = cipher_round_output[1]
            
            print("Left 1 value: " + str(left_side))
            print("Right 1 value " + str(right_side))
            
            print((left_side | (right_side << 32)))
            
        return self._permute((left_side | (right_side << 32)),self._permutation_final, 64)
    
    def _cipherRound(self, left0_32bit, right0_32bit, round_key):
        
        print("Left 0 value: " + str(left0_32bit))
        print("Right 0 value: " + str(right0_32bit))
        print("Round key: " + str(round_key))
        
        print("")
        
        left1_32bit = right0_32bit
       
        right1_32bit = (self._cipherFunction(right0_32bit, round_key) ^ left0_32bit)
        
        return left1_32bit, right1_32bit
        
    
    def _cipherFunction(self, data_32bit, round_key):
        #perform expansion permutation (32bit to 48bit)
        data_48bit = self._permute(data_32bit, self._expansion, 32)
        print("Expansion " + str(data_48bit))
        #Xor value with the round key of iteration
        xor_value = data_48bit ^ round_key
        print("Xor : " + str(xor_value))
        #perform substitution
        substitution = self._substitute(xor_value)
        print("Substitutino: " + str(substitution))
        #Permutation
        return self._permute(substitution, self._permutation, 32)
    
    def _substitute(self, xor_value):        
        output_data = 0
        
        print("XOR VALUE : " + str(xor_value))
        
        #break 48bit xor value into 8 x 6 bit blocks        
        for i in range(0, 8):
            shift_amount = 42 - (i * 6)
            
            block = ((xor_value & (0b111111 << shift_amount)) >> shift_amount)
            print("Block : " + str(block))

            block_outer_bits = block & 0b100001
            
            if self._getNthBit(block_outer_bits, 5):
                block_outer_bits = (block_outer_bits | 2) & 0b11 #Shift the MSb to index 1 to get a proper index in substitution table (row)
            
            block_inner_bits = (block & 0b011110) >> 1  #shifted left to get directly the correct index in substitution table (column)
            
            substituted_block = self._substitution_boxes[i][block_outer_bits][block_inner_bits]
            #Put the substituted block back into the original place in the input
            output_data = output_data | ((substituted_block) << (28 - (i * 4)))
            
        return output_data
            
    
    def _createRoundkeys(self, key_64bit ):        
        #FIRST PERMUTATION        
        key_64bit = self._permute(key_64bit, self._pc_table1, 64)

        left_side =     key_64bit >> 28
        right_side =    (key_64bit & 0xFFFFFFF)
        
        for i in range(0,16):
            #Shift for both of the sides
            left_side = self._leftShift(left_side, 28, self._roundkey_shift[i])
            right_side = self._leftShift(right_side, 28, self._roundkey_shift[i])
            
            #Combine sides
            combined_sides = ((left_side << 28) | right_side)
                        
            #Perform the second permutation
            self._round_keys.append(
                    self._permute(combined_sides, self._pc_table2, 56))

        
    def _byteArrayToInt(self, byte_arr):
        value = 0
        
        for i in range(0, len(byte_arr)):
            value = value | (byte_arr[len(byte_arr) - (i + 1)] << 8 * i)
            
        return value
    
    def _permute(self, value_n_bits, table, var_size):
        permutated_value = 0
        
        for i in range(0,len(table)):
            bit_index = var_size - table[i]

            permutated_value = (permutated_value | (self._getNthBit(value_n_bits, bit_index) << ((len(table) - 1) - i)))
            
        return permutated_value
    
    def _getNthBit(self, value, bit_index):
        if ((value & (1 << bit_index)) != 0):
            return 1
        else:
            return 0
            
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
        
        
                                               
        
            
            
            
            
            

            
        
        