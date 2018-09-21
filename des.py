# -*- coding: utf-8 -*-
"""
Created on Fri Sep 21 17:05:32 2018

@author: Miika
"""

testkey = bytes(range(1,9))


def test():
    
    des = DES()
    
    key_int = des._byteArrayToInt(testkey)
    
    print(key_int)
        
    left_side =     key_int
    right_side =    (key_int & 0xFFFFFFFF) 
    
    print(left_side)
    print(right_side)
    
    left_side = des._permutation(left_side, des._pc_table1_left)
    
    print(left_side)

    right_side = des._permutation(right_side, des._pc_table1_right)
    
    print(right_side)
    

class DES:
    
    _pc_table1_left = 57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36
    _pc_table1_right = 63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4
    _pc_table2 = 14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32
    _key_shift = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

    def __init__(self):
        pass
        
    def _byteArrayToInt(self, byte_arr):
        value = 0
        
        for i in range(0, len(byte_arr)):
            value = value | (byte_arr[len(byte_arr) - (i + 1)] << 8 * i)
            
        return value
    
    def _permutation(self, value_n_bits, table):
        permutated_value = 0
        
        for i in range(0,len(table)):
            permutated_value = permutated_value | (self._getNthBit(value_n_bits, table[i] - 1) << i)
                            
        return permutated_value
    
    def _getNthBit(self,value, bit_index):
        return ((value & (1 << bit_index)) != 0)
        
                                               
        
            
            
            
            
            

            
        
        