# -*- coding: binary -*-

module Rex
  module Arch
    #
    # MIPS 64-bit
    #
    module MIPS64
      # Register number constants
      R0  = ZERO = 0     # constant 0
      R1  = AT = 1       # assembler temporary
      R2  = V0 = 2       # function return value
      R3  = V1 = 3       # function return value
      R4  = A0 = 4       # argument
      R5  = A1 = 5       # argument
      R6  = A2 = 6       # argument
      R7  = A3 = 7       # argument
      R8  = T0 = 8       # temporary
      R9  = T1 = 9       # temporary
      R10 = T2 = 10      # temporary
      R11 = T3 = 11      # temporary
      R12 = T4 = 12      # temporary
      R13 = T5 = 13      # temporary
      R14 = T6 = 14      # temporary
      R15 = T7 = 15      # temporary
      R16 = S0 = 16      # saved register
      R17 = S1 = 17      # saved register
      R18 = S2 = 18      # saved register
      R19 = S3 = 19      # saved register
      R20 = S4 = 20      # saved register
      R21 = S5 = 21      # saved register
      R22 = S6 = 22      # saved register
      R23 = S7 = 23      # saved register
      R24 = T8 = 24      # temporary
      R25 = T9 = 25      # temporary
      R26 = K0 = 26      # reserved for OS
      R27 = K1 = 27      # reserved for OS
      R28 = GP = 28      # global pointer
      R29 = SP = 29      # stack pointer
      R30 = FP = S8 = 30 # frame pointer / saved
      R31 = RA = 31      # return address

      # @return the number associated with a named register
      def self.reg_number(str)
        const_get(str.upcase)
      end

      # Check if a provided number represents a valid register
      # @return [Boolean]
      def self._check_reg(*regs)
        regs.each do |reg|
          raise ArgumentError, "Invalid register #{reg}", caller if reg > 31 || reg < 0
        end

        nil
      end
    end
  end
end
