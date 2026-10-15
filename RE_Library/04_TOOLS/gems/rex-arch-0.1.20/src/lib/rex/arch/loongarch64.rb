# -*- coding: binary -*-

module Rex
  module Arch
    #
    # LoongArch64 64-bit
    #
    module LoongArch64
      # Register number constants
      R0  = ZERO = 0 # constant 0 (hardwired zero)
      R1  = RA = 1   # return address
      R2  = SP = 2   # stack pointer
      R3  = GP = 3   # global pointer
      R4  = TP = 4   # thread pointer
      R5  = T0 = 5   # temporary
      R6  = T1 = 6   # temporary
      R7  = T2 = 7   # temporary
      R8  = T3 = 8   # temporary
      R9  = T4 = 9   # temporary
      R10 = T5 = 10  # temporary
      R11 = T6 = 11  # temporary
      R12 = T7 = 12  # temporary
      R13 = T8 = 13  # temporary
      R14 = T9 = 14  # temporary
      R15 = T10 = 15 # temporary
      R16 = T11 = 16 # temporary
      R17 = T12 = 17 # temporary
      R18 = T13 = 18 # temporary
      R19 = T14 = 19 # temporary
      R20 = T15 = 20 # temporary
      R21 = T16 = 21 # temporary
      R22 = T17 = 22 # temporary
      R23 = T18 = 23 # temporary
      R24 = T19 = 24 # temporary
      R25 = T20 = 25 # temporary
      R26 = T21 = 26 # temporary
      R27 = T22 = 27 # temporary
      R28 = T23 = 28 # temporary
      R29 = FP = 29  # frame pointer
      R30 = S0 = 30  # saved register
      R31 = S1 = 31  # saved register

      # @return the number associated with a named register.
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
