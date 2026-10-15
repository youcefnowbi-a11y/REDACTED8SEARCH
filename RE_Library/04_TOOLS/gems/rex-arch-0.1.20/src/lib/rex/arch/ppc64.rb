# -*- coding: binary -*-

module Rex
  module Arch
    #
    # PPC 64-bit
    #
    module PPC64
      # Register number constants
      R0  = 0       # scratch / special
      R1  = SP = 1  # stack pointer
      R2  = TOC = 2 # table of contents / global pointer
      R3  = 3       # function argument / return value
      R4  = 4       # function argument
      R5  = 5       # function argument
      R6  = 6       # function argument
      R7  = 7       # function argument
      R8  = 8       # function argument
      R9  = 9       # function argument
      R10 = 10      # function argument
      R11 = 11      # temporary
      R12 = 12      # temporary
      R13 = 13      # small data area pointer
      R14 = 14      # callee-saved
      R15 = 15      # callee-saved
      R16 = 16      # callee-saved
      R17 = 17      # callee-saved
      R18 = 18      # callee-saved
      R19 = 19      # callee-saved
      R20 = 20      # callee-saved
      R21 = 21      # callee-saved
      R22 = 22      # callee-saved
      R23 = 23      # callee-saved
      R24 = 24      # callee-saved
      R25 = 25      # callee-saved
      R26 = 26      # callee-saved
      R27 = 27      # callee-saved
      R28 = 28      # callee-saved
      R29 = 29      # callee-saved
      R30 = 30      # callee-saved
      R31 = 31      # callee-saved

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
