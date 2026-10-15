# -*- coding: binary -*-

module Rex
  module Arch
    #
    # z/Arch 64-bit
    #
    module ZArch
      # Register number constants
      R0  = 0       # general purpose, often scratch
      R1  = 1       # general purpose, sometimes function arg
      R2  = 2       # function argument / return value
      R3  = 3       # function argument
      R4  = 4       # function argument
      R5  = 5       # function argument
      R6  = 6       # function argument
      R7  = 7       # function argument
      R8  = 8       # callee-saved / local variable
      R9  = 9       # callee-saved / local variable
      R10 = 10      # callee-saved / local variable
      R11 = 11      # callee-saved / local variable
      R12 = 12      # callee-saved / local variable
      R13 = 13      # callee-saved / local variable
      R14 = LR = 14 # link register (return address)
      R15 = SP = 15 # stack pointer / base register

      # @return the number associated with a named register
      def self.reg_number(str)
        const_get(str.upcase)
      end

      # Check if a provided number represents a valid register
      # @return [Boolean]
      def self._check_reg(*regs)
        regs.each do |reg|
          raise ArgumentError, "Invalid register #{reg}", caller if reg > 15 || reg < 0
        end

        nil
      end
    end
  end
end
