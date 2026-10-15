# -*- coding: binary -*-

module Rex
  module Arch
    #
    # ARM 32-bit
    #
    module ARM
      # Register number constants
      R0  = A1 = 0       # function argument / return value
      R1  = A2 = 1       # function argument
      R2  = A3 = 2       # function argument
      R3  = A4 = 3       # function argument
      R4  = V1 = 4       # variable / callee-saved
      R5  = V2 = 5       # variable / callee-saved
      R6  = V3 = 6       # variable / callee-saved
      R7  = V4 = 7       # variable / callee-saved
      R8  = V5 = 8       # variable / callee-saved
      R9  = V6 = SB = 9  # static base / callee-saved
      R10 = V7 = SL = 10 # stack limit / callee-saved
      R11 = V8 = FP = 11 # frame pointer
      R12 = IP = 12      # intra-procedure scratch
      R13 = SP = 13      # stack pointer
      R14 = LR = 14      # link register (return address)
      R15 = PC = 15      # program counter

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
