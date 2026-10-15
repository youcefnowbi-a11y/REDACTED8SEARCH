# -*- coding: binary -*-

module Rex
  module Arch
    #
    # RISC-V 64-bit
    #
    module RISCV64
      # Register number constants
      ZERO = X0 = 0       # constant 0
      RA   = X1 = 1       # return address
      SP   = X2 = 2       # stack pointer
      GP   = X3 = 3       # global pointer
      TP   = X4 = 4       # thread pointer
      T0   = X5 = 5       # temporary register 0
      T1   = X6 = 6       # temporary register 1
      T2   = X7 = 7       # temporary register 2
      S0   = FP = X8 = 8  # saved register / frame pointer
      S1   = X9 = 9       # saved register
      A0   = X10 = 10     # arg / return value
      A1   = X11 = 11     # arg / return value
      A2   = X12 = 12     # arg
      A3   = X13 = 13     # arg
      A4   = X14 = 14     # arg
      A5   = X15 = 15     # arg
      A6   = X16 = 16     # arg
      A7   = X17 = 17     # arg
      S2   = X18 = 18     # saved register
      S3   = X19 = 19     # saved register
      S4   = X20 = 20     # saved register
      S5   = X21 = 21     # saved register
      S6   = X22 = 22     # saved register
      S7   = X23 = 23     # saved register
      S8   = X24 = 24     # saved register
      S9   = X25 = 25     # saved register
      S10  = X26 = 26     # saved register
      S11  = X27 = 27     # saved register
      T3   = X28 = 28     # temporary register
      T4   = X29 = 29     # temporary register
      T5   = X30 = 30     # temporary register
      T6   = X31 = 31     # temporary register

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
