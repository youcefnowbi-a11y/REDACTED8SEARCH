# -*- coding: binary -*-

module Rex
  module Arch
    #
    # AMD64 (x86_64) 64-bit
    #
    module AMD64
      # Register number constants
      RAX = EAX = AX = AH = AL = 0   # accumulator
      RBX = EBX = BX = BH = BL = 1   # base
      RCX = ECX = CX = CH = CL = 2   # counter
      RDX = EDX = DX = DH = DL = 3   # data
      RSI = ESI = SI = 4             # source index
      RDI = EDI = DI = 5             # destination index
      RBP = EBP = BP = 6             # base pointer
      RSP = ESP = SP = 7             # stack pointer
      R8  = R8D = R8W = R8B = 8      # extended register
      R9  = R9D = R9W = R9B = 9
      R10 = R10D = R10W = R10B = 10
      R11 = R11D = R11W = R11B = 11
      R12 = R12D = R12W = R12B = 12
      R13 = R13D = R13W = R13B = 13
      R14 = R14D = R14W = R14B = 14
      R15 = R15D = R15W = R15B = 15

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
