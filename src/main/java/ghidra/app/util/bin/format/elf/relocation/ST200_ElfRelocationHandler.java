/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.bin.format.elf.relocation;

import java.util.Map;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;
import ghidra.util.exception.NotFoundException;

public class ST200_ElfRelocationHandler extends ElfRelocationHandler {

    @Override
    public boolean canRelocate(ElfHeader elf) {
	return elf.e_machine() == ElfConstants.EM_ST200;
    }

    @Override
    public ST200_ElfRelocationContext createRelocationContext(ElfLoadHelper loadHelper,
							      Map<ElfSymbol, Address> symbolMap) {
	return new ST200_ElfRelocationContext(this, loadHelper, symbolMap);
    }

    @Override
    public RelocationResult relocate(ElfRelocationContext elfRelocationContext,
				     ElfRelocation relocation, Address relocationAddress)
	throws MemoryAccessException, NotFoundException {
	ElfHeader elf = elfRelocationContext.getElfHeader();
	if (!canRelocate(elf)) {
	    return RelocationResult.FAILURE;
	}

	Program program = elfRelocationContext.getProgram();
	Memory memory = program.getMemory();
	boolean is32 = elf.is32Bit();
	int type = relocation.getType();

	if (ST200_ElfRelocationConstants.R_ST200_NONE == type) {
	    return RelocationResult.SKIPPED;
	}

	long addend = relocation.getAddend();
	long offset = relocationAddress.getOffset();
	long base = elfRelocationContext.getImageBaseWordAdjustmentOffset();
	int symbolIndex = relocation.getSymbolIndex();
	ElfSymbol sym = elfRelocationContext.getSymbol(symbolIndex);
	Address symbolAddr = elfRelocationContext.getSymbolAddress(sym);
	long symbolValue = elfRelocationContext.getSymbolValue(sym);
	String symbolName = elfRelocationContext.getSymbolName(symbolIndex);

	switch (type) {
	case ST200_ElfRelocationConstants.R_ST200_16:
	    // S+A
	    markAsWarning(program, relocationAddress, "R_ST200_", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_32:
	    //S+A
	    markAsWarning(program, relocationAddress, "R_ST200_32", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_32_PCREL:
	    // S+A-P
	    markAsWarning(program, relocationAddress, "R_ST200_32_PCREL", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_23_PCREL:
	    // (S + A - P) >> 2
	    markAsWarning(program, relocationAddress, "R_ST200_23_PCREL", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_HI23:
	    // (S + A) >> 9
	    markAsWarning(program, relocationAddress, "R_ST200_HI23", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_LO9:
	    // (S + A) & 0x1ff
	    markAsWarning(program, relocationAddress, "R_ST200_LO9", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_GPREL_HI23:
	    // (@gprel(S + A)) >> 9
	    markAsWarning(program, relocationAddress, "R_ST200_GPREL_HI23", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_GPREL_LO9:
	    // (@gprel(S +A)) & 0x1ff
	    markAsWarning(program, relocationAddress, "R_ST200_GPREL_LO9", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_REL32:
	    // BD + A
	    markAsWarning(program, relocationAddress, "R_ST200_REL32", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_GOTOFF_HI23:
	    // (@gotoff(S + A)) >> 9
	    markAsWarning(program, relocationAddress, "R_ST200_GOTOFF_HI23", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_GOTOFF_LO9:
	    // (@gotoff(S + A)) & 0x1ff
	    markAsWarning(program, relocationAddress, "R_ST200_GOTOFF_LO9", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_LTV32:
	    // @ltv(S + A)
	    // see Table 9.
	    markAsWarning(program, relocationAddress, "R_ST200_LTV32", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_SEGREL32:
	    // @segrel(S + A)
	    markAsWarning(program, relocationAddress, "R_ST200_SEGREL32", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_NEGGPREL_HI23:
	    // (@neggprel(S + A)) >> 9
	    markAsWarning(program, relocationAddress, "R_ST200_NEGGPREL_HI23", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_NEGGPREL_LO9:
	    // (@neggprel(S + A)) & 0x1ff
	    markAsWarning(program, relocationAddress, "R_ST200_NEGGPREL_LO9", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_COPY:
	    // None
	    // see Table 9.
	    markAsWarning(program, relocationAddress, "R_ST200_COPY", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_JMP_SLOT:
	    // S
	    // see Table 9.
	    markAsWarning(program, relocationAddress, "R_ST200_JMP_SLOT", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_TPREL_HI23:
	    // (@tprel(S + A)) >> 9
	    markAsWarning(program, relocationAddress, "R_ST200_TPREL_HI23", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_TPREL_LO9:
	    // (@tprel(S + A)) & 0x1ff
	    markAsWarning(program, relocationAddress, "R_ST200_TPREL_LO9", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_TPREL32:
	    // @tprel(S + A)
	    markAsWarning(program, relocationAddress, "R_ST200_TPREL32", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_GOTOFF_TPREL_HI23:
	    // (@gotoff(@tprel(S + A)))>>9
	    markAsWarning(program, relocationAddress, "R_ST200_GOTOFF_TPREL_HI23", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_GOTOFF_TPREL_LO9:
	    // (@gotoff(@tprel(S + A))) & 0x1ff
	    markAsWarning(program, relocationAddress, "R_ST200_GOTOFF_TPREL_LO9", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_GOTOFF_DTPLDM_HI23:
	    // (@gotoff(@dtpldm(S + A)))>>9
	    markAsWarning(program, relocationAddress, "R_ST200_GOTOFF_DTPLDM_HI23", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_GOTOFF_DTPLDM_LO9:
	    // (@gotoff(@dtpldm(S + A)))& 0x1ff
	    markAsWarning(program, relocationAddress, "R_ST200_GOTOFF_DTPLDM_LO9", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_DTPREL_HI23:
	    // (@dtprel(S + A))>>9
	    markAsWarning(program, relocationAddress, "R_ST200_DTPREL_HI23", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_DTPREL_LO9:
	    // (@dtprel(S + A))& 0x1ff
	    markAsWarning(program, relocationAddress, "R_ST200_DTPREL_LO9", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_DTPMOD32:
	    // @dtpmod(S + A)
	    markAsWarning(program, relocationAddress, "R_ST200_DTPMOD32", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_DTPREL32:
	    // @dtprel(S + A)
	    markAsWarning(program, relocationAddress, "R_ST200_DTPREL32", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_GOTOFF_DTPNDX_HI23:
	    // (@gotoff(@dtpndx(S + A)))>>9
	    markAsWarning(program, relocationAddress, "R_ST200_GOTOFF_DTPNDX_HI23", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	case ST200_ElfRelocationConstants.R_ST200_GOTOFF_DTPNDX_LO9:
	    // (@gotoff(@dtpndx(S + A)))& 0x1
	    markAsWarning(program, relocationAddress, "R_ST200_GOTOFF_DTPNDX_LO9", symbolName,
			  symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	default:
	    markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
			    elfRelocationContext.getLog());
	    return RelocationResult.UNSUPPORTED;
	};

    }
}
