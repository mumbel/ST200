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

public class ST200_ElfRelocationConstants {

    /**
     * 0015 DATA2:  A 16-bit field occupying two bytes with arbitary alignment
     * 0031 DATA4:  A 32-bit field occupying four bytes with arbitrary alignment
     * 0022 BTARG:  The BTARG field of an operation with call or branch format
     * 0022 IMM:    The IMM field of an operation
     * 1220 ISRC2:  The ISRC2 field of an operation
     */
    /**
     * A  - addend, present in relocation in .rela or storage unit for .rel
     * BD - base address different
     * GP - global pointer value
     * P  - place (section offset or address) of storage unit being relocated
     * S  - value of symbol
     * @dtpldm(expr) - computes ti_index structure
     * @dtpmod(expr) - computes dymamic module id
     * @dtpndx(expr) - computes ti_index structure
     * @dtprel(expr) - computes offset of expre from start of TLS
     * @gotoff(expr) - requests createion of got entry
     * @gprel(expr) - gp-relative displacement
     * @ltv(expr) - link-time value of expresison
     * @neggprel(expr) - negative gprel expression
     * @segrel(expr) - segment-relative displacement
     * @tprel(expr) - tp-relative displacement
     */
    public static final int R_ST200_NONE = 0; // None, None
    public static final int R_ST200_16 = 1; // DATA2, S+A
    public static final int R_ST200_32 = 2; // DATA4, S+A
    public static final int R_ST200_32_PCREL = 3; // DATA4, S+A-P
    public static final int R_ST200_23_PCREL = 4; // BTARG, (S + A - P) >> 2
    public static final int R_ST200_HI23 = 5; // IMM, (S + A) >> 9
    public static final int R_ST200_LO9 = 6; // ISRC2, (S + A) & 0x1ff
    public static final int R_ST200_GPREL_HI23 = 7; // IMM, (@gprel(S + A)) >> 9
    public static final int R_ST200_GPREL_LO9 = 8; // ISRC2, (@gprel(S +A)) & 0x1ff
    public static final int R_ST200_REL32 = 9; // DATA4, BD + A
    public static final int R_ST200_GOTOFF_HI23 = 10; // IMM, (@gotoff(S + A)) >> 9
    public static final int R_ST200_GOTOFF_LO9 = 11; // ISRC2, (@gotoff(S + A)) & 0x1ff
    public static final int R_ST200_LTV32 = 14; // DATA4, @ltv(S + A), see Table 9.
    public static final int R_ST200_SEGREL32 = 15; // DATA4, @segrel(S + A)
    public static final int R_ST200_NEGGPREL_HI23 = 22; // IMM, (@neggprel(S + A)) >> 9
    public static final int R_ST200_NEGGPREL_LO9 = 23; // ISRC2, (@neggprel(S + A)) & 0x1ff
    public static final int R_ST200_COPY = 24; // None, None, see Table 9.
    public static final int R_ST200_JMP_SLOT = 25; // DATA4, S, see Table 9.
    public static final int R_ST200_TPREL_HI23 = 26; // IMM, (@tprel(S + A)) >> 9
    public static final int R_ST200_TPREL_LO9 = 27; // ISRC2, (@tprel(S + A)) & 0x1ff
    public static final int R_ST200_TPREL32 = 28; // DATA4, @tprel(S + A)
    public static final int R_ST200_GOTOFF_TPREL_HI23 = 29; // IMM, (@gotoff(@tprel(S + A)))>>9
    public static final int R_ST200_GOTOFF_TPREL_LO9 = 30; // ISRC2, (@gotoff(@tprel(S + A))) & 0x1ff
    public static final int R_ST200_GOTOFF_DTPLDM_HI23 = 31; // IMM, (@gotoff(@dtpldm(S + A)))>>9
    public static final int R_ST200_GOTOFF_DTPLDM_LO9 = 32; // ISRC2, (@gotoff(@dtpldm(S + A)))& 0x1ff
    public static final int R_ST200_DTPREL_HI23 = 33; // IMM, (@dtprel(S + A))>>9
    public static final int R_ST200_DTPREL_LO9 = 34; // ISRC2, (@dtprel(S + A))& 0x1ff
    public static final int R_ST200_DTPMOD32 = 35; // DATA4, @dtpmod(S + A)
    public static final int R_ST200_DTPREL32 = 36; // DATA4, @dtprel(S + A)
    public static final int R_ST200_GOTOFF_DTPNDX_HI23 = 37; // IMM, (@gotoff(@dtpndx(S + A)))>>9
    public static final int R_ST200_GOTOFF_DTPNDX_LO9 = 38; // ISRC2, (@gotoff(@dtpndx(S + A)))& 0x1ff
}
