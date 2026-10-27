# STMicroelectronics ST7 processor module for Ghidra

SLEIGH processor module for the ST7 8-bit microcontroller core (ST72xxx, ST7FLITE and relatives):
disassembly, p-code, and two small analyzers for the interrupt vector table and for the
push/push/ret jump tables the core's manual recommends. Target: **Ghidra 12.1.4** (also builds for
12.1.3 and 12.2).

The SLEIGH definition is Alessandro Gatti's ([@agatti](https://github.com/agatti)) contribution
to Ghidra, [pull request #3631](https://github.com/NationalSecurityAgency/ghidra/pull/3631)
(Apache-2.0, never merged), with its decode fixed and its p-code rewritten and verified by
Ghidra-Rare. See [CREDITS.md](CREDITS.md) for provenance and the list of changes, and
[GHIDRA-RARE.md](GHIDRA-RARE.md) for how it was verified, the numbers, and the remaining gaps.
Prebuilt extension zips for Ghidra 12.1.3, 12.1.4 and 12.2 are on this fork's GitHub Releases
page.

## Languages

| Language ID | Core |
|---|---|
| `ST7:BE:16:default` | ST7 with the single interrupt mask bit `I` (CC = `111HINZC`), as in the programming manual PM0002 |
| `ST72:BE:16:default` | ST7 with the two-bit interrupt priority `I1`/`I0` (CC = `11 I1 H I0 N Z C`) found on newer devices; identical except for the interrupt-level instructions (`SIM`, `RIM`, `JRM`, `JRNM`, `HALT`, `WFI`, `TRAP`) and the CC image |

Both use one 64 KB big-endian address space (`ram`), registers `A X Y SP PC` and flags `H I N Z C`
(`I1 H I0 N Z C`) as separate registers. `CC` exists as a staging register for `PUSH CC`/`POP CC`
(bits 7-5 read as 1, as in the manual's figure). `EXTI` is a pseudo register for the external
interrupt pin tested by `JRIH`/`JRIL`. The processor spec defines the reset (`0xFFFE`) and TRAP
(`0xFFFC`) vectors; an ELF opinion exists for `e_machine` 68 (untested, no ST7 ELF file was
available).

## Analyzers

- **ST7 Interrupt Vectors** marks `0xFFFE` (reset), `0xFFFC` (TRAP) and the interrupt vectors
  below them (to `0xFFE0`, as long as the entries look like vectors), disassembles the handlers
  and makes functions of them.
- **ST7 Stack Dispatch Tables** recognises `ld A,(table,X); push A; dec X; ld A,(table,X); push A;
  ret` (PM0002 section 5.3) and makes functions of the table's targets.

## Limitations of the upstream pull request and their state

The pull request has no README; these come from its review thread and from testing.

| Limitation | State |
|---|---|
| 13 unresolvable pattern conflicts under `sleigh -l` (BTJT/BTJF/BSET/BRES vs NEG/CPL/...), the open question in the thread | Fixed: the single-operand group is constrained to its addressing nibbles, `sleigh -l` is clean |
| Never tested ("do you have an ST7 cross compiler to run the tests?") | Fixed: see GHIDRA-RARE.md. SDCC has no ST7 port; asl, a model of the manual, uCsim and real firmware are used |
| Decode: a pre-byte could follow a pre-byte | Fixed |
| P-code: one-byte pointers used as 16-bit addresses, wrong carry/borrow/half-carry, SRA, RLC/RRC flags, BTJx did not set C, TRAP overwrote A and jumped to 0xFFFC, direct JP/CALL were computed jumps, indirect relative branches jumped into unique space | Fixed (commit message of the p-code rewrite lists each) |
| `RSP` forced `SP` to `0x01FF` ("some datasheets say 0x01FF") | Changed: the low byte of `SP` becomes `0xFF` and the high byte, which the device fixes, is left alone |
| Only reset and TRAP vectors; no jump-table handling | Fixed for the vector table and the stack dispatch idiom (analyzers above) |
| ST7 vs "ST72" naming | Language IDs kept; descriptions now say what differs |
| Interrupt entry, `HALT`, `WFI`, peripheral registers, stack wrap-around | Remaining, see GHIDRA-RARE.md ("Doesn't work") |
| The plan to add ST6, STM8, ST9, ST10 to the same `STM` family directory | Not part of this module (STM8 and ST6 are different instruction sets; Ghidra-Rare has a separate ST9) |
