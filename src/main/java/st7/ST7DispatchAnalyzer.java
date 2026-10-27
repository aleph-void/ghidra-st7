package st7;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Jump tables dispatched with the stack, the idiom of the programming manual's JMPCALLTBL
 * (PM0002 section 5.3):
 *
 * <pre>
 *     ld A,(table,X)    ; low byte   (X = 2*n+1)
 *     push A
 *     dec X
 *     ld A,(table,X)    ; high byte
 *     push A
 *     ret               ; "returns" into table[n]
 * </pre>
 *
 * A RET preceded by two PUSH A of bytes loaded with LD A,(long,X) from the same table (or from
 * adjacent addresses) marks a table of big-endian code pointers. The entries are followed while
 * they point into initialised memory outside the 0xFFE0-0xFFFF vector table (at most 128, the
 * most an index masked to seven bits can select); each target is disassembled and made a function.
 */
public class ST7DispatchAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "ST7 Stack Dispatch Tables";
	private static final String DESCRIPTION =
		"Finds push/push/ret jump tables and makes functions of their targets.";
	private static final int MAX_ENTRIES = 128;

	public ST7DispatchAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.CODE_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		Processor p = program.getLanguage().getProcessor();
		return p.equals(Processor.findOrPossiblyCreateProcessor("ST7")) ||
			p.equals(Processor.findOrPossiblyCreateProcessor("ST72"));
	}

	private static int firstByte(Instruction i) {
		try {
			return i.getByte(0) & 0xff;
		}
		catch (Exception e) {
			return -1;
		}
	}

	private static boolean isPushA(Instruction i) {
		return i != null && i.getLength() == 1 && firstByte(i) == 0x88;
	}

	/** Returns the table address if i is LD A,(long,X) (opcode D6), else -1. */
	private static int ldTable(Instruction i) {
		try {
			if (i != null && i.getLength() == 3 && (i.getByte(0) & 0xff) == 0xD6) {
				return (i.getByte(1) & 0xff) << 8 | (i.getByte(2) & 0xff);
			}
		}
		catch (Exception e) {
			// not decodable
		}
		return -1;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Memory mem = program.getMemory();
		Listing listing = program.getListing();
		PointerDataType p16 = new PointerDataType(null, 2, program.getDataTypeManager());
		for (Instruction ret : listing.getInstructions(set, true)) {
			monitor.checkCancelled();
			if (ret.getLength() != 1 || firstByte(ret) != 0x81) {
				continue; // not RET
			}
			// walk back: PUSH A, [DEC X / other], LD A,(t1,X) ... PUSH A, LD A,(t2,X)
			Instruction cur = ret.getPrevious();
			if (!isPushA(cur)) {
				continue;
			}
			int found = 0;
			int lo = Integer.MAX_VALUE;
			int steps = 0;
			cur = cur.getPrevious();
			// expect: LD A,(T,X) directly before the last PUSH A
			int t = ldTable(cur);
			if (t < 0) {
				continue;
			}
			found = 1;
			lo = t;
			cur = cur.getPrevious();
			while (cur != null && steps++ < 6 && found < 2) {
				if (isPushA(cur)) {
					Instruction ld = cur.getPrevious();
					int t2 = ldTable(ld);
					if (t2 >= 0 && Math.abs(t2 - t) <= 1) {
						lo = Math.min(lo, t2);
						found = 2;
					}
					break;
				}
				cur = cur.getPrevious();
			}
			if (found < 2) {
				continue;
			}
			List<Address> targets = new ArrayList<>();
			int n = 0;
			for (; n < MAX_ENTRIES; n++) {
				int ea = lo + 2 * n;
				if (ea + 1 > 0xFFDF) {
					break;
				}
				Address ta = space.getAddress(ea);
				int w;
				try {
					w = mem.getShort(ta) & 0xffff;
				}
				catch (Exception e) {
					break;
				}
				Address target = space.getAddress(w);
				if (w >= 0xFFE0 || !mem.getAllInitializedAddressSet().contains(target)) {
					break;
				}
				try {
					DataUtilities.createData(program, ta, p16, 2, false,
						DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
				}
				catch (Exception e) {
					break;
				}
				targets.add(target);
			}
			if (targets.isEmpty()) {
				continue;
			}
			AddressSet starts = new AddressSet();
			targets.forEach(starts::add);
			new DisassembleCommand(starts, null, true).applyTo(program, monitor);
			for (Address a : targets) {
				if (listing.getInstructionAt(a) != null &&
					program.getFunctionManager().getFunctionAt(a) == null) {
					new CreateFunctionCmd(a).applyTo(program, monitor);
				}
			}
		}
		return true;
	}
}
