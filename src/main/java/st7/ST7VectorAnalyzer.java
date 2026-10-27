package st7;

import java.util.LinkedHashMap;
import java.util.Map;

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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * ST7 interrupt vector table. The top of the 64 KB address space holds big-endian code pointers:
 * 0xFFFE is the reset vector, 0xFFFC the TRAP vector and the interrupt vectors lie below them
 * (most devices have up to 16 vectors, 0xFFE0-0xFFFF; the count varies with the device, PM0002
 * section 1). Starting at 0xFFFA the table is followed downwards while the entries look like
 * vectors (0x0000/0xFFFF for an unused vector, or an address in initialised memory outside the
 * table); the first entry that does not stops it. Every pointer target is disassembled and made a
 * function.
 */
public class ST7VectorAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "ST7 Interrupt Vectors";
	private static final String DESCRIPTION =
		"Marks up the ST7 reset, TRAP and interrupt vectors at 0xFFE0-0xFFFF and makes functions of the handlers.";
	private static final int TABLE_START = 0xFFE0;

	public ST7VectorAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.before());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		Processor p = program.getLanguage().getProcessor();
		return p.equals(Processor.findOrPossiblyCreateProcessor("ST7")) ||
			p.equals(Processor.findOrPossiblyCreateProcessor("ST72"));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Memory mem = program.getMemory();
		Listing listing = program.getListing();
		FunctionManager fm = program.getFunctionManager();
		Address top = space.getAddress(0xFFFF);
		Address table = space.getAddress(TABLE_START);
		if (!mem.getAllInitializedAddressSet().contains(table, top)) {
			return true; // the image does not reach the vector table
		}
		PointerDataType p16 = new PointerDataType(null, 2, program.getDataTypeManager());
		Map<Address, String> handlers = new LinkedHashMap<>();
		for (int va = 0xFFFE; va >= TABLE_START; va -= 2) {
			monitor.checkCancelled();
			Address a = space.getAddress(va);
			int w;
			try {
				w = mem.getShort(a) & 0xffff;
			}
			catch (Exception e) {
				break;
			}
			boolean unused = w == 0 || w == 0xffff;
			boolean valid = !unused && w < TABLE_START &&
				mem.getAllInitializedAddressSet().contains(space.getAddress(w));
			boolean fixed = va == 0xFFFE || va == 0xFFFC;
			if (!fixed && !unused && !valid) {
				break; // not a vector: the table has fewer entries
			}
			try {
				DataUtilities.createData(program, a, p16, 2, false,
					DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
			}
			catch (Exception e) {
				continue;
			}
			if (valid) {
				String name = va == 0xFFFE ? "RESET_handler"
						: va == 0xFFFC ? "TRAP_handler" : String.format("INT_%04X_handler", va);
				handlers.putIfAbsent(space.getAddress(w), name);
			}
		}
		if (handlers.isEmpty()) {
			return true;
		}
		AddressSet targets = new AddressSet();
		handlers.keySet().forEach(targets::add);
		new DisassembleCommand(targets, null, true).applyTo(program, monitor);
		for (Map.Entry<Address, String> e : handlers.entrySet()) {
			Address t = e.getKey();
			if (listing.getInstructionAt(t) == null) {
				continue;
			}
			if (fm.getFunctionAt(t) == null) {
				new CreateFunctionCmd(t).applyTo(program, monitor);
			}
			Function f = fm.getFunctionAt(t);
			if (f != null && f.getSymbol().getSource() == SourceType.DEFAULT) {
				try {
					f.setName(e.getValue(), SourceType.ANALYSIS);
				}
				catch (Exception ex) {
					// keep the default name
				}
			}
		}
		return true;
	}
}
