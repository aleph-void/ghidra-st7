// Real-code check (run as -postScript after auto-analysis). Writes, with the given prefix:
//   <prefix>.summary  counts: functions, instructions, bookmarks, decompile failures/timeouts/warnings
//   <prefix>.dis      "<addr-hex> <bytes-hex> <instruction>" for every instruction in the listing
//   <prefix>.c        listing + decompiler output of every function
//   <prefix>.funcs    "<entry-address-hex> <name>" for every function
// Script args: <prefix> [decompile-timeout-seconds]
//@category Testing

import java.io.PrintStream;
import java.util.Map;
import java.util.TreeMap;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class RealCheck extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		String prefix = args[0];
		int timeout = args.length > 1 ? Integer.parseInt(args[1]) : 60;
		PrintStream sum = new PrintStream(prefix + ".summary");
		PrintStream dis = new PrintStream(prefix + ".dis");
		PrintStream cout = new PrintStream(prefix + ".c");
		PrintStream fout = new PrintStream(prefix + ".funcs");

		sum.println("language: " + currentProgram.getLanguageID() + " / " +
			currentProgram.getCompilerSpec().getCompilerSpecID());

		int nins = 0;
		long insBytes = 0;
		for (Instruction i : currentProgram.getListing().getInstructions(true)) {
			nins++;
			insBytes += i.getLength();
			StringBuilder hex = new StringBuilder();
			for (byte x : i.getBytes()) {
				hex.append(String.format("%02x", x & 0xff));
			}
			dis.printf("%04x %s %s%n", i.getAddress().getOffset(), hex, i.toString());
		}

		Map<String, Integer> bm = new TreeMap<>();
		java.util.Iterator<Bookmark> it = currentProgram.getBookmarkManager().getBookmarksIterator();
		while (it.hasNext()) {
			Bookmark b = it.next();
			if (b.getTypeString().equals("Error") || b.getTypeString().equals("Warning")) {
				String k = b.getTypeString() + "/" + b.getCategory();
				bm.merge(k, 1, Integer::sum);
				sum.println("bookmark " + k + " @ " + b.getAddress() + ": " + b.getComment());
			}
		}

		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(new DecompileOptions());
		ifc.openProgram(currentProgram);
		int nf = 0, fail = 0, tmo = 0, warnFns = 0, nzero = 0;
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (f.isThunk() || f.isExternal()) {
				continue;
			}
			// code the image does not contain (the firmware copies a routine into RAM and jumps
			// there): the disassembler sees a run of zero bytes, which decodes as BTJT chains
			boolean zero = true;
			for (Instruction i : currentProgram.getListing().getInstructions(f.getBody(), true)) {
				for (byte x : i.getBytes()) {
					zero &= x == 0;
				}
			}
			if (zero) {
				sum.println("skipped (zero-filled, not part of the image): " + f.getName());
				nzero++;
				continue;
			}
			nf++;
			fout.printf("%04x %s%n", f.getEntryPoint().getOffset(), f.getName());
			cout.println("==== " + f.getName() + " @ " + f.getEntryPoint() + "  " + f.getSignature());
			for (Instruction i : currentProgram.getListing().getInstructions(f.getBody(), true)) {
				cout.printf("  %s  %s%n", i.getAddress(), i.toString());
			}
			DecompileResults res = ifc.decompileFunction(f, timeout, monitor);
			if (res.decompileCompleted()) {
				String c = res.getDecompiledFunction().getC();
				cout.println(c);
				if (c.contains("WARNING")) {
					warnFns++;
				}
			}
			else {
				String err = res.getErrorMessage();
				if (res.isTimedOut() || err.toLowerCase().contains("timeout")) {
					tmo++;
				}
				else {
					fail++;
				}
				cout.println("  DECOMPILE FAILED: " + err);
				sum.println("decompile failed: " + f.getName() + ": " + err.trim());
			}
		}
		ifc.dispose();
		sum.println("functions: " + nf + " (+ " + nzero + " zero-filled RAM stub, not decompiled)");
		sum.println("instructions: " + nins + " (" + insBytes + " bytes)");
		sum.println("bookmarks: " + bm);
		sum.println("decompile: " + (nf - fail - tmo) + " ok, " + fail + " failed, " + tmo +
			" timeouts; " + warnFns + " with warnings");
		sum.close();
		dis.close();
		cout.close();
		fout.close();
	}
}
