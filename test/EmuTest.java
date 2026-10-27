// P-code semantics check for the ST7 module. Reads test/emu/cases.txt (expectations worked out by
// hand from the ST7 Family Programming Manual, PM0002), and for each case writes the code at 0x1000,
// sets registers and memory, emulates with Ghidra's EmulatorHelper until the PC reaches the end of
// the code (or the address given by "until"), and compares registers, flags and memory.
//
// Case format (one directive per line, '#' comments):
//   case <name> [only st70|st72] [broken]   "broken" cases carry a deliberately wrong expectation
//   code <hex>                              bytes placed at 0x1000
//   until <hex-address>                     stop when PC reaches this address (default: end of code)
//   set <reg> <value> | set mem:<hex-addr> <value>
//   expect <reg> <value> | expect mem:<hex-addr> <value>
//   end
// Script args: <cases.txt> <outfile>
//@category Testing

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;

public class EmuTest extends GhidraScript {

	private static class Case {
		String name;
		String only = "";
		boolean broken;
		byte[] code;
		long until = -1;
		Map<String, Long> set = new LinkedHashMap<>();
		Map<String, Long> expect = new LinkedHashMap<>();
	}

	private List<Case> load(String path) throws Exception {
		List<Case> cases = new ArrayList<>();
		Case c = null;
		try (BufferedReader r = new BufferedReader(new FileReader(path))) {
			String line;
			while ((line = r.readLine()) != null) {
				int h = line.indexOf('#');
				if (h >= 0) {
					line = line.substring(0, h);
				}
				line = line.trim();
				if (line.isEmpty()) {
					continue;
				}
				String[] f = line.split("\\s+");
				switch (f[0]) {
					case "case":
						c = new Case();
						c.name = f[1];
						for (int i = 2; i < f.length; i++) {
							if (f[i].equals("only")) {
								c.only = f[++i];
							}
							else if (f[i].equals("broken")) {
								c.broken = true;
							}
						}
						break;
					case "code":
						String hex = String.join("", java.util.Arrays.copyOfRange(f, 1, f.length));
						c.code = new byte[hex.length() / 2];
						for (int i = 0; i < c.code.length; i++) {
							c.code[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
						}
						break;
					case "until":
						c.until = Long.parseLong(f[1], 16);
						break;
					case "set":
						c.set.put(f[1], Long.decode(f[2]));
						break;
					case "expect":
						c.expect.put(f[1], Long.decode(f[2]));
						break;
					case "end":
						cases.add(c);
						break;
					default:
						throw new IllegalArgumentException("bad line: " + line);
				}
			}
		}
		return cases;
	}

	private Address addr(long off) {
		return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(off);
	}

	private String runCase(Case c) throws Exception {
		Address start = addr(0x1000);
		Address end = c.until >= 0 ? addr(c.until) : start.add(c.code.length);
		clearListing(new AddressSet(start, start.add(c.code.length)));
		setBytes(start, c.code);
		EmulatorHelper emu = new EmulatorHelper(currentProgram);
		try {
			for (Map.Entry<String, Long> e : c.set.entrySet()) {
				if (e.getKey().startsWith("mem:")) {
					emu.writeMemory(addr(Long.parseLong(e.getKey().substring(4), 16)),
						new byte[] { (byte) (long) e.getValue() });
				}
				else {
					emu.writeRegister(e.getKey(), e.getValue());
				}
			}
			emu.writeRegister(emu.getPCRegister(), start.getOffset());
			int steps = 0;
			while (!emu.getExecutionAddress().equals(end)) {
				if (++steps > 200) {
					return "did not reach the end (pc " + emu.getExecutionAddress() + ")";
				}
				if (!emu.step(monitor)) {
					return "emulation error at " + emu.getExecutionAddress() + ": " +
						emu.getLastError();
				}
			}
			StringBuilder bad = new StringBuilder();
			for (Map.Entry<String, Long> e : c.expect.entrySet()) {
				long got;
				if (e.getKey().startsWith("mem:")) {
					got = emu.readMemory(addr(Long.parseLong(e.getKey().substring(4), 16)),
						1)[0] & 0xff;
				}
				else if (e.getKey().equals("PC")) {
					got = emu.getExecutionAddress().getOffset();
				}
				else {
					got = emu.readRegister(e.getKey()).longValue();
				}
				if (got != e.getValue()) {
					bad.append(String.format(" %s=0x%x (expected 0x%x)", e.getKey(), got,
						e.getValue()));
				}
			}
			return bad.length() == 0 ? null : bad.toString().trim();
		}
		finally {
			emu.dispose();
		}
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		List<Case> cases = load(args[0]);
		PrintStream out = new PrintStream(args[1]);
		String lang = currentProgram.getLanguageID().getIdAsString();
		String variant = lang.startsWith("ST72") ? "st72" : "st70";
		int pass = 0, fail = 0, brokenSeen = 0, brokenMissed = 0;
		for (Case c : cases) {
			if (!c.only.isEmpty() && !c.only.equals(variant)) {
				continue;
			}
			String err = runCase(c);
			if (c.broken) {
				if (err != null) {
					brokenSeen++;
					out.println("PASS (broken expectation detected) " + c.name + ": " + err);
				}
				else {
					brokenMissed++;
					out.println("FAIL " + c.name + ": the deliberately wrong expectation passed");
				}
			}
			else if (err == null) {
				pass++;
				out.println("PASS " + c.name);
			}
			else {
				fail++;
				out.println("FAIL " + c.name + ": " + err);
			}
		}
		out.printf("emulation (%s): %d passed, %d failed, broken expectation %s%n", lang, pass,
			fail + brokenMissed, brokenSeen > 0 && brokenMissed == 0 ? "detected" : "NOT detected");
		out.close();
	}
}
