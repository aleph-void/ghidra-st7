// Single-step state dump for the semantics differential against the uCsim ST7 simulator.
// The program is a 64 KB image (the pattern file written by sem_diff.py) at address 0. For every
// line "<code hex> <A> <X> <Y> <CC> <SP>" of the input the code is placed at 0x1000, the registers
// and flags are set (CC = H<<4 | I<<3 | N<<2 | Z<<1 | C), one instruction is emulated, and the
// result is written as
//   A X Y CC SP PC  followed by "addr=value" for every byte that differs from the image
// (the code bytes themselves excluded).
// Script args: <cases.txt> <outfile>
//@category Testing

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintStream;
import java.util.Arrays;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;

public class EmuDiff extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		PrintStream out = new PrintStream(args[1]);
		boolean st72 = currentProgram.getLanguageID().getIdAsString().startsWith("ST72");
		Address base = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		byte[] image = new byte[65536];
		currentProgram.getMemory().getBytes(base, image);
		Address code = base.add(0x1000);
		EmulatorHelper emu = new EmulatorHelper(currentProgram);
		try (BufferedReader r = new BufferedReader(new FileReader(args[0]))) {
			String line;
			while ((line = r.readLine()) != null) {
				String[] f = line.trim().split("\\s+");
				if (f.length < 6) {
					continue;
				}
				byte[] c = new byte[f[0].length() / 2];
				for (int i = 0; i < c.length; i++) {
					c[i] = (byte) Integer.parseInt(f[0].substring(2 * i, 2 * i + 2), 16);
				}
				long a = Long.decode(f[1]), x = Long.decode(f[2]), y = Long.decode(f[3]);
				long cc = Long.decode(f[4]), sp = Long.decode(f[5]);
				emu.dispose();
				emu = new EmulatorHelper(currentProgram);
				emu.writeMemory(code, c);
				emu.writeRegister("A", a);
				emu.writeRegister("X", x);
				emu.writeRegister("Y", y);
				emu.writeRegister("SP", sp);
				emu.writeRegister("C", cc & 1);
				emu.writeRegister("Z", (cc >> 1) & 1);
				emu.writeRegister("N", (cc >> 2) & 1);
				emu.writeRegister("H", (cc >> 4) & 1);
				if (st72) {
					emu.writeRegister("I0", (cc >> 3) & 1);
					emu.writeRegister("I1", 1);
				}
				else {
					emu.writeRegister("I", (cc >> 3) & 1);
				}
				emu.writeRegister(emu.getPCRegister(), 0x1000);
				boolean ok = emu.step(monitor);
				if (!ok) {
					out.println("ERR " + f[0] + " " + emu.getLastError());
					continue;
				}
				long ra = emu.readRegister("A").longValue(), rx = emu.readRegister("X").longValue(),
						ry = emu.readRegister("Y").longValue();
				long rsp = emu.readRegister("SP").longValue();
				long i = st72 ? emu.readRegister("I0").longValue() : emu.readRegister("I").longValue();
				long rcc = emu.readRegister("C").longValue() | emu.readRegister("Z").longValue() << 1 |
					emu.readRegister("N").longValue() << 2 | i << 3 | emu.readRegister("H").longValue() << 4;
				StringBuilder sb = new StringBuilder();
				byte[] mem = emu.readMemory(base, 65536);
				for (int k = 0; k < 65536; k++) {
					if (mem[k] != image[k] && !(k >= 0x1000 && k < 0x1000 + c.length)) {
						sb.append(String.format(" %04x=%02x", k, mem[k] & 0xff));
					}
				}
				out.printf("OK %02x %02x %02x %02x %04x %04x%s%n", ra, rx, ry, rcc, rsp,
					emu.getExecutionAddress().getOffset(), sb);
			}
		}
		finally {
			emu.dispose();
		}
		out.close();
	}
}
