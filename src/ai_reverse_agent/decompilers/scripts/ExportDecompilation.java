// Ghidra headless post-script: emit one stable JSON record per function.
// @category AIReverse

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class ExportDecompilation extends GhidraScript {
    private static final String PREFIX = "AI_REVERSE_DECOMPILER_JSON:";

    @Override
    protected void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException("decompiler could not open program");
            }
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
                    continue;
                }
                println(PREFIX + toJson(function, result.getDecompiledFunction().getC()));
            }
        }
        finally {
            decompiler.dispose();
        }
    }

    private String toJson(Function function, String pseudoC) throws Exception {
        StringBuilder json = new StringBuilder();
        json.append("{\"name\":\"").append(escape(function.getName())).append("\",");
        json.append("\"start_address\":\"").append(address(function.getEntryPoint().getOffset())).append("\",");
        long end = function.getBody().getMaxAddress().getOffset() + 1;
        json.append("\"end_address\":\"").append(address(end)).append("\",");
        json.append("\"pseudo_c\":\"").append(escape(pseudoC)).append("\",");
        json.append("\"library\":null,\"stack_variables\":[],\"instructions\":[");

        InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
        boolean first = true;
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            if (!first) {
                json.append(',');
            }
            first = false;
            json.append("{\"address\":\"").append(address(instruction.getAddress().getOffset())).append("\",");
            json.append("\"mnemonic\":\"").append(escape(instruction.getMnemonicString())).append("\",");
            json.append("\"op_str\":\"").append(escape(operands(instruction))).append("\",");
            json.append("\"bytes_hex\":\"").append(hex(instruction.getBytes())).append("\"}");
        }
        json.append("]}");
        return json.toString();
    }

    private String operands(Instruction instruction) {
        StringBuilder value = new StringBuilder();
        for (int index = 0; index < instruction.getNumOperands(); index++) {
            if (index > 0) {
                value.append(", ");
            }
            value.append(instruction.getDefaultOperandRepresentation(index));
        }
        return value.toString();
    }

    private String address(long value) {
        return "0x" + Long.toUnsignedString(value, 16);
    }

    private String hex(byte[] value) {
        StringBuilder encoded = new StringBuilder(value.length * 2);
        for (byte item : value) {
            encoded.append(String.format("%02x", item & 0xff));
        }
        return encoded.toString();
    }

    private String escape(String value) {
        StringBuilder escaped = new StringBuilder();
        for (int index = 0; index < value.length(); index++) {
            char item = value.charAt(index);
            switch (item) {
                case '\\': escaped.append("\\\\"); break;
                case '"': escaped.append("\\\""); break;
                case '\n': escaped.append("\\n"); break;
                case '\r': escaped.append("\\r"); break;
                case '\t': escaped.append("\\t"); break;
                default:
                    if (item < 0x20) {
                        escaped.append(String.format("\\u%04x", (int)item));
                    }
                    else {
                        escaped.append(item);
                    }
            }
        }
        return escaped.toString();
    }
}
