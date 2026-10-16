// Export draft C with explicit success/failure records. Never claims matching C.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;

public class DecompWtfXbox360 extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Path root = Paths.get(args[0]);
        int limit = Integer.parseInt(args[1]);
        JsonArray entries = JsonParser.parseString(Files.readString(root.resolve("functions.json"))).getAsJsonObject().getAsJsonArray("functions");
        JsonObject info = JsonParser.parseString(Files.readString(root.resolve("inspection.json"))).getAsJsonObject();
        long base = info.getAsJsonObject("pe").get("image_base").getAsLong();
        // Restrict branch traversal to executable sections, excluding data/pdata.
        AddressSet code = new AddressSet();
        for (JsonElement el : info.getAsJsonObject("pe").getAsJsonArray("sections")) {
            JsonObject s = el.getAsJsonObject();
            long size = s.get("size").getAsLong();
            if (s.get("executable").getAsBoolean() && size > 0) {
                long start = base + s.get("rva").getAsLong();
                code.addRange(toAddr(start), toAddr(start + size - 1));
            }
        }
        int created = 0;
        for (JsonElement el : entries) {
            monitor.checkCancelled();
            JsonObject f = el.getAsJsonObject();
            var address = toAddr(f.get("address").getAsLong());
            if (f.get("size").isJsonNull()) continue;
            long size = f.get("size").getAsLong();
            var body = new AddressSet(address, address.add(size - 1));
            new DisassembleCommand(address, body, true).applyTo(currentProgram, monitor);
            try {
                currentProgram.getFunctionManager().createFunction(f.get("name").getAsString(), address, body, SourceType.IMPORTED);
                created++;
            } catch (Exception e) { println("Function creation failed at " + address + ": " + e.getMessage()); }
        }
        // Unbounded candidates require Ghidra's flow-based body recovery.
        for (JsonElement el : entries) {
            JsonObject f = el.getAsJsonObject();
            if (!f.get("size").isJsonNull()) continue;
            var address = toAddr(f.get("address").getAsLong());
            new DisassembleCommand(address, code, true).applyTo(currentProgram, monitor);
            if (getFunctionContaining(address) == null && createFunction(address, f.get("name").getAsString()) != null) created++;
        }
        Path cdir = root.resolve("draft-c");
        Files.createDirectories(cdir);
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) throw new Exception("Decompiler could not open program");
        int attempted = 0, succeeded = 0, warnings = 0;
        JsonArray results = new JsonArray();
        try {
            for (JsonElement el : entries) {
                if (limit != 0 && attempted >= limit) break;
                monitor.checkCancelled();
                JsonObject row = el.getAsJsonObject().deepCopy();
                var f = getFunctionAt(toAddr(row.get("address").getAsLong()));
                if (f == null) { row.addProperty("error", "no function created"); results.add(row); continue; }
                attempted++;
                var result = decompiler.decompileFunction(f, 30, monitor);
                if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    String file = row.get("name").getAsString() + ".c";
                    String source = result.getDecompiledFunction().getC();
                    boolean warning = source.contains("WARNING:") || source.contains("halt_baddata");
                    row.addProperty("has_warnings", warning);
                    if (warning) warnings++;
                    Files.writeString(cdir.resolve(file), "/* Ghidra draft; unverified types and semantics, not matching source. */\n" + source, StandardCharsets.UTF_8);
                    row.addProperty("file", "draft-c/" + file);
                    succeeded++;
                } else row.addProperty("error", result.getErrorMessage());
                results.add(row);
            }
        } finally { decompiler.dispose(); }
        JsonObject report = new JsonObject();
        report.addProperty("created_functions", created);
        report.addProperty("attempted", attempted);
        report.addProperty("succeeded", succeeded);
        report.addProperty("with_warnings", warnings);
        report.addProperty("matching", false);
        report.add("results", results);
        Files.writeString(root.resolve("decompilation.json"), new GsonBuilder().setPrettyPrinting().create().toJson(report), StandardCharsets.UTF_8);
        println("Xbox 360 export: " + succeeded + "/" + attempted + " draft C functions");
    }
}
