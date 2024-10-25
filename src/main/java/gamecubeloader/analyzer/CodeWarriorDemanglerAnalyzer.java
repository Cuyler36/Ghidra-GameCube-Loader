package gamecubeloader.analyzer;

import gamecubeloader.common.CodeWarriorDemangler;
import ghidra.app.plugin.core.analysis.AbstractDemanglerAnalyzer;
import ghidra.app.util.demangler.DemangledException;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerOptions;
import ghidra.app.util.demangler.MangledContext;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.Program;

/***
 *
 * Demangler analyzer for CodeWarrior symbols.
 */
public class CodeWarriorDemanglerAnalyzer extends AbstractDemanglerAnalyzer {

    private static final String NAME = "Demangle CodeWarrior";
    private static final String DESCRIPTION =
        "After a function is created, this analyzer will attempt to demangle " +
            "the name and apply datatypes to parameters.";

    private CodeWarriorDemangler demangler = new CodeWarriorDemangler();

    public CodeWarriorDemanglerAnalyzer() {
        super(NAME, DESCRIPTION);
        setDefaultEnablement(true);
    }

    @Override
    public boolean canAnalyze(Program program) {
        return demangler.canDemangle(program);
    }

    @Override
    protected DemangledObject doDemangle(MangledContext context, MessageLog log)
            throws DemangledException {
        DemangledObject demangled = demangler.demangle(context);
        return demangled;
    }

}