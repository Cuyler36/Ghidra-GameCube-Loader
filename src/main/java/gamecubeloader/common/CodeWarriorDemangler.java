package gamecubeloader.common;

import java.util.ArrayList;

import ghidra.app.util.demangler.*;
import ghidra.program.model.listing.Program;
import ghidra.util.map.TypeMismatchException;

public final class CodeWarriorDemangler implements Demangler {
    public final String CODEWARRIOR_DEMANGLE_PROP = "DemangleCW"; /* When defined, forces CodeWarrior demangling on all symbols. */
    public final String CODEWARRIOR_NO_DEMANGLE_PROP = "NoDemangleCW"; /* When defined, prevents CodeWarrior demangling on all symbols. */
    
    public String str;
    public boolean containsInvalidSpecifier;

    public CodeWarriorDemangler() { } /* Empty constructor for DemanglerCmd::applyTo */
    
    public CodeWarriorDemangler(String g) {
        this.str = g;
    }

    public boolean isEmpty() { return this.str == null || this.str.length() < 1; }
    public String cw(int n) { String g = this.str.substring(0, n); this.str = this.str.substring(n); return g; }
    public char hd() { return isEmpty() ? 0 : this.str.charAt(0); }
    public boolean isConstFunc() { return (isEmpty() || this.str.length() < 2) ? false : this.str.startsWith("CF") || this.str.startsWith("cF"); }
    public char tk() { char hd = this.hd(); cw(1); return hd; }

    public int nextInteger(char initial) {
        int value = initial - '0';

        while (Character.isDigit(hd()))
            value = value * 10 + (tk() - '0');

        return value;
    }

    public int nextInteger() {
        assert Character.isDigit(hd());
        return nextInteger(tk());
    }

    public boolean hasFunction() {
        return hd() == 'F';
    }

    public DemangledTemplate nextTemplate() {
        assert hd() == '<';

        // Parse a type, then look for the comma.
        var template = new DemangledTemplate();
        while (true) {
            var tok = tk();
            if (tok == '>')
                break;
            assert tok == '<' || tok == ',';
            var type = this.nextType();
            template.addParameter(type);
        }
        return template;
    }

    private void demangleTemplates(DemangledDataType o) {
        var name = o.getName();
        var lb = name.indexOf('<');
        if (lb < 0)
            return;
        var rb = name.lastIndexOf('>');
        var parser = new CodeWarriorDemangler(name.substring(lb, rb + 1));
        var template = parser.nextTemplate();
        o.setName(name.substring(0, lb));
        for (var param : template.getParameters()) {
            if (param.isPrimitive()) {
                o.setName(name.substring(0, lb) + template.toTemplate());
                break;
            }
        }
        
        o.setTemplate(template);
    }

    private static void demangleTemplates(DemangledFunction o) {
        var name = o.getName();
        var lb = name.indexOf('<');
        if (lb < 0)
            return;
        var rb = name.lastIndexOf('>');
        var parser = new CodeWarriorDemangler(name.substring(lb, rb + 1));
        o.setName(name.substring(0, lb));
        o.setTemplate(parser.nextTemplate());
    }

    public static DemangledObject demangleSymbol(String symbolName) {
        // If it doesn't have a __, then it's not mangled.
        if (!symbolName.contains("__"))
            return null;

        // If we start with "@x@", then we're a virtual thunk, with "x" being the offset to the this pointer.
        boolean isThunk = false;
        if (symbolName.startsWith("@")) {
            int thunkAddrIdx = symbolName.lastIndexOf('@');
            symbolName = symbolName.substring(thunkAddrIdx + 1);
            isThunk = true;
        }

        int firstDunder = symbolName.indexOf("__", 1);
        // If the symbol starts with __, exit.
        if (firstDunder < 0)
            return null;
        
        // Ensure that any trailing underscores in the function name are accounted for
        while (symbolName.charAt(firstDunder + 2) == '_') {
            firstDunder++;
        }
        
        String parameters = symbolName.substring(firstDunder + 2);
        // After the dunder comes the class, if it exists, followed by 'F', followed by parameters.
        var demangler = new CodeWarriorDemangler(parameters);

        DemangledDataType parentClass = null;
        if (!demangler.hasFunction())
            parentClass = demangler.nextType();

        var isConstFunc = demangler.isConstFunc();
        if (isConstFunc || demangler.hasFunction()) {
            var d = demangler.nextFunction(parentClass, symbolName);

            if (isThunk)
                d.setThunk(true);

            String functionName = symbolName.substring(0, firstDunder);
            String operatorName = demangleSpecialOperator(functionName);
    
            if (operatorName != null) {
                d.setOverloadedOperator(true);
                d.setName(operatorName);
            } else {
                if (functionName.equals("__ct"))
                    functionName = parentClass.getName();
                else if (functionName.equals("__dt"))
                    functionName = "~" + parentClass.getName();
    
                d.setName(functionName);
    
                CodeWarriorDemangler.demangleTemplates(d);
            }
            
            if (demangler.containsInvalidSpecifier)
                return null;
            
            return d;
        }
        
        // It could be a member or vtable
        if (demangler.isEmpty()) {
            var name = symbolName.substring(0, firstDunder);
            var member = new DemangledVariable(symbolName, name, name);
            
            if (parentClass != null) {
                var namespace = parentClass.getNamespace();
                var className = parentClass.getDemangledName();
                // If the class has a namespace, include that as well.
                if (parentClass.getTemplate() != null)
                    className += parentClass.getTemplate().toTemplate();
                var classNamespace = new DemangledType(null, className, className);
                classNamespace.setNamespace(namespace);
                member.setNamespace(classNamespace);
            }
            
            return member;
        }
        
        return null;
    }

    public DemangledFunction nextFunction(DemangledDataType parentClass, String mangledName) {
        char tok = tk();

        DemangledFunction func = new DemangledFunction(mangledName, null, null);
        func.setCallingConvention(parentClass != null ? "__thiscall" : "__stdcall");

        if (tok == 'C') {
            func.setTrailingConst();
            tok = tk();
        }
        else if (tok == 'c') {
            func.setConst(true);
        }
        assert tok == 'F';

        // Parse parameters.
        while (true) {
            if (this.str.length() == 0)
                break;

            tok = hd();
            if (tok == '_') {
                tk();
                func.setReturnType(this.nextType());
            } else {
                func.addParameter(new DemangledParameter(this.nextType()));
            }
        }

        if (parentClass != null) {
            var namespace = parentClass.getNamespace();
            var className = parentClass.getDemangledName();
            // If the class has a namespace, include that as well.
            if (parentClass.getTemplate() != null)
                className += parentClass.getTemplate().toTemplate();
            var classNamespace = new DemangledType(null, className, className);
            classNamespace.setNamespace(namespace);
            func.setNamespace(classNamespace);
        }

        return func;
    }

    public DemangledDataType nextType() {
        char tok = tk();

        if (Character.isDigit(tok)) {
            // Name or literal integer. Literal integers can show up in template parameters.
            int value = nextInteger(tok);
            if (hd() == '>' || hd() == ',') {
                // Literal integer (template)
                return new DemangledDataType(null, "" + value, "" + value);
            }
            // Name.
            String val = cw(value);
            var d = new DemangledDataType(null, val, val);
            demangleTemplates(d);
            return d;
        } else if (tok == 'Q') {
            // Qualified name.
            int compCount = tk() - '0';

            var names = new ArrayList<String>();
            for (var i = 0; i < compCount; i++) {
                int length = nextInteger();
                names.add(cw(length));
            }

            var val = names.get(compCount - 1);
            var d = new DemangledDataType(null, val, val);
            demangleTemplates(d);
            
            // Create namespaces
            DemangledType namespaceType = new DemangledType(null, names.get(0), names.get(0)); // Top level
            for (String ns : names.subList(1, names.size() - 1))
            {
                DemangledType subNamespace = new DemangledType(null, ns, ns);
                subNamespace.setNamespace(namespaceType);
                namespaceType = subNamespace;
            }
            
            d.setNamespace(namespaceType);
            return d;
        } else if (tok == 'F') {
            var func = new DemangledFunctionPointer(null, null);

            // Parse parameters.
            while (true) {
                if (this.str.length() == 0)
                    break;

                tok = hd();
                
                if (tok == '_') {
                    tk();
                    func.setReturnType(this.nextType());
                    break;
                }
                
                func.addParameter(this.nextType());
            }

            demangleTemplates(func);

            return func;
        } else if (tok == 'P') {
            var d = this.nextType();
            d.incrementPointerLevels();
            return d;
        } else if (tok == 'A') {
            var arraySize = this.nextInteger();
            var typeSeparator = tk();
            assert typeSeparator  == '_';
            var d = this.nextType();
            d.setArray(arraySize);
            return d;
        } else if (tok == 'R') {
            var d = this.nextType();
            d.setReference();
            return d;
        } else if (tok == 'C') {
            var d = this.nextType();
            d.setConst();
            return d;
        } else if (tok == 'U') {
            var d = this.nextType();
            d.setUnsigned();
            return d;
        } else if (tok == 'S') {
            var d = this.nextType();
            d.setSigned();
            return d;
        } else if (tok == 'M') {
            int length = nextInteger();
            var scope = cw(length);
            var d = this.nextType();
            d.setMemberScope(scope);
            return d;
        } else if (tok == 'i') {
            return new DemangledDataType(null, DemangledDataType.INT, DemangledDataType.INT);
        } else if (tok == 'l') {
            return new DemangledDataType(null, DemangledDataType.LONG, DemangledDataType.LONG);
        } else if (tok == 'x') {
            return new DemangledDataType(null, DemangledDataType.LONG_LONG, DemangledDataType.LONG_LONG);
        } else if (tok == 'b') {
            return new DemangledDataType(null, DemangledDataType.BOOL, DemangledDataType.BOOL);
        } else if (tok == 'c') {
            return new DemangledDataType(null, DemangledDataType.CHAR, DemangledDataType.CHAR);
        } else if (tok == 's') {
            return new DemangledDataType(null, DemangledDataType.SHORT, DemangledDataType.SHORT);
        } else if (tok == 'f') {
            return new DemangledDataType(null, DemangledDataType.FLOAT, DemangledDataType.FLOAT);
        } else if (tok == 'd') {
            return new DemangledDataType(null, DemangledDataType.DOUBLE, DemangledDataType.DOUBLE);
        } else if (tok == 'w') {
            return new DemangledDataType(null, DemangledDataType.WCHAR_T, DemangledDataType.WCHAR_T);
        } else if (tok == 'v') {
            return new DemangledDataType(null, DemangledDataType.VOID, DemangledDataType.VOID);
        } else if (tok == 'e') {
            return new DemangledDataType(null, DemangledDataType.VARARGS, DemangledDataType.VARARGS);
        } else {
            // Unknown.
            this.containsInvalidSpecifier = this.containsInvalidSpecifier || tok != '_'; // This is here in case the __ is preceded by more underscores.
            return new DemangledDataType(null, DemangledDataType.UNDEFINED, DemangledDataType.UNDEFINED);
        }
    }

    private static String demangleSpecialOperator(String symbolName) {
        if (symbolName.startsWith("__")) {
            switch (symbolName.substring(2)) {
                case "nw":
                    return "operator new";
                case "nwa":
                    return "operator new[]";
                case "dl":
                    return "operator delete";
                case "dla":
                    return "operator delete[]";
                case "pl":
                    return "operator +";
                case "mi":
                    return "operator -";
                case "ml":
                    return "operator *";
                case "dv":
                    return "operator /";
                case "md":
                    return "operator %";
                case "er":
                    return "operator ^";
                case "ad":
                    return "operator &"; // not sure about this one.
                case "or":
                    return "operator |";
                case "co":
                    return "operator ~";
                case "nt":
                    return "operator !";
                case "as":
                    return "operator =";
                case "lt":
                    return "operator <";
                case "gt":
                    return "operator >";
                case "apl":
                    return "operator +=";
                case "ami":
                    return "operator -=";
                case "amu":
                    return "operator *=";
                case "adv":
                    return "operator /=";
                case "amd":
                    return "operator %=";
                case "aer":
                    return "operator ^=";
                case "aad":
                    return "operator &=";
                case "aor":
                    return "operator |=";
                case "ls":
                    return "operator <<";
                case "rs":
                    return "operator >>";
                case "ars":
                    return "operator >>=";
                case "als":
                    return "operator <<=";
                case "eq":
                    return "operator ==";
                case "ne":
                    return "operator !=";
                case "le":
                    return "operator <=";
                case "ge":
                    return "operator >="; // not sure
                case "aa":
                    return "operator &&";
                case "oo":
                    return "operator ||";
                case "pp":
                    return "operator ++";
                case "mm":
                    return "operator --";
                case "cl":
                    return "operator ()";
                case "vc":
                    return "operator []";
                case "rf":
                    return "operator ->";
                case "cm":
                    return "operator ,";
                case "rm":
                    return "operator ->*";
            }
        }
        
        return null;
    }

    @Override
    public boolean canDemangle(Program program) {
        try {
            final boolean canDemangle = (program.getLanguageID().getIdAsString().equals("PowerPC:BE:32:Gekko_Broadway") ||
                program.getUsrPropertyManager().getVoidPropertyMap(CODEWARRIOR_DEMANGLE_PROP) != null) &&
                program.getUsrPropertyManager().getVoidPropertyMap(CODEWARRIOR_NO_DEMANGLE_PROP) == null;
            return canDemangle;
        }
        catch (TypeMismatchException e) {
            return false;
        }
    }

    @Override
    @SuppressWarnings("removal")
    public DemangledObject demangle(String mangled, boolean demangleOnlyKnownPatterns) throws DemangledException {
        return CodeWarriorDemangler.demangleSymbol(mangled);
    }

    @Override
    public DemangledObject demangle(String mangled, DemanglerOptions options) throws DemangledException {
        return CodeWarriorDemangler.demangleSymbol(mangled);
    }
}
