package gamecubeloader.rso;

public enum RSOSection {

    NULL("", false, false, false),
    INIT( ".init", true, false, true),
    TEXT(".text", true, false, true),
    CTORS( ".ctors", true, false, true),
    DTORS(".dtors", true, false, true),
    RODATA(".rodata", true, false, true),
    DATA(".data", true, false, true),
    BSS(".bss", true, false, true),
    SDATA(".sdata", true, false, true),
    SDATA2(".sdata2", true, false, true),
    NULL2("", false, false, false),
    SBSS(".sbss", true, false, true),
    SBSS2(".sbss2", true, false, true);

    private final String name;
    private final boolean isReadable;
    private final boolean isWriteable;
    private final boolean isExecutable;

    RSOSection(String name, boolean isReadable, boolean isWriteable, boolean isExecutable) {
        this.name = name;
        this.isReadable = isReadable;
        this.isWriteable = isWriteable;
        this.isExecutable = isExecutable;
    }

    public String getName() {
        return name;
    }

    public boolean isReadable() {
        return isReadable;
    }

    public boolean isWriteable() {
        return isWriteable;
    }

    public boolean isExecutable() {
        return isExecutable;
    }
}
