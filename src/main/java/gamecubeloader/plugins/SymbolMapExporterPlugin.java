/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package gamecubeloader.plugins;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Objects;

import javax.swing.SwingUtilities;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.filechooser.FileSystemView;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;

/**
 * The Symbol Map Export plugin allows exporting labels and such as
 * a .map-file that can then be imported into Dolphin Emulator for debugging purpose.
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = SymbolMapExporterPluginPackage.NAME,
    category = PluginCategoryNames.MISC,
    shortDescription = SymbolMapExporterPlugin.DESC,
    description = "This plugin allows exporting symbols to a format that Dolphin can understand."
)
//@formatter:on
public class SymbolMapExporterPlugin extends ProgramPlugin implements ChangeListener {
    private static final String MENU_GROUP_1 = "group1";
    static final String DESC = "Export Symbols to Dolphin Map Format";
    static final String NAME = "Export Symbol Map";

    private String last_saved_path;

    private DockingAction chooseAction;

    public SymbolMapExporterPlugin(PluginTool tool) {
        super(tool, true, true);
    }

    @Override
    public void stateChanged(ChangeEvent e) {
        SwingUtilities.invokeLater(() -> updateActions());
    }

    private void updateActions() {
        enableActions();
    }

    @Override
    protected void init() {
        super.init();
        createStandardActions();
        enableActions();
    }

    @Override
    protected void cleanup() {
        super.cleanup();
    }

    /**
     * Method to create the menu entry.
     */
    private void createStandardActions() {
        DockingAction action = new DockingAction("Export Symbols", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                exportToFile();
            }
        };
        action.setMenuBarData(
                new MenuData(new String[] { ToolConstants.MENU_TOOLS, SymbolMapExporterPlugin.NAME,
                "Export to .map file..." }, null, MENU_GROUP_1, MenuData.NO_MNEMONIC, "1"));
        action.setDescription("Export Symbols to a .map file that Dolphin Emulator can load");
        tool.addAction(action);
        chooseAction = action;
    }

    /**
     * Determines whenever the symbol name is a Ghidra default symbol name.
     * @param symbolName The symbol name to rate.
     * @return true whenever the given symbol name is a Ghirda default generated label, false otherwise.
     */
    private static boolean isGhidraDefaultName(String symbolName) {
        Objects.requireNonNull(symbolName);
        // Generic labels but not those that might have been changed
        if (symbolName.matches("^(LAB|DAT|PTR|FUN|FLOAT|DOUBLE)_[0-9A-Fa-f]+$"))
            return true;

        // Switch-case stuff are basically always uninteresting
        if (symbolName.startsWith("caseD_")
                || symbolName.startsWith("switchD_")
                || symbolName.startsWith("PTR_caseD_"))
            return true;

        return false;
    }

    /**
     * Try to identify the GameID to use as the filename.
     * @return GameID like GAMEP01, or null if it could not be determined.
     */
    private String getGameID() {
        return null; // Currently seemingly impossible in a consistent way
    }

    /**
     * Try to find the path of an dolphin installation to make a convenient
     * default location so you can directly load into Dolphin.
     * @return The directory to dolphin Maps folder, or null if not found.
     */
    private File getDolphinPath() {
        var user_home = System.getProperty("user.home");
        if (user_home == null) {
            return null;
        }

        var possible_paths = new ArrayList<String>(5);

        if (System.getProperty("os.name", "Unknown").toUpperCase().startsWith("WINDOWS")) {
            var default_path = FileSystemView.getFileSystemView().getDefaultDirectory().getPath();
            possible_paths.add(default_path + "/Dolphin Emulator/");
        }

        possible_paths.add(user_home + "/.dolphin-emu/");

        var xdg_data_home = System.getenv("XDG_DATA_HOME");
        if (xdg_data_home == null || xdg_data_home.isBlank()) {
            xdg_data_home = user_home + "/" + ".local/share";
        }
        possible_paths.add(xdg_data_home + "/dolphin-emu/");

        for (var path : possible_paths) {
            var dir = new File(path);
            if (dir.exists()) {
                return dir;
            }
        }

        return null;
    }

    /**
     * Asks the user to choose the location and file name to save in.
     * @return The file to save to, or null if cancelled or something.
     */
    private File chooseFile() {
        var fileChooser = new GhidraFileChooser(null);
        fileChooser.addFileFilter(new ExtensionFileFilter("map", "Symbol Map Files"));
        fileChooser.setTitle("Select where to save the map file");
        fileChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);

        if (last_saved_path != null) {
            fileChooser.setSelectedFile(new File(last_saved_path));
        } else {
            var dolphinPath = getDolphinPath();
            if (dolphinPath != null) {
                var name = getGameID();
                if (name == null)
                    name = this.currentProgram.getName().toString();
                if (name == null)
                    name = "";
                var file = new File(dolphinPath, "Maps/" + name + ".map");
                fileChooser.setSelectedFile(file);
            }
        }

        var selected_file = fileChooser.getSelectedFile(true);
        if (selected_file != null) {
            this.last_saved_path = selected_file.getAbsolutePath();
        }
        return selected_file;
    }

    /**
     * Ask the user where to export the symbol map and export the symbol map.
     */
    private void exportToFile() {
        var selectedFile = chooseFile();
        if (selectedFile == null) {
            Msg.info(this, "Symbol map export file chooser has been cancelled or similar.");
            return;
        }

        long startTime = System.currentTimeMillis();
        try (var fileWriter = new FileWriter(selectedFile);
                var writer = new PrintWriter(fileWriter)) {
            exportToFile(writer);
        } catch (IOException e) {
            Msg.error(this, "Failed to write symbol map", e);
            return;
        } finally {
            long endTime = System.currentTimeMillis();
            Msg.debug(this, String.format("Symbol exporting took %dms", endTime - startTime));
        }

        Msg.info(this, "Successfully exported symbol map to " + selectedFile.getAbsolutePath());
    }

    /**
     * Export the symbols to the symbol map.
     * @param writer Where to write the information to.
     * @throws IOException When some writing error occurs.
     */
    private void exportToFile(PrintWriter writer) throws IOException {
        var symTable = this.currentProgram.getSymbolTable();
        var codeMgr = ((ProgramDB)this.currentProgram).getCodeManager();
        var memory = this.currentProgram.getMemory();

        var functionSymbols = new ArrayList<Symbol>(500); // Rough estimation
        var dataSymbols = new ArrayList<Symbol>(1000); // Rough estimation
        var totalSymbols = 0L;

        for (var sym : symTable.getAllSymbols(true)) {
            totalSymbols++;
            var addr = sym.getAddress().getUnsignedOffset();
            if (addr < 0x80000000L || addr >= 0x81800000L)
                continue; // Ignore out of range addresses

            if (isGhidraDefaultName(sym.getName(true)))
                continue; // Don't save Ghidra generated symbols

            if (sym.getSymbolType() == SymbolType.FUNCTION) {
                functionSymbols.add(sym);
            } else {
                dataSymbols.add(sym);
            }
        }

        Msg.debug(this, String.format(
                "Number of function symbols: %d, data symbols: %d, ignored: %d",
                functionSymbols.size(), dataSymbols.size(),
                totalSymbols - functionSymbols.size() - dataSymbols.size()));

        writer.println(".text section layout");
        for (var sym : functionSymbols) {
            var addr = sym.getAddress().getUnsignedOffset();
            var symName = sym.getName(true);

            var alignment = 8;
            var size = 1L;
            var func = this.currentProgram.getFunctionManager().getFunctionAt(sym.getAddress());
            if (func != null) {
                size = func.getBody().getMaxAddress().getUnsignedOffset() - func.getBody().getMinAddress().getUnsignedOffset() + 1;
                alignment = 4;
            } else {
                Msg.info(this, "Symbol " + symName + " claims to be a function, but no function found at their address!");
                var memBlock = memory.getBlock(sym.getAddress());
                if (memBlock != null && !memBlock.isExecute()) {
                    var data = codeMgr.getDataAt(sym.getAddress());
                    if (data != null) {
                        alignment = data.getDataType().getAlignment();
                        size = data.getDataType().getLength();
                        if (size < 1) {
                            size = 1;
                        }
                    }
                }
            }
            writer.println(String.format("%08x %08x %08x % 2d %s",
                    addr, size, addr, alignment, symName));
        }

        writer.println();
        writer.println(".data section layout");
        for (var sym : dataSymbols) {
            var addr = sym.getAddress().getUnsignedOffset();
            var symName = sym.getName(true);

            var alignment = 0;
            var size = 1L;
            var memBlock = memory.getBlock(sym.getAddress());
            if (memBlock != null && !memBlock.isExecute()) {
                var data = codeMgr.getDataAt(sym.getAddress());
                if (data != null) {
                    alignment = data.getDataType().getAlignment();
                    size = data.getDataType().getLength();
                    if (size < 1) {
                        size = 1;
                    }
                }
            }

            writer.println(String.format("%08x %08x %08x % 2d %s",
                    addr, size, addr, alignment, symName));
        }
    }

    /**
     * Method to properly set action enablement based upon appropriate business logic.
     */
    private void enableActions() {
        chooseAction.setEnabled(true);
    }
}