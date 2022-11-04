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

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;

import javax.swing.SwingUtilities;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.script.AskDialog;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.database.ProgramDB;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.filechooser.ExtensionFileFilter;

/**
 * The FID program plugin is actually ONLY needed for administrative actions in FID.
 * The FID function name search analyzer will occur in Ghidra with or without this
 * plugin enabled.  This plugin has many actions, such as creating, attaching, enabling,
 * populating, and debugging (searching) FID databases.
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = SymbolMapExporterPluginPackage.NAME,
    category = PluginCategoryNames.SEARCH,
    shortDescription = SymbolMapExporterPlugin.DESC,
    description = "This plugin allows exporting symbols to a format that Dolphin can understand."
)
//@formatter:on
public class SymbolMapExporterPlugin extends ProgramPlugin implements ChangeListener {
    private static final String MENU_GROUP_1 = "group1";
    static final String DESC = "Export Symbols to Dolphin Map Format";
    static final String NAME = "Export Symbol Map";

    private DockingAction chooseAction;

    public SymbolMapExporterPlugin(PluginTool tool) {
        super(tool);
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
     * Method to create the "standard" actions, which users controlling or creating
     * FID databases would want to use.
     */
    private void createStandardActions() {
         DockingAction action = new DockingAction("Export Symbols", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                try {
                    exportToFile();
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        };
        action.setMenuBarData(
            new MenuData(new String[] { ToolConstants.MENU_TOOLS, SymbolMapExporterPlugin.NAME,
                "Export to File..." }, null, MENU_GROUP_1, MenuData.NO_MNEMONIC, "1"));
        action.setDescription("Export Symbols to a file");
        tool.addAction(action);
        chooseAction = action;
    }

    /**
     * Method to select which known FID databases are currently active
     * during search.
     * @throws IOException 
     */
    private void exportToFile() throws IOException {
        var fileChooser = new GhidraFileChooser(null);
        fileChooser.addFileFilter(new ExtensionFileFilter("map", "Symbol Map Files"));
        fileChooser.setTitle("Select an output file");
        fileChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
        var selectedFile = fileChooser.getSelectedFile(true);
        if (selectedFile != null) {
            var writer = new PrintWriter(new FileWriter(selectedFile));
            var symTable = this.currentProgram.getSymbolTable();
            for (var sym : symTable.getAllSymbols(true)) {
                var addr = sym.getAddress().getUnsignedOffset();
                if (addr < 0x80000000L || addr >= 0x81800000L)
                    continue; // Ignore out of range addresses
                
                var symName = sym.getName();
                if (symName.startsWith("LAB_") || symName.startsWith("DAT_") || symName.startsWith("PTR_") || symName.startsWith("caseD_") || symName.equals("switchD"))
                    continue; // Don't save Ghidra generated symbols.
                var alignment = 8;
                var size = 1L;
                var func = this.currentProgram.getFunctionManager().getFunctionAt(sym.getAddress());
                if (func != null) {
                    size = func.getBody().getMaxAddress().getUnsignedOffset() - func.getBody().getMinAddress().getUnsignedOffset() + 1;
                    alignment = 4;
                }
                else {
                    var memBlock = this.currentProgram.getMemory().getBlock(sym.getAddress());
                    if (memBlock != null && memBlock.isExecute() == false) {
                        var cm = ((ProgramDB)this.currentProgram).getCodeManager();
                        var data = cm.getDataAt(sym.getAddress());
                        if (data != null) {
                            size = data.getDataType().getLength();
                            alignment = data.getDataType().getAlignment();
                            if (size < 1) {
                                size = 1;
                            }
                        }
                    }
                }
                writer.println(String.format("  %08x %06x %08x %2s %s \t%s", addr, size, addr, Integer.toString(alignment), symName, sym.getParentNamespace().getName()));
            }
            writer.close();
        }
        else {
            Msg.info(this, "A valid map file path must be selected!");
        }
    }

    /**
     * Method to properly set action enablement based upon appropriate business logic.
     */
    private void enableActions() {
        chooseAction.setEnabled(true);
    }
    
    /**
     * Method to ask a user to select from an array of choices (copied from GhidraScript).
     * @param title popup window title
     * @param message message to display during choice
     * @param choices array of choices for the users
     * @param defaultValue the default value to select
     * @return the user's choice, or null
     * @throws CancelledException if the user cancels
     */
    private <T> T askChoice(String title, String message, List<T> choices, T defaultValue) {
        AskDialog<T> dialog =
            new AskDialog<>(null, title, message, AskDialog.STRING, choices, defaultValue);
        if (dialog.isCanceled()) {
            return null;
        }

        T s = dialog.getChoiceValue();
        return s;
    }
}