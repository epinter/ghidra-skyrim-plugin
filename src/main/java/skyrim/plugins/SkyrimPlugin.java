/*
Copyright 2025 Emerson Pinter

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */
package skyrim.plugins;

import dev.pinter.AddressLibraryReader;
import docking.DefaultActionContext;
import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import docking.widgets.combobox.GhidraComboBox;
import generic.jar.ResourceFile;
import ghidra.MiscellaneousPluginPackage;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ProgramSymbolActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.services.ConsoleService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramLocation;
import ghidra.util.StringUtilities;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.HierarchyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@PluginInfo(
        status = PluginStatus.RELEASED,
        packageName = MiscellaneousPluginPackage.NAME,
        category = PluginCategoryNames.COMMON,
        shortDescription = "plugin",
        description = "Plugin to add actions to convert ids and address using address library"
)
public class SkyrimPlugin extends ProgramPlugin {
    private ConsoleService console;
    private static String GAME = "None";
    private String gameVersion;
    private final List<String> versionsAvailable = new ArrayList<>();
    private final List<DockingAction> actionsActive = new ArrayList<>();
    private boolean forcedGame = false;
    private Function lastFunction;

    private static class Cfg {
        public static String OFFSETS_FORMAT = "OFFSETS_FORMAT";
        public static String DEFAULT_GAME_VERSION = "DEFAULT_GAME_VERSION";
        public static String OFFSETS_DIR = "OFFSETS_DIR";
        public static String PE_NAME = "PE_NAME";
        public static String PE_FILEDESC = "PE_FILEDESC";
        public static String EXE_NAME = "EXE_NAME";
    }

    private final static Map<String, Map<String, String>> SUPPORTED_GAMES = Map.ofEntries(
            // OFFSETS_FORMAT:
            //      'ADDRESS' when the offsets file contains the address with imagebase (> 0x140000000L)
            //      'RVA' when the offsets file contains RVA
            // PE_NAME: The string to match the PE properties from binary
            // DEFAULT_GAME_VERSION: fallback version if not detected from PE properties
            Map.entry("Skyrim", Map.ofEntries(
                    Map.entry(Cfg.PE_NAME, "TESV: Skyrim"),
                    Map.entry(Cfg.PE_FILEDESC, "Skyrim"),
                    Map.entry(Cfg.EXE_NAME, "SkyrimSE"),
                    Map.entry(Cfg.DEFAULT_GAME_VERSION, "1.5.97.0"),
                    Map.entry(Cfg.OFFSETS_FORMAT, "RVA"),
                    Map.entry(Cfg.OFFSETS_DIR, "skyrim-offsets"))
            ),
            Map.entry("Starfield", Map.ofEntries(
                    Map.entry(Cfg.PE_NAME, "Starfield"),
                    Map.entry(Cfg.PE_FILEDESC, "Starfield"),
                    Map.entry(Cfg.EXE_NAME, "Starfield"),
                    Map.entry(Cfg.DEFAULT_GAME_VERSION, "1.12.30.0"),
                    Map.entry(Cfg.OFFSETS_FORMAT, "RVA"),
                    Map.entry(Cfg.OFFSETS_DIR, "starfield-offsets"))
            ),
            Map.entry("Fallout4", Map.ofEntries(
                    Map.entry(Cfg.PE_NAME, "Fallout 4"),
                    Map.entry(Cfg.PE_FILEDESC, "Fallout 4"),
                    Map.entry(Cfg.EXE_NAME, "Fallout4"),
                    Map.entry(Cfg.DEFAULT_GAME_VERSION, "1.10.163.0"),
                    Map.entry(Cfg.OFFSETS_FORMAT, "RVA"),
                    Map.entry(Cfg.OFFSETS_DIR, "fallout4-offsets"))
            ),
            Map.entry("SkyrimVR", Map.ofEntries(
                    Map.entry(Cfg.PE_NAME, "TESV: Skyrim VR"),
                    Map.entry(Cfg.PE_FILEDESC, "Skyrim VR"),
                    Map.entry(Cfg.EXE_NAME, "SkyrimVR"),
                    Map.entry(Cfg.DEFAULT_GAME_VERSION, "1.4.15.0"),
                    Map.entry(Cfg.OFFSETS_FORMAT, "RVA"),
                    Map.entry(Cfg.OFFSETS_DIR, "skyrimvr-offsets"))
            ),
            Map.entry("Fallout4VR", Map.ofEntries(
                    Map.entry(Cfg.PE_NAME, "Fallout 4 VR"),
                    Map.entry(Cfg.PE_FILEDESC, "Fallout 4 VR"),
                    Map.entry(Cfg.EXE_NAME, "Fallout4VR"),
                    Map.entry(Cfg.DEFAULT_GAME_VERSION, "1.2.72.0"),
                    Map.entry(Cfg.OFFSETS_FORMAT, "RVA"),
                    Map.entry(Cfg.OFFSETS_DIR, "fallout4vr-offsets"))
            ),
            Map.entry("None", Map.ofEntries(
                    Map.entry(Cfg.PE_NAME, ""),
                    Map.entry(Cfg.PE_FILEDESC, ""),
                    Map.entry(Cfg.EXE_NAME, ""),
                    Map.entry(Cfg.DEFAULT_GAME_VERSION, "0.0.0.0"),
                    Map.entry(Cfg.OFFSETS_FORMAT, "RVA"),
                    Map.entry(Cfg.OFFSETS_DIR, ""))
            )
    );

    public SkyrimPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected void postProgramActivated(Program program) {
        initToolMenu();
        detectGame();
        if (isCompatible()) {
            initialize();
        }
    }

    private void initialize() {
        initGameVersion();

        if (!versionsAvailable.contains(gameVersion) && isCompatible()) {
            logError("AddressLibrary database not found for version '%s', changing version to '%s'", gameVersion, getDefaultGameVersion());
            gameVersion = getDefaultGameVersion();
        }

        createShowActions();
        createCopyActions();
        createShowFromVersionActions();
        createGoMenuItem();
        if (isCompatible()) {
            logInfo("Detected game: %s %s", GAME, gameVersion);
        }
    }

    @Override
    protected void init() {
        console = tool.getService(ConsoleService.class);
    }

    private void saveAction(DockingAction action) {
        actionsActive.add(action);
    }

    private void initToolMenu() {
        new ActionBuilder("Detect game", getName())
                .withContext(DefaultActionContext.class)
                .onAction(a -> {
                    forcedGame = false;
                    for (DockingAction action : actionsActive) {
                        tool.removeAction(action);
                    }
                    detectGame();
                    initialize();
                })
                .enabledWhen(e -> true)
                .menuPath("Tools", "Skyrim Plugin", "Detect game")
                .menuGroup("Skyrim Plugin")
                .buildAndInstall(tool);

        new ActionBuilder("Force game to 'None'", getName())
                .withContext(DefaultActionContext.class)
                .onAction(a -> {
                    forcedGame = true;
                    for (DockingAction action : actionsActive) {
                        tool.removeAction(action);
                    }
                    GAME = "None";
                    actionsActive.clear();
                    logInfo("Game set to 'None'");
                })
                .enabledWhen(e -> true)
                .menuPath("Tools", "Skyrim Plugin", "Force game to", "None")
                .menuGroup("Skyrim Plugin")
                .buildAndInstall(tool);

        for (String g : SUPPORTED_GAMES.keySet()) {
            if (g.equals("None")) {
                continue;
            }
            new ActionBuilder("Force game to " + g, getName())
                    .withContext(DefaultActionContext.class)
                    .onAction(a -> {
                        forcedGame = true;
                        for (DockingAction action : actionsActive) {
                            tool.removeAction(action);
                        }
                        GAME = g;
                        actionsActive.clear();
                        gameVersion = getDefaultGameVersion();
                        initialize();
                        logInfo("Game set to %s", g);
                    })
                    .enabledWhen(e -> true)
                    .menuPath("Tools", "Skyrim Plugin", "Force game to", g)
                    .menuGroup("Skyrim Plugin")
                    .buildAndInstall(tool);
        }
    }

    private void createGoMenuItem() {
        String goToId = "Go to function ID";
        String goToOffset = "Go to function offset";
        saveAction(new ActionBuilder(goToId, getName())
                .withContext(DefaultActionContext.class)
                .onAction(a -> goToId(showGoToIDDialog()))
                .enabledWhen(e -> isValidBinary())
                .menuPath("Navigation", getMenuPath(), goToId)
                .buildAndInstall(tool));

        saveAction(new ActionBuilder(goToOffset, getName())
                .withContext(DefaultActionContext.class)
                .onAction(a -> goToOffset(showGoToOffsetDialog()))
                .enabledWhen(e -> isValidBinary())
                .menuPath("Navigation", getMenuPath(), goToOffset)
                .buildAndInstall(tool));
    }

    private void createShowFromVersionActions() {
        for (String ver : versionsAvailable) {
            String showIdVerPath = "Get ID from version";
            String showIdVerName = "Get ID from ";

            saveAction(new ActionBuilder(showIdVerName + ver + "(decompiler)", getName())
                    .withContext(DecompilerActionContext.class)
                    .onAction(a -> showId(a.getFunction().getEntryPoint(), ver))
                    .enabledWhen(e -> isValidBinary()
                            && !gameVersion.equalsIgnoreCase(ver)
                            && e.getFunction() != null)
                    .popupMenuPath(getMenuPath(), showIdVerPath, "to " + ver)
                    .popupMenuGroup(getMenuGroup())
                    .buildAndInstall(tool));

            saveAction(new ActionBuilder(showIdVerName + ver + "(symbol)", getName())
                    .withContext(ProgramSymbolActionContext.class)
                    .onAction(a -> showId(a.getFirstSymbol().getAddress(), ver))
                    .enabledWhen(e -> isValidBinary()
                            && !gameVersion.equalsIgnoreCase(ver)
                            && e.getFirstSymbol() != null
                            && e.getFirstSymbol().getAddress().isMemoryAddress())
                    .popupMenuPath(getMenuPath(), showIdVerPath, "to " + ver)
                    .popupMenuGroup(getMenuGroup())
                    .buildAndInstall(tool));

            saveAction(new ActionBuilder(showIdVerName + ver + "(listing)", getName())
                    .withContext(ListingActionContext.class).validContextWhen(p -> p.getAddress() != null)
                    .onAction(a -> showId(a.getAddress(), ver))
                    .enabledWhen(e -> isValidBinary()
                            && !gameVersion.equalsIgnoreCase(ver)
                            && e.getAddress() != null)
                    .popupMenuPath(getMenuPath(), showIdVerPath, "to " + ver)
                    .popupMenuGroup(getMenuGroup())
                    .buildAndInstall(tool));
        }
    }

    private void createCopyActions() {
        String copyIdSym = "Copy ID for symbol";
        String copyIdFunc = "Copy ID for function";
        String copyIdOff = "Copy ID for offset";

        saveAction(new ActionBuilder(copyIdFunc, getName())
                .withContext(DecompilerActionContext.class)
                .onAction(a -> copyId(a.getFunction().getEntryPoint()))
                .enabledWhen(e -> isValidBinary() && e.getFunction() != null)
                .popupMenuPath(getMenuPath(), copyIdFunc)
                .popupMenuGroup(getMenuGroup())
                .buildAndInstall(tool));

        saveAction(new ActionBuilder(copyIdSym, getName())
                .withContext(ProgramSymbolActionContext.class)
                .onAction(a -> copyId(a.getFirstSymbol().getAddress()))
                .enabledWhen(e -> isValidBinary() && e.getFirstSymbol() != null && e.getFirstSymbol().getAddress().isMemoryAddress())
                .popupMenuPath(getMenuPath(), copyIdSym)
                .popupMenuGroup(getMenuGroup())
                .buildAndInstall(tool));

        saveAction(new ActionBuilder(copyIdOff, getName())
                .withContext(ListingActionContext.class).validContextWhen(p -> p.getAddress() != null)
                .onAction(a -> copyId(a.getAddress()))
                .enabledWhen(e -> isValidBinary() && e.getAddress() != null)
                .popupMenuPath(getMenuPath(), copyIdOff)
                .popupMenuGroup(getMenuGroup())
                .buildAndInstall(tool));
    }

    private void createShowActions() {
        String showIdSym = "Get ID for symbol";
        String showIdFunc = "Get ID for function";
        String showIdOff = "Get ID for offset";

        saveAction(new ActionBuilder(showIdFunc, getName())
                .withContext(DecompilerActionContext.class)
                .onAction(a -> showId(a.getFunction().getEntryPoint(), gameVersion))
                .enabledWhen(e -> isValidBinary() && e.getFunction() != null)
                .popupMenuPath(getMenuPath(), showIdFunc)
                .popupMenuGroup(getMenuGroup())
                .buildAndInstall(tool));

        saveAction(new ActionBuilder(showIdFunc, getName())
                .withContext(DecompilerActionContext.class)
                .onAction(a -> showReferences(a.getFunction().getEntryPoint(), gameVersion))
                .enabledWhen(e -> isValidBinary() && e.getFunction() != null)
                .popupMenuPath(getMenuPath(), "Get references to")
                .popupMenuGroup(getMenuGroup())
                .buildAndInstall(tool));

        saveAction(new ActionBuilder(showIdSym, getName())
                .withContext(ProgramSymbolActionContext.class)
                .onAction(a -> showId(a.getFirstSymbol().getAddress(), gameVersion))
                .enabledWhen(e -> isValidBinary() && e.getFirstSymbol() != null && e.getFirstSymbol().getAddress().isMemoryAddress())
                .popupMenuPath(getMenuPath(), showIdSym)
                .popupMenuGroup(getMenuGroup())
                .buildAndInstall(tool));

        saveAction(new ActionBuilder(showIdOff, getName())
                .withContext(ListingActionContext.class).validContextWhen(p -> p.getAddress() != null)
                .onAction(a -> showId(a.getAddress(), gameVersion))
                .enabledWhen(e -> isValidBinary() && e.getAddress() != null)
                .popupMenuPath(getMenuPath(), showIdOff)
                .popupMenuGroup(getMenuGroup())
                .buildAndInstall(tool));
    }


    private void initGameVersion() {
        versionsAvailable.clear();
        try {
            ResourceFile[] files = Application.getModuleDataSubDirectory(getOffsetsDir())
                    .listFiles(resourceFile -> resourceFile.getName().matches("^version(?:lib|)-.*\\.(?:bin|csv)"));
            for (ResourceFile f : files) {
                String version = f.getName().replaceAll("^version(?:lib|)-(.*)\\.(?:bin|csv)", "$1");
                if (!StringUtilities.isAllBlank(version)) {
                    versionsAvailable.add(version.replaceAll("-", "."));
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        gameVersion = tool.getService(ProgramManager.class).getCurrentProgram()
                .getOptions(Program.PROGRAM_INFO).getValueAsString("PE Property[ProductVersion]");

        if (StringUtilities.isAllBlank(gameVersion)) {
            logError("%s version not detected, setting to %s", GAME, getDefaultGameVersion());
            gameVersion = getDefaultGameVersion();
        }

        for (String v : versionsAvailable) {
            saveAction(new ActionBuilder("Set game version to " + v, getName())
                    .withContext(DefaultActionContext.class)
                    .onAction(a -> {
                        gameVersion = v;
                        logInfo("Version set to %s", v);
                    })
                    .enabledWhen(e -> isValidBinary())
                    .menuPath("Tools", "Skyrim Plugin", "Set game version to", v.equalsIgnoreCase(gameVersion) ? String.format("Detected (%s)", v) : v)
                    .menuGroup("Skyrim Plugin")
                    .buildAndInstall(tool));
        }
    }

    private void goToId(String idStr) {
        long id;
        if (StringUtilities.isAllBlank(idStr)) {
            return;
        }

        try {
            id = Long.parseLong(idStr);
        } catch (NumberFormatException e) {
            logError("Invalid id");
            return;
        }

        long offset = getOffsetFromId(id, gameVersion);
        if (offset <= 0) {
            logError("Offset not found for ID " + id);
            return;
        }
        Address dest = currentProgram.getImageBase().add(offset);
        if (dest != null) {
            goTo(dest);
        } else {
            logError("Invalid address (ID %s)", id);
        }
    }

    private void goToOffset(String[] params) {
        long offset;
        String version;
        if (params == null || params.length != 2) {
            return;
        }

        version = params[1];
        try {
            offset = Long.parseLong(params[0].replaceAll("(?i)^0x", ""), 16);
        } catch (NumberFormatException e) {
            logError("Invalid offset");
            return;
        }

        long id = getIdFromOffset(offset, version);
        if (id <= 0) {
            logError("ID not found for offset '%s' and version '%s')", offset, version);
            return;
        }
        long otherOffset = getOffsetFromId(id, gameVersion);
        if (otherOffset <= 0) {
            logError("Offset '%s' not found (id = %s)", Long.toHexString(otherOffset).toUpperCase(), id);
            return;
        }
        Address dest = currentProgram.getImageBase().add(otherOffset);
        if (dest != null) {
            goTo(dest);
        } else {
            logError("Invalid address (ID %s)", id);
        }
    }

    private long getRVAFromAddress(Address address) {
        return address.subtract(currentProgram.getImageBase());
    }

    private AddressLibraryReader getAddressLibraryReader(String version) throws IOException {
        AddressLibraryReader.Game game;
        game = switch (GAME) {
            case "Skyrim" -> AddressLibraryReader.Game.Skyrim;
            case "Fallout4" -> AddressLibraryReader.Game.Fallout4;
            case "Starfield" -> AddressLibraryReader.Game.Starfield;
            case "SkyrimVR" -> AddressLibraryReader.Game.SkyrimVR;
            case "Fallout4VR" -> AddressLibraryReader.Game.Fallout4VR;
            default -> AddressLibraryReader.Game.Undefined;
        };
        return AddressLibraryReader.newBuilder()
                .withDirectory(Path.of(Application.getModuleDataSubDirectory(getOffsetsDir()).getAbsolutePath()))
                .withGame(game)
                .withVersion(version)
                .build();
    }

    private long getIdFromOffset(long offset, String version) {
        try {
            if (offset <= 0) {
                logInfo("Invalid offset");
                return 0;
            }

            long address = offset;
            if (isOffsetFormatAddress()) {
                address = offset + currentProgram.getImageBase().getOffset();
            }

            return getAddressLibraryReader(version).getIdByOffset(address);
        } catch (IOException e) {
            logError("Error", e);
            throw new RuntimeException(e);
        }
    }

    private long getOffsetFromId(long id, String version) {
        try {
            if (id <= 0) {
                logInfo("Invalid offset");
                return 0;
            }

            long address = getAddressLibraryReader(version).getOffsetById(id);
            if (isOffsetFormatAddress()) {
                return address - currentProgram.getImageBase().getOffset();
            }
            return address;
        } catch (IOException e) {
            logError("Error", e);
            throw new RuntimeException(e);
        }
    }

    /**
     * Show information from a specific version
     */
    private void showId(Address address, String version) {
        long offset = getRVAFromAddress(address);
        long id = getIdFromOffset(offset, gameVersion);
        if (version.equalsIgnoreCase(gameVersion)) {
            show(address, offset, id, gameVersion);
        } else {
            long otherOffset = getOffsetFromId(id, version);
            if (otherOffset > 0) {
                show(address, otherOffset, id, version, "The ID returned is based on the current binary version, be sure the IDs are compatible.");
            } else {
                logError("Offset not found for ID " + id);
            }
        }
    }

    /**
     * Copy ID to clipboard
     */
    private void copyId(Address address) {
        long offset = getRVAFromAddress(address);
        long id = getIdFromOffset(offset, gameVersion);
        if (id <= 0) {
            Address functionAddress;
            Function function = currentProgram.getListing().getFunctionContaining(address);
            if (function != null) {
                functionAddress = function.getEntryPoint();
                id = getIdFromOffset(getRVAFromAddress(functionAddress), gameVersion);
                if (id > 0) {
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(String.format("%s + 0x%X", id, address.subtract(functionAddress))), null);
                }
            } else {
                String msg = String.format("ID not found for offset %s (%s), version '%s'", Long.toHexString(offset).toUpperCase(), address, gameVersion);
                logError(msg);
                showErrorDialog(msg);
            }
        } else {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(String.valueOf(id)), null);
        }
    }

    /**
     * List references for address
     */
    private void showReferences(Address address, String version) {
        new Thread(() -> {
            ReferenceIterator referencesTo = currentProgram.getReferenceManager().getReferencesTo(address);

            int funcFound = 0;
            while (referencesTo.hasNext()) {
                Reference ref = referencesTo.next();
                Function functionFrom = currentProgram.getListing().getFunctionContaining(ref.getFromAddress());
                if (functionFrom != null) {
                    funcFound++;
                    Address fromFuncAddress = currentProgram.getListing().getFunctionContaining(ref.getFromAddress()).getEntryPoint();
                    long functionOffset = ref.getFromAddress().subtract(fromFuncAddress);
                    logInfo("Reference to '%s', from: Address:%s; ID:%s; Offset:0x%X; FunctionName:%s",
                            address, ref.getFromAddress(), getIdFromOffset(getRVAFromAddress(fromFuncAddress), version), functionOffset, functionFrom.getName()
                    );
                }
            }
            if (funcFound == 0) {
                logInfo("No references found to %s", address.toString().toUpperCase());
            }
        }).start();
    }

    private void show(Address address, long offset, long id, String version) {
        show(address, offset, id, version, "");
    }

    /**
     * Shows message to user with offset and id, to console log and popup
     */
    private void show(Address address, long offset, long id, String version, String message) {
        Address functionAddress = address;
        Function function;
        String symbolName = "";
        String offsetHex = Long.toHexString(offset).toUpperCase();

        if (id <= 0) {
            function = currentProgram.getListing().getFunctionContaining(address);
            if (function != null) {
                functionAddress = function.getEntryPoint();
            } else if (currentProgram.getSymbolTable().getPrimarySymbol(address) != null) {
                Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(address);
                symbolName = symbol.getName();
            } else {
                String msg = String.format("ID not found for offset %s (%s), version '%s'", offsetHex, address, version);
                logError(msg);
                return;
            }
        } else {
            function = currentProgram.getListing().getFunctionAt(functionAddress);
            if (function == null && currentProgram.getSymbolTable().getPrimarySymbol(address) != null) {
                Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(address);
                symbolName = symbol.getName(true);
            }
        }

        if (function != null) {
            symbolName = function.getName(true);
        }

        if (id <= 0) {
            long functionOffset = getRVAFromAddress(functionAddress);
            long functionId = getIdFromOffset(functionOffset, version);
            String instOffset = null;

            if (function != null) {
                instOffset = Long.toHexString(address.subtract(currentProgram.getListing().getFunctionContaining(address).getEntryPoint())).toUpperCase();
            }

            if (functionId > 0 && functionOffset > 0 && !StringUtilities.isAllBlank(instOffset)) {
                logInfo("[version '%s'] ID for offset 0x%s (from 0x%s '%s'): [%s] + 0x%s",
                        version, offsetHex, functionAddress.toString().toUpperCase(), symbolName, functionId, instOffset);
                showInfoDialog(String.format(GAME + " Version %s%n<html><b>Offset 0x%s</b> (from 0x%s '%s')</html>%n<html>ID [<b>%s</b>]</html>%nFunction Offset: +0x%s%n%s",
                        version, offsetHex, functionAddress.toString().toUpperCase(), symbolName, functionId, instOffset, message));
            } else {
                String msg = String.format("ID not found for offset %s (%s), version '%s'", offsetHex, address, version);
                logError(msg);
                showErrorDialog(msg);
            }
        } else {
            logInfo("[version '%s'] ID for offset 0x%s (address 0x%s '%s'): [%s]",
                    version, offsetHex, functionAddress.toString().toUpperCase(), symbolName, id);
            showInfoDialog(String.format(GAME + " Version '%s'%n<html><b>Offset 0x%s</b> (from 0x%s '%s')</html>%n<html>ID [<b>%s</b>]</html>%n%s",
                    version, offsetHex, functionAddress.toString().toUpperCase(), symbolName, id, message));
        }
    }

    /**
     * Validates if opened program is a game binary.
     */
    private boolean isValidBinary() {
        if (forcedGame) {
            return true;
        }
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm != null) {
            String peVersionFile = pm.getCurrentProgram().getOptions(Program.PROGRAM_INFO).getValueAsString("PE Property[ProductVersion]");
            String peDescFile = pm.getCurrentProgram().getOptions(Program.PROGRAM_INFO).getValueAsString("PE Property[FileDescription]");
            String peNameFile = pm.getCurrentProgram().getOptions(Program.PROGRAM_INFO).getValueAsString("PE Property[ProductName]");
            String peName = getGamePeName();
            String peDesc = getGamePeDesc();
            return !StringUtilities.isAllBlank(peVersionFile)
                    && (peDescFile.matches("(?i)^" + peDesc + "$")
                    || peNameFile.matches("(?i)^" + peName + "$")
                    || pm.getCurrentProgram().getName().matches("(?i)^" + getGameExeName()));
        }
        return false;
    }

    private void detectGame() {
        ProgramManager pm = tool.getService(ProgramManager.class);

        String peVersionFile = pm.getCurrentProgram().getOptions(Program.PROGRAM_INFO).getValueAsString("PE Property[ProductVersion]");
        String peDescFile = pm.getCurrentProgram().getOptions(Program.PROGRAM_INFO).getValueAsString("PE Property[FileDescription]");
        String peNameFile = pm.getCurrentProgram().getOptions(Program.PROGRAM_INFO).getValueAsString("PE Property[ProductName]");
        for (String gameName : SUPPORTED_GAMES.keySet()) {
            String peName = SUPPORTED_GAMES.get(gameName).get(Cfg.PE_NAME);
            String peDesc = SUPPORTED_GAMES.get(gameName).get(Cfg.PE_FILEDESC);
            if (!StringUtilities.isAllBlank(peVersionFile)
                    && (peDescFile.matches("(?i)^" + peDesc + "$")
                    || peNameFile.matches("(?i)^" + peName + "$")
                    || pm.getCurrentProgram().getName().matches("(?i)^" + SUPPORTED_GAMES.get(gameName).get(Cfg.EXE_NAME)))) {
                GAME = gameName;
                break;
            }
        }
    }

    private String getMenuPath() {
        return GAME;
    }

    private String getMenuGroup() {
        return GAME;
    }

    private String getPopupTitle() {
        return GAME + " Plugin";
    }

    private String getGameSetting(String name) {
        return SUPPORTED_GAMES.get(GAME).get(name);
    }

    private String getOffsetsDir() {
        return getGameSetting(Cfg.OFFSETS_DIR);
    }

    private boolean isOffsetFormatAddress() {
        return getGameSetting(Cfg.OFFSETS_FORMAT).equals("ADDRESS");
    }

    private String getDefaultGameVersion() {
        return getGameSetting(Cfg.DEFAULT_GAME_VERSION);
    }

    private String getGamePeName() {
        return getGameSetting(Cfg.PE_NAME);
    }

    private String getGamePeDesc() {
        return getGameSetting(Cfg.PE_FILEDESC);
    }

    private String getGameExeName() {
        return getGameSetting(Cfg.EXE_NAME);
    }

    private boolean isCompatible() {
        return !GAME.equals("None");
    }

    /**
     * Show information dialog
     */
    private void showInfoDialog(String message) {
        showPopup(message, JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * Show error dialog
     */
    private void showErrorDialog(String message) {
        showPopup(message, JOptionPane.ERROR_MESSAGE);
    }

    /**
     * Show modal dialog
     */
    private void showPopup(String message, int type) {
        JPanel panel = new JPanel(new GridLayout(0, 1));
        for (String line : message.split("\n")) {
            JLabel label = new JLabel(line, JLabel.CENTER);
            panel.add(label);
        }
        //noinspection MagicConstant
        JOptionPane.showMessageDialog(null, panel, getPopupTitle(), type);
    }

    private String showGoToIDDialog() {
        JPanel panel = new JPanel(new BorderLayout());
        JLabel labelId = new JLabel("ID");
        JTextField textId = createJTextField();

        labelId.setBorder(BorderFactory.createCompoundBorder(
                labelId.getBorder(),
                BorderFactory.createEmptyBorder(5, 5, 5, 10)));
        panel.add(labelId, BorderLayout.WEST);
        panel.add(textId, BorderLayout.CENTER);
        panel.setVisible(true);

        Object[] choices = {"Go", "Cancel"};
        int selected = JOptionPane.showOptionDialog(null,
                panel,
                getPopupTitle(),
                JOptionPane.YES_NO_OPTION,
                JOptionPane.PLAIN_MESSAGE,
                null,
                choices,
                choices[0]);

        if (selected == 0) {
            return textId.getText().trim();
        } else {
            return null;
        }

    }

    private String[] showGoToOffsetDialog() {
        JPanel panel = new JPanel(new BorderLayout());
        JLabel labelId = new JLabel("Offset");
        JTextField textOffset = createJTextField();

        labelId.setBorder(BorderFactory.createCompoundBorder(
                labelId.getBorder(),
                BorderFactory.createEmptyBorder(5, 5, 5, 10)));

        GhidraComboBox<String> version = new GhidraComboBox<>();
        version.addItem(gameVersion);
        version.setSelectedItem(0);

        for (String v : versionsAvailable) {
            if (!v.equals(gameVersion)) {
                version.addItem(v);
            }
        }

        panel.add(labelId, BorderLayout.WEST);
        panel.add(textOffset, BorderLayout.CENTER);
        panel.add(version, BorderLayout.SOUTH);
        panel.setVisible(true);

        Object[] choices = {"Go", "Cancel"};
        int selected = JOptionPane.showOptionDialog(null,
                panel,
                getPopupTitle(),
                JOptionPane.YES_NO_OPTION,
                JOptionPane.PLAIN_MESSAGE,
                null,
                choices,
                choices[0]);

        if (selected == 0) {
            return new String[]{textOffset.getText().trim(), (String) version.getSelectedItem()};
        } else {
            return null;
        }

    }

    private static JTextField createJTextField() {
        JTextField textId = new JTextField();

        textId.addHierarchyListener(e -> {
            final Component c = e.getComponent();
            if (c.isShowing() && (e.getChangeFlags() & HierarchyEvent.SHOWING_CHANGED) != 0) {
                Window toplevel = SwingUtilities.getWindowAncestor(c);
                toplevel.addWindowFocusListener(new WindowAdapter() {
                    public void windowGainedFocus(WindowEvent e) {
                        c.requestFocus();
                    }
                });
            }
        });
        return textId;
    }

    private void logInfo(String format, Object... args) {
        String logTag = "[SkyrimPlugin] ";
        if (isCompatible()) {
            logTag = String.format("[%sPlugin] ", GAME);
        }

        if (args.length > 0) {
            console.println(String.format(logTag + format, args));
        } else {
            console.println(logTag + format);
        }
    }

    private void logError(String format, Object... args) {
        String logTag = "[SkyrimPlugin] ";
        if (isCompatible()) {
            logTag = String.format("[%sPlugin] ", GAME);
        }

        if (args.length > 0) {
            console.printlnError(String.format(logTag + format, args));
        } else {
            console.printlnError(logTag + format);
        }
    }

    @Override
    protected void locationChanged(ProgramLocation loc) {
        if (loc == null) {
            return;
        }
        Function currentFunction = currentProgram.getFunctionManager().getFunctionContaining(loc.getAddress());
        if (currentFunction == null) {
            return;
        }

        if (currentProgram.getFunctionManager().isInFunction(loc.getAddress())
                && (lastFunction == null || currentFunction.getEntryPoint().getOffset() != lastFunction.getEntryPoint().getOffset())) {
            long id = getIdFromOffset(currentFunction.getEntryPoint().subtract(currentProgram.getImageBase()), gameVersion);
            if (id > 0) {
                logInfo("Visited function %s (0x%s): ID %s",
                        currentFunction.getName(),
                        loc.getAddress().toString().toUpperCase(),
                        id
                );
                tool.setStatusInfo("Current function ID " + id);
            }
        }
        lastFunction = currentProgram.getFunctionManager().getFunctionContaining(loc.getAddress());
    }
}
