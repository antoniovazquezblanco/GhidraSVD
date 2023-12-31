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
package svd;

import java.io.File;
import java.io.IOException;

import javax.swing.JComponent;
import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;

import docking.action.builder.ActionBuilder;
import docking.tool.ToolConstants;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;
import io.svdparser.SvdAddressBlock;
import io.svdparser.SvdDevice;
import io.svdparser.SvdParserException;
import io.svdparser.SvdPeripheral;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Import external SVD files.",
	description = "This plugin manages the import of SVD files to add memory map information to a program."
)
//@formatter:on
public class SVDPlugin extends ProgramPlugin {
	private static final String LAST_SVDFILE_PREFERENCE_KEY = "Svd.LastFile";

	public SVDPlugin(PluginTool tool) {
		super(tool);
		createActions();
	}

	private void createActions() {
		new ActionBuilder("Load SVD File", this.getName()).withContext(ProgramActionContext.class)
				.validContextWhen(pac -> pac.getProgram() != null).menuPath(ToolConstants.MENU_FILE, "Load SVD File...")
				.menuGroup("Import SVD", "5").onAction(pac -> loadSvd(pac)).buildAndInstall(tool);
	}

	private void loadSvd(ProgramActionContext pac) {
		Program program = pac.getProgram();
		AutoAnalysisManager currentAutoAnalysisManager = AutoAnalysisManager.getAnalysisManager(program);
		if (currentAutoAnalysisManager.isAnalyzing()) {
			Msg.showWarn(getClass(), null, "Load SVD", "Unable to load SVD file while analysis is running.");
			return;
		}
		
		File file = getSvdFileFromDialog(pac.getComponentProvider().getComponent());
		if (file == null)
			return;

		Msg.info(getClass(), "Loading " + file.getPath());
		SvdDevice device;
		try {
			device = SvdDevice.fromFile(file);
		} catch (SvdParserException | SAXException | IOException | ParserConfigurationException e) {
			Msg.showWarn(getClass(), null, "Load SVD", "Unable to load SVD file!");
			e.printStackTrace();
			return;
		}
		
		for (SvdPeripheral periph : device.getPeripherals()) {
			Msg.info(getClass(), "Processing " + periph.getName() + " peripheral...");
			processPeripheral(program, periph);
		}
	}
	
	private void processPeripheral(Program program, SvdPeripheral periph) {
		String periphName = periph.getName();
		for (SvdAddressBlock addrBlock : periph.getAddressBlocks()) {
			String blockUsage = addrBlock.getUsage();
			String regionName = periphName + ((blockUsage != null && !blockUsage.isEmpty()) ? ("_" + blockUsage) : "");

			createPeripheralBlockMemoryRegion(program, periph, addrBlock, regionName);
			createPeripheralBlockDataType(periph, addrBlock, regionName);
		}
	}

	private void createPeripheralBlockMemoryRegion(Program program, SvdPeripheral periph, SvdAddressBlock addrBlock, String regionName) {
		Memory memory = program.getMemory();
		AddressSpace addrSpace = program.getAddressFactory().getDefaultAddressSpace();
		Address addr = addrSpace.getAddress(periph.getBaseAddr() + addrBlock.getOffset());
		int transactionId = program.startTransaction("SVD memory block creation");
		boolean ok = createMemoryRegion(memory, regionName, addr, addrBlock.getSize());
		program.endTransaction(transactionId, ok);
	}

	private boolean createMemoryRegion(Memory memory, String name, Address addr, Long size) {
		try {
			MemoryBlock memBlock = memory.createUninitializedBlock(name, addr, size, false);
			boolean isRam = name.equals("memory");
			memBlock.setRead(true);
			memBlock.setWrite(true);
			memBlock.setExecute(isRam);
			memBlock.setVolatile(!isRam);
			memBlock.setComment("Generated by Device Tree Blob");
			return true;
		} catch (MemoryConflictException e) {
			Msg.error(getClass(),
					"Could not create a region for " + name + "@" + String.format("0x%08x", addr.getOffset()) + "+"
							+ String.format("0x%08x", size) + ". It conflicts with an existing region!",
					e);
		} catch (LockException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (AddressOverflowException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}

	private void createPeripheralBlockDataType(SvdPeripheral periph, SvdAddressBlock addrBlock, String regionName) {
		// TODO
	}
	
	private File getSvdFileFromDialog(JComponent parent) {
		GhidraFileChooser chooser = new GhidraFileChooser(parent);
		chooser.addFileFilter(ExtensionFileFilter.forExtensions("SVD", "svd"));
		chooser.setMultiSelectionEnabled(false);
		chooser.setApproveButtonText("Choose");
		chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		chooser.setTitle("Select SVD");

		String lastFile = Preferences.getProperty(LAST_SVDFILE_PREFERENCE_KEY);
		if (lastFile != null) {
			chooser.setSelectedFile(new File(lastFile));
		}

		File file = chooser.getSelectedFile();
		chooser.dispose();

		if (file == null || !file.isFile())
			return null;

		Preferences.setProperty(LAST_SVDFILE_PREFERENCE_KEY, file.getPath());
		return file;
	}
}
