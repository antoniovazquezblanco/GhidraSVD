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
import java.util.Arrays;

import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;

import docking.action.builder.ActionBuilder;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.Msg;
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

		File file = SvdFileDialog.getSvdFileFromDialog(pac.getComponentProvider().getComponent());
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

	private String getMemoryProperties(String name) {
		String properties = "rw";
		if (name.contains("RAM") || name.contains("memory")) {
			properties += 'e';
		} else {
			properties += 'v';
		}
		return properties;
	}

	private void createPeripheralBlockMemoryRegion(Program program, SvdPeripheral periph, SvdAddressBlock addrBlock,
			String regionName) {
		Memory memory = program.getMemory();
		AddressSpace addrSpace = program.getAddressFactory().getDefaultAddressSpace();
		Long addr = periph.getBaseAddr() + addrBlock.getOffset();
		Long size = addrBlock.getSize();

		MemoryBlock[] collidingBlocks = getCollidingMemoryBlocks(memory, addr, size);
		if (collidingBlocks.length == 0) {
			int transactionId = program.startTransaction("SVD memory block creation");
			boolean ok = createMemoryRegion(memory, regionName, addrSpace.getAddress(addr), size);
			program.endTransaction(transactionId, ok);
		} else {
			Msg.error(getClass(),
					"Could not create a region for " + name + "@" + String.format("0x%08x", addr) + "+"
							+ String.format("0x%08x", size) + ". It conflicts with an existing region!");
		}
	}

	private MemoryBlock[] getCollidingMemoryBlocks(Memory memory, Long address, Long size) {
		return Arrays.stream(memory.getBlocks())
				.filter(x -> doesMemoryBlockCollide(x, address, address + size)).toArray(MemoryBlock[]::new);
	}

	private boolean doesMemoryBlockCollide(MemoryBlock block, Long regionStart, Long regionEnd) {
		Long blockStart = block.getStart().getOffset();
		Long blockEnd = block.getEnd().getOffset();
		return (regionStart <= blockEnd && regionEnd >= blockStart);
	}

	private boolean createMemoryRegion(Memory memory, String name, Address addr, Long size) {
		try {
			String memProperties = getMemoryProperties(name);
			MemoryBlock memBlock = memory.createUninitializedBlock(name, addr, size, false);
			memBlock.setRead(memProperties.contains("r"));
			memBlock.setWrite(memProperties.contains("w"));
			memBlock.setExecute(memProperties.contains("e"));
			memBlock.setVolatile(memProperties.contains("v"));
			memBlock.setComment("Generated by Device Tree Blob");
			return true;
		} catch (MemoryConflictException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
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
}
