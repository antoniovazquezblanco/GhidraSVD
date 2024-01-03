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
import java.util.HashMap;
import java.util.Map;

import javax.swing.JComponent;
import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;

import docking.action.builder.ActionBuilder;
import docking.tool.ToolConstants;
import docking.widgets.OptionDialog;
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
import svd.MemoryUtils.MemRangeRelation;

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

		JComponent parentComponent = pac.getComponentProvider().getComponent();
		File file = SvdFileDialog.getSvdFileFromDialog(parentComponent);
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

		Map<Block, BlockInfo> blocks = createBlocksFromDevice(device);

		for (BlockInfo blockInfo : blocks.values()) {
			Msg.info(getClass(), "Processing " + blockInfo.name + "...");
			processBlock(parentComponent, program, blockInfo);
		}
	}

	private Map<Block, BlockInfo> createBlocksFromDevice(SvdDevice device) {
		Map<Block, BlockInfo> blocks = new HashMap<Block, BlockInfo>();

		// Convert all peripherals to blocks...
		for (SvdPeripheral periph : device.getPeripherals()) {
			for (SvdAddressBlock block : periph.getAddressBlocks()) {
				// Create a block..
				Block b = new Block(periph.getBaseAddr() + block.getOffset(), block.getSize());

				// Check if block exists...
				BlockInfo bInfo = blocks.get(b);
				if (bInfo == null)
					bInfo = new BlockInfo();

				// Fill in block info...
				if (bInfo.block == null)
					bInfo.block = b;
				String name = getPeriphBlockName(periph, block);
				if (bInfo.name == null)
					bInfo.name = name;
				else
					bInfo.name += "/" + name;
				bInfo.isReadable = true;
				bInfo.isWritable = true;
				bInfo.isExecutable = name.contains("RAM") || name.contains("memory");
				bInfo.isVolatile = !bInfo.isExecutable;
				bInfo.peripherals.add(periph);

				// Save the data...
				blocks.put(b, bInfo);
			}
		}
		return blocks;
	}

	private String getPeriphBlockName(SvdPeripheral periph, SvdAddressBlock block) {
		String name = periph.getName();
		String blockUsage = block.getUsage();
		if (blockUsage != null && !blockUsage.isEmpty() && !blockUsage.contains("registers")) {
			name += "_" + blockUsage;
		}
		return name;
	}

	private void processBlock(JComponent parentComponent, Program program, BlockInfo blockInfo) {
		Memory memory = program.getMemory();
		MemoryBlock[] collidingMemoryBlocks = MemoryUtils.getBlockCollidingMemoryBlocks(memory, blockInfo.block);
		if (collidingMemoryBlocks.length == 0) {
			createMemoryBlock(program, blockInfo);
		} else if (collidingMemoryBlocks.length == 1 && MemoryUtils.getMemoryBlockRelation(collidingMemoryBlocks[0],
				blockInfo.block) == MemRangeRelation.RANGES_ARE_EQUAL) {
			updateMatchingMemoryBlock(parentComponent, program, collidingMemoryBlocks[0], blockInfo);
		} else {
			Msg.showWarn(getClass(), null, "Load SVD", "Could not create a region for " + blockInfo.name + "@"
					+ String.format("0x%08x", blockInfo.block.getAddress()) + "+"
					+ String.format("0x%08x", blockInfo.block.getSize()) + ". It conflicts with an existing region!");
		}
	}

	private void createMemoryBlock(Program program, BlockInfo blockInfo) {
		Memory memory = program.getMemory();
		AddressSpace addrSpace = program.getAddressFactory().getDefaultAddressSpace();
		Address addr = addrSpace.getAddress(blockInfo.block.getAddress());
		int transactionId = program.startTransaction("SVD memory block creation");
		boolean ok = false;
		try {
			MemoryBlock memBlock = memory.createUninitializedBlock(name, addr, blockInfo.block.getSize().longValue(),
					false);
			memBlock.setRead(blockInfo.isReadable);
			memBlock.setWrite(blockInfo.isWritable);
			memBlock.setExecute(blockInfo.isExecutable);
			memBlock.setVolatile(blockInfo.isVolatile);
			memBlock.setComment("Generated by Device Tree Blob");
			ok = true;
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
		program.endTransaction(transactionId, ok);
	}

	private void updateMatchingMemoryBlock(JComponent parentComponent, Program program,
			MemoryBlock collidingMemoryBlock, BlockInfo blockInfo) {
		if (!collidingMemoryBlock.getName().equals(blockInfo.name)
				&& OptionDialog.showYesNoDialog(parentComponent, "Load SVD",
						"An existing memory block with name \"" + collidingMemoryBlock.getName()
								+ "\" is in the same region as the \"" + blockInfo.name
								+ "\" peripheral. Do you want to rename it to \"" + blockInfo.name
								+ "\"?") == OptionDialog.OPTION_ONE) {
			int transactionId = program.startTransaction("SVD memory block rename");
			boolean ok = false;
			try {
				collidingMemoryBlock.setName(blockInfo.name);
				collidingMemoryBlock.setComment("Changed by Device Tree Blob");
				ok = true;
			} catch (IllegalArgumentException | LockException e) {
				e.printStackTrace();
			}
			program.endTransaction(transactionId, ok);
		}
		if (collidingMemoryBlock.isRead() != blockInfo.isReadable && OptionDialog.showYesNoDialog(parentComponent,
				"Load SVD",
				"Memory block \"" + collidingMemoryBlock.getName() + "\" is marked as"
						+ ((!collidingMemoryBlock.isRead()) ? " non" : "")
						+ " readable. The SVD file suggests it should be"
						+ (collidingMemoryBlock.isRead() ? " non" : "") + " readable. Do you want to changee it to"
						+ (collidingMemoryBlock.isRead() ? " non" : "") + " readable?") == OptionDialog.OPTION_ONE) {
			int transactionId = program
					.startTransaction("SVD " + collidingMemoryBlock.getName() + " memory block property change");
			boolean ok = false;
			try {
				collidingMemoryBlock.setRead(blockInfo.isReadable);
				collidingMemoryBlock.setComment("Changed by Device Tree Blob");
				ok = true;
			} catch (IllegalArgumentException e) {
				e.printStackTrace();
			}
			program.endTransaction(transactionId, ok);
		}

		if (collidingMemoryBlock.isWrite() != blockInfo.isWritable && OptionDialog.showYesNoDialog(parentComponent,
				"Load SVD",
				"Memory block \"" + collidingMemoryBlock.getName() + "\" is marked as"
						+ ((!collidingMemoryBlock.isWrite()) ? " non" : "")
						+ " writable. The SVD file suggests it should be"
						+ (collidingMemoryBlock.isWrite() ? " non" : "") + " writable. Do you want to changee it to"
						+ (collidingMemoryBlock.isWrite() ? " non" : "") + " writable?") == OptionDialog.OPTION_ONE) {
			int transactionId = program
					.startTransaction("SVD " + collidingMemoryBlock.getName() + " memory block property change");
			boolean ok = false;
			try {
				collidingMemoryBlock.setWrite(blockInfo.isWritable);
				collidingMemoryBlock.setComment("Changed by Device Tree Blob");
				ok = true;
			} catch (IllegalArgumentException e) {
				e.printStackTrace();
			}
			program.endTransaction(transactionId, ok);
		}

		if (collidingMemoryBlock.isExecute() != blockInfo.isExecutable && OptionDialog.showYesNoDialog(parentComponent,
				"Load SVD",
				"Memory block \"" + collidingMemoryBlock.getName() + "\" is marked as"
						+ ((!collidingMemoryBlock.isExecute()) ? " non" : "")
						+ " executable. The SVD file suggests it should be"
						+ (collidingMemoryBlock.isExecute() ? " non" : "") + " executable. Do you want to changee it to"
						+ (collidingMemoryBlock.isExecute() ? " non" : "")
						+ " executable?") == OptionDialog.OPTION_ONE) {
			int transactionId = program
					.startTransaction("SVD " + collidingMemoryBlock.getName() + " memory block property change");
			boolean ok = false;
			try {
				collidingMemoryBlock.setExecute(blockInfo.isExecutable);
				collidingMemoryBlock.setComment("Changed by Device Tree Blob");
				ok = true;
			} catch (IllegalArgumentException e) {
				e.printStackTrace();
			}
			program.endTransaction(transactionId, ok);
		}

		if (collidingMemoryBlock.isVolatile() != blockInfo.isVolatile && OptionDialog.showYesNoDialog(parentComponent,
				"Load SVD",
				"Memory block \"" + collidingMemoryBlock.getName() + "\" is marked as"
						+ ((!collidingMemoryBlock.isVolatile()) ? " non" : "")
						+ " volatile. The SVD file suggests it should be"
						+ (collidingMemoryBlock.isVolatile() ? " non" : "") + " volatile. Do you want to changee it to"
						+ (collidingMemoryBlock.isVolatile() ? " non" : "")
						+ " volatile?") == OptionDialog.OPTION_ONE) {
			int transactionId = program
					.startTransaction("SVD " + collidingMemoryBlock.getName() + " memory block property change");
			boolean ok = false;
			try {
				collidingMemoryBlock.setVolatile(blockInfo.isVolatile);
				collidingMemoryBlock.setComment("Changed by Device Tree Blob");
				ok = true;
			} catch (IllegalArgumentException e) {
				e.printStackTrace();
			}
			program.endTransaction(transactionId, ok);
		}
	}
}
