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
package svd.task;

import java.util.HashMap;
import java.util.Map;

import docking.widgets.OptionDialog;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import io.svdparser.SvdAddressBlock;
import io.svdparser.SvdDevice;
import io.svdparser.SvdPeripheral;
import svd.MemoryUtils;
import svd.MemoryUtils.MemRangeRelation;
import svd.model.Block;
import svd.model.BlockInfo;

public class SvdMemoryMapUpdateTask extends Task {
	private SvdDevice mSvdDevice;
	private Program mProgram;
	private Memory mMemory;

	public SvdMemoryMapUpdateTask(Program program, SvdDevice device) {
		super("Create SVD Memory Map Regions", true, false, true, true);
		mProgram = program;
		mMemory = program.getMemory();
		mSvdDevice = device;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		// Convert the SVD device information to our internal representation...
		monitor.setMessage("Obtaining memory blocks...");
		Map<Block, BlockInfo> memBlocks = getMemoryBlocks(monitor, mSvdDevice);

		// Process the blocks...
		monitor.setMessage("Processing memory blocks...");
		processBlocks(monitor, memBlocks);
	}

	private Map<Block, BlockInfo> getMemoryBlocks(TaskMonitor monitor, SvdDevice device) throws CancelledException {
		Map<Block, BlockInfo> memBlocks = new HashMap<Block, BlockInfo>();
		// Convert all peripherals to blocks...
		for (SvdPeripheral periph : mSvdDevice.getPeripherals()) {
			for (SvdAddressBlock block : periph.getAddressBlocks()) {
				// Check for cancellation
				monitor.checkCancelled();

				// Create a block..
				Block b = new Block(periph.getBaseAddr() + block.getOffset(), block.getSize());

				// Check if block exists...
				BlockInfo bInfo = memBlocks.get(b);
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
				memBlocks.put(b, bInfo);
			}
		}
		return memBlocks;
	}

	private String getPeriphBlockName(SvdPeripheral periph, SvdAddressBlock block) {
		String name = periph.getName();
		String blockUsage = block.getUsage();
		if (blockUsage != null && !blockUsage.isEmpty() && !blockUsage.contains("registers")) {
			name += "_" + blockUsage;
		}
		return name;
	}

	private void processBlocks(TaskMonitor monitor, Map<Block, BlockInfo> memBlocks) throws CancelledException {
		for (BlockInfo blockInfo : memBlocks.values()) {
			monitor.setMessage("Processing " + blockInfo.name + "...");
			monitor.checkCancelled();
			processBlockMemory(blockInfo);
		}
	}

	private boolean processBlockMemory(BlockInfo blockInfo) {
		MemoryBlock[] collidingMemoryBlocks = MemoryUtils.getBlockCollidingMemoryBlocks(mMemory, blockInfo.block);
		if (collidingMemoryBlocks.length == 0) {
			createMemoryBlock(blockInfo);
		} else if (collidingMemoryBlocks.length == 1 && MemoryUtils.getMemoryBlockRelation(collidingMemoryBlocks[0],
				blockInfo.block) == MemRangeRelation.RANGES_ARE_EQUAL) {
			updateMatchingMemoryBlock(collidingMemoryBlocks[0], blockInfo);
		} else {
			Msg.showWarn(getClass(), null, "Load SVD", "Could not create a region for " + blockInfo.name + "@"
					+ String.format("0x%08x", blockInfo.block.getAddress()) + "+"
					+ String.format("0x%08x", blockInfo.block.getSize()) + ". It conflicts with an existing region!");
			return false;
		}
		return true;
	}

	private void createMemoryBlock(BlockInfo blockInfo) {
		AddressSpace addrSpace = mProgram.getAddressFactory().getDefaultAddressSpace();
		Address addr = addrSpace.getAddress(blockInfo.block.getAddress());
		int transactionId = mProgram.startTransaction("SVD memory block creation");
		boolean ok = false;
		try {
			MemoryBlock memBlock = mMemory.createUninitializedBlock(blockInfo.name, addr,
					blockInfo.block.getSize().longValue(), false);
			memBlock.setRead(blockInfo.isReadable);
			memBlock.setWrite(blockInfo.isWritable);
			memBlock.setExecute(blockInfo.isExecutable);
			memBlock.setVolatile(blockInfo.isVolatile);
			memBlock.setComment("Generated by SVD");
			ok = true;
		} catch (LockException e) {
			Msg.showError(this, null, getTaskTitle(), e, e);
		} catch (MemoryConflictException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (AddressOverflowException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		mProgram.endTransaction(transactionId, ok);
	}

	private void updateMatchingMemoryBlock(MemoryBlock collidingMemoryBlock, BlockInfo blockInfo) {
		if (!collidingMemoryBlock.getName().equals(blockInfo.name) && OptionDialog.showYesNoDialog(null, "Load SVD",
				"An existing memory block with name \"" + collidingMemoryBlock.getName()
						+ "\" is in the same region as the \"" + blockInfo.name
						+ "\" peripheral. Do you want to rename it to \"" + blockInfo.name
						+ "\"?") == OptionDialog.OPTION_ONE) {
			int transactionId = mProgram.startTransaction("SVD memory block rename");
			boolean ok = false;
			try {
				collidingMemoryBlock.setName(blockInfo.name);
				collidingMemoryBlock.setComment("Changed by SVD");
				ok = true;
			} catch (IllegalArgumentException | LockException e) {
				e.printStackTrace();
			}
			mProgram.endTransaction(transactionId, ok);
		}
		if (collidingMemoryBlock.isRead() != blockInfo.isReadable && OptionDialog.showYesNoDialog(null, "Load SVD",
				"Memory block \"" + collidingMemoryBlock.getName() + "\" is marked as"
						+ ((!collidingMemoryBlock.isRead()) ? " non" : "")
						+ " readable. The SVD file suggests it should be"
						+ (collidingMemoryBlock.isRead() ? " non" : "") + " readable. Do you want to change it to"
						+ (collidingMemoryBlock.isRead() ? " non" : "") + " readable?") == OptionDialog.OPTION_ONE) {
			int transactionId = mProgram
					.startTransaction("SVD " + collidingMemoryBlock.getName() + " memory block property change");
			boolean ok = false;
			try {
				collidingMemoryBlock.setRead(blockInfo.isReadable);
				collidingMemoryBlock.setComment("Changed by SVD");
				ok = true;
			} catch (IllegalArgumentException e) {
				e.printStackTrace();
			}
			mProgram.endTransaction(transactionId, ok);
		}

		if (collidingMemoryBlock.isWrite() != blockInfo.isWritable && OptionDialog.showYesNoDialog(null, "Load SVD",
				"Memory block \"" + collidingMemoryBlock.getName() + "\" is marked as"
						+ ((!collidingMemoryBlock.isWrite()) ? " non" : "")
						+ " writable. The SVD file suggests it should be"
						+ (collidingMemoryBlock.isWrite() ? " non" : "") + " writable. Do you want to change it to"
						+ (collidingMemoryBlock.isWrite() ? " non" : "") + " writable?") == OptionDialog.OPTION_ONE) {
			int transactionId = mProgram
					.startTransaction("SVD " + collidingMemoryBlock.getName() + " memory block property change");
			boolean ok = false;
			try {
				collidingMemoryBlock.setWrite(blockInfo.isWritable);
				collidingMemoryBlock.setComment("Changed by SVD");
				ok = true;
			} catch (IllegalArgumentException e) {
				e.printStackTrace();
			}
			mProgram.endTransaction(transactionId, ok);
		}

		if (collidingMemoryBlock.isExecute() != blockInfo.isExecutable && OptionDialog.showYesNoDialog(null, "Load SVD",
				"Memory block \"" + collidingMemoryBlock.getName() + "\" is marked as"
						+ ((!collidingMemoryBlock.isExecute()) ? " non" : "")
						+ " executable. The SVD file suggests it should be"
						+ (collidingMemoryBlock.isExecute() ? " non" : "") + " executable. Do you want to change it to"
						+ (collidingMemoryBlock.isExecute() ? " non" : "")
						+ " executable?") == OptionDialog.OPTION_ONE) {
			int transactionId = mProgram
					.startTransaction("SVD " + collidingMemoryBlock.getName() + " memory block property change");
			boolean ok = false;
			try {
				collidingMemoryBlock.setExecute(blockInfo.isExecutable);
				collidingMemoryBlock.setComment("Changed by SVD");
				ok = true;
			} catch (IllegalArgumentException e) {
				e.printStackTrace();
			}
			mProgram.endTransaction(transactionId, ok);
		}

		if (collidingMemoryBlock.isVolatile() != blockInfo.isVolatile && OptionDialog.showYesNoDialog(null, "Load SVD",
				"Memory block \"" + collidingMemoryBlock.getName() + "\" is marked as"
						+ ((!collidingMemoryBlock.isVolatile()) ? " non" : "")
						+ " volatile. The SVD file suggests it should be"
						+ (collidingMemoryBlock.isVolatile() ? " non" : "") + " volatile. Do you want to change it to"
						+ (collidingMemoryBlock.isVolatile() ? " non" : "")
						+ " volatile?") == OptionDialog.OPTION_ONE) {
			int transactionId = mProgram
					.startTransaction("SVD " + collidingMemoryBlock.getName() + " memory block property change");
			boolean ok = false;
			try {
				collidingMemoryBlock.setVolatile(blockInfo.isVolatile);
				collidingMemoryBlock.setComment("Changed by SVD");
				ok = true;
			} catch (IllegalArgumentException e) {
				e.printStackTrace();
			}
			mProgram.endTransaction(transactionId, ok);
		}
	}
}