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

import java.util.ArrayList;
import java.util.List;

import ghidra.framework.plugintool.PluginTool;
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
import svd.MemoryBlockOperation;
import svd.MemoryBlockOperation.MemoryBlockOperationType;
import svd.MemoryUtils;
import svd.MemoryUtils.MemRangeRelation;
import svd.ui.SvdMemoryBlockOperationsDialog;

public class SvdMemoryMapUpdateTask extends Task {
	private SvdDevice mSvdDevice;
	private Program mProgram;
	private Memory mMemory;
	private PluginTool mTool;

	public SvdMemoryMapUpdateTask(PluginTool tool, Program program, SvdDevice device) {
		super("Create SVD Memory Map Regions", true, false, true, true);
		mTool = tool;
		mProgram = program;
		mMemory = program.getMemory();
		mSvdDevice = device;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		List<MemoryBlockOperation> operations = getMemoryOperations(monitor);

		// Show dialog for user to review and accept operations
		SvdMemoryBlockOperationsDialog dialog = new SvdMemoryBlockOperationsDialog(operations);
		mTool.showDialog(dialog);
		if (!dialog.isAccepted()) {
			throw new CancelledException();
		}

		for (MemoryBlockOperation op : operations) {
			monitor.checkCancelled();
			applyMemoryOperation(op);
		}
	}

	private List<MemoryBlockOperation> getMemoryOperations(TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Processing memory block operations...");
		List<MemoryBlockOperation> operations = new ArrayList<MemoryBlockOperation>();
		for (SvdPeripheral periph : mSvdDevice.getPeripherals()) {
			for (SvdAddressBlock block : periph.getAddressBlocks()) {
				monitor.checkCancelled();
				operations.add(getMemoryOperation(periph, block));
			}
		}
		return operations;
	}

	private MemoryBlockOperation getMemoryOperation(SvdPeripheral periph, SvdAddressBlock block) {
		// Fill known block information...
		MemoryBlockOperation op = new MemoryBlockOperation();
		op.Name = getPeriphBlockName(periph, block);
		op.Address = periph.getBaseAddr() + block.getOffset();
		op.Size = block.getSize();
		op.Read = true;
		op.Write = true;
		op.Execute = op.Name.contains("RAM") || op.Name.contains("memory");
		op.Volatile = !op.Execute;

		// Check if there are any colliding blocks...
		MemoryBlock[] collidingMemoryBlocks = MemoryUtils.getBlockCollidingMemoryBlocks(mMemory, op.Address, op.Size);
		if (collidingMemoryBlocks.length == 0) {
			// No colliding blocks so just create a new one...
			op.Type = MemoryBlockOperationType.CREATE;
			return op;
		} else if (collidingMemoryBlocks.length == 1 && MemoryUtils.getMemoryBlockRelation(collidingMemoryBlocks[0],
				op.Address, op.Size) == MemRangeRelation.RANGES_ARE_EQUAL) {
			// There is a colliding block. It also has the same address and size...
			// Check if all properties are the same, if so, no operation...
			if (collidingMemoryBlocks[0].getName() == op.Name && collidingMemoryBlocks[0].isRead() == op.Read
					&& collidingMemoryBlocks[0].isWrite() == op.Write
					&& collidingMemoryBlocks[0].isExecute() == op.Execute
					&& collidingMemoryBlocks[0].isVolatile() == op.Volatile)
				return null;
			// Both blocks are not the same, propose an update...
			op.Type = MemoryBlockOperationType.UPDATE;
			op.CollidingBlock = collidingMemoryBlocks[0];
			return op;
		}

		// Multiple collisions...
		Msg.showWarn(getClass(), null, "Load SVD",
				"Could not create a region for " + op.Name + "@" + String.format("0x%08x", op.Address) + "+"
						+ String.format("0x%08x", op.Size) + ". It conflicts with an existing region!");
		return null;
	}

	private String getPeriphBlockName(SvdPeripheral periph, SvdAddressBlock block) {
		String name = periph.getName();
		String blockUsage = block.getUsage();
		if (blockUsage != null && !blockUsage.isEmpty() && !blockUsage.contains("registers")) {
			name += "_" + blockUsage;
		}
		return name;
	}

	private void applyMemoryOperation(MemoryBlockOperation op) {
		switch (op.Type) {
		case MemoryBlockOperationType.CREATE:
			applyMemoryCreateOperation(op);
			break;
		case MemoryBlockOperationType.UPDATE:
			applyMemoryUpdateOperation(op);
			break;
		default:
			break;
		}
	}

	private void applyMemoryCreateOperation(MemoryBlockOperation op) {
		AddressSpace addrSpace = mProgram.getAddressFactory().getDefaultAddressSpace();
		Address addr = addrSpace.getAddress(op.Address);
		int transactionId = mProgram.startTransaction("SVD memory block creation");
		boolean ok = false;
		try {
			MemoryBlock memBlock = mMemory.createUninitializedBlock(op.Name, addr, op.Size, false);
			memBlock.setRead(op.Read);
			memBlock.setWrite(op.Write);
			memBlock.setExecute(op.Execute);
			memBlock.setVolatile(op.Volatile);
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

	private void applyMemoryUpdateOperation(MemoryBlockOperation op) {
		if (!op.CollidingBlock.getName().equals(op.Name)) {
			int transactionId = mProgram.startTransaction("SVD memory block rename");
			boolean ok = false;
			try {
				op.CollidingBlock.setName(op.Name);
				op.CollidingBlock.setComment("Changed by SVD");
				ok = true;
			} catch (IllegalArgumentException | LockException e) {
				e.printStackTrace();
			}
			mProgram.endTransaction(transactionId, ok);
		}
		if (op.CollidingBlock.isRead() != op.Read) {
			int transactionId = mProgram.startTransaction("SVD memory block read property");
			boolean ok = false;
			try {
				op.CollidingBlock.setRead(op.Read);
				op.CollidingBlock.setComment("Changed by SVD");
				ok = true;
			} catch (IllegalArgumentException e) {
				e.printStackTrace();
			}
			mProgram.endTransaction(transactionId, ok);
		}

		if (op.CollidingBlock.isWrite() != op.Write) {
			int transactionId = mProgram.startTransaction("SVD memory block write property");
			boolean ok = false;
			try {
				op.CollidingBlock.setWrite(op.Write);
				op.CollidingBlock.setComment("Changed by SVD");
				ok = true;
			} catch (IllegalArgumentException e) {
				e.printStackTrace();
			}
			mProgram.endTransaction(transactionId, ok);
		}

		if (op.CollidingBlock.isExecute() != op.Execute) {
			int transactionId = mProgram.startTransaction("SVD memory block exec property");
			boolean ok = false;
			try {
				op.CollidingBlock.setExecute(op.Execute);
				op.CollidingBlock.setComment("Changed by SVD");
				ok = true;
			} catch (IllegalArgumentException e) {
				e.printStackTrace();
			}
			mProgram.endTransaction(transactionId, ok);
		}

		if (op.CollidingBlock.isVolatile() != op.Volatile) {
			int transactionId = mProgram.startTransaction("SVD memory block volatile property");
			boolean ok = false;
			try {
				op.CollidingBlock.setVolatile(op.Volatile);
				op.CollidingBlock.setComment("Changed by SVD");
				ok = true;
			} catch (IllegalArgumentException e) {
				e.printStackTrace();
			}
			mProgram.endTransaction(transactionId, ok);
		}
	}
}