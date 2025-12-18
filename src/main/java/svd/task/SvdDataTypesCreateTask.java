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

import java.util.Comparator;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import io.svdparser.SvdAddressBlock;
import io.svdparser.SvdDevice;
import io.svdparser.SvdField;
import io.svdparser.SvdPeripheral;
import io.svdparser.SvdRegister;

public class SvdDataTypesCreateTask extends Task {
	private Program mProgram;
	private SymbolTable mSymTable;
	private AddressSpace mAddrSpace;
	private SvdDevice mSvdDevice;

	public SvdDataTypesCreateTask(Program program, SvdDevice svdDevice) {
		super("Create SVD Symbols and Data Types", true, false, true, true);
		mProgram = program;
		mAddrSpace = mProgram.getAddressFactory().getDefaultAddressSpace();
		mSymTable = program.getSymbolTable();
		mSvdDevice = svdDevice;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		// Create a namespace for peripheral info...
		Namespace namespace = getOrCreateNamespace("Peripherals");

		for (SvdPeripheral periph : mSvdDevice.getPeripherals()) {
			monitor.setMessage("Processing symbols and data types for " + periph.getName() + "...");
			monitor.checkCancelled();
			processPeripheral(monitor, namespace, periph);
		}
	}

	private Namespace getOrCreateNamespace(String name) {
		Namespace namespace = mSymTable.getNamespace(name, null);
		if (namespace != null)
			return namespace;

		int transactionId = mProgram.startTransaction("SVD " + name + " namespace creation");
		boolean ok = false;
		try {
			namespace = mSymTable.createNameSpace(null, name, SourceType.IMPORTED);
			ok = true;
		} catch (DuplicateNameException | InvalidInputException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		mProgram.endTransaction(transactionId, ok);
		return namespace;
	}

	private void processPeripheral(TaskMonitor monitor, Namespace namespace, SvdPeripheral periph)
			throws CancelledException {
		monitor.checkCancelled();
		createPeripheralSymbol(namespace, periph);

		for (SvdAddressBlock block : periph.getAddressBlocks()) {
			monitor.checkCancelled();
			processPeripheralAddressBlock(monitor, namespace, periph, block);
		}
	}

	private void createPeripheralSymbol(Namespace namespace, SvdPeripheral periph) {
		Address addr = mAddrSpace.getAddress(periph.getBaseAddr().longValue());
		String name = periph.getName();

		int transactionId = mProgram.startTransaction("Creating symbol for " + name);
		boolean ok = false;
		try {
			mSymTable.createLabel(addr, name, namespace, SourceType.IMPORTED);
			ok = true;
		} catch (InvalidInputException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		mProgram.endTransaction(transactionId, ok);
	}

	private void processPeripheralAddressBlock(TaskMonitor monitor, Namespace namespace, SvdPeripheral periph,
			SvdAddressBlock block) throws CancelledException {
		monitor.checkCancelled();
		StructureDataType dataType = createPeripheralBlockDataType(periph, block);
		monitor.checkCancelled();
		commitPeripheralBlockDataType(dataType);
		monitor.checkCancelled();
		createListingBlockData(dataType, periph, block);
	}

	private StructureDataType createPeripheralBlockDataType(SvdPeripheral periph, SvdAddressBlock block) {
		String struct_name = getPeriphBlockDataTypeName(periph, block);
		StructureDataType struct = new StructureDataType(struct_name, block.getSize().intValue());
		for (SvdRegister reg : periph.getRegisters())
			// TODO: Handle out of bounds values?
			if (reg.getOffset() < block.getSize())
				struct.replaceAtOffset(reg.getOffset(), createRegisterDataType(reg), reg.getSize() / 8, reg.getName(),
						reg.getDescription());
		return struct;
	}

	private DataType createRegisterDataType(SvdRegister reg) {
		List<SvdField> fields = reg.getFields();

		// If this is a register without fields, return the basic unsigned type...
		if (fields == null || fields.isEmpty())
			return new UnsignedLongDataType();

		// Fields, insert bit fields at their exact bit offsets...
		StructureDataType struct = new StructureDataType(reg.getName() + "_t", reg.getSize() / 8);
		struct.setPackingEnabled(true);
		fields.sort(Comparator.comparingInt(SvdField::getBitOffset));
		int fieldNumber = 0;
		for (SvdField field : fields) {
			// Skip fields that exceed the register size
			if (field.getBitOffset() + field.getBitWidth() > reg.getSize()) {
				// TODO: Handle this?
				continue;
			}
			try {
				struct.insertBitField(fieldNumber++, reg.getSize(), field.getBitOffset(), new UnsignedLongDataType(),
						field.getBitWidth(), field.getName(), field.getDescription());
			} catch (InvalidDataTypeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return struct;
	}

	private String getPeriphBlockDataTypeName(SvdPeripheral periph, SvdAddressBlock block) {
		String name = periph.getName();
		String blockUsage = block.getUsage();
		if (blockUsage != null && !blockUsage.isEmpty()) {
			name += "_" + blockUsage;
		}
		return name + "_t";
	}

	private void commitPeripheralBlockDataType(StructureDataType dataType) {
		// Add struct to the data type manager...
		ProgramBasedDataTypeManager dataTypeManager = mProgram.getDataTypeManager();
		int transactionId = mProgram.startTransaction("SVD " + dataType.getName() + " data type creation");
		boolean ok = false;
		try {
			dataTypeManager.addDataType(dataType, DataTypeConflictHandler.REPLACE_HANDLER);
			ok = true;
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
		}
		mProgram.endTransaction(transactionId, ok);
	}

	private void createListingBlockData(StructureDataType dataType, SvdPeripheral periph, SvdAddressBlock block) {
		// Calculate address of the block...
		Long addrValue = periph.getBaseAddr() + block.getOffset();
		Address addr = mAddrSpace.getAddress(addrValue.longValue());

		// Add data type to listing...
		Listing listing = mProgram.getListing();
		int transactionId = mProgram.startTransaction("SVD " + dataType.getName() + " data type listing placement");
		boolean ok = false;
		try {
			listing.createData(addr, dataType);
			ok = true;
		} catch (CodeUnitInsertionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		mProgram.endTransaction(transactionId, ok);
	}
}