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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.DataOrganization;
import ghidra.program.model.data.DataOrganizationImpl;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.data.Structure;
import io.svdparser.SvdAddressBlock;
import io.svdparser.SvdDevice;
import io.svdparser.SvdField;
import io.svdparser.SvdPeripheral;
import io.svdparser.SvdRegister;

class SvdDataTypesCreateTaskTest {
	private static SvdDevice device;

	@BeforeAll
	static void setUp() throws Exception {
		// Data type managers need an initialized Ghidra application...
		if (!Application.isInitialized())
			Application.initializeApplication(new GhidraApplicationLayout(), new ApplicationConfiguration());
		device = SvdDevice.fromFile(new File("src/test/resources/register_sizes.svd"));
	}

	@Test
	void testRegisterSizesWithDefaultDataOrganization() {
		assertRegisterSizes(DataOrganizationImpl.getDefaultOrganization(null));
	}

	@Test
	void testRegisterSizesWith64BitLong() {
		// LP64 targets such as AArch64...
		DataOrganizationImpl dataOrg = DataOrganizationImpl.getDefaultOrganization(null);
		dataOrg.setLongSize(8);
		assertRegisterSizes(dataOrg);
	}

	@Test
	void testRegisterSizesWith16BitInt() {
		// 16 bit targets such as MSP430 or AVR...
		DataOrganizationImpl dataOrg = DataOrganizationImpl.getDefaultOrganization(null);
		dataOrg.setIntegerSize(2);
		assertRegisterSizes(dataOrg);
	}

	/**
	 * Commit the peripheral data types to a data type manager using the given data
	 * organization, as it happens when importing into a program, and check that
	 * every register and field keeps the size declared in the SVD file.
	 */
	private static void assertRegisterSizes(DataOrganization dataOrg) {
		StandAloneDataTypeManager dtm = new StandAloneDataTypeManager("test", dataOrg);
		int transactionId = dtm.startTransaction("Commit SVD data types");
		try {
			for (SvdPeripheral periph : device.getPeripherals())
				for (SvdAddressBlock block : periph.getAddressBlocks()) {
					Structure struct = (Structure) dtm.addDataType(
							SvdDataTypesCreateTask.createPeripheralBlockDataType(periph, block),
							DataTypeConflictHandler.REPLACE_HANDLER);
					for (SvdRegister reg : periph.getRegisters())
						assertRegisterSize(struct, reg);
				}
		} finally {
			dtm.endTransaction(transactionId, false);
			dtm.close();
		}
	}

	private static void assertRegisterSize(Structure struct, SvdRegister reg) {
		DataTypeComponent component = struct.getComponentAt(reg.getOffset());
		assertNotNull(component, reg.getName() + " is missing");
		assertEquals(reg.getSize() / 8, component.getLength(), reg.getName() + " component length");
		assertEquals(reg.getSize() / 8, component.getDataType().getLength(),
				reg.getName() + " data type " + component.getDataType().getName() + " length");

		if (reg.getFields() == null || reg.getFields().isEmpty())
			return;
		Structure fields = (Structure) component.getDataType();
		for (SvdField field : reg.getFields()) {
			DataTypeComponent fieldComponent = findComponent(fields, field.getName());
			assertNotNull(fieldComponent, reg.getName() + "." + field.getName() + " is missing");
			BitFieldDataType bitField = (BitFieldDataType) fieldComponent.getDataType();
			assertEquals(field.getBitWidth(), bitField.getBitSize(),
					reg.getName() + "." + field.getName() + " bit width");
		}
	}

	private static DataTypeComponent findComponent(Structure struct, String name) {
		for (DataTypeComponent component : struct.getDefinedComponents())
			if (name.equals(component.getFieldName()))
				return component;
		return null;
	}
}
