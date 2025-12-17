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
package svd.ui;

import javax.swing.table.DefaultTableModel;

import svd.MemoryBlockOperation;

public class SvdMemoryBlockOperationsTableModel extends DefaultTableModel {
    private static final String[] COLUMN_NAMES = {"Operation Type", "Name", "Address", "Size", "Read", "Write", "Execute", "Volatile"};

    public SvdMemoryBlockOperationsTableModel() {
        super(COLUMN_NAMES, 0);
    }

    public void addRow(MemoryBlockOperation op) {
        Object[] row = {
            op.Type.toString(),
            op.Name,
            String.format("0x%08X", op.Address),
            String.format("0x%08X", op.Size),
            op.Read,
            op.Write,
            op.Execute,
            op.Volatile
        };
        super.addRow(row);
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return false;
    }

    @Override
    public Class<?> getColumnClass(int column) {
        switch (column) {
            case 0: return String.class;
            case 1: return String.class;
            case 2: return String.class;
            case 3: return String.class;
            case 4: return Boolean.class;
            case 5: return Boolean.class;
            case 6: return Boolean.class;
            case 7: return Boolean.class;
            default: return String.class;
        }
    }
}