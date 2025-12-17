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

import java.awt.BorderLayout;
import java.util.List;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;


import docking.DialogComponentProvider;
import svd.MemoryBlockOperation;

public class SvdMemoryBlockOperationsDialog extends DialogComponentProvider {
    private JTable operationsTable;
    private SvdMemoryBlockOperationsTableModel tableModel;
    private boolean accepted = false;

    public SvdMemoryBlockOperationsDialog(List<MemoryBlockOperation> operations) {
        super("SVD Memory Block Operations", true, true, true, false);

        initializeTable(operations);
        addWorkPanel(createMainPanel());
        addOKButton();
        addCancelButton();
        setDefaultButton(okButton);
    }

    private void initializeTable(List<MemoryBlockOperation> operations) {
        tableModel = new SvdMemoryBlockOperationsTableModel();

        for (MemoryBlockOperation op : operations) {
            tableModel.addRow(op);
        }

        operationsTable = new JTable(tableModel);
        operationsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        operationsTable.getTableHeader().setReorderingAllowed(false);
    }

    private JPanel createMainPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(new JScrollPane(operationsTable), BorderLayout.CENTER);

        JLabel infoLabel = new JLabel("<html>The following memory block operations will be performed.<br>Review and click OK to proceed or Cancel to abort.</html>");
        panel.add(infoLabel, BorderLayout.NORTH);

        return panel;
    }

    @Override
    protected void okCallback() {
        accepted = true;
        close();
    }

    @Override
    protected void cancelCallback() {
        accepted = false;
        close();
    }

    public boolean isAccepted() {
        return accepted;
    }
}