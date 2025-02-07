package svd.ui;

import java.awt.BorderLayout;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import docking.ReusableDialogComponentProvider;
import docking.widgets.table.AbstractGTableModel;
import docking.widgets.table.GTable;
import io.svdparser.SvdDevice;
import io.svdparser.SvdPeripheral;

public class SvdInfoDialog extends ReusableDialogComponentProvider {

	public SvdInfoDialog(SvdDevice dev) {
		super("SVD Information");
		addWorkPanel(createMainPanel(dev));
	}

	private JComponent createMainPanel(SvdDevice dev) {
		JPanel panel = new JPanel(new BorderLayout());

		SvdPeripheralTableModel svdPeriphModel = new SvdPeripheralTableModel(dev);
		GTable svdPeriphTable = new GTable(svdPeriphModel);
		JScrollPane svdPeriphTableScroll = new JScrollPane(svdPeriphTable);
		panel.add(svdPeriphTableScroll);

		addOKButton();

		return panel;
	}

	public class SvdPeripheralTableModel extends AbstractGTableModel<SvdPeripheral> {

		private List<ReferenceCol> columns = new ArrayList<>();
		private List<SvdPeripheral> rowDataList;

		SvdPeripheralTableModel(SvdDevice dev) {
			rowDataList = dev.getPeripherals();
			columns.add(new NameColumn());
			columns.add(new BaseAddressColumn());
		}

		@Override
		public String getName() {
			return "Peripherals";
		}

		@Override
		public List<SvdPeripheral> getModelData() {
			return rowDataList;
		}

		@Override
		public int getColumnCount() {
			return columns.size();
		}

		@Override
		public String getColumnName(int column) {
			return columns.get(column).getName();
		}

		@Override
		public Class<?> getColumnClass(int columnIndex) {
			return columns.get(columnIndex).getColumnClass();
		}

		@Override
		public Object getColumnValueForRow(SvdPeripheral t, int columnIndex) {
			return columns.get(columnIndex).getValueForRow(rowDataList, t);
		}

		@Override
		public boolean isCellEditable(int rowIndex, int columnIndex) {
			return false;
		}

		private abstract class ReferenceCol {
			private String name;
			private Class<?> classType;

			ReferenceCol(String name, Class<?> classType) {
				this.name = name;
				this.classType = classType;
			}

			public String getName() {
				return name;
			}

			public Class<?> getColumnClass() {
				return classType;
			}

			protected abstract Object getValueForRow(List<SvdPeripheral> data, SvdPeripheral t);
		}

		private class NameColumn extends ReferenceCol {
			NameColumn() {
				super("Name", String.class);
			}

			@Override
			protected Object getValueForRow(List<SvdPeripheral> data, SvdPeripheral t) {
				return t.getName();
			}
		}

		private class BaseAddressColumn extends ReferenceCol {
			BaseAddressColumn() {
				super("Base addr", String.class);
			}

			@Override
			protected Object getValueForRow(List<SvdPeripheral> data, SvdPeripheral t) {
				return String.format("0x%04x", t.getBaseAddr());
			}
		}

	}
}
