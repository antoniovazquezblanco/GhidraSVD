package svd.model;

import java.util.ArrayList;
import java.util.List;

import io.svdparser.SvdPeripheral;

public class BlockInfo {
	public Block block;
	public String name;
	public boolean isReadable;
	public boolean isWritable;
	public boolean isExecutable;
	public boolean isVolatile;
	public List<SvdPeripheral> peripherals;
	
	public BlockInfo() {
		peripherals = new ArrayList<SvdPeripheral>();
	}
}
