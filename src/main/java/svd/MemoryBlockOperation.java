package svd;

import ghidra.program.model.mem.MemoryBlock;

public class MemoryBlockOperation {
	public enum MemoryBlockOperationType {
		CREATE,
		UPDATE
	}
	
	public MemoryBlockOperationType Type;
	public String Name;
	public long Address;
	public long Size;
	public boolean Read;
	public boolean Write;
	public boolean Execute;
	public boolean Volatile;
	public MemoryBlock CollidingBlock;
}
