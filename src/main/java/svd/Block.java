package svd;

import java.util.Objects;

public class Block {
	private Long mAddress;
	private Long mSize;
	private int mHashCode;

	public Block(Long addr, Long size) {
		mAddress = addr;
		mSize = size;
		mHashCode = Objects.hash(addr, size);
	}

	public Long getAddress() {
		return mAddress;
	}

	public Long getSize() {
		return mSize;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		Block that = (Block) o;
		return this.mAddress.longValue() == that.getAddress().longValue()
				&& this.mSize.longValue() == that.getSize().longValue();
	}

	@Override
	public int hashCode() {
		return mHashCode;
	}
}
