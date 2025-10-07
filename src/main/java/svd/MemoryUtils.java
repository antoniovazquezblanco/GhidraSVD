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
package svd;

import java.util.Arrays;

import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import svd.model.Block;

public class MemoryUtils {
	public static boolean doesMemoryBlockCollideWithRegion(MemoryBlock block, Long regionStart, Long regionSize) {
		Long blockStart = block.getStart().getOffset();
		Long blockEnd = block.getEnd().getOffset();
		Long regionEnd = regionStart + regionSize - 1;
		return (regionStart.longValue() <= blockEnd.longValue() && regionEnd.longValue() >= blockStart.longValue());
	}

	public static MemoryBlock[] getBlockCollidingMemoryBlocks(Memory memory, Block block) {
		return Arrays.stream(memory.getBlocks())
				.filter(x -> doesMemoryBlockCollideWithRegion(x, block.getAddress(), block.getSize())).toArray(MemoryBlock[]::new);
	}
	
	public enum MemRangeRelation {
		RANGES_ARE_EQUAL,
		RANGE1_CONTAINS_RANGE2,
		RANGE2_CONTAINS_RANGE1,
		RANGE1_BEFORE_RANGE2,
		RANGE1_AFTER_RANGE2,
	}
	
	public static MemRangeRelation getMemoryBlockRelation(MemoryBlock block1, Block block2) {
		Long block1Start = block1.getStart().getOffset();
		Long block1End = block1.getEnd().getOffset();
		Long block2Start = block2.getAddress();
		Long block2End = block2.getAddress() + block2.getSize() - 1;
		if(block1Start.longValue() == block2Start.longValue() && block1End.longValue() == block2End.longValue()) {
			return MemRangeRelation.RANGES_ARE_EQUAL;
		} else if (block1Start.longValue() <= block2Start.longValue() && block1End.longValue() >= block2End.longValue()) {
			return MemRangeRelation.RANGE1_CONTAINS_RANGE2;
		} else if (block1Start.longValue() >= block2Start.longValue() && block1End.longValue() <= block2End.longValue()) {
			return MemRangeRelation.RANGE2_CONTAINS_RANGE1;
		} else if (block1Start.longValue() <= block2Start.longValue() && block1End.longValue() <= block2End.longValue()) {
			return MemRangeRelation.RANGE1_BEFORE_RANGE2;
		} else if (block1Start.longValue() >= block2Start.longValue() && block1End.longValue() >= block2End.longValue()) {
			return MemRangeRelation.RANGE1_AFTER_RANGE2;
		}
		return null;
	}
}
