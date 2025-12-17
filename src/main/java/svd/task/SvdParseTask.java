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

import java.io.File;
import java.io.IOException;

import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;

import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import io.svdparser.SvdDevice;
import io.svdparser.SvdParserException;

public class SvdParseTask extends Task {
	private File mSvdFile;
	private boolean mSuccess;
	private SvdDevice mSvdDevice;
	private Exception mException;

	public SvdParseTask(Program program, File svdFile) {
		super("Parse SVD", false, false, true, true);
		mSvdFile = svdFile;
		mException = null;
		mSvdDevice = null;
		mSuccess = false;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Parsing " + mSvdFile.getPath() + "...");

		try {
			mSvdDevice = SvdDevice.fromFile(mSvdFile);
		} catch (SvdParserException | SAXException | IOException | ParserConfigurationException e) {
			mException = e;
			mSuccess = false;
			return;
		}

		mSuccess = true;
	}

	public boolean isSuccess() {
		return mSuccess;
	}

	public SvdDevice getSvdDevice() {
		return mSvdDevice;
	}

	public Exception getException() {
		return mException;
	}
}
