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

import java.io.File;
import java.io.IOException;

import javax.swing.JComponent;
import javax.swing.SwingConstants;
import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;

import docking.action.builder.ActionBuilder;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskBuilder;
import ghidra.util.task.TaskLauncher;
import io.svdparser.SvdDevice;
import io.svdparser.SvdParserException;
import svd.ui.SvdFileDialog;
import svd.ui.SvdInfoDialog;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Import external SVD files.",
	description = "This plugin manages the import of SVD files to add memory map information to a program."
)
//@formatter:on
public class SVDPlugin extends ProgramPlugin {

	public SVDPlugin(PluginTool tool) {
		super(tool);
		createActions();
	}

	private void createActions() {
		new ActionBuilder("Load SVD File", this.getName()).withContext(ProgramActionContext.class)
				.validContextWhen(pac -> pac.getProgram() != null).menuPath(ToolConstants.MENU_FILE, "Load SVD File...")
				.menuGroup("Import SVD", "5").onAction(pac -> {
					try {
						loadSvd(pac);
					} catch (SvdParserException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (SAXException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (ParserConfigurationException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}).buildAndInstall(tool);
	}

	private void loadSvd(ProgramActionContext pac) throws SvdParserException, SAXException, IOException, ParserConfigurationException {
		Program program = pac.getProgram();
		AutoAnalysisManager currentAutoAnalysisManager = AutoAnalysisManager.getAnalysisManager(program);
		if (currentAutoAnalysisManager.isAnalyzing()) {
			Msg.showWarn(getClass(), null, "Load SVD", "Unable to load SVD file while analysis is running.");
			return;
		}

		tool.setStatusInfo("Loading SVD.");

		JComponent parentComponent = pac.getComponentProvider().getComponent();
		File file = SvdFileDialog.getSvdFileFromDialog(parentComponent);
		if (file == null) {
			tool.setStatusInfo("SVD loading was cancelled.");
			return;
		}

		SvdDevice device = SvdDevice.fromFile(file);
		SvdInfoDialog svdInfoDialog = new SvdInfoDialog(device);
		tool.showDialog(svdInfoDialog);

		SvdLoadTask loadTask = new SvdLoadTask(program, file);
		TaskBuilder.withTask(loadTask).setStatusTextAlignment(SwingConstants.LEADING).setLaunchDelay(0);
		new TaskLauncher(loadTask);

		tool.setStatusInfo("SVD loader finished.");
	}
}
