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

import javax.swing.JComponent;

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
import svd.task.SvdDataTypesCreateTask;
import svd.task.SvdMemoryMapUpdateTask;
import svd.task.SvdParseTask;
import svd.ui.SvdFileDialog;

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

	@SuppressWarnings("removal")
	private void createActions() {
		new ActionBuilder("Load SVD File", this.getName()).withContext(ProgramActionContext.class)
				.validContextWhen(pac -> pac.getProgram() != null).menuPath(ToolConstants.MENU_FILE, "Load SVD File...")
				.menuGroup("Import PDB", "5").onAction(pac -> loadSvd(pac)).buildAndInstall(tool);
	}

	private void loadSvd(ProgramActionContext pac) {
		Program program = pac.getProgram();
		AutoAnalysisManager currentAutoAnalysisManager = AutoAnalysisManager.getAnalysisManager(program);
		if (currentAutoAnalysisManager.isAnalyzing()) {
			Msg.showWarn(getClass(), null, "Load SVD", "Unable to load SVD file while analysis is running.");
			return;
		}

		tool.setStatusInfo("Loading SVD...");

		JComponent parentComponent = pac.getComponentProvider().getComponent();
		File file = SvdFileDialog.getSvdFileFromDialog(parentComponent);
		if (file == null) {
			tool.setStatusInfo("SVD loading was cancelled.");
			return;
		}

		// Try to parse the file...
		SvdParseTask parseTask = new SvdParseTask(program, file);
		tool.execute(parseTask);
		if (!parseTask.isSuccess()) {
			Msg.error(getClass(), "Unable to parse SVD file!", parseTask.getException());
			return;
		}

		// Create the new memory map regions...
		SvdMemoryMapUpdateTask memoryTask = new SvdMemoryMapUpdateTask(tool, program, parseTask.getSvdDevice());
		tool.execute(memoryTask);

		// Create symbols and data types...
		SvdDataTypesCreateTask symbolTask = new SvdDataTypesCreateTask(program, parseTask.getSvdDevice());
		tool.execute(symbolTask);

		tool.setStatusInfo("SVD information loaded!");
	}
}
