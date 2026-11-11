package gamecubeloader.common;

import java.awt.GraphicsEnvironment;

import ghidra.util.SystemUtilities;

public final class Prompts {
	private Prompts() {}

	/**
	 * Whether a loader may ask the user something. False under analyzeHeadless or without a display: nobody can
	 * answer, and a dialog there blocks the import. Callers fall back to what "No"/"Cancel" would have done.
	 */
	public static boolean canPrompt() {
		return !SystemUtilities.isInHeadlessMode() && !GraphicsEnvironment.isHeadless();
	}
}
