// Copyright 2013 Martin Boonk
//
// This file is part of the OpenTLSSClib.
//
// The OpenTLSSClib is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The OpenTLSSClib is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the OpenTLSSClib.  If not, see <http://www.gnu.org/licenses/>.

package de.opentlssc.tls;

import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Manage the allocated and used transient arrays to be able to use the ram efficient.
 * 
 * @author Martin Boonk
 *
 */
class TransientTools {
	private ByteArray [] workspaces;
	private ByteArray [] bigWorkspaces;
	
	TransientTools(){
		bigWorkspaces = new ByteArray [LibraryConfiguration.CONFIG_BIG_WORKSPACES];
		for (short i = 0; i < bigWorkspaces.length; i++){
			bigWorkspaces[i] = new ByteArray();
			if (i < LibraryConfiguration.CONFIG_TRANSIENT_BIG_WORKSPACES){
				bigWorkspaces[i].content = JCSystem.makeTransientByteArray(LibraryConfiguration.CONFIG_TRANSIENT_BIG_WORKSPACE_LENGTH, JCSystem.CLEAR_ON_DESELECT);
			}else{
				bigWorkspaces[i].content = new byte [LibraryConfiguration.CONFIG_TRANSIENT_BIG_WORKSPACE_LENGTH];
			}
		}

		workspaces = new ByteArray [LibraryConfiguration.CONFIG_WORKSPACES];
		for (short i = 0; i < workspaces.length; i++){
			workspaces[i] = new ByteArray();
			if (i < LibraryConfiguration.CONFIG_TRANSIENT_WORKSPACES){
				workspaces[i].content = JCSystem.makeTransientByteArray(LibraryConfiguration.CONFIG_TRANSIENT_WORKSPACE_LENGTH, JCSystem.CLEAR_ON_DESELECT);
			}else{
				workspaces[i].content = new byte [LibraryConfiguration.CONFIG_TRANSIENT_WORKSPACE_LENGTH];
			}
		}
	}
	
	/**
	 * Free a transient array to be allocated again. This only works for arrays allocated
	 * by getWorkspace().
	 * 
	 * @param workspace
	 */
	void freeWorkspace(byte [] workspace){
		ByteArray [] ws;
		if (workspace.length == LibraryConfiguration.CONFIG_TRANSIENT_BIG_WORKSPACE_LENGTH){
			ws = bigWorkspaces;
		} else {
			ws = workspaces;
		}
		for (short i = 0; i < ws.length; i++){
			if (ws[i].content == workspace){
				Util.arrayFillNonAtomic(workspace, Constants.ZERO, (short) workspace.length,(byte) 0);
				ws[i].locked = false;
				ws[i].user = null;
				return;
			}
		}
	}
	
	/**
	 * Allocate an array for use by a specific identifier. This method will return one
	 * transient array per size and caller/identifier object. If it is used in a non-static
	 * method, in most cases "this" as identifier is enough.
	 * 
	 * @param caller
	 * @param big
	 * @return
	 */
	byte [] getWorkspace(Object caller, boolean big){
		ByteArray [] ws = workspaces;
		if (big){
			ws = bigWorkspaces;
		}
				
		for (short i = 0; i < ws.length; i++){
			if (!ws[i].locked){
				ws[i].locked = true;
				ws[i].user = caller;
				return ws[i].content;
			}
		}
		return null;
	}

	void reset() {
		for (short i = 0; i < workspaces.length; i++) {
			workspaces[i].locked = false;
			workspaces[i].user = null;
		}
		for (short i = 0; i < bigWorkspaces.length; i++) {
			bigWorkspaces[i].locked = false;
			bigWorkspaces[i].user = null;
		}
	}
}
