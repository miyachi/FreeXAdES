/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package jp.langedge.FreeXAdES;

/**
 * IFreeTimeStamp : FreeTimeStamp main interface class.
 * @author miyachi
 *
 */
public interface IFreeTimeStamp {

	/** �G���[��`.
	 */
	// ����I���̓[��
	public static final int FTERR_NO_ERROR			= 0;			///< ����I���i�G���[�Ȃ��j
	// -100�`-999�͌x��
	// -1000�ԑ�͈�ʃG���[
	public static final int FTERR_INVALID_ARG		= -1000;		///< �����G���[

}
