/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.jnsa.eswg.FreeXAdES;

import org.w3c.dom.*;				// Document�N���X���ɗ��p

public class FreeXAdES {

	/** XAdES�̃��x�� FXA_LEVEL.
	 */
	public static final int	FXL_NONE			= 0;	// XAdES/XmlDsig����
	public static final int	FXL_XmlDsig			= 1;	// XmlDsig (��XAdES)
	public static final int	FXL_XAdES_B			= 2;	// XAdES-B (XAdES-BES/EPES)
	public static final int	FXL_XAdES_T			= 3;	// XAdES-T
	public static final int	FXL_XAdES_LT		= 4;	// XAdES-LT (XAdES-X Long)
	public static final int	FXL_XAdES_LTA		= 5;	// XAdES-LTA (XAdES-A)

	/** XAdES namespace ��`.
	 */
	private static String XadesUri
		= "http://uri.etsi.org/01903#";					// ETSI TS 101 903 BASE
	private static String XadesNamespaceUri_141
		= "http://uri.etsi.org/01903/v1.4.1#";			// ETSI TS 101 903 V1.4.1
	private static String XadesNamespaceUri_132
		= "http://uri.etsi.org/01903/v1.3.2#";			// ETSI TS 101 903 V1.3.2
	
	/** �������،��ʃX�e�[�^�X(��ETSI TS 102 853 v1.1.1����) FXA_VERIFY_STATUS.
	 */
	public static final int	FXV_NO_SIGN			= 0;	// ����������
	public static final int	FXV_VALID			= 1;	// ���،��ʐ���
	public static final int	FXV_INDETERMINATE	= 2;	// ���،��ʕs��
	public static final int	FXV_INVALID			= 3;	// ���،��ʕs��

	/** �v���C�x�[�g�v�f.
	 */
	private Document doc = null;			// ���C���h�L�������g
	
	public FreeXAdES() {
		doc = null;
	}

}
