/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.jnsa.eswg.FreeXAdES;

import org.w3c.dom.*;				// Documentクラス他に利用

public class FreeXAdES {

	/** XAdESのレベル FXA_LEVEL.
	 */
	public static final int	FXL_NONE			= 0;	// XAdES/XmlDsig無し
	public static final int	FXL_XmlDsig			= 1;	// XmlDsig (非XAdES)
	public static final int	FXL_XAdES_B			= 2;	// XAdES-B (XAdES-BES/EPES)
	public static final int	FXL_XAdES_T			= 3;	// XAdES-T
	public static final int	FXL_XAdES_LT		= 4;	// XAdES-LT (XAdES-X Long)
	public static final int	FXL_XAdES_LTA		= 5;	// XAdES-LTA (XAdES-A)

	/** XAdES namespace 定義.
	 */
	private static String XadesUri
		= "http://uri.etsi.org/01903#";					// ETSI TS 101 903 BASE
	private static String XadesNamespaceUri_141
		= "http://uri.etsi.org/01903/v1.4.1#";			// ETSI TS 101 903 V1.4.1
	private static String XadesNamespaceUri_132
		= "http://uri.etsi.org/01903/v1.3.2#";			// ETSI TS 101 903 V1.3.2
	
	/** 署名検証結果ステータス(※ETSI TS 102 853 v1.1.1準拠) FXA_VERIFY_STATUS.
	 */
	public static final int	FXV_NO_SIGN			= 0;	// 署名が無い
	public static final int	FXV_VALID			= 1;	// 検証結果正常
	public static final int	FXV_INDETERMINATE	= 2;	// 検証結果不明
	public static final int	FXV_INVALID			= 3;	// 検証結果不正

	/** プライベート要素.
	 */
	private Document doc = null;			// メインドキュメント
	
	public FreeXAdES() {
		doc = null;
	}

}
