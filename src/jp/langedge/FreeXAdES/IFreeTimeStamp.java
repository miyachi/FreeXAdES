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

	/** エラー定義.
	 */
	// 正常終了はゼロ
	public static final int FTERR_NO_ERROR			= 0;			///< 正常終了（エラーなし）
	// -100～-999は警告
	// -1000番台は一般エラー
	public static final int FTERR_INVALID_ARG		= -1000;		///< 引数エラー

}
