/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package jp.langedge.FreeXAdES;

// ---------------------------------------------------------------------------
// ASN.1/BER(DER)オブジェクト解析定義
public class ASN1_OBJ {
	public	byte	head_	= 0;			///< ヘッダ本体のコピー	
	public	byte	class_	= 0;			///< クラス情報(CLS_TAGTYPE/CLS_CONTEXTSPECIFIC等)
	public	boolean	construct_ = false;		///< trueなら構造型
	public	byte 	tag_	= 0;			///< タグ種類(DERTag)
	public	int  	pos_	= 0;			///< data中の開始位置
	public	int		len_	= 0;			///< 値サイズ
	public	byte[]  value_	= null;			///< 値/オブジェクトのバイト配列
}
