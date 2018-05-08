/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package jp.langedge.FreeXAdES;

import java.security.cert.X509Certificate;

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
	// -6000番台はFreeTimeStampのエラー
	public static final int FTERR_TS_REQ			= -6000;		///< TSリクエスト生成エラー
	public static final int FTERR_TS_CONNECT		= -6001;		///< HTTP接続によるT取得エラー
	public static final int FTERR_TS_RES			= -6002;		///< TSリクエスト解析エラー
	public static final int FTERR_INVALID_TST		= -6010;		///< TSトークン解析エラー
	public static final int FTERR_INVALID_TSTINFO	= -6011;		///< TSTInfo解析エラー
	public static final int FTERR_INVALID_SIGNINFO	= -6012;		///< SignerInfo解析エラー
	public static final int FTERR_INVALID_TSACERT	= -6013;		///< TSA証明書が見つからないエラー
	public static final int FTERR_TS_DIGEST			= -6100;		///< TSTのダイジェスト不一致エラー
	public static final int FTERR_TSTINFO_DIGEST	= -6101;		///< TSTInfoのダイジェスト不一致エラー

	/* --------------------------------------------------------------------------- */
	/* タイムスタンプ取得 */
	
	/** タイムスタンプをサーバ（TSA）から取得する
	 * ハッシュ値とタイムスタンプサーバのURLを指定してタイムスタンプトークンを取得する。
	 * @param hash タイムスタンプ対象のハッシュ値をバイナリで指定
	 * @param url タイムスタンプサーバのURLを指定
	 * @param userid タイムスタンプサーバでBasic認証が必要な場合にユーザIDを指定、使わない場合はnull指定（オプション）
	 * @param passwd タイムスタンプサーバでBasic認証が必要な場合にパスワードを指定、使わない場合はnull指定（オプション）
	 * @return エラーなし FTERR_NO_ERROR が返る
	 * @return エラーあり FTERR_NO_ERROR 以外が返る（エラー値が返る）
	 */
	public int getFromServer(byte[] hash, String url, String userid, String passwd);

	/** タイムスタンプトークンのバイナリをセットする
	 * タイムスタンプ時刻等を取得する為にタイムスタンプトークンをセットする。
	 * @param token タイムスタンプトークンをバイナリで指定
	 * @return エラーなし FTERR_NO_ERROR が返る
	 * @return エラーあり FTERR_NO_ERROR 以外が返る（エラー値が返る）
	 */
	public int setToken(byte[] token);

	/** タイムスタンプトークンがセット済みかどうかを返す
	 * getFromServer()またはsetToken()によりタイムスタンプトークンがセット済みかどうかを返す。
	 * @return セット済みなら true を、未セットなら false を返す
	 */
	public boolean empty();

	/** タイムスタンプトークンのタイムスタンプ時刻を文字列で返す
	 * タイムスタンプトークン中のタイムスタンプ時刻を返す。
	 * @return セット済みならを、未セットなら null を返す
	 */
	public String getTimeStampDate(); 

	/** タイムスタンプトークンのシリアル番号をバイナリで返す
	 * タイムスタンプトークン中のシリアル番号を返す。
	 * @return セット済みならシリアル番号を、未セットなら null を返す
	 */
	public byte[] getSerial();

	/** タイムスタンプトークンのナンスをバイナリで返す
	 * タイムスタンプトークン中のナンスを返す。
	 * @return セット済みならナンスを、未セットなら null を返す
	 */
	public byte[] getNonce();

	/** タイムスタンプトークンの対象ハッシュ値（messageImprint）のアルゴリズムを返す
	 * タイムスタンプトークン中の対象ハッシュのアルゴリズムを返す。
	 * @return セット済みならアルゴリズム名を、未セットなら null を返す
	 */
	public String getMsgImprintAlg();

	/** タイムスタンプトークンの対象ハッシュ値（messageImprint）をバイナリで返す
	 * タイムスタンプトークン中の対象ハッシュ値を返す。
	 * @return セット済みならハッシュ値を、未セットなら null を返す
	 */
	public byte[] getMsgImprint();

	/** タイムスタンプトークンのTSA証明書を返す
	 * タイムスタンプトークン中のTSA証明書（署名証明書）を返す。
	 * @return セット済みなら証明書を、未セットなら null を返す
	 */
	public X509Certificate getSignerCert();

	/** タイムスタンプトークン中の全ての証明書を配列で返す
	 * タイムスタンプトークンに含まれる全ての証明書を証明書配列で返す。
	 * @return セット済みなら証明書配列を、未セットなら null を返す
	 */
	public X509Certificate[] getAllCerts();

	/** タイムスタンプトークン概要を文字列で返す
	 * タイムスタンプトークンの概要を文字列で返す。
	 * @return セット済みならタイムスタンプトークン情報を、未セットなら null を返す
	 */
	public String getInfo();

	/** タイムスタンプトークンをバイナリで返す
	 * タイムスタンプトークンをバイナリで返す。
	 * @return セット済みならタイムスタンプトークンバイナリを、未セットなら null を返す
	 */
	public byte[] getToken();

	/** タイムスタンプトークンを検証して結果を返す
	 * タイムスタンプトークンへのTSA証明書による署名等を検証して結果を返す。
	 * @param hash タイムスタンプ対象のハッシュ値をバイナリで指定
	 * @return エラーなし FTERR_NO_ERROR が返る
	 * @return エラーあり FTERR_NO_ERROR 以外が返る（エラー値が返る）
	 */
	public int verify(byte[] hash);

}
