/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package jp.langedge.FreeXAdES;

import javax.xml.crypto.dsig.DigestMethod;

/**
 * IFreeXAdES : FreeXAdES main interface class.
 * @author miyachi
 *
 */
public interface IFreeXAdES {

	/** エラー定義.
	 */
	// 正常終了はゼロ
	public static final int FXERR_NO_ERROR			= 0;			///< 正常終了（エラーなし）
	// -100～-999は警告
	// -1000番台は一般エラー
	public static final int FXERR_INVALID_ARG		= -1000;		///< 引数エラー
	public static final int FXERR_NOT_INIT			= -1000;		///< 初期化エラー
	public static final int FXERR_FILE_NOTFOUND		= -1010;		///< 指定ファイルが見つからない
	public static final int FXERR_FILE_READ			= -1011;		///< ファイル読み込みエラー
	public static final int FXERR_FILE_WRITE		= -1012;		///< ファイル書き込みエラー
	public static final int FXERR_XML_MARSHAL		= -1020;		///< XMLマーシャリングエラー
	// -2000番台は証明書/鍵のエラー
	public static final int FXERR_PKI_UNK_ALG		= -2000;		///< 不明アルゴリズムが使われた
	public static final int FXERR_PKI_INVALID_ALG	= -2001;		///< アルゴリズムパラメーターが異常
	public static final int FXERR_PKI_CERT			= -2002;		///< 証明書エラー
	public static final int FXERR_PKI_KEY			= -2003;		///< 公開鍵エラー
	public static final int FXERR_PKI_KEY_STORE		= -2004;		///< 鍵ストアエラー
	public static final int FXERR_PKI_SIGN			= -2005;		///< 署名実行時のエラー
	public static final int FXERR_PKI_CONFIG		= -2006;		///< コンフィギュレーションエラー
	// -3000番台はFreeXAdESのエラー
	public static final int FXERR_NO_REFS			= -3000;		///< Reference設定が無い
	// -9000番台は例外等のエラー
	public static final int FXERR_NOT_SUPPORT		= -9000;		///< 現在未サポートの機能
	public static final int FXERR_EXCEPTION			= -9900;		///< 例外発生
	public static final int FXERR_IO_EXCEPTION		= -9901;		///< IO例外発生
	public static final int FXERR_UNK_EXCEPTION		= -9990;		///< 未定義例外発生
	public static final int FXERR_ERROR				= -9999;		///< エラー
	
	/** XAdES namespace 定義.
	 */
	public static String XADES_SIGN_PROP
		= "http://uri.etsi.org/01903#SignedProperties";	// ETSI TS 101 903 SignedProperties
	public static String XADES_V141
		= "http://uri.etsi.org/01903/v1.4.1#";			// ETSI TS 101 903 V1.4.1
	public static String XADES_V132
		= "http://uri.etsi.org/01903/v1.3.2#";			// ETSI TS 101 903 V1.3.2
	
	/** XML署名 SHA-2 定義.
	 */
	public static String SIGN_RSA_SHA256
		= "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";	// RSA-SHA256
	public static String SIGN_RSA_SHA384
		= "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";	// RSA-SHA384
	public static String SIGN_RSA_SHA512
		= "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";	// RSA-SHA512
	public static String HASH_SHA384
		= "http://www.w3.org/2001/04/xmlenc#sha384";			// SHA-384
	
	/* --------------------------------------------------------------------------- */

	/** XAdESのレベル FXA_LEVEL.
	 */
	public static final int	FXL_NONE			= 0;	// XAdES/XmlDsig無し
	public static final int	FXL_XMLDSIG			= 1;	// XmlDsig (非XAdES)
	public static final int	FXL_XAdES_B			= 2;	// XAdES-B (XAdES-BES/EPES)
	public static final int	FXL_XAdES_T			= 3;	// XAdES-T
	public static final int	FXL_XAdES_LT		= 4;	// XAdES-LT (XAdES-X Long)
	public static final int	FXL_XAdES_LTA		= 5;	// XAdES-LTA (XAdES-A)

	/* --------------------------------------------------------------------------- */

	/** argument type.
	 */
	public static final int FXAT_FILE_PATH		= 0;	// 引数targetはファイルパス
	public static final int FXAT_XML_STRING		= 1;	// 引数targetはXML文字列
	public static final int FXAT_XML_ID			= 2;	// 引数targetはXMLのID(1文字目は#)
	public static final int FXAT_DATA_STRING	= 3;	// 引数targetは文字列データ（非XML）

	/** Reference flag.
	 */
	public static final int FXRF_NONE			= 0;
	public static final int FXRF_TRANS_C14N		= 0x00000001;
	public static final int FXRF_TRANS_C14N_EX	= 0x00000002;
	public static final int FXRF_TRANS_BASE64	= 0x00000004;
	public static final int FXRF_TRANS_XPATH	= 0x00000008;

	/* --------------------------------------------------------------------------- */

	/** Signature flag.
	 */
	public static final int FXSF_NONE			= 0;	
	public static final int FXSF_NO_XADES_OBJ	= 0x00000001;	///< XAdESオブジェクトを追加しない(XmlDsigになる)
	public static final int FXSF_NO_SIGN_TIME	= 0x00000002;	///< XAdESオブジェクトのSigningTimeを追加しない

	/* --------------------------------------------------------------------------- */

	/** Verify flag.
	 */
	public static final int FXVF_NONE			= 0;
	public static final int FXVF_NO_CERT_VERIFY	= 0x00000001;	///< 証明書の検証を行わない（改ざんのみチェック）
	public static final int FXVF_NO_VALUES		= 0x00000002;	///< 検証結果XMLに証明書/失効情報の値を含まない

	/* --------------------------------------------------------------------------- */

	/** 署名検証結果ステータス　(※ETSI TS 102 853 v1.1.1準拠)
	 */
	public static final int	FXVS_NO_SIGN			= 0;	// 署名が無い
	public static final int	FXVS_VALID				= 1;	// 検証結果正常
	public static final int	FXVS_INDETERMINATE		= 2;	// 検証結果不明
	public static final int	FXVS_INVALID			= 3;	// 検証結果不正

	/* --------------------------------------------------------------------------- */
	/* 署名XMLのセット */
	
	/** 署名XMLをセットする
	 * 署名時はEnvelopedまたは同一XML内Detachedの時に対象XMLを指定する。
	 * 検証時は検証対象となる署名済みXML(Signature要素を含むXML)を指定する。
	 * @param xml 署名時は対象XML、検証時は署名済みXML、をUTF-8バイナリで指定
	 * @return エラーなし FXERR_NO_ERROR が返る
	 * @return エラーあり FXERR_NO_ERROR 以外が返る（エラー値が返る）
	 */
	public int setXml(byte[] xml);

	/** 署名XMLの読み込み
	 * ファイルや文字列から署名XMLを読み込みセットする
	 * fxaTypeの指定により処理が分かれる。
	 * @param target FXAT_FILE_PATHならファイルパス、FXAT_XML_STRINGならXML文字列、を指定
	 * @param fxaType FXAT_FILE_PATH か FXAT_XML_STRING が指定可能
	 * @return エラーなし FXERR_NO_ERROR が返る
	 * @return エラーあり FXERR_NO_ERROR 以外が返る（エラー値が返る）
	 */
	public int loadXml(String target, int fxaType);

	/* --------------------------------------------------------------------------- */
	/* 署名XMLの取得 */

	/** 署名済みXMLを取得する
	 * 署名済みXMLをUTF-8バイナリ形式で取得する
	 * @return 非null 署名済みXMLが返る
	 * @return null エラー（getLastError()でエラー値取得可能）
	 */
	public byte[] getXml();

	/** 署名済みXMLをファイル保存する
	 * 署名済みXMLを指定されたファイルパスにUTF-8形式で書き込む
	 * @return エラーなし FXERR_NO_ERROR が返る
	 * @return エラーあり FXERR_NO_ERROR 以外が返る（エラー値が返る）
	 */
	public int saveXml(String path);

	/** 署名済みXMLを文字列で取得する
	 * 署名済みXMLを文字列として取得する
	 * @return 非null 署名済みXML文字列が返る
	 * @return null エラー（getLastError()でエラー値取得可能）
	 */
	public String saveXml();

	/* --------------------------------------------------------------------------- */
	/* 署名対象（Reference）の追加 */

	/** Detached(外部)署名対象の追加
	 * Detached形式の署名対象（Reference）を追加する。
	 * fxaTypeの指定により処理が分かれる。
	 * FXAT_FILE_PATH 引数targetはファイルパス、外部ファイルのDetached
	 * FXAT_XML_ID 引数targetはXMLのID(1文字目は#)、内部ファイルのDetached（事前にsetXmlが必要）
	 * @param target FXAT_FILE_PATHならファイルパス、FXAT_XML_IDならXMLのID文字列(1文字目は#)、を指定
	 * @param fxaType　FXAT_FILE_PATH か FXAT_XML_ID が指定可能
	 * @param fxrFlag　FXAT_FILE_PATH　の時に FXRF_TRANS_C14N か FXRF_TRANS_C14N_EX が指定可能
	 * @return エラーなし FXERR_NO_ERROR が返る
	 * @return エラーあり FXERR_NO_ERROR 以外が返る（エラー値が返る）
	 */
	public int addDetached(String target, int fxaType, int fxrFlag);

	/** Enveloping(内部)署名対象の追加
	 * Enveloping形式の署名対象（Reference）と署名対象オブジェクトを追加する。
	 * fxaTypeの指定により処理が分かれる。
	 * FXAT_FILE_PATH 引数targetはファイルパス、外部ファイルから読み込み
	 * FXAT_XML_STRING 引数targetはXML文字列
	 * FXAT_DATA_STRING 引数targetはデータ文字列
	 * @param target FXAT_FILE_PATHならファイルパス、FXAT_XML_STRINGならXML文字列、FXAT_DATA_STRINGなら文字列、を指定
	 * @param fxaType　FXAT_FILE_PATH か FXAT_XML_STRING か FXAT_DATA_STRING が指定可能
	 * @param fxrFlag　FXAT_FILE_PATH か FXAT_DATA_STRING の時に FXRF_TRANS_BASE64 が指定可能
	 * @return エラーなし FXERR_NO_ERROR が返る
	 * @return エラーあり FXERR_NO_ERROR 以外が返る（エラー値が返る）
	 */
	public int addEnveloping(String target, int fxaType, int fxrFlag);

	/** Enveloped(内包)署名対象の追加
	 * Enveloped形式の署名対象（Reference）を追加する。
	 * fxaTypeの指定により処理が分かれる。
	 * FXAT_FILE_PATH 引数targetはファイルパス、外部ファイルから読み込み
	 * FXAT_XML_STRING 引数targetはXML文字列
	 * @param target FXAT_FILE_PATHならファイルパス、FXAT_XML_STRINGならXML文字列を指定、setXml済みならnullを指定
	 * @param fxaType　FXAT_FILE_PATH か FXAT_XML_STRING が指定可能
	 * @param xpath　オプションでXPathによる署名対象が指定可能(指定しない場合はnullを指定可能)
	 * @return エラーなし FXERR_NO_ERROR が返る
	 * @return エラーあり FXERR_NO_ERROR 以外が返る（エラー値が返る）
	 */
	public int addEnveloped(String target, int fxaType, String xpath);

	/* --------------------------------------------------------------------------- */
	/* 署名処理 */

	/** 署名を実行する
	 * 指定されたPKCS#12ファイルにより署名を実行しXAdES-BESを生成する。
	 * @param p12file 署名に利用するPKCS#12ファイルの指定
	 * @param p12pswd 署名に利用するPKCS#12パスワードの指定
	 * @param fxsFlag 署名時のフラグ指定（通常は 0:FXSF_NONE で良い）
	 * @param id Signature要素に付けるIdの指定（nullにて省略可能）
	 * @param xpath 内部Detachedの場合にSignature要素を追加する場所を指定（nullならルート要素下）
	 * @return エラーなし FXERR_NO_ERROR が返る
	 * @return エラーあり FXERR_NO_ERROR 以外が返る（エラー値が返る）
	 */
	public int execSign(String p12file, String p12pswd, int fxsFlag, String id, String xpath);

	/* --------------------------------------------------------------------------- */
	/* 検証処理 */

	/** 署名を検証する
	 * 現在セットされた署名を検証して検証結果XMLを返す。
	 * 署名後かsetXml後に検証可能。
	 * @param fxvFlag 検証時のフラグ指定（通常は 0:FXVF_NONE で良い）
	 * @param xpath 検証対象となるSignature要素をXPathで指定（署名が1つだけならnullにて省略可能）
	 * @return 非null 検証結果XMLのUTF-8バイナリが返る
	 * @return null エラー（getLastError()でエラー値取得可能）
	 * @note 現在署名値のみ検証（FXVF_NO_CERT_VERIFY指定時と同じ） TODO:証明書の検証
	 */
	public byte[] verifySign(int fxvFlag, String xpath);

	/** 検証結果XMLから署名検証結果ステータスを取得
	 * 検証結果XMLのルート要素から署名検証結果ステータスを取得して返す。
	 * @param verifiedXml 検証結果XML（verifySign()の戻り値）
	 * @return 0以上 署名検証結果ステータスが返る
	 * @return 0未満 エラー値が返る
	 */
	public int getVerifiedStatus(byte[] verifiedXml);

	/** 検証結果XMLからエラーを取得
	 * 検証結果XMLのエラーと警告の値を配列で取得する。
	 * @param verifiedXml 検証結果XML（verifySign()の戻り値）
	 * @return 非null 検証結果XML中のエラーと警告の値が配列で返る
	 * @return null エラーは無かった
	 */
	public int[] getVerifiedErrors(byte[] verifiedXml);
	
	/* --------------------------------------------------------------------------- */
	/* 補助 */

	/** URIの基点となるルートディレクトリを指定
	 * URI指定される外部ファイルのDetached等で利用される。
	 * @param rootDir 基点となるルートディレクトリのパスを指定（"/"で終端させる）
	 */
	public void setRootDir(String rootDir);
	
	/** ハッシュ計算/署名計算時に使われるハッシュアルゴリズムを指定
	 * 省略時には DigestMethod.SHA256 が使われる。
	 * @param hashAlg DigestMethod を指定
	 */
	public void setHashAlg(String hashAlg);
	
	/** 最後のエラー値を取得
	 * @return エラーなし FXERR_NO_ERROR が返る
	 * @return エラーあり FXERR_NO_ERROR 以外が返る（エラー値が返る）
	 */
	public int getLastError();

	/** 最後のエラー値をクリア
	 */
	public void clearLastError();

	/* --------------------------------------------------------------------------- */
}
