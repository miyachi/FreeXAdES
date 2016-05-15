/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package jp.langedge.FreeXAdES;

import java.io.*;
import java.util.*;
import javax.xml.crypto.*;
import javax.xml.crypto.dom.*;
import javax.xml.crypto.dsig.*;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.*;				// Documentクラス他に利用
import org.xml.sax.SAXException;

/**
 * FreeXAdES main class.
 * @author miyachi
 *
 */
public class FreeXAdES implements IFreeXAdES {

	/** プライベート要素.
	 */
	private Document signDoc_ = null;						// メインドキュメント
	private List<Reference> refs_ = null;
	
	/** エラー対応
	 */
	private	int lastError_ = FXERR_NO_ERROR;				// 最後のエラー値を保持
	public int getLastError() { return lastError_; }		// 最後のエラー値を取得
	public void clearLastError() {							// 最後のエラー値をクリア
		lastError_ = FXERR_NO_ERROR;
	}
	private int setLastError(int fxerr) {					// エラー値セット(内部用)
		lastError_ = fxerr;
		return fxerr;
	}
	
	/* --------------------------------------------------------------------------- */
	/* コンストラクタ等 */
	
	/* コンストラクタ */
	public FreeXAdES() {
		clearLastError();
		this.signDoc_ = null;
		this.refs_ = null;
	}

	/* ファイナライズ */
	public void finalize () {
		clearLastError();
		this.signDoc_ = null;
		this.refs_ = null;		
	}
	
	/* --------------------------------------------------------------------------- */
	/* 署名XMLのセット */
	
	/* 署名XMLをセットする */
	public int setXml(byte[] xml) {
		int rc = FXERR_NO_ERROR;
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
    	ByteArrayInputStream inStream = new ByteArrayInputStream(xml);
		try {
			this.signDoc_ = dbf.newDocumentBuilder().parse(inStream);
		} catch (IOException e) {
			e.printStackTrace();
			rc = setLastError(FXERR_IO_EXCEPTION);
		} catch (Exception e) {	// SAXException, ParserConfigurationException
			e.printStackTrace();
			rc = setLastError(FXERR_EXCEPTION);
		}
		return rc;		
	}
	
	/* 署名XMLの読み込み */
	public int loadXml(String target, int fxaType) {
		int rc = FXERR_NO_ERROR;
		switch(fxaType) {
		case IFreeXAdES.FXAT_FILE_PATH:
			break;
		case IFreeXAdES.FXAT_XML_STRING:
			try {
				byte[] utf8 = target.getBytes("UTF-8");
				rc = setXml(utf8);
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
				rc = setLastError(FXERR_EXCEPTION);
			}
			break;
		default:
			break;
		}
		return rc;
	}

	/* --------------------------------------------------------------------------- */
	/* 署名XMLの取得 */

	/* 署名済みXMLを取得する */
	public byte[] getXml() {
		return null;		
	}

	/* 署名済みXMLをファイル保存する */
	public int saveXml(String path) {
		return FXERR_NO_ERROR;		
	}

	/* 署名済みXMLを文字列で取得する */
	public String saveXml() {
		String xml = null;
		try {
			byte[] utf8 = getXml();
			xml = new String(utf8, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			setLastError(FXERR_EXCEPTION);
		}
		return xml;		
	}

	/* --------------------------------------------------------------------------- */
	/* 署名対象（Reference）の追加 */

	/* Detached(外部)署名対象の追加 */
	public int addDetached(String target, int fxaType, int fxrFlag) {
		int rc = FXERR_NO_ERROR;
		return rc;
	}

	/* Enveloping(内部)署名対象の追加 */
	public int addEnveloping(String target, int fxaType, int fxrFlag) {
		int rc = FXERR_NO_ERROR;
		return rc;
//		return FXERR_NOT_SUPPORT;
	}

	/* Enveloped(内包)署名対象の追加 */
	public int addEnveloped(String target, int fxaType, String xpath) {
		int rc = FXERR_NO_ERROR;
		return rc;
	}

	/* --------------------------------------------------------------------------- */

	/* Reference追加 */
	private int addReference() {
		int rc = FXERR_NO_ERROR;
//		if(this.refs_ == null)
//			this.refs_ = 
		return rc;		
	}

	/* --------------------------------------------------------------------------- */
	/* 署名処理 */

	/* 署名を実行する */
	public int execSign(String p12file, String p12pswd, int fxsFlag, String id) {
		int rc = FXERR_NO_ERROR;
		return rc;
	}

	/* --------------------------------------------------------------------------- */
	/* 検証処理 */

	/* 署名を検証する */
	public byte[] verifySign(int fxvFlag, String xpath) {
		return null;
	}

	/* 検証結果XMLから署名検証結果ステータスを取得 */
	public int getVerifiedStatus(byte[] verifiedXml) {
		int rc = FXERR_NO_ERROR;
		return rc;
	}

	/* 検証結果XMLからエラーを取得 */
	public int[] getVerifiedErrors(byte[] verifiedXml) {
		return null;
	}
	
	/* --------------------------------------------------------------------------- */
}
