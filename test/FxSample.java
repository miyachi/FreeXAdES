/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import javax.xml.crypto.dsig.DigestMethod;
import jp.langedge.FreeXAdES.*;

/**
 * FxSample : FreeXAdES sample class.
 * @author miyachi
 *
 */
public class FxSample {

    //////////////////////////////////////////////////////////////////////////////
    // 署名対象

	private static String testDataFile_ = "aaa.txt";		// 内容は"aaa"

    //////////////////////////////////////////////////////////////////////////////
	// 署名用PKCS#12設定

	// 署名用設定
    private static String pkcs12File_ = "signer.p12";		// PKCS#12ファイル
    private static String pkcs12Pswd_ = "test1";			// PKCS#12パスワード

    // タイムスタンプ用設定
    private static String tsUrl_ = "http://eswg.jnsa.org/freetsa";	// TSAサーバ
	private static String tsUserid_ = null;		// オプション：TSAサーバBasic認証用ユーザID
	private static String tsPasswd_ = null;		// オプション：TSAサーバBasic認証用パスワード

    //////////////////////////////////////////////////////////////////////////////

    // ---------------------------------------------------------------------------
    // メイン関数.
	public static void main(String[] args)
	{
		// 試験XAdES形式の指定 false なら Enveloping形式、true なら Detached形式
		boolean detached = true;

		// インスタンス生成・初期化
		System.out.println(" - create.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;
		FreeXAdES xades = new FreeXAdES();
		if(xades == null)
		{
			System.out.println(" * ERROR: create instance.");
			return;
		}
		xades.setHashAlg(DigestMethod.SHA256);
//		xades.setHashAlg(DigestMethod.SHA512);

		if(detached)
		{
			// 外部Detachedの追加
			System.out.println(" - add Detached.");
			int fxaType = IFreeXAdES.FXAT_FILE_PATH;
			int fxrFlag = IFreeXAdES.FXRF_NONE;
			rc = xades.addDetached(testDataFile_, fxaType, fxrFlag);
		}
		else
		{
			// Enveloping追加
			System.out.println(" - add Enveloping.");
			int fxaType = IFreeXAdES.FXAT_FILE_PATH;
			int fxrFlag = IFreeXAdES.FXRF_TRANS_BASE64;
			String objId = null;
			rc = xades.addEnveloping(testDataFile_, fxaType, fxrFlag, objId);
		}
		if(rc != IFreeXAdES.FXERR_NO_ERROR)
		{
			System.out.println(" * ERROR: add xades target - " + rc);
			return;
		}

		// ES-B(署名)の実行
		System.out.println(" - exec Sign.");
		String id = "FreeXAdES-SAMPLE";
		int fxsFlag = IFreeXAdES.FXSF_NONE;
		rc = xades.execSign(pkcs12File_, pkcs12Pswd_, fxsFlag, id, null);
		if(rc != IFreeXAdES.FXERR_NO_ERROR)
		{
			System.out.println(" * ERROR: add xades target - " + rc);
			return;
		}

		// ES-T(署名タイムスタンプ)の追加
		System.out.println(" - add ES-T.");
		rc = xades.addEsT(tsUrl_, tsUserid_, tsPasswd_, "ES-T-test", null);
		if(rc != IFreeXAdES.FXERR_NO_ERROR)
		{
			System.out.println(" * ERROR: add signature timestamp - " + rc);
			return;
		}

		// 保存
		System.out.println(" - save XAdES-T.");
		String file = "FxSample-T.xml";
		rc = xades.saveXml(file);
		if(rc != IFreeXAdES.FXERR_NO_ERROR)
		{
			System.out.println(" * ERROR: save XAdES file - " + rc);
			return;
		}

		// 検証
		int fxvFlag = IFreeXAdES.FXVF_NONE;
		String vxpath = null;
		rc = xades.verifySign(fxvFlag, vxpath);
		switch(rc) {
		case IFreeXAdES.FXVS_VALID:
			System.out.println(" - exec Verify = [OK]");
			break;
		case IFreeXAdES.FXVS_INVALID:
			System.out.println(" * exec Verify = [INVALID]");
			break;
		case IFreeXAdES.FXVS_NO_SIGN:
			System.out.println(" * exec Verify = [no-sign]");
			break;
		default:
			System.out.println(" * exec Verify = [unknown error] - " + rc);
			break;
		}

		System.out.println(" - done.");
	}


}
