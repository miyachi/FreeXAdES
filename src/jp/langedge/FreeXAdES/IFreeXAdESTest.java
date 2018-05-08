/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package jp.langedge.FreeXAdES;

import static org.junit.Assert.*;

import javax.xml.crypto.dsig.DigestMethod;

import org.junit.Test;

/**
 * IFreeXAdESTest : FreeXAdES JUnit test class.
 * @author miyachi
 *
 */
public class IFreeXAdESTest {

    //////////////////////////////////////////////////////////////////////////////
    // 署名対象

	/** Java6～Java8のXMLSignatureでXML要素のEnvelopingを利用する場合の相互運用性問題
	 * Enveloping対象となるXML要素の名前空間等の属性の正規化が.NET等と異なる。
	 * 	駄目な例１：ルート要素が空の名前空間だと正規化時に xmlns="" が省略される => testXmlNg1_
	 *	 -> http://xmlconsortium.org/seminar09/100310-11+16-18/data/100316/20100316week-wgsec-3_2-signtool.pdf
	 * 	駄目な例2：ルート要素にId属性を付けると正規化時に xmlns 属性と順番が入れ替わる	 => testXmlNg2_
	 * ※ FreeXAdES ToDo: 自前でEnveloping要素を正規化計算して正しく計算できるようにする。
	 */

	private static String testXml_							// 試験用XML
	= "<MyData xmlns=\"http://eswg.jnsa.org/freexades/MyData\">"
	+ "  <Data Id=\"D1\" price=\"680\">書籍</Data>"
	+ "  <Data price=\"100\" Id=\"D2\">文具(ノート)</Data>"
	+ "</MyData>";

	/*
	private static String testXmlNg1_						// 試験用XML(NG:空名前空間)
	= "<MyData xmlns=\"\">"
	+ "  <Data Id=\"D1\" price=\"680\">書籍</Data>"
	+ "  <Data price=\"100\" Id=\"D2\">文具(ノート)</Data>"
	+ "</MyData>";
	private static String testXmlNg2_						// 試験用XML(NG:ルートにId要素)
	= "<MyData xmlns=\"http://eswg.jnsa.org/freexades/MyData\" Id=\"Root\">"
	+ "  <Data Id=\"D1\" price=\"680\">書籍</Data>"
	+ "  <Data price=\"100\" Id=\"D2\">文具(ノート)</Data>"
	+ "</MyData>";
	*/

	private static String testData_	= "aaa";				// 試験用データ

	private static String testXmlFile_ = "MyData.xml";		// 内容はtestXml_と同じ
	private static String testDataFile_ = "aaa.txt";		// 内容はtestData_と同じ
	private static String testXAdESFile_ = "signed.xml";	// 内容はEnvelopingB64.xmlと同じ

    //////////////////////////////////////////////////////////////////////////////
	// 署名用PKCS#12設定
	
	/** 現在はPKCS#12のみ対応
	 * JNSA PKI SandBox Project - SandBox CA Repository - を利用
	 *	http://eswg.jnsa.org/sandbox/freeca/
	 */

	// 署名用設定
    private static String pkcs12File_ = "signer.p12";		// PKCS#12ファイル
    private static String pkcs12Pswd_ = "test1";			// PKCS#12パスワード

    // タイムスタンプ用設定
    private static String tsUrl_ = "http://eswg.jnsa.org/freetsa";	// TSAサーバ
	private static String tsUserid_ = null;		// オプション：TSAサーバBasic認証用ユーザID
	private static String tsPasswd_ = null;		// オプション：TSAサーバBasic認証用パスワード

    //////////////////////////////////////////////////////////////////////////////

	/* XAdES試験 */
	@Test
	public void testFreeXAdES() {
		testDetachedOut();
		testDetachedIn();
		testEnvelopingXml();
		testEnvelopingBase64();
		testEnveloped();
	}

	/* 他の試験から呼び出される（共通） */
    private void testVerify(String file) {
    	// ファイルから検証
    	System.out.println(" - verify XAdES.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;

		// インスタンス生成・初期化
		FreeXAdES xades = new FreeXAdES();
		assertNotNull(xades);

		// ファイル読み込み
		xades.setRootDir("./test/");
		rc = xades.loadXml(file, IFreeXAdES.FXAT_FILE_PATH);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 検証
		int fxvFlag = IFreeXAdES.FXVF_NONE;
		String vxpath = null;
		rc = xades.verifySign(fxvFlag, vxpath);
		switch(rc) {
		case IFreeXAdES.FXVS_VALID:
			System.out.println(" [ verify = OK. ]");
			break;
		case IFreeXAdES.FXVS_INVALID:
			System.out.println(" [ verify = NG! ]");
			break;
		case IFreeXAdES.FXVS_NO_SIGN:
			System.out.println(" [ verify = no-sign. ]");
			break;
		default:
			System.out.println(" [ verify = unknown. ]");
			break;
		}    	
		assertEquals(rc, IFreeXAdES.FXVS_VALID);

		int level = xades.getVerifyLevel();
		switch(level)
		{
		case IFreeXAdES.FXL_NONE:		// XAdES/XmlDsig無し
			System.out.println(" - XAdES Level: no sign");
			break;
		case IFreeXAdES.FXL_XMLDSIG:	// XmlDsig (非XAdES)
			System.out.println(" - XAdES Level: XmlDsig");
			break;
		case IFreeXAdES.FXL_XAdES_B:	// XAdES-B (XAdES-BES/EPES)
			System.out.println(" - XAdES Level: XAdES-B");
			break;
		case IFreeXAdES.FXL_XAdES_T:	// XAdES-T
			System.out.println(" - XAdES Level: XAdES-T");
			break;
		case IFreeXAdES.FXL_XAdES_LT:	// XAdES-LT (XAdES-X Long)
			System.out.println(" - XAdES Level: XAdES-LT");
			break;
		case IFreeXAdES.FXL_XAdES_LTA:	// XAdES-LTA (XAdES-A)
			System.out.println(" - XAdES Level: XAdES-LTA");
			break;
		}

		// 終了・解放
		xades.finalize();
    }
    
//	@Test
    public void testDetachedOut() {
		// 外部ファイルDetached(URI指定)の試験
		System.out.println("testDetachedOut call");
		String typeName = "DetachedOut";
		
		// インスタンス生成・初期化
		System.out.println(" - create.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;
		FreeXAdES xades = new FreeXAdES();
		assertNotNull(xades);
		xades.setRootDir("./test/");
//		xades.setHashAlg(DigestMethod.SHA1);
		xades.setHashAlg(DigestMethod.SHA512);

		// 外部Detachedの追加1
		System.out.println(" - add Detached 1.");
		int fxaType = IFreeXAdES.FXAT_FILE_PATH;
		int fxrFlag = IFreeXAdES.FXRF_TRANS_C14N;
		rc = xades.addDetached(testXmlFile_, fxaType, fxrFlag);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 外部Detachedの追加2
		System.out.println(" - add Detached 2.");
		fxrFlag = IFreeXAdES.FXRF_NONE;
		rc = xades.addDetached(testDataFile_, fxaType, fxrFlag);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 署名実行
		System.out.println(" - exec Sign.");
		String id = typeName;
		int fxsFlag = IFreeXAdES.FXSF_NONE;
		rc = xades.execSign(pkcs12File_, pkcs12Pswd_, fxsFlag, id, null);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 保存
		System.out.println(" - save XAdES.");
		String file = typeName + ".xml";
		rc = xades.saveXml(file);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 表示
		System.out.println(" - print XAdES.");
		byte[] xml = xades.getXml();
		assertNotNull(xml);
		System.out.println(new String(xml));
		
		// 検証
		testVerify(file);
		
		// 終了・解放
		System.out.println(" - finalize.");
		xades.finalize();
	}

//	@Test
	public void testDetachedIn() {
		// ファイル内Detached（Id指定）の試験
		System.out.println("testDetachedIn call");
		String typeName = "DetachedIn";
		
		// インスタンス生成・初期化
		System.out.println(" - create.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;
		FreeXAdES xades = new FreeXAdES();
		assertNotNull(xades);
		xades.setRootDir("./test/");

		// 本体XMLの読み込み(ファイルから)
		System.out.println(" - set body from file.");
		rc = xades.loadXml(testXmlFile_, IFreeXAdES.FXAT_FILE_PATH);
//		rc = xades.loadXml(testXmlNg1_, IFreeXAdES.FXAT_XML_STRING);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);
		
		// 内部Detachedの追加1
		System.out.println(" - add Detached 1.");
		int fxaType = IFreeXAdES.FXAT_XML_ID;
		int fxrFlag = IFreeXAdES.FXRF_NONE;
		rc = xades.addDetached("#D1", fxaType, fxrFlag);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 内部Detachedの追加2
		System.out.println(" - add Detached 2.");
		rc = xades.addDetached("#D2", fxaType, fxrFlag);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 署名実行
		System.out.println(" - exec Sign.");
		String id = typeName;
		int fxsFlag = IFreeXAdES.FXSF_NONE;
		// xpathで署名を付ける場所を指定可能（null指定ならルート要素下）
//		String xpath = "/MyData";						// 名前空間無しの場合これでも良い
		String xpath = "//*[local-name()='MyData']";	// 要素名で指定の場合は名前空間に依存しない
		rc = xades.execSign(pkcs12File_, pkcs12Pswd_, fxsFlag, id, xpath);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 保存
		System.out.println(" - save XAdES.");
		String file = typeName + ".xml";
		rc = xades.saveXml(file);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 検証
		testVerify(file);
		
		// 終了・解放
		System.out.println(" - finalize.");
		xades.finalize();
	}

//	@Test
	public void testEnvelopingXml() {
		// XML形式のEnveloping（内包）の試験
		System.out.println("testEnvelopingXml call");
		String typeName = "EnvelopingXml";
		
		// インスタンス生成・初期化
		System.out.println(" - create.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;
		FreeXAdES xades = new FreeXAdES();
		assertNotNull(xades);
		xades.setRootDir("./test/");

		// Enveloping追加
		System.out.println(" - add Enveloping XML.");
		int fxaType = IFreeXAdES.FXAT_XML_STRING;
		int fxrFlag = IFreeXAdES.FXRF_TRANS_C14N;
		String objId = "TEST";
		rc = xades.addEnveloping(testXml_, fxaType, fxrFlag, objId);
//		rc = xades.addEnveloping(testXmlNg1_, fxaType, fxrFlag);
//		rc = xades.addEnveloping(testXmlNg2_, fxaType, fxrFlag);
//		rc = xades.addEnveloping(testXmlFile_, IFreeXAdES.FXAT_FILE_PATH, fxrFlag);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// Enveloping追加
		System.out.println(" - add Enveloping DATA.");
		fxaType = IFreeXAdES.FXAT_DATA_STRING;
		fxrFlag = IFreeXAdES.FXRF_NONE;
		objId = null;
		rc = xades.addEnveloping(testData_, fxaType, fxrFlag, objId);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);
		
		// 署名実行
		System.out.println(" - exec Sign.");
		String id = typeName;
		int fxsFlag = IFreeXAdES.FXSF_NONE;
		rc = xades.execSign(pkcs12File_, pkcs12Pswd_, fxsFlag, id, null);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 保存
		System.out.println(" - save XAdES.");
		String file = typeName + ".xml";
		rc = xades.saveXml(file);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 検証
		testVerify(file);
		
		// 終了・解放
		System.out.println(" - finalize.");
		xades.finalize();
	}

//	@Test
	public void testEnvelopingBase64() {
		// Base64形式のEnveloping（内包）の試験
		System.out.println("testEnvelopingBase64 call");
		String typeName = "EnvelopingB64";
		
		// インスタンス生成・初期化
		System.out.println(" - create.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;
		FreeXAdES xades = new FreeXAdES();
		assertNotNull(xades);
		xades.setRootDir("./test/");

		// Enveloping追加
		System.out.println(" - add Enveloping.");
		int fxaType = IFreeXAdES.FXAT_DATA_STRING;
		int fxrFlag = IFreeXAdES.FXRF_TRANS_BASE64;
		String objId = null;
		rc = xades.addEnveloping(testData_, fxaType, fxrFlag, objId);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 署名実行
		System.out.println(" - exec Sign.");
		String id = typeName;
		int fxsFlag = IFreeXAdES.FXSF_NONE;
		rc = xades.execSign(pkcs12File_, pkcs12Pswd_, fxsFlag, id, null);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 保存
		System.out.println(" - save XAdES.");
		String file = typeName + ".xml";
		rc = xades.saveXml(file);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 検証
		testVerify(file);
		
		// 終了・解放
		System.out.println(" - finalize.");
		xades.finalize();
	}

//	@Test
	public void testEnveloped() {
		// Enveloped（埋込）の試験
		System.out.println("testEnveloped call");
		String typeName = "Enveloped";
		
		// インスタンス生成・初期化
		System.out.println(" - create.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;
		FreeXAdES xades = new FreeXAdES();
		assertNotNull(xades);
		xades.setRootDir("./test/");

		// 本体XMLの読み込み(XMLから)
		System.out.println(" - set body from xml.");
		rc = xades.loadXml(testXml_, IFreeXAdES.FXAT_XML_STRING);
//		rc = xades.loadXml(testXmlNg1_, IFreeXAdES.FXAT_XML_STRING);
//		rc = xades.loadXml(testXmlFile_, IFreeXAdES.FXAT_FILE_PATH);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// Envelopedの追加
		System.out.println(" - add Enveloped.");
		String target = null;					// loadXmlで指定済み
		int fxaType = IFreeXAdES.FXAT_NOT_USE;	// 未使用
		int fxrFlag = IFreeXAdES.FXRF_NONE;
		rc = xades.addEnveloped(target, fxaType, fxrFlag, null);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 署名実行
		System.out.println(" - exec Sign.");
		String id = typeName;
		int fxsFlag = IFreeXAdES.FXSF_NONE;
		rc = xades.execSign(pkcs12File_, pkcs12Pswd_, fxsFlag, id, null);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 保存
		System.out.println(" - save XAdES.");
		String file = typeName + ".xml";
		rc = xades.saveXml(file);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 表示
		System.out.println(" - print XAdES.");
		byte[] xml = xades.getXml();
		assertNotNull(xml);
		System.out.println(new String(xml));

		// 検証
		testVerify(file);
		
		// 終了・解放
		System.out.println(" - finalize.");
		xades.finalize();
	}

	@Test
	public void testEsT() {
		// Enveloped（埋込）の試験
		System.out.println("testEsT call");
		String typeName = "ES-T";
		
		// インスタンス生成・初期化
		System.out.println(" - create.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;
		FreeXAdES xades = new FreeXAdES();
		assertNotNull(xades);
		xades.setRootDir("./test/");

		// 本体XMLの読み込み(XMLから)
		System.out.println(" - set XAdES from xml.");
		rc = xades.loadXml(testXAdESFile_, IFreeXAdES.FXAT_FILE_PATH);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// ES-Tの追加
		System.out.println(" - add ES-T.");
		rc = xades.addEsT(tsUrl_, tsUserid_, tsPasswd_, "ES-T-test", null);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 保存
		System.out.println(" - save XAdES.");
		String file = typeName + ".xml";
		rc = xades.saveXml(file);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 表示
		System.out.println(" - print XAdES.");
		byte[] xml = xades.getXml();
		assertNotNull(xml);
		System.out.println(new String(xml));

		// 検証
		testVerify(file);
		
		// 終了・解放
		System.out.println(" - finalize.");
		xades.finalize();
	}

	@Test
	public void testTimeStamp() {
		// Enveloped（埋込）の試験
		System.out.println("testTimeStamp call");
		
		// インスタンス生成・初期化
		System.out.println(" - create.");
		int rc = IFreeTimeStamp.FTERR_NO_ERROR;
		FreeTimeStamp timestamp = new FreeTimeStamp();
		assertNotNull(timestamp);

		// ハッシュ対象の用意
		String target = "aaa";
		String hashAlgName = "SHA-256";
		byte[] hash = FreePKI.getHash(target.getBytes(), hashAlgName);
		assertNotNull(hash);
		
		// タイムスタンプの取得
		System.out.println(" - get TimeStamp.");
		rc = timestamp.getFromServer(hash, tsUrl_, tsUserid_, tsPasswd_);
		assertEquals(rc, IFreeTimeStamp.FTERR_NO_ERROR);

		// 表示
		System.out.println(" - print TimeStamp info.");
		String info = timestamp.getInfo();
		assertNotNull(info);
		System.out.println(info);
		
		// 終了・解放
		System.out.println(" - finalize.");
		timestamp.finalize();
	}
}
