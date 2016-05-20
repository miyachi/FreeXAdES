/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package jp.langedge.FreeXAdES;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 * IFreeXAdESTest : FreeXAdES JUnit test class.
 * @author miyachi
 *
 */
public class IFreeXAdESTest {

    //////////////////////////////////////////////////////////////////////////////
    // 署名対象

	private static String testXml_							// 試験用XML
			= "<MyData xmlns=\"\" Id=\"ROOT\">"
			+ "  <Data Id=\"D1\" price=\"680\">書籍</Data>"
			+ "  <Data price=\"100\" Id=\"D2\">文具(ノート)</Data>"
			+ "</MyData>";
	private static String testData_							// 試験用データ
			= "aaa";
	private static String testXmlFile_ = "MyData.xml";		// 内容はtestXml_と同じ
	private static String testDataFile_ = "aaa.txt";		// 内容はtestData_と同じ

    //////////////////////////////////////////////////////////////////////////////
	// 署名用PKCS#12設定

    private static String pkcs12File_ = "signer.p12";		// PKCS#12ファイル
    private static String pkcs12Pswd_ = "test1";			// PKCS#12パスワード

    //////////////////////////////////////////////////////////////////////////////

	@Test
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

		// 外部Detachedの追加
		System.out.println(" - add Detached.");
		int fxaType = IFreeXAdES.FXAT_FILE_PATH;
		int fxrFlag = IFreeXAdES.FXRF_TRANS_C14N;
		rc = xades.addDetached(testXmlFile_, fxaType, fxrFlag);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 署名実行
		System.out.println(" - exec Sign.");
		String id = typeName;
		int fxsFlag = IFreeXAdES.FXSF_NONE;
		rc = xades.execSign(pkcs12File_, pkcs12Pswd_, fxsFlag, id, null);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 保存
		System.out.println(" - save XAdES.");
		rc = xades.saveXml(typeName + ".xml");
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 終了・解放
		System.out.println(" - finalize.");
		xades.finalize();
	}

    @Test
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
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);
		
		// 内部Detachedの追加
		System.out.println(" - add Detached.");
		int fxaType = IFreeXAdES.FXAT_XML_ID;
		int fxrFlag = IFreeXAdES.FXRF_NONE;
		rc = xades.addDetached("#D1", fxaType, fxrFlag);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 署名実行
		System.out.println(" - exec Sign.");
		String id = typeName;
		int fxsFlag = IFreeXAdES.FXSF_NONE;
		String xpath = "/MyData";
		rc = xades.execSign(pkcs12File_, pkcs12Pswd_, fxsFlag, id, xpath);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 保存
		System.out.println(" - save XAdES.");
		rc = xades.saveXml(typeName + ".xml");
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 終了・解放
		System.out.println(" - finalize.");
		xades.finalize();
	}

	@Test
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
		System.out.println(" - add Enveloping.");
		int fxaType = IFreeXAdES.FXAT_XML_STRING;
		int fxrFlag = IFreeXAdES.FXRF_TRANS_C14N;
		rc = xades.addEnveloping(testXml_, fxaType, fxrFlag);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 署名実行
		System.out.println(" - exec Sign.");
		String id = typeName;
		int fxsFlag = IFreeXAdES.FXSF_NONE;
		rc = xades.execSign(pkcs12File_, pkcs12Pswd_, fxsFlag, id, null);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 保存
		System.out.println(" - save XAdES.");
		rc = xades.saveXml(typeName + ".xml");
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 終了・解放
		System.out.println(" - finalize.");
		xades.finalize();
	}

	@Test
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
		rc = xades.addEnveloping(testDataFile_, fxaType, fxrFlag);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 署名実行
		System.out.println(" - exec Sign.");
		String id = typeName;
		int fxsFlag = IFreeXAdES.FXSF_NONE;
		rc = xades.execSign(pkcs12File_, pkcs12Pswd_, fxsFlag, id, null);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 保存
		System.out.println(" - save XAdES.");
		rc = xades.saveXml(typeName + ".xml");
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 終了・解放
		System.out.println(" - finalize.");
		xades.finalize();
	}

	@Test
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
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// Envelopedの追加
		System.out.println(" - add Enveloped.");
		int fxaType = IFreeXAdES.FXAT_FILE_PATH;	// 未使用
		rc = xades.addEnveloped(null, fxaType, null);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 署名実行
		System.out.println(" - exec Sign.");
		String id = typeName;
		int fxsFlag = IFreeXAdES.FXSF_NONE;
		rc = xades.execSign(pkcs12File_, pkcs12Pswd_, fxsFlag, id, null);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 保存
		System.out.println(" - save XAdES.");
		rc = xades.saveXml(typeName + ".xml");
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 終了・解放
		System.out.println(" - finalize.");
		xades.finalize();
	}

}
