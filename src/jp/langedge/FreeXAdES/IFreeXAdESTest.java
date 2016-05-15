package jp.langedge.FreeXAdES;

import static org.junit.Assert.*;

import org.junit.Test;

public class IFreeXAdESTest {

    //////////////////////////////////////////////////////////////////////////////
    // 署名対象

	private static String testXml_ = "<MyData xmlns=\"\"><Data Id=\"D1\">book</Data><Data Id=\"D2\">note</Data></MyData>";
	private static String testData_ = "aaa";
	private static String testFile_ = "test.txt";

    //////////////////////////////////////////////////////////////////////////////
	// 署名用PKCS#12設定

    private static String pkcs12File_ = "LeTest.p12";				// ファイル
    private static String pkcs12Pswd_ = "test";						// パスワード

    //////////////////////////////////////////////////////////////////////////////

	@Test
	public void testDetachedOut() {
		System.out.println("testDetachedOut call");
		
		// インスタンス生成・初期化
		System.out.println(" - create.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;
		FreeXAdES xades = new FreeXAdES();

		// 終了・解放
		System.out.println(" - finalize.");
		xades.finalize();
	}

    @Test
	public void testDetachedIn() {
		System.out.println("testDetachedIn call");
		
		// インスタンス生成・初期化
		System.out.println(" - create.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;
		FreeXAdES xades = new FreeXAdES();

		// 終了・解放
		System.out.println(" - finalize.");
		xades.finalize();
	}

	@Test
	public void testEnvelopingXml() {
		System.out.println("testEnvelopingXml call");
		
		// インスタンス生成・初期化
		System.out.println(" - create.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;
		FreeXAdES xades = new FreeXAdES();

		// 終了・解放
		System.out.println(" - finalize.");
		xades.finalize();
	}

	@Test
	public void testEnvelopingFile() {
		System.out.println("testEnvelopingFile call");
		
		// インスタンス生成・初期化
		System.out.println(" - create.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;
		FreeXAdES xades = new FreeXAdES();

		// 終了・解放
		System.out.println(" - finalize.");
		xades.finalize();
	}

	@Test
	public void testEnvelopingBase64() {
		System.out.println("testEnvelopingBase64 call");
		
		// インスタンス生成・初期化
		System.out.println(" - create.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;
		FreeXAdES xades = new FreeXAdES();

		// Enveloping追加
		System.out.println(" - addEnveloping.");
		rc = xades.addEnveloping(testData_, IFreeXAdES.FXAT_DATA_STRING, IFreeXAdES.FXRF_TRANS_BASE64);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 署名実行
		System.out.println(" - execSign.");
		String id = "Signature1";
		int fxsFlag = IFreeXAdES.FXSF_NONE;
		rc = xades.execSign(pkcs12File_, pkcs12Pswd_, fxsFlag, id);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// 終了・解放
		System.out.println(" - finalize.");
		xades.finalize();
	}

	@Test
	public void testEnveloped() {
		System.out.println("testEnveloped call");
		
		// インスタンス生成・初期化
		System.out.println(" - create.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;
		FreeXAdES xades = new FreeXAdES();

		// 終了・解放
		System.out.println(" - finalize.");
		xades.finalize();
	}

}
