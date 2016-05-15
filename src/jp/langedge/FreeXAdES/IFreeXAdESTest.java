package jp.langedge.FreeXAdES;

import static org.junit.Assert.*;

import org.junit.Test;

public class IFreeXAdESTest {

    //////////////////////////////////////////////////////////////////////////////
    // �����Ώ�

	private static String testXml_ = "<MyData xmlns=\"\"><Data Id=\"D1\">book</Data><Data Id=\"D2\">note</Data></MyData>";
	private static String testData_ = "aaa";
	private static String testFile_ = "test.txt";

    //////////////////////////////////////////////////////////////////////////////
	// �����pPKCS#12�ݒ�

    private static String pkcs12File_ = "LeTest.p12";				// �t�@�C��
    private static String pkcs12Pswd_ = "test";						// �p�X���[�h

    //////////////////////////////////////////////////////////////////////////////

	@Test
	public void testDetachedOut() {
		System.out.println("testDetachedOut call");
		
		// �C���X�^���X�����E������
		System.out.println(" - create.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;
		FreeXAdES xades = new FreeXAdES();

		// �I���E���
		System.out.println(" - finalize.");
		xades.finalize();
	}

    @Test
	public void testDetachedIn() {
		System.out.println("testDetachedIn call");
		
		// �C���X�^���X�����E������
		System.out.println(" - create.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;
		FreeXAdES xades = new FreeXAdES();

		// �I���E���
		System.out.println(" - finalize.");
		xades.finalize();
	}

	@Test
	public void testEnvelopingXml() {
		System.out.println("testEnvelopingXml call");
		
		// �C���X�^���X�����E������
		System.out.println(" - create.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;
		FreeXAdES xades = new FreeXAdES();

		// �I���E���
		System.out.println(" - finalize.");
		xades.finalize();
	}

	@Test
	public void testEnvelopingFile() {
		System.out.println("testEnvelopingFile call");
		
		// �C���X�^���X�����E������
		System.out.println(" - create.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;
		FreeXAdES xades = new FreeXAdES();

		// �I���E���
		System.out.println(" - finalize.");
		xades.finalize();
	}

	@Test
	public void testEnvelopingBase64() {
		System.out.println("testEnvelopingBase64 call");
		
		// �C���X�^���X�����E������
		System.out.println(" - create.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;
		FreeXAdES xades = new FreeXAdES();

		// Enveloping�ǉ�
		System.out.println(" - addEnveloping.");
		rc = xades.addEnveloping(testData_, IFreeXAdES.FXAT_DATA_STRING, IFreeXAdES.FXRF_TRANS_BASE64);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �������s
		System.out.println(" - execSign.");
		String id = "Signature1";
		int fxsFlag = IFreeXAdES.FXSF_NONE;
		rc = xades.execSign(pkcs12File_, pkcs12Pswd_, fxsFlag, id);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �I���E���
		System.out.println(" - finalize.");
		xades.finalize();
	}

	@Test
	public void testEnveloped() {
		System.out.println("testEnveloped call");
		
		// �C���X�^���X�����E������
		System.out.println(" - create.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;
		FreeXAdES xades = new FreeXAdES();

		// �I���E���
		System.out.println(" - finalize.");
		xades.finalize();
	}

}
