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
    // �����Ώ�

	private static String testXml_							// �����pXML
			= "<MyData xmlns=\"\" Id=\"ROOT\">"
			+ "  <Data Id=\"D1\" price=\"680\">����</Data>"
			+ "  <Data price=\"100\" Id=\"D2\">����(�m�[�g)</Data>"
			+ "</MyData>";
	private static String testData_							// �����p�f�[�^
			= "aaa";
	private static String testXmlFile_ = "MyData.xml";		// ���e��testXml_�Ɠ���
	private static String testDataFile_ = "aaa.txt";		// ���e��testData_�Ɠ���

    //////////////////////////////////////////////////////////////////////////////
	// �����pPKCS#12�ݒ�

    private static String pkcs12File_ = "signer.p12";		// PKCS#12�t�@�C��
    private static String pkcs12Pswd_ = "test1";			// PKCS#12�p�X���[�h

    //////////////////////////////////////////////////////////////////////////////

	@Test
	public void testDetachedOut() {
		// �O���t�@�C��Detached(URI�w��)�̎���
		System.out.println("testDetachedOut call");
		String typeName = "DetachedOut";
		
		// �C���X�^���X�����E������
		System.out.println(" - create.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;
		FreeXAdES xades = new FreeXAdES();
		assertNotNull(xades);
		xades.setRootDir("./test/");

		// �O��Detached�̒ǉ�
		System.out.println(" - add Detached.");
		int fxaType = IFreeXAdES.FXAT_FILE_PATH;
		int fxrFlag = IFreeXAdES.FXRF_TRANS_C14N;
		rc = xades.addDetached(testXmlFile_, fxaType, fxrFlag);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �������s
		System.out.println(" - exec Sign.");
		String id = typeName;
		int fxsFlag = IFreeXAdES.FXSF_NONE;
		rc = xades.execSign(pkcs12File_, pkcs12Pswd_, fxsFlag, id, null);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �ۑ�
		System.out.println(" - save XAdES.");
		rc = xades.saveXml(typeName + ".xml");
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �I���E���
		System.out.println(" - finalize.");
		xades.finalize();
	}

    @Test
	public void testDetachedIn() {
		// �t�@�C����Detached�iId�w��j�̎���
		System.out.println("testDetachedIn call");
		String typeName = "DetachedIn";
		
		// �C���X�^���X�����E������
		System.out.println(" - create.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;
		FreeXAdES xades = new FreeXAdES();
		assertNotNull(xades);
		xades.setRootDir("./test/");

		// �{��XML�̓ǂݍ���(�t�@�C������)
		System.out.println(" - set body from file.");
		rc = xades.loadXml(testXmlFile_, IFreeXAdES.FXAT_FILE_PATH);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);
		
		// ����Detached�̒ǉ�
		System.out.println(" - add Detached.");
		int fxaType = IFreeXAdES.FXAT_XML_ID;
		int fxrFlag = IFreeXAdES.FXRF_NONE;
		rc = xades.addDetached("#D1", fxaType, fxrFlag);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �������s
		System.out.println(" - exec Sign.");
		String id = typeName;
		int fxsFlag = IFreeXAdES.FXSF_NONE;
		String xpath = "/MyData";
		rc = xades.execSign(pkcs12File_, pkcs12Pswd_, fxsFlag, id, xpath);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �ۑ�
		System.out.println(" - save XAdES.");
		rc = xades.saveXml(typeName + ".xml");
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �I���E���
		System.out.println(" - finalize.");
		xades.finalize();
	}

	@Test
	public void testEnvelopingXml() {
		// XML�`����Enveloping�i����j�̎���
		System.out.println("testEnvelopingXml call");
		String typeName = "EnvelopingXml";
		
		// �C���X�^���X�����E������
		System.out.println(" - create.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;
		FreeXAdES xades = new FreeXAdES();
		assertNotNull(xades);
		xades.setRootDir("./test/");

		// Enveloping�ǉ�
		System.out.println(" - add Enveloping.");
		int fxaType = IFreeXAdES.FXAT_XML_STRING;
		int fxrFlag = IFreeXAdES.FXRF_TRANS_C14N;
		rc = xades.addEnveloping(testXml_, fxaType, fxrFlag);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �������s
		System.out.println(" - exec Sign.");
		String id = typeName;
		int fxsFlag = IFreeXAdES.FXSF_NONE;
		rc = xades.execSign(pkcs12File_, pkcs12Pswd_, fxsFlag, id, null);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �ۑ�
		System.out.println(" - save XAdES.");
		rc = xades.saveXml(typeName + ".xml");
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �I���E���
		System.out.println(" - finalize.");
		xades.finalize();
	}

	@Test
	public void testEnvelopingBase64() {
		// Base64�`����Enveloping�i����j�̎���
		System.out.println("testEnvelopingBase64 call");
		String typeName = "EnvelopingB64";
		
		// �C���X�^���X�����E������
		System.out.println(" - create.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;
		FreeXAdES xades = new FreeXAdES();
		assertNotNull(xades);
		xades.setRootDir("./test/");

		// Enveloping�ǉ�
		System.out.println(" - add Enveloping.");
		int fxaType = IFreeXAdES.FXAT_DATA_STRING;
		int fxrFlag = IFreeXAdES.FXRF_TRANS_BASE64;
		rc = xades.addEnveloping(testDataFile_, fxaType, fxrFlag);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �������s
		System.out.println(" - exec Sign.");
		String id = typeName;
		int fxsFlag = IFreeXAdES.FXSF_NONE;
		rc = xades.execSign(pkcs12File_, pkcs12Pswd_, fxsFlag, id, null);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �ۑ�
		System.out.println(" - save XAdES.");
		rc = xades.saveXml(typeName + ".xml");
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �I���E���
		System.out.println(" - finalize.");
		xades.finalize();
	}

	@Test
	public void testEnveloped() {
		// Enveloped�i�����j�̎���
		System.out.println("testEnveloped call");
		String typeName = "Enveloped";
		
		// �C���X�^���X�����E������
		System.out.println(" - create.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;
		FreeXAdES xades = new FreeXAdES();
		assertNotNull(xades);
		xades.setRootDir("./test/");

		// �{��XML�̓ǂݍ���(XML����)
		System.out.println(" - set body from xml.");
		rc = xades.loadXml(testXml_, IFreeXAdES.FXAT_XML_STRING);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// Enveloped�̒ǉ�
		System.out.println(" - add Enveloped.");
		int fxaType = IFreeXAdES.FXAT_FILE_PATH;	// ���g�p
		rc = xades.addEnveloped(null, fxaType, null);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �������s
		System.out.println(" - exec Sign.");
		String id = typeName;
		int fxsFlag = IFreeXAdES.FXSF_NONE;
		rc = xades.execSign(pkcs12File_, pkcs12Pswd_, fxsFlag, id, null);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �ۑ�
		System.out.println(" - save XAdES.");
		rc = xades.saveXml(typeName + ".xml");
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �I���E���
		System.out.println(" - finalize.");
		xades.finalize();
	}

}
