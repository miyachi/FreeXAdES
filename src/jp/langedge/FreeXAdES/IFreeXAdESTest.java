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
    // �����Ώ�

	/** Java6�`Java8��XMLSignature��XML�v�f��Enveloping�𗘗p����ꍇ�̑��݉^�p�����
	 * Enveloping�ΏۂƂȂ�XML�v�f�̖��O��ԓ��̑����̐��K����.NET���ƈقȂ�B
	 * 	�ʖڂȗ�P�F���[�g�v�f����̖��O��Ԃ��Ɛ��K������ xmlns="" ���ȗ������ => testXmlNg1_
	 *	 -> http://xmlconsortium.org/seminar09/100310-11+16-18/data/100316/20100316week-wgsec-3_2-signtool.pdf
	 * 	�ʖڂȗ�2�F���[�g�v�f��Id������t����Ɛ��K������ xmlns �����Ə��Ԃ�����ւ��	 => testXmlNg2_
	 * �� FreeXAdES ToDo: ���O��Enveloping�v�f�𐳋K���v�Z���Đ������v�Z�ł���悤�ɂ���B
	 */

	private static String testXml_							// �����pXML
	= "<MyData xmlns=\"http://eswg.jnsa.org/freexades/MyData\">"
	+ "  <Data Id=\"D1\" price=\"680\">����</Data>"
	+ "  <Data price=\"100\" Id=\"D2\">����(�m�[�g)</Data>"
	+ "</MyData>";

	/*
	private static String testXmlNg1_						// �����pXML(NG:�󖼑O���)
	= "<MyData xmlns=\"\">"
	+ "  <Data Id=\"D1\" price=\"680\">����</Data>"
	+ "  <Data price=\"100\" Id=\"D2\">����(�m�[�g)</Data>"
	+ "</MyData>";
	private static String testXmlNg2_						// �����pXML(NG:���[�g��Id�v�f)
	= "<MyData xmlns=\"http://eswg.jnsa.org/freexades/MyData\" Id=\"Root\">"
	+ "  <Data Id=\"D1\" price=\"680\">����</Data>"
	+ "  <Data price=\"100\" Id=\"D2\">����(�m�[�g)</Data>"
	+ "</MyData>";
	*/

	private static String testData_	= "aaa";				// �����p�f�[�^

	private static String testXmlFile_ = "MyData.xml";		// ���e��testXml_�Ɠ���
	private static String testDataFile_ = "aaa.txt";		// ���e��testData_�Ɠ���
	private static String testXAdESFile_ = "signed.xml";	// ���e��EnvelopingB64.xml�Ɠ���

    //////////////////////////////////////////////////////////////////////////////
	// �����pPKCS#12�ݒ�
	
	/** ���݂�PKCS#12�̂ݑΉ�
	 * JNSA PKI SandBox Project - SandBox CA Repository - �𗘗p
	 *	http://eswg.jnsa.org/sandbox/freeca/
	 */

	// �����p�ݒ�
    private static String pkcs12File_ = "signer.p12";		// PKCS#12�t�@�C��
    private static String pkcs12Pswd_ = "test1";			// PKCS#12�p�X���[�h

    // �^�C���X�^���v�p�ݒ�
    private static String tsUrl_ = "http://eswg.jnsa.org/freetsa";	// TSA�T�[�o
	private static String tsUserid_ = null;		// �I�v�V�����FTSA�T�[�oBasic�F�ؗp���[�UID
	private static String tsPasswd_ = null;		// �I�v�V�����FTSA�T�[�oBasic�F�ؗp�p�X���[�h

    //////////////////////////////////////////////////////////////////////////////

	/* XAdES���� */
	@Test
	public void testFreeXAdES() {
		testDetachedOut();
		testDetachedIn();
		testEnvelopingXml();
		testEnvelopingBase64();
		testEnveloped();
	}

	/* ���̎�������Ăяo�����i���ʁj */
    private void testVerify(String file) {
    	// �t�@�C�����猟��
    	System.out.println(" - verify XAdES.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;

		// �C���X�^���X�����E������
		FreeXAdES xades = new FreeXAdES();
		assertNotNull(xades);

		// �t�@�C���ǂݍ���
		xades.setRootDir("./test/");
		rc = xades.loadXml(file, IFreeXAdES.FXAT_FILE_PATH);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// ����
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
		case IFreeXAdES.FXL_NONE:		// XAdES/XmlDsig����
			System.out.println(" - XAdES Level: no sign");
			break;
		case IFreeXAdES.FXL_XMLDSIG:	// XmlDsig (��XAdES)
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

		// �I���E���
		xades.finalize();
    }
    
//	@Test
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
//		xades.setHashAlg(DigestMethod.SHA1);
		xades.setHashAlg(DigestMethod.SHA512);

		// �O��Detached�̒ǉ�1
		System.out.println(" - add Detached 1.");
		int fxaType = IFreeXAdES.FXAT_FILE_PATH;
		int fxrFlag = IFreeXAdES.FXRF_TRANS_C14N;
		rc = xades.addDetached(testXmlFile_, fxaType, fxrFlag);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �O��Detached�̒ǉ�2
		System.out.println(" - add Detached 2.");
		fxrFlag = IFreeXAdES.FXRF_NONE;
		rc = xades.addDetached(testDataFile_, fxaType, fxrFlag);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �������s
		System.out.println(" - exec Sign.");
		String id = typeName;
		int fxsFlag = IFreeXAdES.FXSF_NONE;
		rc = xades.execSign(pkcs12File_, pkcs12Pswd_, fxsFlag, id, null);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �ۑ�
		System.out.println(" - save XAdES.");
		String file = typeName + ".xml";
		rc = xades.saveXml(file);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �\��
		System.out.println(" - print XAdES.");
		byte[] xml = xades.getXml();
		assertNotNull(xml);
		System.out.println(new String(xml));
		
		// ����
		testVerify(file);
		
		// �I���E���
		System.out.println(" - finalize.");
		xades.finalize();
	}

//	@Test
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
//		rc = xades.loadXml(testXmlNg1_, IFreeXAdES.FXAT_XML_STRING);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);
		
		// ����Detached�̒ǉ�1
		System.out.println(" - add Detached 1.");
		int fxaType = IFreeXAdES.FXAT_XML_ID;
		int fxrFlag = IFreeXAdES.FXRF_NONE;
		rc = xades.addDetached("#D1", fxaType, fxrFlag);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// ����Detached�̒ǉ�2
		System.out.println(" - add Detached 2.");
		rc = xades.addDetached("#D2", fxaType, fxrFlag);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �������s
		System.out.println(" - exec Sign.");
		String id = typeName;
		int fxsFlag = IFreeXAdES.FXSF_NONE;
		// xpath�ŏ�����t����ꏊ���w��\�inull�w��Ȃ烋�[�g�v�f���j
//		String xpath = "/MyData";						// ���O��Ԗ����̏ꍇ����ł��ǂ�
		String xpath = "//*[local-name()='MyData']";	// �v�f���Ŏw��̏ꍇ�͖��O��ԂɈˑ����Ȃ�
		rc = xades.execSign(pkcs12File_, pkcs12Pswd_, fxsFlag, id, xpath);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �ۑ�
		System.out.println(" - save XAdES.");
		String file = typeName + ".xml";
		rc = xades.saveXml(file);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// ����
		testVerify(file);
		
		// �I���E���
		System.out.println(" - finalize.");
		xades.finalize();
	}

//	@Test
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
		System.out.println(" - add Enveloping XML.");
		int fxaType = IFreeXAdES.FXAT_XML_STRING;
		int fxrFlag = IFreeXAdES.FXRF_TRANS_C14N;
		String objId = "TEST";
		rc = xades.addEnveloping(testXml_, fxaType, fxrFlag, objId);
//		rc = xades.addEnveloping(testXmlNg1_, fxaType, fxrFlag);
//		rc = xades.addEnveloping(testXmlNg2_, fxaType, fxrFlag);
//		rc = xades.addEnveloping(testXmlFile_, IFreeXAdES.FXAT_FILE_PATH, fxrFlag);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// Enveloping�ǉ�
		System.out.println(" - add Enveloping DATA.");
		fxaType = IFreeXAdES.FXAT_DATA_STRING;
		fxrFlag = IFreeXAdES.FXRF_NONE;
		objId = null;
		rc = xades.addEnveloping(testData_, fxaType, fxrFlag, objId);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);
		
		// �������s
		System.out.println(" - exec Sign.");
		String id = typeName;
		int fxsFlag = IFreeXAdES.FXSF_NONE;
		rc = xades.execSign(pkcs12File_, pkcs12Pswd_, fxsFlag, id, null);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �ۑ�
		System.out.println(" - save XAdES.");
		String file = typeName + ".xml";
		rc = xades.saveXml(file);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// ����
		testVerify(file);
		
		// �I���E���
		System.out.println(" - finalize.");
		xades.finalize();
	}

//	@Test
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
		String objId = null;
		rc = xades.addEnveloping(testData_, fxaType, fxrFlag, objId);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �������s
		System.out.println(" - exec Sign.");
		String id = typeName;
		int fxsFlag = IFreeXAdES.FXSF_NONE;
		rc = xades.execSign(pkcs12File_, pkcs12Pswd_, fxsFlag, id, null);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �ۑ�
		System.out.println(" - save XAdES.");
		String file = typeName + ".xml";
		rc = xades.saveXml(file);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// ����
		testVerify(file);
		
		// �I���E���
		System.out.println(" - finalize.");
		xades.finalize();
	}

//	@Test
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
//		rc = xades.loadXml(testXmlNg1_, IFreeXAdES.FXAT_XML_STRING);
//		rc = xades.loadXml(testXmlFile_, IFreeXAdES.FXAT_FILE_PATH);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// Enveloped�̒ǉ�
		System.out.println(" - add Enveloped.");
		String target = null;					// loadXml�Ŏw��ς�
		int fxaType = IFreeXAdES.FXAT_NOT_USE;	// ���g�p
		int fxrFlag = IFreeXAdES.FXRF_NONE;
		rc = xades.addEnveloped(target, fxaType, fxrFlag, null);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �������s
		System.out.println(" - exec Sign.");
		String id = typeName;
		int fxsFlag = IFreeXAdES.FXSF_NONE;
		rc = xades.execSign(pkcs12File_, pkcs12Pswd_, fxsFlag, id, null);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �ۑ�
		System.out.println(" - save XAdES.");
		String file = typeName + ".xml";
		rc = xades.saveXml(file);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �\��
		System.out.println(" - print XAdES.");
		byte[] xml = xades.getXml();
		assertNotNull(xml);
		System.out.println(new String(xml));

		// ����
		testVerify(file);
		
		// �I���E���
		System.out.println(" - finalize.");
		xades.finalize();
	}

	@Test
	public void testEsT() {
		// Enveloped�i�����j�̎���
		System.out.println("testEsT call");
		String typeName = "ES-T";
		
		// �C���X�^���X�����E������
		System.out.println(" - create.");
		int rc = IFreeXAdES.FXERR_NO_ERROR;
		FreeXAdES xades = new FreeXAdES();
		assertNotNull(xades);
		xades.setRootDir("./test/");

		// �{��XML�̓ǂݍ���(XML����)
		System.out.println(" - set XAdES from xml.");
		rc = xades.loadXml(testXAdESFile_, IFreeXAdES.FXAT_FILE_PATH);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// ES-T�̒ǉ�
		System.out.println(" - add ES-T.");
		rc = xades.addEsT(tsUrl_, tsUserid_, tsPasswd_, "ES-T-test", null);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �ۑ�
		System.out.println(" - save XAdES.");
		String file = typeName + ".xml";
		rc = xades.saveXml(file);
		assertEquals(rc, IFreeXAdES.FXERR_NO_ERROR);

		// �\��
		System.out.println(" - print XAdES.");
		byte[] xml = xades.getXml();
		assertNotNull(xml);
		System.out.println(new String(xml));

		// ����
		testVerify(file);
		
		// �I���E���
		System.out.println(" - finalize.");
		xades.finalize();
	}

	@Test
	public void testTimeStamp() {
		// Enveloped�i�����j�̎���
		System.out.println("testTimeStamp call");
		
		// �C���X�^���X�����E������
		System.out.println(" - create.");
		int rc = IFreeTimeStamp.FTERR_NO_ERROR;
		FreeTimeStamp timestamp = new FreeTimeStamp();
		assertNotNull(timestamp);

		// �n�b�V���Ώۂ̗p��
		String target = "aaa";
		String hashAlgName = "SHA-256";
		byte[] hash = FreePKI.getHash(target.getBytes(), hashAlgName);
		assertNotNull(hash);
		
		// �^�C���X�^���v�̎擾
		System.out.println(" - get TimeStamp.");
		rc = timestamp.getFromServer(hash, tsUrl_, tsUserid_, tsPasswd_);
		assertEquals(rc, IFreeTimeStamp.FTERR_NO_ERROR);

		// �\��
		System.out.println(" - print TimeStamp info.");
		String info = timestamp.getInfo();
		assertNotNull(info);
		System.out.println(info);
		
		// �I���E���
		System.out.println(" - finalize.");
		timestamp.finalize();
	}
}
