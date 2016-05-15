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

import org.w3c.dom.*;				// Document�N���X���ɗ��p
import org.xml.sax.SAXException;

/**
 * FreeXAdES main class.
 * @author miyachi
 *
 */
public class FreeXAdES implements IFreeXAdES {

	/** �v���C�x�[�g�v�f.
	 */
	private Document signDoc_ = null;						// ���C���h�L�������g
	private List<Reference> refs_ = null;
	
	/** �G���[�Ή�
	 */
	private	int lastError_ = FXERR_NO_ERROR;				// �Ō�̃G���[�l��ێ�
	public int getLastError() { return lastError_; }		// �Ō�̃G���[�l���擾
	public void clearLastError() {							// �Ō�̃G���[�l���N���A
		lastError_ = FXERR_NO_ERROR;
	}
	private int setLastError(int fxerr) {					// �G���[�l�Z�b�g(�����p)
		lastError_ = fxerr;
		return fxerr;
	}
	
	/* --------------------------------------------------------------------------- */
	/* �R���X�g���N�^�� */
	
	/* �R���X�g���N�^ */
	public FreeXAdES() {
		clearLastError();
		this.signDoc_ = null;
		this.refs_ = null;
	}

	/* �t�@�C�i���C�Y */
	public void finalize () {
		clearLastError();
		this.signDoc_ = null;
		this.refs_ = null;		
	}
	
	/* --------------------------------------------------------------------------- */
	/* ����XML�̃Z�b�g */
	
	/* ����XML���Z�b�g���� */
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
	
	/* ����XML�̓ǂݍ��� */
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
	/* ����XML�̎擾 */

	/* �����ς�XML���擾���� */
	public byte[] getXml() {
		return null;		
	}

	/* �����ς�XML���t�@�C���ۑ����� */
	public int saveXml(String path) {
		return FXERR_NO_ERROR;		
	}

	/* �����ς�XML�𕶎���Ŏ擾���� */
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
	/* �����ΏہiReference�j�̒ǉ� */

	/* Detached(�O��)�����Ώۂ̒ǉ� */
	public int addDetached(String target, int fxaType, int fxrFlag) {
		int rc = FXERR_NO_ERROR;
		return rc;
	}

	/* Enveloping(����)�����Ώۂ̒ǉ� */
	public int addEnveloping(String target, int fxaType, int fxrFlag) {
		int rc = FXERR_NO_ERROR;
		return rc;
//		return FXERR_NOT_SUPPORT;
	}

	/* Enveloped(����)�����Ώۂ̒ǉ� */
	public int addEnveloped(String target, int fxaType, String xpath) {
		int rc = FXERR_NO_ERROR;
		return rc;
	}

	/* --------------------------------------------------------------------------- */

	/* Reference�ǉ� */
	private int addReference() {
		int rc = FXERR_NO_ERROR;
//		if(this.refs_ == null)
//			this.refs_ = 
		return rc;		
	}

	/* --------------------------------------------------------------------------- */
	/* �������� */

	/* ���������s���� */
	public int execSign(String p12file, String p12pswd, int fxsFlag, String id) {
		int rc = FXERR_NO_ERROR;
		return rc;
	}

	/* --------------------------------------------------------------------------- */
	/* ���؏��� */

	/* ���������؂��� */
	public byte[] verifySign(int fxvFlag, String xpath) {
		return null;
	}

	/* ���،���XML���珐�����،��ʃX�e�[�^�X���擾 */
	public int getVerifiedStatus(byte[] verifiedXml) {
		int rc = FXERR_NO_ERROR;
		return rc;
	}

	/* ���،���XML����G���[���擾 */
	public int[] getVerifiedErrors(byte[] verifiedXml) {
		return null;
	}
	
	/* --------------------------------------------------------------------------- */
}
