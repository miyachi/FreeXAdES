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
    // �����Ώ�

	private static String testDataFile_ = "aaa.txt";		// ���e��"aaa"

    //////////////////////////////////////////////////////////////////////////////
	// �����pPKCS#12�ݒ�

	// �����p�ݒ�
    private static String pkcs12File_ = "signer.p12";		// PKCS#12�t�@�C��
    private static String pkcs12Pswd_ = "test1";			// PKCS#12�p�X���[�h

    // �^�C���X�^���v�p�ݒ�
    private static String tsUrl_ = "http://eswg.jnsa.org/freetsa";	// TSA�T�[�o
	private static String tsUserid_ = null;		// �I�v�V�����FTSA�T�[�oBasic�F�ؗp���[�UID
	private static String tsPasswd_ = null;		// �I�v�V�����FTSA�T�[�oBasic�F�ؗp�p�X���[�h

    //////////////////////////////////////////////////////////////////////////////

    // ---------------------------------------------------------------------------
    // ���C���֐�.
	public static void main(String[] args)
	{
		// ����XAdES�`���̎w�� false �Ȃ� Enveloping�`���Atrue �Ȃ� Detached�`��
		boolean detached = true;

		// �C���X�^���X�����E������
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
			// �O��Detached�̒ǉ�
			System.out.println(" - add Detached.");
			int fxaType = IFreeXAdES.FXAT_FILE_PATH;
			int fxrFlag = IFreeXAdES.FXRF_NONE;
			rc = xades.addDetached(testDataFile_, fxaType, fxrFlag);
		}
		else
		{
			// Enveloping�ǉ�
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

		// ES-B(����)�̎��s
		System.out.println(" - exec Sign.");
		String id = "FreeXAdES-SAMPLE";
		int fxsFlag = IFreeXAdES.FXSF_NONE;
		rc = xades.execSign(pkcs12File_, pkcs12Pswd_, fxsFlag, id, null);
		if(rc != IFreeXAdES.FXERR_NO_ERROR)
		{
			System.out.println(" * ERROR: add xades target - " + rc);
			return;
		}

		// ES-T(�����^�C���X�^���v)�̒ǉ�
		System.out.println(" - add ES-T.");
		rc = xades.addEsT(tsUrl_, tsUserid_, tsPasswd_, "ES-T-test", null);
		if(rc != IFreeXAdES.FXERR_NO_ERROR)
		{
			System.out.println(" * ERROR: add signature timestamp - " + rc);
			return;
		}

		// �ۑ�
		System.out.println(" - save XAdES-T.");
		String file = "FxSample-T.xml";
		rc = xades.saveXml(file);
		if(rc != IFreeXAdES.FXERR_NO_ERROR)
		{
			System.out.println(" * ERROR: save XAdES file - " + rc);
			return;
		}

		// ����
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
