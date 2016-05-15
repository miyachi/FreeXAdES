/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package jp.langedge.FreeXAdES;

public interface IFreeXAdES {

	/** �G���[��`.
	 */
	// ����I���̓[��
	public static final int FXERR_NO_ERROR			= 0;			///< �G���[�Ȃ�
	// -100�`-999�͌x��
	// -1000�ԑ�͈�ʃG���[
	public static final int FXERR_INVALID_ARG		= -1000;		///< �����G���[
	// -9000�ԑ�͗�O���̃G���[
	public static final int FXERR_NOT_SUPPORT		= -9000;		///< ���ݖ��T�|�[�g�̋@�\
	public static final int FXERR_EXCEPTION			= -9900;		///< ��O����
	public static final int FXERR_IO_EXCEPTION		= -9901;		///< IO��O����
	public static final int FXERR_UNK_EXCEPTION		= -9990;		///< ����`��O����
	public static final int FXERR_ERROR				= -9999;		///< �G���[
	
	/** XAdES namespace ��`.
	 */
	public static String XADES_SIGN_PROP
		= "http://uri.etsi.org/01903#SignedProperties";	// ETSI TS 101 903 SignedProperties
	public static String XADES_V141
		= "http://uri.etsi.org/01903/v1.4.1#";			// ETSI TS 101 903 V1.4.1
	public static String XADES_V132
		= "http://uri.etsi.org/01903/v1.3.2#";			// ETSI TS 101 903 V1.3.2
	
	/* --------------------------------------------------------------------------- */

	/** XAdES�̃��x�� FXA_LEVEL.
	 */
	public static final int	FXL_NONE			= 0;	// XAdES/XmlDsig����
	public static final int	FXL_XMLDSIG			= 1;	// XmlDsig (��XAdES)
	public static final int	FXL_XAdES_B			= 2;	// XAdES-B (XAdES-BES/EPES)
	public static final int	FXL_XAdES_T			= 3;	// XAdES-T
	public static final int	FXL_XAdES_LT		= 4;	// XAdES-LT (XAdES-X Long)
	public static final int	FXL_XAdES_LTA		= 5;	// XAdES-LTA (XAdES-A)

	/* --------------------------------------------------------------------------- */

	/** argument type.
	 */
	public static final int FXAT_FILE_PATH		= 0;	// ����target�̓t�@�C���p�X
	public static final int FXAT_XML_STRING		= 1;	// ����target��XML������
	public static final int FXAT_XML_ID			= 2;	// ����target��XML��ID(1�����ڂ�#)
	public static final int FXAT_DATA_STRING	= 3;	// ����target�͕�����f�[�^�i��XML�j

	/** Reference flag.
	 */
	public static final int FXRF_NONE			= 0;
	public static final int FXRF_TRANS_C14N		= 0x00000001;
	public static final int FXRF_TRANS_C14N_EX	= 0x00000002;
	public static final int FXRF_TRANS_BASE64	= 0x00000004;
	public static final int FXRF_TRANS_XPATH	= 0x00000008;

	/* --------------------------------------------------------------------------- */

	/** Signature flag.
	 */
	public static final int FXSF_NONE			= 0;	
	public static final int FXSF_NO_XADES_OBJ	= 0x00000001;	///< XAdES�I�u�W�F�N�g��ǉ����Ȃ�(XmlDsig�ɂȂ�)
	public static final int FXSF_NO_SIGN_TIME	= 0x00000002;	///< XAdES�I�u�W�F�N�g��SigningTime��ǉ����Ȃ�

	/* --------------------------------------------------------------------------- */

	/** Verify flag.
	 */
	public static final int FXVF_NONE			= 0;
	public static final int FXVF_NO_CERT_VERIFY	= 0x00000001;	///< �ؖ����̌��؂��s��Ȃ��i������̂݃`�F�b�N�j
	public static final int FXVF_NO_VALUES		= 0x00000002;	///< ���،���XML�ɏؖ���/�������̒l���܂܂Ȃ�

	/* --------------------------------------------------------------------------- */

	/** �������،��ʃX�e�[�^�X�@(��ETSI TS 102 853 v1.1.1����)
	 */
	public static final int	FXVS_NO_SIGN			= 0;	// ����������
	public static final int	FXVS_VALID				= 1;	// ���،��ʐ���
	public static final int	FXVS_INDETERMINATE		= 2;	// ���،��ʕs��
	public static final int	FXVS_INVALID			= 3;	// ���،��ʕs��

	/* --------------------------------------------------------------------------- */
	/* ����XML�̃Z�b�g */
	
	/** ����XML���Z�b�g����
	 * ��������Enveloped�܂��͓���XML��Detached�̎��ɑΏ�XML���w�肷��B
	 * ���؎��͌��ؑΏۂƂȂ鏐���ς�XML(Signature�v�f���܂�XML)���w�肷��B
	 * @param xml �������͑Ώ�XML�A���؎��͏����ς�XML�A��UTF-8�o�C�i���Ŏw��
	 * @return �G���[�Ȃ� FXERR_NO_ERROR ���Ԃ�
	 * @return �G���[���� FXERR_NO_ERROR �ȊO���Ԃ�i�G���[�l���Ԃ�j
	 */
	public int setXml(byte[] xml);

	/** ����XML�̓ǂݍ���
	 * �t�@�C���╶���񂩂珐��XML��ǂݍ��݃Z�b�g����
	 * fxaType�̎w��ɂ�菈�����������B
	 * @param target FXAT_FILE_PATH�Ȃ�t�@�C���p�X�AFXAT_XML_STRING�Ȃ�XML������A���w��
	 * @param fxaType FXAT_FILE_PATH �� FXAT_XML_STRING ���w��\
	 * @return �G���[�Ȃ� FXERR_NO_ERROR ���Ԃ�
	 * @return �G���[���� FXERR_NO_ERROR �ȊO���Ԃ�i�G���[�l���Ԃ�j
	 */
	public int loadXml(String target, int fxaType);

	/* --------------------------------------------------------------------------- */
	/* ����XML�̎擾 */

	/** �����ς�XML���擾����
	 * �����ς�XML��UTF-8�o�C�i���`���Ŏ擾����
	 * @return ��null �����ς�XML���Ԃ�
	 * @return null �G���[�igetLastError()�ŃG���[�l�擾�\�j
	 */
	public byte[] getXml();

	/** �����ς�XML���t�@�C���ۑ�����
	 * �����ς�XML���w�肳�ꂽ�t�@�C���p�X��UTF-8�`���ŏ�������
	 * @return �G���[�Ȃ� FXERR_NO_ERROR ���Ԃ�
	 * @return �G���[���� FXERR_NO_ERROR �ȊO���Ԃ�i�G���[�l���Ԃ�j
	 */
	public int saveXml(String path);

	/** �����ς�XML�𕶎���Ŏ擾����
	 * �����ς�XML�𕶎���Ƃ��Ď擾����
	 * @return ��null �����ς�XML�����񂪕Ԃ�
	 * @return null �G���[�igetLastError()�ŃG���[�l�擾�\�j
	 */
	public String saveXml();

	/* --------------------------------------------------------------------------- */
	/* �����ΏہiReference�j�̒ǉ� */

	/** Detached(�O��)�����Ώۂ̒ǉ�
	 * Detached�`���̏����ΏہiReference�j��ǉ�����B
	 * fxaType�̎w��ɂ�菈�����������B
	 * FXAT_FILE_PATH ����target�̓t�@�C���p�X�A�O���t�@�C����Detached
	 * FXAT_XML_ID ����target��XML��ID(1�����ڂ�#)�A�����t�@�C����Detached�i���O��setXml���K�v�j
	 * @param target FXAT_FILE_PATH�Ȃ�t�@�C���p�X�AFXAT_XML_ID�Ȃ�XML��ID������(1�����ڂ�#)�A���w��
	 * @param fxaType�@FXAT_FILE_PATH �� FXAT_XML_ID ���w��\
	 * @param fxrFlag�@FXAT_FILE_PATH�@�̎��� FXRF_TRANS_C14N �� FXRF_TRANS_C14N_EX ���w��\
	 * @return �G���[�Ȃ� FXERR_NO_ERROR ���Ԃ�
	 * @return �G���[���� FXERR_NO_ERROR �ȊO���Ԃ�i�G���[�l���Ԃ�j
	 */
	public int addDetached(String target, int fxaType, int fxrFlag);

	/** Enveloping(����)�����Ώۂ̒ǉ�
	 * Enveloping�`���̏����ΏہiReference�j�Ə����ΏۃI�u�W�F�N�g��ǉ�����B
	 * fxaType�̎w��ɂ�菈�����������B
	 * FXAT_FILE_PATH ����target�̓t�@�C���p�X�A�O���t�@�C������ǂݍ���
	 * FXAT_XML_STRING ����target��XML������
	 * FXAT_DATA_STRING ����target�̓f�[�^������
	 * @param target FXAT_FILE_PATH�Ȃ�t�@�C���p�X�AFXAT_XML_STRING�Ȃ�XML������AFXAT_DATA_STRING�Ȃ當����A���w��
	 * @param fxaType�@FXAT_FILE_PATH �� FXAT_XML_STRING �� FXAT_DATA_STRING ���w��\
	 * @param fxrFlag�@FXAT_FILE_PATH �� FXAT_DATA_STRING �̎��� FXRF_TRANS_BASE64 ���w��\
	 * @return �G���[�Ȃ� FXERR_NO_ERROR ���Ԃ�
	 * @return �G���[���� FXERR_NO_ERROR �ȊO���Ԃ�i�G���[�l���Ԃ�j
	 */
	public int addEnveloping(String target, int fxaType, int fxrFlag);

	/** Enveloped(����)�����Ώۂ̒ǉ�
	 * Enveloped�`���̏����ΏہiReference�j��ǉ�����B
	 * fxaType�̎w��ɂ�菈�����������B
	 * FXAT_FILE_PATH ����target�̓t�@�C���p�X�A�O���t�@�C������ǂݍ���
	 * FXAT_XML_STRING ����target��XML������
	 * @param target FXAT_FILE_PATH�Ȃ�t�@�C���p�X�AFXAT_XML_STRING�Ȃ�XML��������w��AsetXml�ς݂Ȃ�null���w��
	 * @param fxaType�@FXAT_FILE_PATH �� FXAT_XML_STRING ���w��\
	 * @param xpath�@�I�v�V������XPath�ɂ�鏐���Ώۂ��w��\(�w�肵�Ȃ��ꍇ��null���w��\)
	 * @return �G���[�Ȃ� FXERR_NO_ERROR ���Ԃ�
	 * @return �G���[���� FXERR_NO_ERROR �ȊO���Ԃ�i�G���[�l���Ԃ�j
	 */
	public int addEnveloped(String target, int fxaType, String xpath);

	/* --------------------------------------------------------------------------- */
	/* �������� */

	/** ���������s����
	 * �w�肳�ꂽPKCS#12�t�@�C���ɂ�菐�������s��XAdES-BES�𐶐�����B
	 * @param p12file �����ɗ��p����PKCS#12�t�@�C���̎w��
	 * @param p12pswd �����ɗ��p����PKCS#12�p�X���[�h�̎w��
	 * @param fxsFlag �������̃t���O�w��i�ʏ�� 0:FXSF_NONE �ŗǂ��j
	 * @param id Signature�v�f�ɕt����Id�̎w��inull�ɂďȗ��\�j
	 * @return �G���[�Ȃ� FXERR_NO_ERROR ���Ԃ�
	 * @return �G���[���� FXERR_NO_ERROR �ȊO���Ԃ�i�G���[�l���Ԃ�j
	 */
	public int execSign(String p12file, String p12pswd, int fxsFlag, String id);

	/* --------------------------------------------------------------------------- */
	/* ���؏��� */

	/** ���������؂���
	 * ���݃Z�b�g���ꂽ���������؂��Č��،���XML��Ԃ��B
	 * �����ォsetXml��Ɍ��؉\�B
	 * @param fxvFlag ���؎��̃t���O�w��i�ʏ�� 0:FXVF_NONE �ŗǂ��j
	 * @param xpath ���ؑΏۂƂȂ�Signature�v�f��XPath�Ŏw��i������1�����Ȃ�null�ɂďȗ��\�j
	 * @return ��null ���،���XML��UTF-8�o�C�i�����Ԃ�
	 * @return null �G���[�igetLastError()�ŃG���[�l�擾�\�j
	 * @note ���ݏ����l�̂݌��؁iFXVF_NO_CERT_VERIFY�w�莞�Ɠ����j TODO:�ؖ����̌���
	 */
	public byte[] verifySign(int fxvFlag, String xpath);

	/** ���،���XML���珐�����،��ʃX�e�[�^�X���擾
	 * ���،���XML�̃��[�g�v�f���珐�����،��ʃX�e�[�^�X���擾���ĕԂ��B
	 * @param verifiedXml ���،���XML�iverifySign()�̖߂�l�j
	 * @return 0�ȏ� �������،��ʃX�e�[�^�X���Ԃ�
	 * @return 0���� �G���[�l���Ԃ�
	 */
	public int getVerifiedStatus(byte[] verifiedXml);

	/** ���،���XML����G���[���擾
	 * ���،���XML�̃G���[�ƌx���̒l��z��Ŏ擾����B
	 * @param verifiedXml ���،���XML�iverifySign()�̖߂�l�j
	 * @return ��null ���،���XML���̃G���[�ƌx���̒l���z��ŕԂ�
	 * @return null �G���[�͖�������
	 */
	public int[] getVerifiedErrors(byte[] verifiedXml);
	
	/* --------------------------------------------------------------------------- */
	/* �⏕ */

	/** �Ō�̃G���[�l���擾
	 * @return �G���[�Ȃ� FXERR_NO_ERROR ���Ԃ�
	 * @return �G���[���� FXERR_NO_ERROR �ȊO���Ԃ�i�G���[�l���Ԃ�j
	 */
	public int getLastError();

	/** �Ō�̃G���[�l���N���A
	 */
	public void clearLastError();

	/* --------------------------------------------------------------------------- */
}
