/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package jp.langedge.FreeXAdES;

import java.security.cert.X509Certificate;

/**
 * IFreeTimeStamp : FreeTimeStamp main interface class.
 * @author miyachi
 *
 */
public interface IFreeTimeStamp {

	/** �G���[��`.
	 */
	// ����I���̓[��
	public static final int FTERR_NO_ERROR			= 0;			///< ����I���i�G���[�Ȃ��j
	// -100�`-999�͌x��
	// -1000�ԑ�͈�ʃG���[
	public static final int FTERR_INVALID_ARG		= -1000;		///< �����G���[
	// -6000�ԑ��FreeTimeStamp�̃G���[
	public static final int FTERR_TS_REQ			= -6000;		///< TS���N�G�X�g�����G���[
	public static final int FTERR_TS_CONNECT		= -6001;		///< HTTP�ڑ��ɂ��T�擾�G���[
	public static final int FTERR_TS_RES			= -6002;		///< TS���N�G�X�g��̓G���[
	public static final int FTERR_INVALID_TST		= -6010;		///< TS�g�[�N����̓G���[
	public static final int FTERR_INVALID_TSTINFO	= -6011;		///< TSTInfo��̓G���[
	public static final int FTERR_INVALID_SIGNINFO	= -6012;		///< SignerInfo��̓G���[
	public static final int FTERR_INVALID_TSACERT	= -6013;		///< TSA�ؖ�����������Ȃ��G���[
	public static final int FTERR_TS_DIGEST			= -6100;		///< TST�̃_�C�W�F�X�g�s��v�G���[
	public static final int FTERR_TSTINFO_DIGEST	= -6101;		///< TSTInfo�̃_�C�W�F�X�g�s��v�G���[

	/* --------------------------------------------------------------------------- */
	/* �^�C���X�^���v�擾 */
	
	/** �^�C���X�^���v���T�[�o�iTSA�j����擾����
	 * �n�b�V���l�ƃ^�C���X�^���v�T�[�o��URL���w�肵�ă^�C���X�^���v�g�[�N�����擾����B
	 * @param hash �^�C���X�^���v�Ώۂ̃n�b�V���l���o�C�i���Ŏw��
	 * @param url �^�C���X�^���v�T�[�o��URL���w��
	 * @param userid �^�C���X�^���v�T�[�o��Basic�F�؂��K�v�ȏꍇ�Ƀ��[�UID���w��A�g��Ȃ��ꍇ��null�w��i�I�v�V�����j
	 * @param passwd �^�C���X�^���v�T�[�o��Basic�F�؂��K�v�ȏꍇ�Ƀp�X���[�h���w��A�g��Ȃ��ꍇ��null�w��i�I�v�V�����j
	 * @return �G���[�Ȃ� FTERR_NO_ERROR ���Ԃ�
	 * @return �G���[���� FTERR_NO_ERROR �ȊO���Ԃ�i�G���[�l���Ԃ�j
	 */
	public int getFromServer(byte[] hash, String url, String userid, String passwd);

	/** �^�C���X�^���v�g�[�N���̃o�C�i�����Z�b�g����
	 * �^�C���X�^���v���������擾����ׂɃ^�C���X�^���v�g�[�N�����Z�b�g����B
	 * @param token �^�C���X�^���v�g�[�N�����o�C�i���Ŏw��
	 * @return �G���[�Ȃ� FTERR_NO_ERROR ���Ԃ�
	 * @return �G���[���� FTERR_NO_ERROR �ȊO���Ԃ�i�G���[�l���Ԃ�j
	 */
	public int setToken(byte[] token);

	/** �^�C���X�^���v�g�[�N�����Z�b�g�ς݂��ǂ�����Ԃ�
	 * getFromServer()�܂���setToken()�ɂ��^�C���X�^���v�g�[�N�����Z�b�g�ς݂��ǂ�����Ԃ��B
	 * @return �Z�b�g�ς݂Ȃ� true ���A���Z�b�g�Ȃ� false ��Ԃ�
	 */
	public boolean empty();

	/** �^�C���X�^���v�g�[�N���̃^�C���X�^���v�����𕶎���ŕԂ�
	 * �^�C���X�^���v�g�[�N�����̃^�C���X�^���v������Ԃ��B
	 * @return �Z�b�g�ς݂Ȃ���A���Z�b�g�Ȃ� null ��Ԃ�
	 */
	public String getTimeStampDate(); 

	/** �^�C���X�^���v�g�[�N���̃V���A���ԍ����o�C�i���ŕԂ�
	 * �^�C���X�^���v�g�[�N�����̃V���A���ԍ���Ԃ��B
	 * @return �Z�b�g�ς݂Ȃ�V���A���ԍ����A���Z�b�g�Ȃ� null ��Ԃ�
	 */
	public byte[] getSerial();

	/** �^�C���X�^���v�g�[�N���̃i���X���o�C�i���ŕԂ�
	 * �^�C���X�^���v�g�[�N�����̃i���X��Ԃ��B
	 * @return �Z�b�g�ς݂Ȃ�i���X���A���Z�b�g�Ȃ� null ��Ԃ�
	 */
	public byte[] getNonce();

	/** �^�C���X�^���v�g�[�N���̑Ώۃn�b�V���l�imessageImprint�j�̃A���S���Y����Ԃ�
	 * �^�C���X�^���v�g�[�N�����̑Ώۃn�b�V���̃A���S���Y����Ԃ��B
	 * @return �Z�b�g�ς݂Ȃ�A���S���Y�������A���Z�b�g�Ȃ� null ��Ԃ�
	 */
	public String getMsgImprintAlg();

	/** �^�C���X�^���v�g�[�N���̑Ώۃn�b�V���l�imessageImprint�j���o�C�i���ŕԂ�
	 * �^�C���X�^���v�g�[�N�����̑Ώۃn�b�V���l��Ԃ��B
	 * @return �Z�b�g�ς݂Ȃ�n�b�V���l���A���Z�b�g�Ȃ� null ��Ԃ�
	 */
	public byte[] getMsgImprint();

	/** �^�C���X�^���v�g�[�N����TSA�ؖ�����Ԃ�
	 * �^�C���X�^���v�g�[�N������TSA�ؖ����i�����ؖ����j��Ԃ��B
	 * @return �Z�b�g�ς݂Ȃ�ؖ������A���Z�b�g�Ȃ� null ��Ԃ�
	 */
	public X509Certificate getSignerCert();

	/** �^�C���X�^���v�g�[�N�����̑S�Ă̏ؖ�����z��ŕԂ�
	 * �^�C���X�^���v�g�[�N���Ɋ܂܂��S�Ă̏ؖ������ؖ����z��ŕԂ��B
	 * @return �Z�b�g�ς݂Ȃ�ؖ����z����A���Z�b�g�Ȃ� null ��Ԃ�
	 */
	public X509Certificate[] getAllCerts();

	/** �^�C���X�^���v�g�[�N���T�v�𕶎���ŕԂ�
	 * �^�C���X�^���v�g�[�N���̊T�v�𕶎���ŕԂ��B
	 * @return �Z�b�g�ς݂Ȃ�^�C���X�^���v�g�[�N�������A���Z�b�g�Ȃ� null ��Ԃ�
	 */
	public String getInfo();

	/** �^�C���X�^���v�g�[�N�����o�C�i���ŕԂ�
	 * �^�C���X�^���v�g�[�N�����o�C�i���ŕԂ��B
	 * @return �Z�b�g�ς݂Ȃ�^�C���X�^���v�g�[�N���o�C�i�����A���Z�b�g�Ȃ� null ��Ԃ�
	 */
	public byte[] getToken();

	/** �^�C���X�^���v�g�[�N�������؂��Č��ʂ�Ԃ�
	 * �^�C���X�^���v�g�[�N���ւ�TSA�ؖ����ɂ�鏐���������؂��Č��ʂ�Ԃ��B
	 * @param hash �^�C���X�^���v�Ώۂ̃n�b�V���l���o�C�i���Ŏw��
	 * @return �G���[�Ȃ� FTERR_NO_ERROR ���Ԃ�
	 * @return �G���[���� FTERR_NO_ERROR �ȊO���Ԃ�i�G���[�l���Ԃ�j
	 */
	public int verify(byte[] hash);

}
