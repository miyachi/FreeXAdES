/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package jp.langedge.FreeXAdES;

import javax.security.cert.X509Certificate;

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

	/** �^�C���X�^���v�g�[�N�����o�C�i���ŕԂ�
	 * �^�C���X�^���v�g�[�N�����o�C�i���ŕԂ��B
	 * @return �Z�b�g�ς݂Ȃ�^�C���X�^���v�g�[�N���o�C�i�����A���Z�b�g�Ȃ� null ��Ԃ�
	 */
	public byte[] getToken();

	/** �^�C���X�^���v�g�[�N���̏��������؂��Č��ʂ�Ԃ�
	 * �^�C���X�^���v�g�[�N���ւ�TSA�ؖ����ɂ�鏐�������؂��Č��ʂ�Ԃ��B
	 * @return �G���[�Ȃ� FTERR_NO_ERROR ���Ԃ�
	 * @return �G���[���� FTERR_NO_ERROR �ȊO���Ԃ�i�G���[�l���Ԃ�j
	 */
	public int verify();

}
