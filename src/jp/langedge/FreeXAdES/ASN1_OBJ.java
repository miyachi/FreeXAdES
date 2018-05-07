/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package jp.langedge.FreeXAdES;

// ---------------------------------------------------------------------------
// ASN.1/BER(DER)�I�u�W�F�N�g��͒�`
public class ASN1_OBJ {
	public	byte	head_	= 0;			///< �w�b�_�{�̂̃R�s�[	
	public	byte	class_	= 0;			///< �N���X���(CLS_TAGTYPE/CLS_CONTEXTSPECIFIC��)
	public	boolean	construct_ = false;		///< true�Ȃ�\���^
	public	byte 	tag_	= 0;			///< �^�O���(DERTag)
	public	int  	pos_	= 0;			///< data���̊J�n�ʒu
	public	int		len_	= 0;			///< �l�T�C�Y
	public	byte[]  value_	= null;			///< �l/�I�u�W�F�N�g�̃o�C�g�z��
}
