package jp.langedge.FreeXAdES;

// ---------------------------------------------------------------------------
// ASN.1/BER(DER)�I�u�W�F�N�g��͒�`
public class ASN1_OBJ {
	public	byte	head_	= 0;			// �w�b�_�{�̂̃R�s�[	
	public	byte	class_	= 0;			// �N���X���(CLS_TAGTYPE/CLS_CONTEXTSPECIFIC��)
	public	boolean	construct_ = false;		// true�Ȃ�\���^
	public	byte 	tag_	= 0;			// �^�O���(DERTag)
	public	int  	pos_	= 0;			// data���̊J�n�ʒu
	public	int		len_	= 0;			// �l�T�C�Y
	public	byte[]  value_	= null;			// �l�o�C�g�z��
}
