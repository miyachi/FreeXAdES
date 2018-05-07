/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package jp.langedge.FreeXAdES;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * FreePKI : Crypto or PKI utility class.
 * @author miyachi
 *
 */
public class FreePKI {

	/** �n�b�V���l���v�Z����
	 * �w��A���S���Y���ɂ��n�b�V���l�̌v�Z���s��
	 * @param data �n�b�V���v�Z�̑Ώۃf�[�^���o�C�i���Ŏw�肷��
	 * @param hashAlgName �n�b�V���A���S���Y�����w��A"SHA-256", "SHA-384", "SHA-512" ��
	 * @return �n�b�V���l���Ԃ�
	 */
	public static byte[] getHash(byte[] data, String hashAlgName)
	{
		byte[] hash = null;
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance(hashAlgName);
	        md.update(data);
	        hash = md.digest();
		} catch (NoSuchAlgorithmException e) {
			hash = null;
			e.printStackTrace();
		}
        return hash;
	}
	
	/** ASN.1/BER(DER)�I�u�W�F�N�g���
	 * ASN.1/BER(DER)��1�I�u�W�F�N�g����͂��ď���Ԃ�
	 * @param data ASN.1/BER(DER)���o�C�i���Ŏw�肷��
	 * @param pos ��͊J�n�ʒu���w�肷��
	 * @return ASN.1�I�u�W�F�N�g��񂪕Ԃ�
	 */
	public static ASN1_OBJ parseObj(byte[] data, int pos)
	{
		return parseObj(data, pos, false);
	}
	
	/** ASN.1/BER(DER)�I�u�W�F�N�g���
	 * ASN.1/BER(DER)��1�I�u�W�F�N�g����͂��ď���Ԃ�
	 * @param data ASN.1/BER(DER)���o�C�i���Ŏw�肷��
	 * @param pos ��͊J�n�ʒu���w�肷��
	 * @param body false�̏ꍇ�ɂ͒l�̂݁Atrue�Ȃ�I�u�W�F�N�g�S�̂�Ԃ�
	 * @return ASN.1�I�u�W�F�N�g��񂪕Ԃ�
	 */
	public static ASN1_OBJ parseObj(byte[] data, int pos, boolean body)
	{
		if(data == null || data.length < 2)
			return null;
		int start = pos;
		int max = data.length;

		ASN1_OBJ obj = new ASN1_OBJ();
		byte tag_field = data[pos++];
		obj.head_ = tag_field;
		obj.class_ = (byte)(tag_field & DERHead.CLS_MASK);
		obj.tag_   = (byte)(tag_field & DERHead.TAG_MASK);
		if((tag_field & DERHead.CONSTRUCTED) == 0x00)
			obj.construct_ = false;
		else
			obj.construct_ = true;

		if( ( data[pos] & DERHead.LEN_EXTEND ) == 0 ) {
			// �������P�o�C�g
			obj.len_= (int)data[pos++];
		} else {
			// �����͊g������Ă���
			int sz = data[pos++] & DERHead.LEN_MASK;
			if( pos > max )
				return null;
			if( sz > 4 || sz <= 0 )
				return null;
			int sz2 = 0;
			for( int i=sz-1; i>=0; i-- ) {
				sz2 |= (data[pos++] & 0xff) << ( 8 * i );
				if( pos > max )
					return null;
			}
			if( sz2 <= 0 || sz2 > max - pos)
				return null;
			obj.len_ = sz2;
		}
		if(obj.len_ <= 0)
			return null;

		if(body)
		{
			int len = pos - start + obj.len_;
			obj.value_ = new byte[len];
	        System.arraycopy( data, start, obj.value_, 0, len );	// value�̃R�s�[
		}
		else
		{
			obj.value_ = new byte[obj.len_];
	        System.arraycopy( data, pos, obj.value_, 0, obj.len_ );	// value�̃R�s�[
		}
        obj.pos_  = pos + obj.len_;
		return obj;
	}

	/** OID��v�̃`�F�b�N
	 * OID�o�C�i���Ǝw��OID���������ǂ�����Ԃ�
	 * @param value ASN.1/BER(DER)��OID���o�C�i���Ŏw�肷��
	 * @param oid ��r����OID���w�肷��
	 * @return ��v�̏ꍇ�ɂ�true���Ԃ�
	 */
	public static boolean isOID(byte[] value, byte[] oid)
	{
		return isEqual(value, oid);
	}
	
	/** �o�C�g�z���v�̃`�F�b�N
	 * 2�̃o�C�g�z�񂪓������ǂ�����Ԃ�
	 * @param arg1 �o�C�g�z��1���w�肷��
	 * @param arg2 �o�C�g�z��2���w�肷
	 * @return ��v�̏ꍇ�ɂ�true���Ԃ�
	 */
	public static boolean isEqual(byte[] arg1, byte[] arg2)
	{
		if(arg1 == null || arg2 == null)
			return false;
		if(arg1.length != arg2.length)		
			return false;
		if(arg1.length <= 0)		
			return false;
		for(int i=0; i<arg1.length; i++)
		{
			if(arg1[i] != arg2[i])
				return false;
		}
		return true;		
	}
	
	/** �o�C�g�z���HEX������
	 * �o�C�g�z���HEX�����񉻂��ĕԂ�
	 * @param arg �o�C�g�z����w�肷��
	 * @return HEX�����񂪕Ԃ�
	 */
	public static String toHex(byte[] arg)
	{
		if(arg == null || arg.length <= 0)
			return null;
		String hex = "";
		for(int i=0; i<arg.length; i++)
		{
			hex += String.format("%02x", arg[i]);
		}
		return hex;	
	}
	
	// ---------------------------------------------------------------------------
    // OID��`.
	public interface OID {
	    public static final byte[] SIGNED_DATA =		// 1.2.840.113549.1.7.2
	    	{ 0x2a, (byte)0x86, 0x48, (byte)0x86, (byte)0xf7, 0x0d, 0x01, 0x07, 0x02 };
	    public static final byte[] CONTENT_TYPE =		// 1.2.840.113549.1.9.3
	    	{ 0x2a, (byte)0x86, 0x48, (byte)0x86, (byte)0xf7, 0x0d, 0x01, 0x09, 0x03 };
	    public static final byte[] MESSAGE_DIGEST =		// 1.2.840.113549.1.9.4
	    	{ 0x2a, (byte)0x86, 0x48, (byte)0x86, (byte)0xf7, 0x0d, 0x01, 0x09, 0x04 };
	    public static final byte[] SIGNING_TIME =		// 1.2.840.113549.1.9.5
	    	{ 0x2a, (byte)0x86, 0x48, (byte)0x86, (byte)0xf7, 0x0d, 0x01, 0x09, 0x05 };
	    public static final byte[] TIMESTAMP_TOKEN =	// 1.2.840.113549.1.9.16.1.4
	    	{ 0x2a, (byte)0x86, 0x48, (byte)0x86, (byte)0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04 };
	    public static final byte[] SIGNING_CERT =		// 1.2.840.113549.1.9.16.2.12
	    	{ 0x2a, (byte)0x86, 0x48, (byte)0x86, (byte)0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x0c };
	    public static final byte[] RSA_ENC =			// 1.2.840.113549.1.1.1
	    	{ 0x2a, (byte)0x86, 0x48, (byte)0x86, (byte)0xf7, 0x0d, 0x01, 0x01, 0x01 };
	    public static final byte[] SHA_1 =				// 1.3.14.3.2.26
	    	{ 0x2b, 0x0e, 0x03, 0x02, 0x1a };
	    public static final byte[] SHA_256 =			// 2.16.840.1.101.3.4.2.1
	    	{ 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
	    public static final byte[] SHA_384 =			// 2.16.840.1.101.3.4.2.2
	    	{ 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
	    public static final byte[] SHA_512 =			// 2.16.840.1.101.3.4.2.3
	    	{ 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 }; 
	}

	// ---------------------------------------------------------------------------
    // ASN.1/BER(DER)�w�b�_��`.
	public interface DERHead {
	    // �\�����t���O
	    public static final byte CONSTRUCTED         = 0x20;		// 1bit  : 0=�P��^ / 1=�\���^(�l��ASN.1�I�u�W�F�N�g[�^�O�ԍ�+�l�̒���+�l]�ƂȂ��Ă���)
	    // �N���X
	    public static final byte CLS_MASK            = (byte)0xc0;	// 2bits : 00=ISO-TAG / 01=���p(���Ή�) / 10=Context-Specific / 11=�Ǝ�(���Ή�)
	    public static final byte CLS_TAGTYPE         = 0x00;
	    public static final byte CLS_APPLICATION     = 0x40;
	    public static final byte CLS_PRIVATE         = (byte)0xc0;
	    public static final byte CLS_CONTEXTSPECIFIC = (byte)0x80;
	    // �^�O
	    public static final byte TAG_MASK    	     = 0x1f;
	    // �l��
	    public static final byte LEN_MASK            = 0x1f;
	    public static final byte LEN_EXTEND          = (byte)0x80;
	}

	// ---------------------------------------------------------------------------
    // ASN.1/BER(DER)�^�O��`
	public interface DERTag {
		// �^�O
	    public static final byte BOOLEAN             = 0x01;
	    public static final byte INTEGER             = 0x02;
	    public static final byte BIT_STRING          = 0x03;
	    public static final byte OCTET_STRING        = 0x04;
	    public static final byte NULL                = 0x05;
	    public static final byte OBJECT_IDENTIFIER   = 0x06;
	    public static final byte EXTERNAL            = 0x08;
	    public static final byte ENUMERATED          = 0x0a;
	    public static final byte SEQUENCE            = 0x10;
	    public static final byte SET                 = 0x11;
	    public static final byte NUMERIC_STRING      = 0x12;
	    public static final byte PRINTABLE_STRING    = 0x13;
	    public static final byte T61_STRING          = 0x14;
	    public static final byte VIDEOTEX_STRING     = 0x15;
	    public static final byte IA5_STRING          = 0x16;
	    public static final byte UTC_TIME            = 0x17;
	    public static final byte GENERALIZED_TIME    = 0x18;
	    public static final byte GRAPHIC_STRING      = 0x19;
	    public static final byte VISIBLE_STRING      = 0x1a;
	    public static final byte GENERAL_STRING      = 0x1b;
	    public static final byte UNIVERSAL_STRING    = 0x1c;
	    public static final byte BMP_STRING          = 0x1e;
	    public static final byte UTF8_STRING         = 0x0c;
	}

}
