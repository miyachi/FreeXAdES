/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package jp.langedge.FreeXAdES;

import java.io.*;
//import java.math.BigInteger;
import java.util.*;
import java.net.*;

import javax.security.cert.X509Certificate;

//import java.security.*;
//import java.security.cert.*;
//import java.security.cert.Certificate;	// ��������ׂɃC���|�[�g
//import java.text.SimpleDateFormat;

/**
 * FreeTimeStamp : FreeTimeStamp main implement class.
 * @author miyachi
 *
 */
public class FreeTimeStamp implements IFreeTimeStamp {

	private static final int NONCE_SIZE			= 8;	

	private byte[]	token_	= null;
	
	/* �^�C���X�^���v���T�[�o�iTSA�j����擾���� */
	@Override
	public int getFromServer(byte[] hash, String url, String userid, String passwd)
	{

		// nonce�̐���
		byte[] nonce = new byte[NONCE_SIZE];
		new Random().nextBytes(nonce);

		// �^�C���X�^���v���N�G�X�g�̐���
		byte[] req = makeRequest(hash, nonce);
		if(req == null)
			return FTERR_TS_REQ;

		// �^�C���X�^���v�T�[�o�ڑ�
		byte[] resp = httpConnect(url, req, userid, passwd);
		if(resp == null)
			return FTERR_TS_CONNECT;

		// �^�C���X�^���v���X�|���X�̉�́i�^�C���X�^���v�g�[�N���擾�j
		byte[] token = parseResponse(resp, nonce);
		if(token == null)
			return FTERR_TS_RES;

		return setToken(token);
	}

	/* �^�C���X�^���v�g�[�N���̃o�C�i�����Z�b�g���� */
	@Override
	public int setToken(byte[] token)
	{
		token_ = token;
		return FTERR_NO_ERROR;
	}

	/* �^�C���X�^���v�g�[�N�����Z�b�g�ς݂��ǂ�����Ԃ� */
	@Override
	public boolean empty()
	{
		if(token_ == null)
			return false;
		return true;
	}

	/* �^�C���X�^���v�g�[�N���̃^�C���X�^���v�����𕶎���ŕԂ� */
	@Override
	public String getTimeStampDate()
	{
		return null;
	}

	/* �^�C���X�^���v�g�[�N���̑Ώۃn�b�V���l�imessageImprint�j���o�C�i���ŕԂ� */
	@Override
	public byte[] getMsgImprint()
	{
		return null;
	}

	/* �^�C���X�^���v�g�[�N����TSA�ؖ�����Ԃ� */
	@Override
	public X509Certificate getSignerCert()
	{
		return null;
	}

	/* �^�C���X�^���v�g�[�N�����̑S�Ă̏ؖ�����z��ŕԂ� */
	@Override
	public X509Certificate[] getAllCerts()
	{
		return null;
	}

	/* �^�C���X�^���v�g�[�N�����o�C�i���ŕԂ� */
	public byte[] getToken()
	{
		return token_;
	}

	/* �^�C���X�^���v�g�[�N���̏��������؂��Č��ʂ�Ԃ� */
	public int verify()
	{
		return -1;
	}

	/**
	 * �^�C���X�^���v�̃��N�G�X�g���̐���.
	 * <p>
	 * RFC3161/SHA-512�̃��N�G�X�g���i�o�C�i���`���j�𐶐����ĕԂ��B
	 * 
	 * @param hash �^�C���X�^���v�擾�v��������n�b�V���l�iSHA-1=20�o�C�g/SHA-256=32�o�C�g/SHA-512=64�o�C�g�j
	 * @param nonce �i���X�i�����l�j���w��i8�o�C�g�Œ�j
	 * @return �����������N�G�X�g���i�o�C�i���`���j��Ԃ�
	 */
	private byte[] makeRequest (
			byte[] hash,			// 32/64 �o�C�g
			byte[] nonce			// 8 �o�C�g
			)
	{
		byte[] req = null;

		// SHA-256 ���N�G�X�g����`
		byte[] sha256req = {
				0x30, 0x41,							// Request SEQUENCE (65�o�C�g)
				0x02, 0x01, 0x01,					// Version INTEGER (1�o�C�g) value: 1
				0x30, 0x2f,							// MessageImprint SEQUENCE (47�o�C�g)
				0x30, 0x0b,							// AlgorithmOID SEQUENCE (11�o�C�g)
				0x06, 0x09,							// OID (9�o�C�g)
				0x60, (byte)0x86, 0x48, 0x01, 0x65,	// OIDSHA256 value: 2.16.840.1.101.3.4.2.1
				0x03, 0x04, 0x02, 0x01,
				0x04, 0x20,							// Hash OCTET STRING (32�o�C�g)
				0x00, 0x00, 0x00, 0x00, 0x00,		// Placeholders for Hash (+22�o�C�g)
				0x00, 0x00, 0x00, 0x00, 0x00,		// 10
				0x00, 0x00, 0x00, 0x00, 0x00,		// 15
				0x00, 0x00, 0x00, 0x00, 0x00,		// 20
				0x00, 0x00, 0x00, 0x00, 0x00,		// 25
				0x00, 0x00, 0x00, 0x00, 0x00,		// 30
				0x00, 0x00,							// 35
				0x02, 0x08,							// Nonce INTEGER (8�o�C�g)
				0x00, 0x00,	0x00, 0x00, 0x00,		// Placeholders for Nonce (+56�o�C�g)
				0x00, 0x00, 0x00,					// 8
				0x01, 0x01,	(byte)0xff				// RequestCertificate BOOLEAN (1�o�C�g) value: true
		};

		// SHA-512 ���N�G�X�g����`
		byte[] sha512req = {
				0x30, 0x61,							// Request SEQUENCE (97�o�C�g)
				0x02, 0x01, 0x01,					// Version INTEGER (1�o�C�g) value: 1
				0x30, 0x4f,							// MessageImprint SEQUENCE (79�o�C�g)
				0x30, 0x0b,							// AlgorithmOID SEQUENCE (11�o�C�g)
				0x06, 0x09,							// OID (9�o�C�g)
				0x60, (byte)0x86, 0x48, 0x01, 0x65,	// OIDSHA512 value: 2.16.840.1.101.3.4.2.3
				0x03, 0x04, 0x02, 0x03,
				0x04, 0x40,							// Hash OCTET STRING (64�o�C�g)
				0x00, 0x00, 0x00, 0x00, 0x00,		// Placeholders for Hash (+22�o�C�g)
				0x00, 0x00, 0x00, 0x00, 0x00,		// 10
				0x00, 0x00, 0x00, 0x00, 0x00,		// 15
				0x00, 0x00, 0x00, 0x00, 0x00,		// 20
				0x00, 0x00, 0x00, 0x00, 0x00,		// 25
				0x00, 0x00, 0x00, 0x00, 0x00,		// 30
				0x00, 0x00, 0x00, 0x00, 0x00,		// 35
				0x00, 0x00, 0x00, 0x00, 0x00,		// 40
				0x00, 0x00, 0x00, 0x00, 0x00,		// 45
				0x00, 0x00, 0x00, 0x00, 0x00,		// 50
				0x00, 0x00, 0x00, 0x00, 0x00,		// 55
				0x00, 0x00, 0x00, 0x00, 0x00,		// 60
				0x00, 0x00, 0x00, 0x00,				// 64
				0x02, 0x08,							// Nonce INTEGER (8�o�C�g)
				0x00, 0x00,	0x00, 0x00, 0x00,		// Placeholders for Nonce (+88�o�C�g)
				0x00, 0x00, 0x00,					// 8
				0x01, 0x01,	(byte)0xff				// RequestCertificate BOOLEAN (1�o�C�g) value: true
		};

		try {
			if( hash.length == 64 ) {
				// SHA-512
				req = sha512req;
	            System.arraycopy( hash, 0, req, 22, hash.length );			// �n�b�V���l�̃Z�b�g
	            if( nonce.length == NONCE_SIZE )
	            	System.arraycopy( nonce, 0, req, 88, nonce.length );	// �����l�̃Z�b�g
			} else if( hash.length == 32 ) {
				// SHA-256
				req = sha256req;
	            System.arraycopy( hash, 0, req, 22, hash.length );			// �n�b�V���l�̃Z�b�g
	            if( nonce.length == NONCE_SIZE )
	            	System.arraycopy( nonce, 0, req, 56, nonce.length );	// �����l�̃Z�b�g
			} else {
				// ERROR
				return req;
			}
		} catch (Exception e) {
       	    System.out.println(e);
       	    req = null;
		}
		return req;
	}

	/**
	 * �^�C���X�^���v�̃��X�|���X���̉��.
	 * <p>
	 * RFC3161�̃��X�|���X���i�o�C�i���`���j����͂��ă^�C���X�^���v�g�[�N����Ԃ��B
	 * 
	 * @param res �^�C���X�^���v�T�[�o����Ԃ��ꂽ���X�|���X���i�o�C�i���`���j
	 * @param nonce �i���X�i�����l�j���w��i8�o�C�g�j
	 * @return OK�Ȃ�擾�����^�C���X�^���v�g�[�N���i�o�C�i���`���j��Ԃ�
	 */
	private byte[] parseResponse (
			byte[] res,
			byte[] nonce			// 8 �o�C�g
			)
	{
		byte[] tst = null;
		if( res == null )
			return null;
		int res_len = res.length;

		try {
			int len = -1;
			if( res_len < 2 )
				throw new Exception("res too short");

			int idx = 0;
			if( res[idx++] != ( DERTag.SEQUENCE | DERTag.CONSTRUCTED ) )
				throw new Exception("format error 1");	// �ŏ���SEQUENCE�ł͖��������iTST�ł͖����j
			if( idx > res_len )
				throw new Exception("format error 2");

			if( ( res[idx] & DERTag.LEN_EXTEND ) == 0 ) {
				// �������P�o�C�g
				len = res[idx++];
			} else {
				// �����͊g������Ă���
				int sz = res[idx++] & DERTag.LEN_MASK;
				if( idx > res_len )
					throw new Exception("format error 3");
				if( sz > 4 || sz <= 0 )
					throw new Exception("format error 4");
				int sz2 = 0;
				for( int i=sz-1; i>=0; i-- ) {
					sz2 |= (res[idx++] & 0xff) << ( 8 * i );
					if( idx > res_len )
						throw new Exception("format error 5");
				}
				if( sz2 <= 0 || sz2 > res_len - idx )
					throw new Exception("format error 6");
				len = sz2;
			}
			if( idx > res_len )
				throw new Exception("format error 7");

			// Status�̎擾
			int status = 0;
			if( res[idx++] != ( DERTag.SEQUENCE | DERTag.CONSTRUCTED ) )
				throw new Exception("format error 8");	// ����SEQUENCE�ł͖�������
			if( idx > res_len )
				throw new Exception("format error 9");
			if( ( res[idx++] & DERTag.LEN_EXTEND ) != 0 )
				throw new Exception("format error 10");	// �g���͂Ƃ肠�����Ή����Ȃ�
			if( idx > res_len )
				throw new Exception("format error 11");
			if( res[idx++] != DERTag.INTEGER )
				throw new Exception("format error 12");	// Status��INTEGER
			if( idx > res_len )
				throw new Exception("format error 13");
			int isz = res[idx++];						// �T�C�Y
			if( idx > res_len )
				throw new Exception("format error 14");
			for( int j=isz-1; j>=0; j-- ) {
				status |= (res[idx++] & 0xff) << ( 8 * j );
				if( idx > res_len )
					throw new Exception("format error 15");
			}
			if( status != PKIStatus.GRANTED && status != PKIStatus.GRANT_W_MODS )
				throw new Exception("invalid server res status");	// �T�[�o����G���[���Ԃ���

			// �c�肪TST�̂͂�
			len = (int)(res_len - idx);
			if( len > res_len )
				throw new Exception("format error 16");
			tst = new byte[len];
            System.arraycopy( res, idx, tst, 0, len );	// TST�̃R�s�[

		} catch (Exception e) {
       	    System.out.println(e);
	    	System.out.println("���ʉ�̓G���[");
		}
		return tst;
	}

    // ---------------------------------------------------------------------------
    // HTTP�ʐM.
	private byte[] httpConnect (
			String url,
			byte[] send,
			String userid,
			String passwd
			)
	{
		byte[] back = null;

		try
		{

			URL server = new URL(url);
			HttpURLConnection connection = null;

			try
			{
				// �ʐM����
				connection = (HttpURLConnection) server.openConnection();
				connection.setRequestMethod("POST");
				connection.setDoOutput(true);
				connection.setRequestProperty("Content-Type", "application/timestamp-query");
				connection.setUseCaches(false);

				// �^�C���X�^���v���N�G�X�g�̏�������
				OutputStream os = new BufferedOutputStream(connection.getOutputStream());
				os.write(send);
         		os.flush();

				if (connection.getResponseCode() == HttpURLConnection.HTTP_OK)
				{
					BufferedInputStream bis = new BufferedInputStream(connection.getInputStream());
					int nBufSize = 1024 * 100;		// �Ƃ肠�����^�C���X�^���v������100KB�����Ƃ���
					byte[] buf = new byte[nBufSize];
					int len = bis.read(buf);
					bis.close();
					if(len <= 0)
					{
	    				System.out.println("HTTP�����G���[");
					}
					else
					{
						// ���������̂Ń^�C���X�^���v���X�|���X���Ԃ��Ă���͂�
						back = Arrays.copyOf(buf, len);
					}
				}
			}
			finally
			{
				if (connection != null)
				{
				    connection.disconnect();
				}
			}
		} catch (Exception e) {
       	    System.out.println(e);
	    	System.out.println("HTTP�ڑ��G���[");
		}
		return back;
	}

    // ---------------------------------------------------------------------------
    // �^�C���X�^���v���X�|���X�̃X�e�[�^�X.
	public interface PKIStatus {
	    public static final int	GRANTED			= 0;	// TST���܂�
	    public static final int	GRANT_W_MODS	= 1;	// TST���܂݁A�v���C�x�[�g�g�����܂�
	    public static final int	REJECTION		= 2;	// TST���܂܂��A���ۂ��ꂽ
	    public static final int	WAITING			= 3;	// TST���܂܂��A���V�[�g�̂݊܂�
	    public static final int	REVOCAT_WARN	= 4;	// TST���܂܂��ATSU�ؖ����̎������߂�
	    public static final int	REVOCAT_NOTF	= 5;	// TST���܂܂��ATSU�ؖ������������Ă���
	}

    // ---------------------------------------------------------------------------
    // ASN.1/BER(DER)�^�O��`.
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
	    // �N���X�E�\�����t���O
	    public static final byte CONSTRUCTED         = 0x20;
	    public static final byte APPLICATION         = 0x40;
	    public static final byte CONTEXT_SPECIFIC    = (byte)0x80;
	    public static final byte PRIVATE             = (byte)0xc0;
	    // �}�X�N
	    public static final byte TAGNUM_MASK         = 0x1f;
	    public static final byte TAGCONSTFLAG_MASK   = 0x20;
	    public static final byte TAGCLASS_MASK       = (byte)0xC0;
	    // �l��
	    public static final byte LEN_MASK            = 0x1f;
	    public static final byte LEN_EXTEND          = (byte)0x80;
	}

}
