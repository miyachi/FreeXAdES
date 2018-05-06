/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package jp.langedge.FreeXAdES;

import java.io.*;
import java.util.*;
import java.net.*;

import javax.security.cert.X509Certificate;

import jp.langedge.FreeXAdES.FreePKI;
import jp.langedge.FreeXAdES.FreePKI.DERHead;
import jp.langedge.FreeXAdES.FreePKI.DERTag;

/**
 * FreeTimeStamp : FreeTimeStamp main implement class.
 * @author miyachi
 *
 */
public class FreeTimeStamp implements IFreeTimeStamp {

	private static final int NONCE_SIZE			= 8;	

	private byte[]	token_	= null;
	private byte[]	msgImprint_ = null;
	private String	timeStampDate_ = null;
	private X509Certificate		tsaCert_ = null;
	private X509Certificate[]	certs_ = null;
	
	/* �R���X�g���N�^ */
	public FreeTimeStamp() {
		clear();
	}

	/* �R���X�g���N�^ */
	public FreeTimeStamp(byte[] token) {
		clear();
		setToken(token);
	}

	/* �t�@�C�i���C�Y */
	public void finalize () {
		clear();
	}

	/* �N���A */
	private void clear() {
		token_ = null;
	}

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
		if(token == null)
		{
			// �N���A
			clear();
			return FTERR_NO_ERROR;
		}

		// ���
		int rc = parseToken(token);
		if(rc == FTERR_NO_ERROR)
		{
			// ��͐���
			token_ = token;
		}
		else
		{
			// �G���[�N���A
			clear();
		}
		return rc;
	}

	/* �^�C���X�^���v�g�[�N�����Z�b�g�ς݂��ǂ�����Ԃ� */
	@Override
	public boolean empty()
	{
		if(token_ == null)
			return true;
		return false;
	}

	/* �^�C���X�^���v�g�[�N���̃^�C���X�^���v�����𕶎���ŕԂ� */
	@Override
	public String getTimeStampDate()
	{
		if(empty())
			return null;
		return timeStampDate_;
	}

	/* �^�C���X�^���v�g�[�N���̑Ώۃn�b�V���l�imessageImprint�j���o�C�i���ŕԂ� */
	@Override
	public byte[] getMsgImprint()
	{
		if(empty())
			return null;
		return msgImprint_;
	}

	/* �^�C���X�^���v�g�[�N����TSA�ؖ�����Ԃ� */
	@Override
	public X509Certificate getSignerCert()
	{
		if(empty())
			return null;
		return tsaCert_;
	}

	/* �^�C���X�^���v�g�[�N�����̑S�Ă̏ؖ�����z��ŕԂ� */
	@Override
	public X509Certificate[] getAllCerts()
	{
		if(empty())
			return null;
		return certs_;
	}

	/* �^�C���X�^���v�g�[�N���T�v�𕶎���ŕԂ� */
	@Override
	public String getInfo()
	{
		if(empty())
			return null;
		return "ToDo ToDo.";
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
		int status = 0;
		byte[] tst = null;
		if( res == null )
			return null;
		int res_len = res.length;

		try {
			int len = -1;
			if( res_len < 2 )
				throw new Exception("res too short");

			ASN1_OBJ tsr, obj, obj2;
			tsr = FreePKI.parseObj(res, 0);
			if(tsr == null)
				throw new Exception("TSResponse parse error");
			if(tsr.tag_ != DERTag.SEQUENCE || tsr.construct_ != true)
				throw new Exception("TSResponse format error 1");
			// TSResponse�̉��
			obj = FreePKI.parseObj(tsr.value_, 0);
			if(obj == null)
				throw new Exception("TSResponse format error 2");
			if(obj.tag_ != DERTag.SEQUENCE || obj.construct_ != true)
				throw new Exception("TSResponse format error 3");
			// status�̎擾
			obj2 = FreePKI.parseObj(obj.value_, 0);
			if(obj2 == null)
				throw new Exception("TSResponse format error 4");
			if(obj2.tag_ != DERTag.INTEGER)
				throw new Exception("TSResponse format error 5");
			for( int j=obj2.len_-1; j>=0; j-- ) {
				status |= (obj2.value_[j] & 0xff) << ( 8 * j );
			}
			if( status != TSResStatus.GRANTED && status != TSResStatus.GRANT_W_MODS )
				throw new Exception("invalid server res status = " + status);	// �T�[�o����G���[���Ԃ���

			// �c�肪TST
			len = tsr.len_ - obj.pos_;
			if( len <= 0 )
				throw new Exception("format error 16");
			tst = new byte[len];
            System.arraycopy( tsr.value_, obj.pos_, tst, 0, len );	// TST�̃R�s�[

		} catch (Exception e) {
       	    System.out.println(e);
//	    	System.out.println("���ʉ�̓G���[");
		}
		return tst;
	}
	
	/* �^�C���X�^���v�g�[�N���̉�� */
	private int parseToken (byte[] token)
	{
		if(token == null)
			return FTERR_INVALID_TST;

		try {
			ASN1_OBJ tst, obj, obj2;
			tst = FreePKI.parseObj(token, 0);
			if(tst == null)
				throw new Exception("TimeStampToken parse error");
			if(tst.tag_ != DERTag.SEQUENCE || tst.construct_ != true)
				throw new Exception("TimeStampToken format error 1");
			obj = FreePKI.parseObj(tst.value_, 0);
			if(obj == null)
				throw new Exception("TimeStampToken format error 2");
			if(obj.tag_ != DERTag.OBJECT_IDENTIFIER || obj.construct_ != false)
				throw new Exception("TimeStampToken format error 3");
			obj = FreePKI.parseObj(tst.value_, obj.pos_);
			if(obj == null)
				throw new Exception("TimeStampToken format error 2");
			if(obj.class_ != DERHead.CLS_CONTEXTSPECIFIC || obj.tag_ != 0 || obj.construct_ != true)
				throw new Exception("TimeStampToken format error 3");
			obj = FreePKI.parseObj(obj.value_, 0);
			if(obj == null)
				throw new Exception("TimeStampToken format error 2");
			if(obj.tag_ != DERTag.SEQUENCE || obj.construct_ != true)
				throw new Exception("TimeStampToken format error 1");
			obj2 = FreePKI.parseObj(obj.value_, 0);
			if(obj2 == null)
				throw new Exception("TimeStampToken format error 2");
			if(obj2.tag_ != DERTag.INTEGER || obj2.construct_ != false)
				throw new Exception("TimeStampToken format error 3");
			obj2 = FreePKI.parseObj(obj.value_, obj2.pos_);
			if(obj2 == null)
				throw new Exception("TimeStampToken format error 2");

		} catch (Exception e) {
       	    System.out.println(e);
//	    	System.out.println("���ʉ�̓G���[");
		}

		return FTERR_NO_ERROR;
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
	public interface TSResStatus {
	    public static final int	GRANTED			= 0;	// TST���܂�
	    public static final int	GRANT_W_MODS	= 1;	// TST���܂݁A�v���C�x�[�g�g�����܂�
	    public static final int	REJECTION		= 2;	// TST���܂܂��A���ۂ��ꂽ
	    public static final int	WAITING			= 3;	// TST���܂܂��A���V�[�g�̂݊܂�
	    public static final int	REVOCAT_WARN	= 4;	// TST���܂܂��ATSU�ؖ����̎������߂�
	    public static final int	REVOCAT_NOTF	= 5;	// TST���܂܂��ATSU�ؖ������������Ă���
	}

    // ---------------------------------------------------------------------------
	// �^�C���X�^���v�g�[�N��ASN.1��`
	/*

		// ------------------------------------------------------------------------------
		// �ȉ��̓^�C���X�^���v�iRFC3161�j���

		TimeStampToken ::= ContentInfo
		    -- contentType �́A[CMS] �Œ�`����Ă��� id-signedData �ł���B
		    -- content �́A[CMS] �Œ�`����Ă��� SignedData �ł���B
		    -- SignedData ���� eContentType �́Aid-ct-TSTInfo �ł���B
		    -- SignedData ���� eContent�́ATSTInfo �ł���B

		TSTInfo ::= SEQUENCE { 
		    version INTEGER { v1(1) }, 
		    policy TSAPolicyId, 
		    messageImprint MessageImprint, 
		    -- TimeStampReq �̓����t�B�[���h�̒l�Ɠ����l�������Ȃ���΂Ȃ�Ȃ��iMUST�j�B
		    serialNumber INTEGER, 
		    -- �^�C���X�^���v���[�U�́A160 �r�b�g�܂ł̐����ɓK�����鏀�������Ă����Ȃ���΂Ȃ�Ȃ��iMUST�j�B
		    genTime GeneralizedTime, 
		    accuracy Accuracy OPTIONAL, 
		    ordering BOOLEAN DEFAULT FALSE, 
		    nonce INTEGER OPTIONAL, 
		    -- TimeStampReq �ɓ����t�B�[���h���������ꍇ�A�����l�łȂ���΂Ȃ�Ȃ��iMUST�j�B
		    tsa [0] GeneralName OPTIONAL, 
		    extensions [1] IMPLICIT Extensions OPTIONAL }

		Accuracy ::= SEQUENCE { 
		    seconds INTEGER OPTIONAL, 
		    millis [0] INTEGER (1..999) OPTIONAL, 
		    micros [1] INTEGER (1..999) OPTIONAL }

		SignedData ::= SEQUENCE {
		    version CMSVersion,
		    digestAlgorithms DigestAlgorithmIdentifiers,
		    encapContentInfo EncapsulatedContentInfo,
		    certificates [0] IMPLICIT CertificateSet OPTIONAL,
		    crls [1] IMPLICIT CertificateRevocationLists OPTIONAL,
		    signerInfos SignerInfos }

		DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier

		// ------------------------------------------------------------------------------
		// �ȉ���CMS�iRFC3852�j���

		SignerInfos ::= SET OF SignerInfo

		EncapsulatedContentInfo ::= SEQUENCE {
		    eContentType ContentType,
		    eContent [0] EXPLICIT OCTET STRING OPTIONAL }

		ContentType ::= OBJECT IDENTIFIER

		SignerInfo ::= SEQUENCE {
			version               CMSVersion,
			sid                   SignerIdentifier,
			digestAlgorithm       DigestAlgorithmIdentifier,
			signedAttrs           [0] IMPLICIT SignedAttributes OPTIONAL,
			signatureAlgorithm    SignatureAlgorithmIdentifier,
			signature             SignatureValue,
			unsignedAttrs         [1] IMPLICIT UnsignedAttributes OPTIONAL }

		SignerIdentifier ::= CHOICE {
			issuerAndSerialNumber IssuerAndSerialNumber,
			subjectKeyIdentifier  [0] SubjectKeyIdentifier }

		SignedAttributes ::= SET SIZE (1..MAX) OF Attribute

		UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute

		Attribute ::= SEQUENCE {
			attrType     OBJECT IDENTIFIER,
			attrValues   SET OF AttributeValue }

		AttributeValue ::= ANY

		SignatureValue ::= OCTET STRING

	  */

}
