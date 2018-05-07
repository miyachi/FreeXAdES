/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package jp.langedge.FreeXAdES;

import java.io.*;
import java.util.*;
import java.net.*;

import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;

import jp.langedge.FreeXAdES.FreePKI;
import jp.langedge.FreeXAdES.FreePKI.*;

/**
 * FreeTimeStamp : FreeTimeStamp main implement class.
 * @author miyachi
 *
 */
public class FreeTimeStamp implements IFreeTimeStamp {

	private static final int NONCE_SIZE			= 8;	// �m���X�T�C�Y

	private byte[]	token_	= null;						// �^�C���X�^���v�g�[�N��
	private byte[]	msgImprint_ = null;					// �^�C���X�^���v�Ώۃn�b�V���l
	private String	timeStampDate_ = null;				// �^�C���X�^���v����

	private X509Certificate			tsaCert_ = null;	// TSA(����)�ؖ���
	private List<X509Certificate>	certs_   = null;	// �ؖ����Q

	private byte[]	tstInfo_ = null;					// TSTInfo
	private byte[]	signedAtrb_ = null;					// SignedAttribute
	private String	hashAlg_ = null;					// �n�b�V���A���S���Y��
	private byte[]	hash_ = null;
	private String	signAlg_ = null;					// �����A���S���Y��
	private byte[]	signature_ = null;					// �����l
	
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
		msgImprint_ = null;
		timeStampDate_ = null;
		tsaCert_ = null;
		if(certs_ == null)
			certs_ = new ArrayList<X509Certificate>();
		certs_.clear();
		tstInfo_ = null;
		signedAtrb_ = null;
		hashAlg_ = null;
		hash_ = null;
		signAlg_ = null;
		signature_ = null;
		
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

		// �^�C���X�^���v�g�[�N���̉��
		int rc = setToken(token);
		if(rc != FTERR_NO_ERROR)
			return rc;

		// �n�b�V���l�̊m�F
		if(!FreePKI.isEqual(hash, msgImprint_))
			return FTERR_TS_RES;

		return FTERR_NO_ERROR;
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
		return (X509Certificate[])certs_.toArray();
	}

	/* �^�C���X�^���v�g�[�N���T�v�𕶎���ŕԂ� */
	@Override
	public String getInfo()
	{
		if(empty())
			return null;
		String info = "[TimeStamp]";
		if(empty())
		{
			info += "empty!";
			return info;
		}
		if(timeStampDate_ != null)
			info += "\n Date: " + timeStampDate_;
		if(msgImprint_ != null)
			info += "\n Hash: " + FreePKI.toHex(msgImprint_);
		if(tsaCert_ != null)
			info += "\n TSA: " + tsaCert_.getSubjectX500Principal().getName();
		return info;
	}

	/* �^�C���X�^���v�g�[�N�����o�C�i���ŕԂ� */
	public byte[] getToken()
	{
		return token_;
	}

	/* �^�C���X�^���v�g�[�N���̏��������؂��Č��ʂ�Ԃ� */
	public int verify(byte[] hash)
	{
		if(!FreePKI.isEqual(hash, msgImprint_))
			return FTERR_TS_DIGEST;
		return FTERR_NO_ERROR;
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

			// �c�肪�^�C���X�^���v�g�[�N��
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
		int rc = FTERR_NO_ERROR;
		if(token == null)
			return FTERR_INVALID_TST;

		try {
			ASN1_OBJ tst, obj, obj2, obj3, obj4;
			tst = FreePKI.parseObj(token, 0);
			if(tst == null || tst.tag_ != DERTag.SEQUENCE || tst.construct_ != true)
				throw new Exception("TimeStampToken format error 1");
			obj = FreePKI.parseObj(tst.value_, 0);
			if(obj == null || obj.tag_ != DERTag.OBJECT_IDENTIFIER || !FreePKI.isOID(obj.value_, OID.SIGNED_DATA))
				throw new Exception("TimeStampToken format error 2");
			obj = FreePKI.parseObj(tst.value_, obj.pos_);
			if(obj == null || obj.class_ != DERHead.CLS_CONTEXTSPECIFIC || obj.tag_ != 0 || obj.construct_ != true)
				throw new Exception("TimeStampToken format error 3");
			obj = FreePKI.parseObj(obj.value_, 0);
			if(obj == null || obj.tag_ != DERTag.SEQUENCE || obj.construct_ != true)
				throw new Exception("TimeStampToken format error 4");
			obj2 = FreePKI.parseObj(obj.value_, 0);				// obj = version
			if(obj2 == null || obj2.tag_ != DERTag.INTEGER || obj2.construct_ != false)
				throw new Exception("TimeStampToken format error 5");
			obj2 = FreePKI.parseObj(obj.value_, obj2.pos_);		// obj = sign hash type
			if(obj2 == null || obj2.tag_ != DERTag.SET || obj2.construct_ != true)
				throw new Exception("TimeStampToken format error 6");
			obj2 = FreePKI.parseObj(obj.value_, obj2.pos_);		// obj = TSTinfo out
			if(obj2 == null || obj2.tag_ != DERTag.SEQUENCE || obj2.construct_ != true)
				throw new Exception("TimeStampToken format error 7");
			obj3 = FreePKI.parseObj(obj2.value_, 0);			// obj = sign hash type
			if(obj3 == null || obj3.tag_ != DERTag.OBJECT_IDENTIFIER || !FreePKI.isOID(obj3.value_, OID.TIMESTAMP_TOKEN))
				throw new Exception("TimeStampToken format error 8");
			obj3 = FreePKI.parseObj(obj2.value_, obj3.pos_);	// obj = TSTinfo
			if(obj3 == null || obj3.class_ != DERHead.CLS_CONTEXTSPECIFIC || obj3.tag_ != 0 || obj3.construct_ != true)
				throw new Exception("TimeStampToken format error 9");
			obj4 = FreePKI.parseObj(obj3.value_, 0);			// obj = TSTinfo
			if(obj4 == null ||obj4.tag_ != DERTag.OCTET_STRING || obj4.construct_ != false)
				throw new Exception("TimeStampToken format error 10");
			rc = parseTSTInfo(obj4.value_);
			if(rc != FTERR_NO_ERROR)
				return rc;
			if(obj.value_.length <= obj2.pos_)
				throw new Exception("TimeStampToken format error 11");
			obj2 = FreePKI.parseObj(obj.value_, obj2.pos_);		// obj = option cert or crl
			if(obj2 == null || obj2.construct_ != true)
				throw new Exception("TimeStampToken format error 12");
			if(obj2.class_ == DERHead.CLS_CONTEXTSPECIFIC)
			{
				// cert or crl
				if(obj2.tag_ == 0)
				{
					// cert
					obj3.pos_ = 0;
					while(obj2.value_.length > obj3.pos_)
					{
						boolean body = true;	// body = true �ɂ��l�ł͖����S�̂��擾
						obj3 = FreePKI.parseObj(obj2.value_, obj3.pos_, body);
						if(obj3 == null || obj3.tag_ != DERTag.SEQUENCE || obj3.construct_ != true)
							throw new Exception("TimeStampToken format error 13");
						X509Certificate cert = null;
						try {
							CertificateFactory cf = CertificateFactory.getInstance("X.509");
							ByteArrayInputStream bais = new ByteArrayInputStream(obj3.value_);
							cert = (X509Certificate)cf.generateCertificate(bais);
//							System.out.println(cert.toString());
							certs_.add(cert);
						} catch (CertificateException e) {
//							e.printStackTrace();
							cert = null;
						}
					}
					if(obj.value_.length <= obj2.pos_)
						throw new Exception("TimeStampToken format error 14");
					obj2 = FreePKI.parseObj(obj.value_, obj2.pos_);				
				}
				if(obj2.class_ == DERHead.CLS_CONTEXTSPECIFIC && obj2.tag_ == 1)
				{
					// crl(���ݖ��T�|�[�g)
					if(obj.value_.length <= obj2.pos_)
						throw new Exception("TimeStampToken format error 15");
					obj2 = FreePKI.parseObj(obj.value_, obj2.pos_);				
				}
			}
			// signer info
			if(obj2 == null || obj2.tag_ != DERTag.SET || obj2.construct_ != true)
				throw new Exception("TimeStampToken format error 16");
			rc = parseSignerInfo(obj2.value_);

		} catch (Exception e) {
       	    System.out.println(e);
//	    	System.out.println("���ʉ�̓G���[");
			rc = FTERR_INVALID_TST;
		}

		return rc;
	}

	/* TSTInfo���̉�� */
	private int parseTSTInfo (byte[] info)
	{
		int rc = FTERR_NO_ERROR;
		if(info == null)
			return FTERR_INVALID_TSTINFO;

		tstInfo_ = null;
		try {
			ASN1_OBJ tstinfo, obj, obj2, obj3;
			tstinfo = FreePKI.parseObj(info, 0);
			if(tstinfo == null || tstinfo.tag_ != DERTag.SEQUENCE || tstinfo.construct_ != true)
				throw new Exception("TSTInfo format error 1");
			// version
			obj = FreePKI.parseObj(tstinfo.value_, 0);
			if(obj == null || obj.tag_ != DERTag.INTEGER || obj.construct_ != false)
				throw new Exception("TSTInfo format error 2");
			// policy
			obj = FreePKI.parseObj(tstinfo.value_, obj.pos_);
			if(obj == null || obj.tag_ != DERTag.OBJECT_IDENTIFIER || obj.construct_ != false)
				throw new Exception("TSTInfo format error 3");
			// messageImprint info
			obj = FreePKI.parseObj(tstinfo.value_, obj.pos_);
			if(obj == null || obj.tag_ != DERTag.SEQUENCE || obj.construct_ != true)
				throw new Exception("TSTInfo format error 4");
			// hash algorithm
			obj2 = FreePKI.parseObj(obj.value_, 0);
			if(obj2 == null || obj2.tag_ != DERTag.SEQUENCE || obj2.construct_ != true)
				throw new Exception("TSTInfo format error 5");
			obj3 = FreePKI.parseObj(obj2.value_, 0);	// hash alg OID
			if(obj3 == null || obj3.tag_ != DERTag.OBJECT_IDENTIFIER || obj3.construct_ != false)
				throw new Exception("TSTInfo format error 6");
			// messageImprint
			obj2 = FreePKI.parseObj(obj.value_, obj2.pos_);
			if(obj2 == null || obj2.tag_ != DERTag.OCTET_STRING || obj2.construct_ != false)
				throw new Exception("TSTInfo format error 7");
			msgImprint_ = obj2.value_;
			// serialNumber
			obj = FreePKI.parseObj(tstinfo.value_, obj.pos_);
			if(obj == null || obj.tag_ != DERTag.INTEGER || obj.construct_ != false)
				throw new Exception("TSTInfo format error 8");
			// genTime
			obj = FreePKI.parseObj(tstinfo.value_, obj.pos_);
			if(obj == null || obj.tag_ != DERTag.GENERALIZED_TIME || obj.construct_ != false)
				throw new Exception("TSTInfo format error 9");
			timeStampDate_ = new String(obj.value_);
			// �ȉ���͂͏ȗ�
		} catch (Exception e) {
       	    System.out.println(e);
//	    	System.out.println("���ʉ�̓G���[");
			rc = FTERR_INVALID_TSTINFO;
		}
		if(rc == FTERR_NO_ERROR)
			tstInfo_ = info;
		return rc;
	}


	/* SignerInfo���̉�� */
	private int parseSignerInfo (byte[] info)
	{
		int rc = FTERR_NO_ERROR;
		if(info == null)
			return FTERR_INVALID_SIGNINFO;

		signedAtrb_ = null;
		hashAlg_ = null;
		signAlg_ = null;
		signature_ = null;

		// SignerInfo���
		try {
			ASN1_OBJ signerinfo, obj, obj2;
			signerinfo = FreePKI.parseObj(info, 0);
			if(signerinfo == null || signerinfo.tag_ != DERTag.SEQUENCE || signerinfo.construct_ != true)
				throw new Exception("SignerInfo format error 1");
			// version
			obj = FreePKI.parseObj(signerinfo.value_, 0);
			if(obj == null || obj.tag_ != DERTag.INTEGER || obj.construct_ != false)
				throw new Exception("SignerInfo format error 2");
			// sid
			obj = FreePKI.parseObj(signerinfo.value_, obj.pos_);
			if(obj == null || obj.tag_ != DERTag.SEQUENCE || obj.construct_ != true)
				throw new Exception("SignerInfo format error 3");
			// digestAlgorithm
			obj = FreePKI.parseObj(signerinfo.value_, obj.pos_);
			if(obj == null || obj.tag_ != DERTag.SEQUENCE || obj.construct_ != true)
				throw new Exception("SignerInfo format error 4");
			obj2 = FreePKI.parseObj(obj.value_, 0);	// hash alg OID
			if(obj2 == null || obj2.tag_ != DERTag.OBJECT_IDENTIFIER || obj2.construct_ != false)
				throw new Exception("SignerInfo format error 5");
			// �����A���S���Y��
			if(FreePKI.isOID(obj2.value_, OID.SHA_256)) {
				hashAlg_ = "SHA-256";
				signAlg_ = "SHA256WithRSA";
			} else if(FreePKI.isOID(obj2.value_, OID.SHA_384)) {
				hashAlg_ = "SHA-384";
				signAlg_ = "SHA384WithRSA";
			} else if(FreePKI.isOID(obj2.value_, OID.SHA_512)) {
				hashAlg_ = "SHA-512";
				signAlg_ = "SHA512WithRSA";
			} else if(FreePKI.isOID(obj2.value_, OID.SHA_1)) {
				hashAlg_ = "SHA-1";
				signAlg_ = "SHA1WithRSA";
			} else
				throw new Exception("unknown algorithm");
			// signedAttrs check
			obj = FreePKI.parseObj(signerinfo.value_, obj.pos_, true);
			if(obj == null || obj.construct_ != true)
				throw new Exception("SignerInfo format error 6");
			if(obj.class_ == DERHead.CLS_CONTEXTSPECIFIC || obj.tag_ == 0)
			{
				// �����Ώ�
				signedAtrb_ = obj.value_;
				signedAtrb_[0] = DERTag.SET | DERHead.CONSTRUCTED;	// ���؂ׂ̈ɍŏ���CONTEXTSPECIFIC��SET�ɕύX����
				// signedAttrs
				rc = parseSignedAtrb(signedAtrb_);
				if(rc != FTERR_NO_ERROR)
					return rc;
				// ��
				obj = FreePKI.parseObj(signerinfo.value_, obj.pos_);
			}
			// signatureAlgorithm
			if(obj == null || obj.tag_ != DERTag.SEQUENCE || obj.construct_ != true)
				throw new Exception("SignerInfo format error 7");
			obj2 = FreePKI.parseObj(obj.value_, 0);	// sign alg OID
			if(obj2 == null || obj2.tag_ != DERTag.OBJECT_IDENTIFIER || !FreePKI.isOID(obj2.value_, OID.RSA_ENC) || obj2.construct_ != false)
				throw new Exception("SignerInfo format error 8");
			// signature
			obj = FreePKI.parseObj(signerinfo.value_, obj.pos_);
			if(obj == null || obj.tag_ != DERTag.OCTET_STRING || obj.construct_ != false)
				throw new Exception("SignerInfo format error 9");
			signature_ = obj.value_;
			// �ȉ���͂͏ȗ�
		} catch (Exception e) {
       	    System.out.println(e);
//	    	System.out.println("���ʉ�̓G���[");
			rc = FTERR_INVALID_SIGNINFO;
		}

		// �����ؖ����̊m�F
		tsaCert_ = null;
		for(int i=0; i<certs_.size(); i++)
		{
			X509Certificate cert = certs_.get(i);
			if(cert == null)
				continue;
//      	System.out.println(cert.getSubjectX500Principal().getName());
			try {
				PublicKey key = cert.getPublicKey();
				Signature signature = Signature.getInstance(signAlg_);
				signature.initVerify(key);
				signature.update(signedAtrb_);
				boolean rslt = signature.verify(signature_);
				if(rslt)
				{
					// ����TSA�ؖ���������
					tsaCert_ = cert;
					break;
				}
			} catch (Exception e) {
				// ���؎��s
//	       	    System.out.println(e);
			}
		}
		if(tsaCert_ == null)
			rc = FTERR_INVALID_TSACERT;
		return rc;
	}

	/* TSTInfo���̉�� */
	private int parseSignedAtrb (byte[] atrb)
	{
		int rc = FTERR_NO_ERROR;
		if(atrb == null)
			return FTERR_INVALID_SIGNINFO;

		hash_ = null;
		try {
			ASN1_OBJ signatrb, obj, obj2, obj3;
			signatrb = FreePKI.parseObj(atrb, 0);
			if(signatrb == null || signatrb.tag_ != DERTag.SET || signatrb.construct_ != true)
				throw new Exception("SignedAtrb format error 1");
			obj = new ASN1_OBJ();
			obj.pos_ = 0;
			while(obj.pos_ < signatrb.value_.length)
			{
				obj = FreePKI.parseObj(signatrb.value_, obj.pos_);
				if(obj == null || obj.tag_ != DERTag.SEQUENCE || obj.construct_ != true)
					continue;
				obj2 = FreePKI.parseObj(obj.value_, 0);
				if(obj2 == null || obj2.tag_ != DERTag.OBJECT_IDENTIFIER || obj2.construct_ != false)
					continue;
				if(!FreePKI.isOID(obj2.value_, OID.MESSAGE_DIGEST))
					continue;
				obj2 = FreePKI.parseObj(obj.value_, obj2.pos_);
				if(obj2 == null || obj2.tag_ != DERTag.SET || obj2.construct_ != true)
					continue;
				obj3 = FreePKI.parseObj(obj2.value_, 0);
				if(obj3 == null || obj3.tag_ != DERTag.OCTET_STRING || obj3.construct_ != false)
					continue;
				hash_ = obj3.value_;
				break;
			}
		} catch (Exception e) {
       	    System.out.println(e);
//	    	System.out.println("���ʉ�̓G���[");
			rc = FTERR_INVALID_TSTINFO;
		}
		if(hash_ != null)
		{
			byte[] hash = FreePKI.getHash(tstInfo_, hashAlg_);
			if(!FreePKI.isEqual(hash, hash_))
				rc = FTERR_TSTINFO_DIGEST;
		}
		return rc;
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
