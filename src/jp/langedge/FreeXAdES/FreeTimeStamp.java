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
	
	/* コンストラクタ */
	public FreeTimeStamp() {
		clear();
	}

	/* コンストラクタ */
	public FreeTimeStamp(byte[] token) {
		clear();
		setToken(token);
	}

	/* ファイナライズ */
	public void finalize () {
		clear();
	}

	/* クリア */
	private void clear() {
		token_ = null;
	}

	/* タイムスタンプをサーバ（TSA）から取得する */
	@Override
	public int getFromServer(byte[] hash, String url, String userid, String passwd)
	{

		// nonceの生成
		byte[] nonce = new byte[NONCE_SIZE];
		new Random().nextBytes(nonce);

		// タイムスタンプリクエストの生成
		byte[] req = makeRequest(hash, nonce);
		if(req == null)
			return FTERR_TS_REQ;

		// タイムスタンプサーバ接続
		byte[] resp = httpConnect(url, req, userid, passwd);
		if(resp == null)
			return FTERR_TS_CONNECT;

		// タイムスタンプレスポンスの解析（タイムスタンプトークン取得）
		byte[] token = parseResponse(resp, nonce);
		if(token == null)
			return FTERR_TS_RES;

		return setToken(token);
	}

	/* タイムスタンプトークンのバイナリをセットする */
	@Override
	public int setToken(byte[] token)
	{
		if(token == null)
		{
			// クリア
			clear();
			return FTERR_NO_ERROR;
		}

		// 解析
		int rc = parseToken(token);
		if(rc == FTERR_NO_ERROR)
		{
			// 解析成功
			token_ = token;
		}
		else
		{
			// エラークリア
			clear();
		}
		return rc;
	}

	/* タイムスタンプトークンがセット済みかどうかを返す */
	@Override
	public boolean empty()
	{
		if(token_ == null)
			return true;
		return false;
	}

	/* タイムスタンプトークンのタイムスタンプ時刻を文字列で返す */
	@Override
	public String getTimeStampDate()
	{
		if(empty())
			return null;
		return timeStampDate_;
	}

	/* タイムスタンプトークンの対象ハッシュ値（messageImprint）をバイナリで返す */
	@Override
	public byte[] getMsgImprint()
	{
		if(empty())
			return null;
		return msgImprint_;
	}

	/* タイムスタンプトークンのTSA証明書を返す */
	@Override
	public X509Certificate getSignerCert()
	{
		if(empty())
			return null;
		return tsaCert_;
	}

	/* タイムスタンプトークン中の全ての証明書を配列で返す */
	@Override
	public X509Certificate[] getAllCerts()
	{
		if(empty())
			return null;
		return certs_;
	}

	/* タイムスタンプトークン概要を文字列で返す */
	@Override
	public String getInfo()
	{
		if(empty())
			return null;
		return "ToDo ToDo.";
	}

	/* タイムスタンプトークンをバイナリで返す */
	public byte[] getToken()
	{
		return token_;
	}

	/* タイムスタンプトークンの署名を検証して結果を返す */
	public int verify()
	{
		return -1;
	}

	/**
	 * タイムスタンプのリクエスト情報の生成.
	 * <p>
	 * RFC3161/SHA-512のリクエスト情報（バイナリ形式）を生成して返す。
	 * 
	 * @param hash タイムスタンプ取得要求をするハッシュ値（SHA-1=20バイト/SHA-256=32バイト/SHA-512=64バイト）
	 * @param nonce ナンス（乱数値）を指定（8バイト固定）
	 * @return 生成したリクエスト情報（バイナリ形式）を返す
	 */
	private byte[] makeRequest (
			byte[] hash,			// 32/64 バイト
			byte[] nonce			// 8 バイト
			)
	{
		byte[] req = null;

		// SHA-256 リクエスト情報定義
		byte[] sha256req = {
				0x30, 0x41,							// Request SEQUENCE (65バイト)
				0x02, 0x01, 0x01,					// Version INTEGER (1バイト) value: 1
				0x30, 0x2f,							// MessageImprint SEQUENCE (47バイト)
				0x30, 0x0b,							// AlgorithmOID SEQUENCE (11バイト)
				0x06, 0x09,							// OID (9バイト)
				0x60, (byte)0x86, 0x48, 0x01, 0x65,	// OIDSHA256 value: 2.16.840.1.101.3.4.2.1
				0x03, 0x04, 0x02, 0x01,
				0x04, 0x20,							// Hash OCTET STRING (32バイト)
				0x00, 0x00, 0x00, 0x00, 0x00,		// Placeholders for Hash (+22バイト)
				0x00, 0x00, 0x00, 0x00, 0x00,		// 10
				0x00, 0x00, 0x00, 0x00, 0x00,		// 15
				0x00, 0x00, 0x00, 0x00, 0x00,		// 20
				0x00, 0x00, 0x00, 0x00, 0x00,		// 25
				0x00, 0x00, 0x00, 0x00, 0x00,		// 30
				0x00, 0x00,							// 35
				0x02, 0x08,							// Nonce INTEGER (8バイト)
				0x00, 0x00,	0x00, 0x00, 0x00,		// Placeholders for Nonce (+56バイト)
				0x00, 0x00, 0x00,					// 8
				0x01, 0x01,	(byte)0xff				// RequestCertificate BOOLEAN (1バイト) value: true
		};

		// SHA-512 リクエスト情報定義
		byte[] sha512req = {
				0x30, 0x61,							// Request SEQUENCE (97バイト)
				0x02, 0x01, 0x01,					// Version INTEGER (1バイト) value: 1
				0x30, 0x4f,							// MessageImprint SEQUENCE (79バイト)
				0x30, 0x0b,							// AlgorithmOID SEQUENCE (11バイト)
				0x06, 0x09,							// OID (9バイト)
				0x60, (byte)0x86, 0x48, 0x01, 0x65,	// OIDSHA512 value: 2.16.840.1.101.3.4.2.3
				0x03, 0x04, 0x02, 0x03,
				0x04, 0x40,							// Hash OCTET STRING (64バイト)
				0x00, 0x00, 0x00, 0x00, 0x00,		// Placeholders for Hash (+22バイト)
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
				0x02, 0x08,							// Nonce INTEGER (8バイト)
				0x00, 0x00,	0x00, 0x00, 0x00,		// Placeholders for Nonce (+88バイト)
				0x00, 0x00, 0x00,					// 8
				0x01, 0x01,	(byte)0xff				// RequestCertificate BOOLEAN (1バイト) value: true
		};

		try {
			if( hash.length == 64 ) {
				// SHA-512
				req = sha512req;
	            System.arraycopy( hash, 0, req, 22, hash.length );			// ハッシュ値のセット
	            if( nonce.length == NONCE_SIZE )
	            	System.arraycopy( nonce, 0, req, 88, nonce.length );	// 乱数値のセット
			} else if( hash.length == 32 ) {
				// SHA-256
				req = sha256req;
	            System.arraycopy( hash, 0, req, 22, hash.length );			// ハッシュ値のセット
	            if( nonce.length == NONCE_SIZE )
	            	System.arraycopy( nonce, 0, req, 56, nonce.length );	// 乱数値のセット
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
	 * タイムスタンプのレスポンス情報の解析.
	 * <p>
	 * RFC3161のレスポンス情報（バイナリ形式）を解析してタイムスタンプトークンを返す。
	 * 
	 * @param res タイムスタンプサーバから返されたレスポンス情報（バイナリ形式）
	 * @param nonce ナンス（乱数値）を指定（8バイト）
	 * @return OKなら取得したタイムスタンプトークン（バイナリ形式）を返す
	 */
	private byte[] parseResponse (
			byte[] res,
			byte[] nonce			// 8 バイト
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
			// TSResponseの解析
			obj = FreePKI.parseObj(tsr.value_, 0);
			if(obj == null)
				throw new Exception("TSResponse format error 2");
			if(obj.tag_ != DERTag.SEQUENCE || obj.construct_ != true)
				throw new Exception("TSResponse format error 3");
			// statusの取得
			obj2 = FreePKI.parseObj(obj.value_, 0);
			if(obj2 == null)
				throw new Exception("TSResponse format error 4");
			if(obj2.tag_ != DERTag.INTEGER)
				throw new Exception("TSResponse format error 5");
			for( int j=obj2.len_-1; j>=0; j-- ) {
				status |= (obj2.value_[j] & 0xff) << ( 8 * j );
			}
			if( status != TSResStatus.GRANTED && status != TSResStatus.GRANT_W_MODS )
				throw new Exception("invalid server res status = " + status);	// サーバからエラーが返った

			// 残りがTST
			len = tsr.len_ - obj.pos_;
			if( len <= 0 )
				throw new Exception("format error 16");
			tst = new byte[len];
            System.arraycopy( tsr.value_, obj.pos_, tst, 0, len );	// TSTのコピー

		} catch (Exception e) {
       	    System.out.println(e);
//	    	System.out.println("結果解析エラー");
		}
		return tst;
	}
	
	/* タイムスタンプトークンの解析 */
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
//	    	System.out.println("結果解析エラー");
		}

		return FTERR_NO_ERROR;
	}

    // ---------------------------------------------------------------------------
    // HTTP通信.
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
				// 通信準備
				connection = (HttpURLConnection) server.openConnection();
				connection.setRequestMethod("POST");
				connection.setDoOutput(true);
				connection.setRequestProperty("Content-Type", "application/timestamp-query");
				connection.setUseCaches(false);

				// タイムスタンプリクエストの書き込み
				OutputStream os = new BufferedOutputStream(connection.getOutputStream());
				os.write(send);
         		os.flush();

				if (connection.getResponseCode() == HttpURLConnection.HTTP_OK)
				{
					BufferedInputStream bis = new BufferedInputStream(connection.getInputStream());
					int nBufSize = 1024 * 100;		// とりあえずタイムスタンプ応答は100KB未満とする
					byte[] buf = new byte[nBufSize];
					int len = bis.read(buf);
					bis.close();
					if(len <= 0)
					{
	    				System.out.println("HTTP応答エラー");
					}
					else
					{
						// 成功したのでタイムスタンプレスポンスが返っているはず
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
	    	System.out.println("HTTP接続エラー");
		}
		return back;
	}

	// ---------------------------------------------------------------------------
    // タイムスタンプレスポンスのステータス.
	public interface TSResStatus {
	    public static final int	GRANTED			= 0;	// TSTを含む
	    public static final int	GRANT_W_MODS	= 1;	// TSTを含み、プライベート拡張を含む
	    public static final int	REJECTION		= 2;	// TSTを含まず、拒否された
	    public static final int	WAITING			= 3;	// TSTを含まず、レシートのみ含む
	    public static final int	REVOCAT_WARN	= 4;	// TSTを含まず、TSU証明書の失効が近い
	    public static final int	REVOCAT_NOTF	= 5;	// TSTを含まず、TSU証明書が失効している
	}

    // ---------------------------------------------------------------------------
	// タイムスタンプトークンASN.1定義
	/*

		// ------------------------------------------------------------------------------
		// 以下はタイムスタンプ（RFC3161）より

		TimeStampToken ::= ContentInfo
		    -- contentType は、[CMS] で定義されている id-signedData である。
		    -- content は、[CMS] で定義されている SignedData である。
		    -- SignedData 中の eContentType は、id-ct-TSTInfo である。
		    -- SignedData 中の eContentは、TSTInfo である。

		TSTInfo ::= SEQUENCE { 
		    version INTEGER { v1(1) }, 
		    policy TSAPolicyId, 
		    messageImprint MessageImprint, 
		    -- TimeStampReq の同じフィールドの値と同じ値を持たなければならない（MUST）。
		    serialNumber INTEGER, 
		    -- タイムスタンプユーザは、160 ビットまでの整数に適応する準備をしておかなければならない（MUST）。
		    genTime GeneralizedTime, 
		    accuracy Accuracy OPTIONAL, 
		    ordering BOOLEAN DEFAULT FALSE, 
		    nonce INTEGER OPTIONAL, 
		    -- TimeStampReq に同じフィールドがあった場合、同じ値でなければならない（MUST）。
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
		// 以下はCMS（RFC3852）より

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
