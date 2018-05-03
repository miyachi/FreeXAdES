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
//import java.security.cert.Certificate;	// 明示する為にインポート
//import java.text.SimpleDateFormat;

/**
 * FreeTimeStamp : FreeTimeStamp main implement class.
 * @author miyachi
 *
 */
public class FreeTimeStamp implements IFreeTimeStamp {

	private static final int NONCE_SIZE			= 8;	

	private byte[]	token_	= null;
	
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
		token_ = token;
		return FTERR_NO_ERROR;
	}

	/* タイムスタンプトークンがセット済みかどうかを返す */
	@Override
	public boolean empty()
	{
		if(token_ == null)
			return false;
		return true;
	}

	/* タイムスタンプトークンのタイムスタンプ時刻を文字列で返す */
	@Override
	public String getTimeStampDate()
	{
		return null;
	}

	/* タイムスタンプトークンの対象ハッシュ値（messageImprint）をバイナリで返す */
	@Override
	public byte[] getMsgImprint()
	{
		return null;
	}

	/* タイムスタンプトークンのTSA証明書を返す */
	@Override
	public X509Certificate getSignerCert()
	{
		return null;
	}

	/* タイムスタンプトークン中の全ての証明書を配列で返す */
	@Override
	public X509Certificate[] getAllCerts()
	{
		return null;
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
				throw new Exception("format error 1");	// 最初がSEQUENCEでは無かった（TSTでは無い）
			if( idx > res_len )
				throw new Exception("format error 2");

			if( ( res[idx] & DERTag.LEN_EXTEND ) == 0 ) {
				// 長さが１バイト
				len = res[idx++];
			} else {
				// 長さは拡張されている
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

			// Statusの取得
			int status = 0;
			if( res[idx++] != ( DERTag.SEQUENCE | DERTag.CONSTRUCTED ) )
				throw new Exception("format error 8");	// 次がSEQUENCEでは無かった
			if( idx > res_len )
				throw new Exception("format error 9");
			if( ( res[idx++] & DERTag.LEN_EXTEND ) != 0 )
				throw new Exception("format error 10");	// 拡張はとりあえず対応しない
			if( idx > res_len )
				throw new Exception("format error 11");
			if( res[idx++] != DERTag.INTEGER )
				throw new Exception("format error 12");	// StatusはINTEGER
			if( idx > res_len )
				throw new Exception("format error 13");
			int isz = res[idx++];						// サイズ
			if( idx > res_len )
				throw new Exception("format error 14");
			for( int j=isz-1; j>=0; j-- ) {
				status |= (res[idx++] & 0xff) << ( 8 * j );
				if( idx > res_len )
					throw new Exception("format error 15");
			}
			if( status != PKIStatus.GRANTED && status != PKIStatus.GRANT_W_MODS )
				throw new Exception("invalid server res status");	// サーバからエラーが返った

			// 残りがTSTのはず
			len = (int)(res_len - idx);
			if( len > res_len )
				throw new Exception("format error 16");
			tst = new byte[len];
            System.arraycopy( res, idx, tst, 0, len );	// TSTのコピー

		} catch (Exception e) {
       	    System.out.println(e);
	    	System.out.println("結果解析エラー");
		}
		return tst;
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
	public interface PKIStatus {
	    public static final int	GRANTED			= 0;	// TSTを含む
	    public static final int	GRANT_W_MODS	= 1;	// TSTを含み、プライベート拡張を含む
	    public static final int	REJECTION		= 2;	// TSTを含まず、拒否された
	    public static final int	WAITING			= 3;	// TSTを含まず、レシートのみ含む
	    public static final int	REVOCAT_WARN	= 4;	// TSTを含まず、TSU証明書の失効が近い
	    public static final int	REVOCAT_NOTF	= 5;	// TSTを含まず、TSU証明書が失効している
	}

    // ---------------------------------------------------------------------------
    // ASN.1/BER(DER)タグ定義.
	public interface DERTag {
		// タグ
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
	    // クラス・構造化フラグ
	    public static final byte CONSTRUCTED         = 0x20;
	    public static final byte APPLICATION         = 0x40;
	    public static final byte CONTEXT_SPECIFIC    = (byte)0x80;
	    public static final byte PRIVATE             = (byte)0xc0;
	    // マスク
	    public static final byte TAGNUM_MASK         = 0x1f;
	    public static final byte TAGCONSTFLAG_MASK   = 0x20;
	    public static final byte TAGCLASS_MASK       = (byte)0xC0;
	    // 値長
	    public static final byte LEN_MASK            = 0x1f;
	    public static final byte LEN_EXTEND          = (byte)0x80;
	}

}
