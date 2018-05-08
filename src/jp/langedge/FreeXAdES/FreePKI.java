/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package jp.langedge.FreeXAdES;

import java.io.*;
import java.util.*;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import java.net.HttpURLConnection;
import java.net.URL;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * FreePKI : Crypto and PKI utility class.
 * @author miyachi
 *
 */
public class FreePKI {

	/** ハッシュ値を計算する
	 * 指定アルゴリズムによりハッシュ値の計算を行う
	 * @param data ハッシュ計算の対象データをバイナリで指定する
	 * @param hashAlgName ハッシュアルゴリズムを指定、"SHA-256", "SHA-384", "SHA-512" 等
	 * @return ハッシュ値が返る
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
	
	/** ASN.1/BER(DER)オブジェクト解析
	 * ASN.1/BER(DER)の1オブジェクトを解析して情報を返す
	 * @param data ASN.1/BER(DER)をバイナリで指定する
	 * @param pos 解析開始位置を指定する
	 * @return ASN.1オブジェクト情報が返る
	 */
	public static ASN1_OBJ parseObj(byte[] data, int pos)
	{
		return parseObj(data, pos, false);
	}
	
	/** ASN.1/BER(DER)オブジェクト解析
	 * ASN.1/BER(DER)の1オブジェクトを解析して情報を返す
	 * @param data ASN.1/BER(DER)をバイナリで指定する
	 * @param pos 解析開始位置を指定する
	 * @param body falseの場合には値のみ、trueならオブジェクト全体を返す
	 * @return ASN.1オブジェクト情報が返る
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
			// 長さが１バイト
			obj.len_= (int)data[pos++];
		} else {
			// 長さは拡張されている
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
	        System.arraycopy( data, start, obj.value_, 0, len );	// valueのコピー
		}
		else
		{
			obj.value_ = new byte[obj.len_];
	        System.arraycopy( data, pos, obj.value_, 0, obj.len_ );	// valueのコピー
		}
        obj.pos_  = pos + obj.len_;
		return obj;
	}

	/** OID一致のチェック
	 * OIDバイナリと指定OIDが同じかどうかを返す
	 * @param value ASN.1/BER(DER)のOIDをバイナリで指定する
	 * @param oid 比較するOIDを指定する
	 * @return 一致の場合にはtrueが返る
	 */
	public static boolean isOID(byte[] value, byte[] oid)
	{
		return isEqual(value, oid);
	}
	
	/** バイト配列一致のチェック
	 * 2つのバイト配列が同じかどうかを返す
	 * @param arg1 バイト配列1を指定する
	 * @param arg2 バイト配列2を指定す
	 * @return 一致の場合にはtrueが返る
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
	
	/** バイト配列のHEX文字列化
	 * バイト配列をHEX文字列化して返す
	 * @param arg バイト配列を指定する
	 * @return HEX文字列が返る
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
	
	/** GENERALIZED_TIMEのW3C-DTF変更
	 * GENERALIZED_TIMEをW3C-DTF化して返す、YYYY-MM-DDThh:mm:ss.sTZD
	 * @param genTime GENERALIZED_TIMEを指定する
	 * @return DTF文字列が返る
	 */
	public static String toDTF(String genTime)
	{
		String dtf = "";
		if(genTime.length() >= 4)
			dtf += genTime.substring(0, 4);
		if(genTime.length() >= 6)
			dtf += "-" + genTime.substring(4, 6);
		if(genTime.length() >= 8)
			dtf += "-" + genTime.substring(6, 8);
		if(genTime.length() >= 10)
			dtf += "T" + genTime.substring(8, 10);
		if(genTime.length() >= 12)
			dtf += ":" + genTime.substring(10, 12);
		if(genTime.length() >= 14)
			dtf += ":" + genTime.substring(12, 14);
		if(genTime.length() >= 15)
		{
			if(!"Z".equals(genTime.substring(14, 15)))
				dtf += ".";
			dtf += genTime.substring(14);
		}
		return dtf;
	}
	
	// ---------------------------------------------------------------------------
    // OID定義.
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
    // ASN.1/BER(DER)ヘッダ定義.
	public interface DERHead {
	    // 構造化フラグ
	    public static final byte CONSTRUCTED         = 0x20;		// 1bit  : 0=単一型 / 1=構造型(値がASN.1オブジェクト[タグ番号+値の長さ+値]となっている)
	    // クラス
	    public static final byte CLS_MASK            = (byte)0xc0;	// 2bits : 00=ISO-TAG / 01=応用(未対応) / 10=Context-Specific / 11=独自(未対応)
	    public static final byte CLS_TAGTYPE         = 0x00;
	    public static final byte CLS_APPLICATION     = 0x40;
	    public static final byte CLS_PRIVATE         = (byte)0xc0;
	    public static final byte CLS_CONTEXTSPECIFIC = (byte)0x80;
	    // タグ
	    public static final byte TAG_MASK    	     = 0x1f;
	    // 値長
	    public static final byte LEN_MASK            = 0x1f;
	    public static final byte LEN_EXTEND          = (byte)0x80;
	}

	// ---------------------------------------------------------------------------
    // ASN.1/BER(DER)タグ定義
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
	}

	// ---------------------------------------------------------------------------
	// PKIではCRL/OCSP/TimeStamp等の取得にてHTTP通信を利用する.

	/** HTTP通信の実行
	 * POST/GETによるHTTP通信を実行して結果を返す
	 * @param url 必須：接続先を指定する
	 * @param send 非nullならPOST通信用のバイト配列を指定する、nullならGET通信となる
	 * @param contentType Content-Typeを指定する、POST通信時に指定
	 * @param userid オプション：Basic認証用のユーザID、不要ならnullを指定する
	 * @param passwd オプション：Basic認証用のパスワード、不要ならnullを指定する
	 * @return HTTP通信に成功した場合にはサーバ応答バイナリが返る
	 */
	public static byte[] httpConnect (
			String url,
			byte[] send,
			String contentType,
			String userid,
			String passwd
			)
	{
		byte[] back = null;
        InputStream in = null;
        ByteArrayOutputStream tmp = null;

        if(url == null)
        	return back;

        try
		{
			/* とりえあずHTTPSのトラスト確認はしない実装 */
            // 証明書情報は全てnullを返す
            TrustManager[] tm = { new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
                @Override
                public void checkClientTrusted(X509Certificate[] chain,
                        String authType) throws CertificateException {
                }
                @Override
                public void checkServerTrusted(X509Certificate[] chain,
                        String authType) throws CertificateException {
                }
            } };
            // SSL接続の初期化
            SSLContext sslcontext = SSLContext.getInstance("SSL");
            sslcontext.init(null, tm, null);
            // ホスト名の検証ルールは何が来てもtrueを返す
            HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String hostname,
                        SSLSession session) {
                    return true;
                }
            });

            // URL初期化
            URL server = new URL(url);
			HttpURLConnection connection = null;

			try
			{
				// 通信準備
				connection = (HttpURLConnection)server.openConnection();
				// SSL設定
				if(server.getProtocol().equals("https")) {
					// SSL接続設定のセット
					((HttpsURLConnection)connection).setSSLSocketFactory(sslcontext.getSocketFactory());
				}
				connection.setConnectTimeout(30*1000);		// 30秒でタイムアウト
				connection.setUseCaches(false);				// キャッシュは使わない
				connection.setRequestProperty("Connection", "Keep-Alive");
				if(userid != null && passwd != null) {
					// Basic認証設定
					String token = userid + ":" + passwd;
					String basic = Base64.getEncoder().encodeToString(token.getBytes());
					connection.setRequestProperty("Authorization", "Basic " + basic);
				}
				if(send != null && send.length > 0)
				{
					// POST
					connection.setRequestMethod("POST");
					connection.setDoOutput(true);
					if(contentType == null)
						contentType = "text/plain";
					connection.setRequestProperty("Content-Type", contentType);
					// リクエストの書き込み
					OutputStream os = new BufferedOutputStream(connection.getOutputStream());
					os.write(send);
	         		os.flush();
				}
				else
				{
					// GET
					connection.setRequestMethod("GET");
				}
				
				// 接続
				connection.connect();

				// 結果確認
				if (connection.getResponseCode() == HttpURLConnection.HTTP_OK)
				{
					// 接続成功(応答の読み込み)
					in = connection.getInputStream();
					BufferedInputStream bis = new BufferedInputStream(in);
					// 中間書き込みバッファ
					tmp = new ByteArrayOutputStream();
					BufferedOutputStream bos = new BufferedOutputStream(tmp);
					int read = 0;
					int bufSize = 10240;		// 1回の読み込みバッファサイズ
					byte[] buffer = new byte[bufSize];
					// 読み込みループ
					while(true){
						read = bis.read(buffer);
						if(read==-1)
							break;
						bos.write(buffer, 0, read);
					}
					// 書き込みをフラッシュしてバイト配列取得
					bos.flush();
					back = tmp.toByteArray();
				}
				else
				{
					// 接続失敗
		      	    System.out.println("http error: status = " + connection.getResponseCode());
					back = null;
				}
			}
			finally
			{
				if (tmp != null)
					tmp.close();
				if (in != null)
					in.close();
				if (connection != null)
				    connection.disconnect();
			}
		} catch (Exception e) {
       	    System.out.println(e);
//	    	System.out.println("HTTP接続エラー");
		}
		return back;
	}

}
