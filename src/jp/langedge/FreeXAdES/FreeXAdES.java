/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package jp.langedge.FreeXAdES;

import java.io.*;
import java.math.BigInteger;
import java.util.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;	// 明示する為にインポート
import java.text.SimpleDateFormat;
import java.net.*;

import javax.security.cert.X509Certificate;
import javax.xml.crypto.*;
import javax.xml.crypto.dom.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.*;
import javax.xml.crypto.dsig.keyinfo.*;
import javax.xml.crypto.dsig.spec.*;
import javax.xml.parsers.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.*;
import javax.xml.transform.stream.*;
import javax.xml.xpath.*;
import org.w3c.dom.*;				// Documentクラス他に利用

/**
 * FreeXAdES : FreeXAdES main implement class.
 * @author miyachi
 *
 */
public class FreeXAdES implements IFreeXAdES {

	/** プライベート要素.
	 */
	private XMLSignatureFactory sigFact_ = null;			// XML署名ファクトリ
	private Document signDoc_ = null;						// メインドキュメント
	private String hashAlg_ = null;							// ハッシュ方式
	private List<Reference> refs_ = null;					// 参照
	private List<XMLObject> objs_ = null;					// オブジェクト
	private String rootDir_ = null;							// ベースになるルートディレクトリ
	
	/* --------------------------------------------------------------------------- */
	/* コンストラクタ等 */
	
	/* コンストラクタ */
	public FreeXAdES() {
		clear();
        // XMLSignatureFactoryのDOM実装を取得する
		sigFact_ = XMLSignatureFactory.getInstance("DOM");
	}

	/* ファイナライズ */
	public void finalize () {
		clear();
		sigFact_ = null;
	}

	/* クリア */
	private void clear() {
		clearLastError();
		signDoc_ = null;
		hashAlg_ = null;
		refs_ = null;
		objs_ = null;
		rootDir_ = null;
	}

	/* --------------------------------------------------------------------------- */
	/* 署名XMLのセット */
	
	/* 署名XMLをセットする */
	@Override
	public int setXml(byte[] xml) {
		int rc = FXERR_NO_ERROR;
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
    	ByteArrayInputStream inStream = new ByteArrayInputStream(xml);
		try {
			signDoc_ = dbf.newDocumentBuilder().parse(inStream);
		} catch (IOException e) {
			e.printStackTrace();
			rc = setLastError(FXERR_IO_EXCEPTION);
		} catch (Exception e) {
			e.printStackTrace();
			rc = setLastError(FXERR_XML_PARSE);
		}
		return rc;		
	}
	
	/* 署名XMLの読み込み */
	@Override
	public int loadXml(String target, int fxaType) {
		int rc = FXERR_NO_ERROR;
		byte[] bin = getBinary(target, fxaType);
		if(bin == null)
			return getLastError();
		rc = setXml(bin);
		return rc;
	}

	/* --------------------------------------------------------------------------- */
	/* 署名XMLの取得 */

	/* 署名済みXMLを取得する */
	@Override
	public byte[] getXml() {
		byte[] xml = null;
		try {
			ByteArrayOutputStream bs = new ByteArrayOutputStream();
			TransformerFactory tff = TransformerFactory.newInstance();
			Transformer tf = tff.newTransformer();
			tf.transform(new DOMSource(signDoc_), new StreamResult(bs));
			xml = bs.toByteArray();
			if(xml == null)
				setLastError(FXERR_XML_GET);
		} catch (Exception e) {
			e.printStackTrace();
			setLastError(FXERR_XML_GET);
		}
		return xml;		
	}

	/* 署名済みXMLをファイル保存する */
	@Override
	public int saveXml(String path) {
		// XML署名文書を出力。
		int rc = FXERR_NO_ERROR;

		if(signDoc_ == null)
			return setLastError(FXERR_NOT_INIT);
		
		String saveFile = getPath(path);
		try {
			OutputStream os = new FileOutputStream(saveFile);
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer trans = tf.newTransformer();
			trans.transform(new DOMSource(signDoc_), new StreamResult(os));
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			rc = FXERR_FILE_NOTFOUND;
		} catch (Exception e) {
			e.printStackTrace();
			rc = FXERR_FILE_WRITE;
		}
		return rc;		
	}

	/* 署名済みXMLを文字列で取得する */
	@Override
	public String saveXml() {
		String xml = null;
		try {
			byte[] utf8 = getXml();
			if(utf8 != null)
				xml = new String(utf8, "UTF-8");
			if(xml == null)
				setLastError(FXERR_XML_CONV);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			setLastError(FXERR_XML_CONV);
		}
		return xml;		
	}

	/* --------------------------------------------------------------------------- */
	/* 署名対象（Reference）の追加 */

	/* Detached(外部)署名対象の追加 */
	@Override
	public int addDetached(String target, int fxaType, int fxrFlag) {
		int rc = FXERR_NO_ERROR;
		DigestMethod dm = getDigestMethod();
		List<Transform> trForms = null;
		byte[] hash = null;

		switch(fxaType) {
		case FXAT_FILE_PATH:
			// 外部ファイル
			int flagMask = FXRF_TRANS_C14N | FXRF_TRANS_C14N_EX;
			if((fxrFlag & flagMask) != 0) {
				// C14N/C14N_EXの指定があった
				trForms = new ArrayList<Transform>();
				Transform c14n = getCanonicalMethod(fxrFlag);
				if(c14n == null)
					return getLastError();
				trForms.add(c14n);
			}
			break;
		case FXAT_XML_ID:
			// ID参照（うまく動作しないので自前でId要素を探しC14N正規化とハッシュ計算している）
			try {
				// 名前空間に依存しない為にXPathで検索
				XPathFactory xpf = XPathFactory.newInstance();
				XPath xp = xpf.newXPath();
				String xpath = "//*[@Id='" + target.substring(1) + "']";
				XPathExpression expr = xp.compile(xpath);
				Element elmt = (Element)expr.evaluate(signDoc_, XPathConstants.NODE);
				if(elmt == null)
					return setLastError(FXERR_ID_NOTFOUND);
				byte[] c14n = getC14N(elmt, fxrFlag);
				if(c14n == null)
					return getLastError();
				hash = getHash(c14n);
				if(hash == null)
					return getLastError();
			} catch (XPathExpressionException e) {
				e.printStackTrace();
				rc = FXERR_XML_XPATH;
			}
			if(hash == null)
				rc = FXERR_PKI_HASH;
			break;
		default:
			rc = FXERR_INVALID_ARG;
			break;
		}

		if(rc != FXERR_NO_ERROR)
			return setLastError(rc);

		Reference ref = null;
		if(hash != null) {
			// ハッシュ計算済み
			ref = sigFact_.newReference(target, dm, trForms, null, null, hash);
		} else {
			// ハッシュ計算は署名時に行う
			ref = sigFact_.newReference(target, dm, trForms, null, null);			
		}
		if(refs_ == null)
			refs_ = new ArrayList<Reference>();
		refs_.add(ref);
		return rc;
	}
	
	/* Enveloping(内部)署名対象の追加 */
	@Override
	public int addEnveloping(String target, int fxaType, int fxrFlag, String id) {
		int rc = FXERR_NO_ERROR;
		String Id = id;
		if(Id == null) {
			if(objs_ == null)
				Id = "Eping-Obj-0";
			else
				Id = "Eping-Obj-" + String.valueOf(objs_.size());
		}
		DigestMethod dm = getDigestMethod();
		List<Transform> trForms = null;
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		try {
			int flagMask = FXRF_TRANS_C14N | FXRF_TRANS_C14N_EX;
			if(fxaType == FXAT_XML_STRING || (fxrFlag & flagMask) != 0) {
				// XML
				trForms = new ArrayList<Transform>();
				Transform c14n = getCanonicalMethod(fxrFlag);
				if(c14n == null)
					return getLastError();
				trForms.add(c14n);
				byte[] xml = getBinary(target, fxaType);
				if(xml == null)
					return getLastError();
				ByteArrayInputStream inStream = new ByteArrayInputStream(xml);
				Document doc = dbf.newDocumentBuilder().parse(inStream);
				Element element = doc.getDocumentElement();
				XMLStructure content = new DOMStructure(element);
				XMLObject obj = sigFact_.newXMLObject(Collections.singletonList(content), Id, null, null);
				if(objs_ == null)
					objs_ = new ArrayList<XMLObject>();
				objs_.add(obj);
			} else {
				// DATA
				Document doc = dbf.newDocumentBuilder().newDocument();
				byte[] data = getBinary(target, fxaType);
				if((fxrFlag & FXRF_TRANS_BASE64) != 0) {
					// Base64化する
					trForms = new ArrayList<Transform>();
					Transform tr = sigFact_.newTransform(Transform.BASE64, (TransformParameterSpec)null);
					trForms.add(tr);
					String base64 = Base64.getEncoder().encodeToString(data);
					Node text = doc.createTextNode(base64);
					XMLStructure content = new DOMStructure(text);
					String mimeType = "text/plain";
					String Encoding = "http://www.w3.org/2000/09/xmldsig#base64";
					XMLObject obj = sigFact_.newXMLObject(Collections.singletonList(content), Id, mimeType, Encoding);
					if(objs_ == null)
						objs_ = new ArrayList<XMLObject>();
					objs_.add(obj);
				} else {
					// Base64化しない
					Node text = doc.createTextNode(new String(data, "UTF-8"));
					XMLStructure content = new DOMStructure(text);
					String mimeType = "text/plain";
					XMLObject obj = sigFact_.newXMLObject(Collections.singletonList(content), Id, mimeType, null);
					if(objs_ == null)
						objs_ = new ArrayList<XMLObject>();
					objs_.add(obj);
				}
			}
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			rc = FXERR_PKI_UNK_ALG;
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
			rc = FXERR_PKI_INVALID_ALG;
		} catch (IOException e) {
			e.printStackTrace();
			rc = FXERR_IO_EXCEPTION;
		} catch (Exception e) {
			e.printStackTrace();
			rc = FXERR_EXCEPTION;
		}
		if(rc != FXERR_NO_ERROR)
			return setLastError(rc);

		String refId = "#" + Id;
		String type = OBJECT_URI;
		Reference ref = sigFact_.newReference(refId, dm, trForms, type, null);
		if(refs_ == null)
			refs_ = new ArrayList<Reference>();
		refs_.add(ref);
		return rc;
	}

	/* Enveloped(内包)署名対象の追加 */
	@Override
	public int addEnveloped(String target, int fxaType, int fxrFlag, String xpath) {
		int rc = FXERR_NO_ERROR;
		DigestMethod dm = getDigestMethod();
		List<Transform> trForms = new ArrayList<Transform>();
		try {
			// Enveloped指定
			Transform eped = sigFact_.newTransform(Transform.ENVELOPED, (TransformParameterSpec)null);
			trForms.add(eped);
			// C14N正規化指定
			Transform c14n = getCanonicalMethod(fxrFlag);
			if(c14n == null)
				return getLastError();
			trForms.add(c14n);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			rc = FXERR_PKI_UNK_ALG;
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
			rc = FXERR_PKI_INVALID_ALG;
		}
		Reference ref = sigFact_.newReference("", dm, trForms, null, null);
		if(refs_ == null)
			refs_ = new ArrayList<Reference>();
		refs_.add(ref);
		return rc;
	}

	/* --------------------------------------------------------------------------- */
	/* 署名処理 */

	/* 署名を実行する */
	@Override
	public int execSign(String p12file, String p12pswd, int fxsFlag, String id, String xpath) {
		int rc = FXERR_NO_ERROR;

        String sigId = id;
        if(sigId == null)
        	sigId = "Signature1";

        if(refs_ == null)
			return setLastError(FXERR_NO_REFS);

		// PKCS#12ファイルから証明書と秘密鍵を取得
		String path = getPath(p12file);
		KeyStore ks = null;
		String myAlias = null;
		Certificate cert = null;
		PublicKey pubKey = null;
		PrivateKey privKey = null;
		try {
			// PKCS#12ファイルの確認
			ks = KeyStore.getInstance("PKCS12");
			FileInputStream fis;
			fis = new FileInputStream(path);
			ks.load(fis, p12pswd.toCharArray());
			for (Enumeration<String> e = ks.aliases(); e.hasMoreElements() ;)
			{
				String alias = e.nextElement();
				if(ks.getKey(alias, p12pswd.toCharArray()) != null)
				{
					myAlias = alias;	// PKCS#12ファイルに含まれ最初に秘密鍵を持つ証明書のalias名
					break;
				}
			}
			// 証明書と公開鍵と秘密鍵の取得
			cert = ks.getCertificate(myAlias);
			pubKey = cert.getPublicKey();
			privKey = (PrivateKey)ks.getKey(myAlias, p12pswd.toCharArray());
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
			rc = FXERR_FILE_NOTFOUND;
		} catch (IOException e1) {
			e1.printStackTrace();
			rc = FXERR_IO_EXCEPTION;
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
			rc = FXERR_PKI_UNK_ALG;
		} catch (CertificateException e1) {
			e1.printStackTrace();
			rc = FXERR_PKI_CERT;
		} catch (UnrecoverableKeyException e1) {
			e1.printStackTrace();
			rc = FXERR_PKI_KEY;
		} catch (KeyStoreException e1) {
			e1.printStackTrace();
			rc = FXERR_PKI_KEY_STORE;
		};
		if(rc != FXERR_NO_ERROR)
			return setLastError(rc);
		if(cert == null || pubKey == null || privKey == null)
			return setLastError(FXERR_ERROR);
		
		if((fxsFlag & FXSF_NO_XADES_OBJ) == 0) {
			// XAdESのオブジェクトと参照を追加
			rc = addXadesObject(sigId, cert, fxsFlag);
			if(rc != FXERR_NO_ERROR)
				return rc;
		}

		try {
			// ドキュメントの準備
			Node parent = null;
			if(signDoc_ == null) {
				// 新しいドキュメントを生成する（Enveloped/内部Detached以外）
		        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
				dbf.setNamespaceAware(true);
				signDoc_ = dbf.newDocumentBuilder().newDocument();
				parent = signDoc_;
			} else {
				if(xpath == null) {
					parent = signDoc_.getDocumentElement();
				} else {
					XPathFactory xpf = XPathFactory.newInstance();
					XPath xp = xpf.newXPath();
					try {
						XPathExpression expr = xp.compile(xpath);
						parent = (Node)expr.evaluate(signDoc_, XPathConstants.NODE);
					} catch (XPathExpressionException e) {
						e.printStackTrace();
						return setLastError(FXERR_XML_XPATH);
					}
				}
			}
			if(parent == null)
				return setLastError(FXERR_XML_PARENT);
			
			// KeyValue生成とKeyInfoを作成してセット
			KeyInfoFactory kif = sigFact_.getKeyInfoFactory();
			KeyValue keyValue = kif.newKeyValue(pubKey);
			X509Data certs = kif.newX509Data(Collections.singletonList(cert));
			List<XMLStructure> kis = new ArrayList<XMLStructure>();
			kis.add(keyValue);
			kis.add(certs);
			String keyId = id;
			if(keyId != null)
				keyId = keyId + "-key";
			KeyInfo keyInfo = kif.newKeyInfo(kis, keyId);

			// SignedInfoを生成する
			CanonicalizationMethod cm = getCanonicalMethod(fxsFlag);
			if(cm == null)
				return getLastError();
			SignatureMethod sm = getSignatureMethod();
			if(sm == null)
				return getLastError();
			SignedInfo signedInfo = sigFact_.newSignedInfo(cm, sm, refs_);

			// Signature要素を作成
			XMLSignature signature = sigFact_.newXMLSignature(signedInfo, keyInfo, objs_, sigId, null);

			// DOM用署名情報をセット
			DOMSignContext dsc = new DOMSignContext(privKey, parent);

			// 現在位置をセット(外部Detached用)
			String dir = rootDir_;
			if(dir == null)
				dir = ".";
			String cpath = new File(dir).getCanonicalPath();
			cpath = "file:///" + cpath.replace('\\', '/') + "/";
			dsc.setBaseURI(cpath);
			
			// 署名
			signature.sign(dsc);

		} catch (IOException e) {
			e.printStackTrace();
			rc = FXERR_FILE_READ;
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
			rc = FXERR_PKI_CONFIG;
		} catch (MarshalException e) {
			e.printStackTrace();
			rc = FXERR_XML_MARSHAL;
		} catch (XMLSignatureException e) {
			e.printStackTrace();
			rc = FXERR_PKI_SIGN;
		} catch (KeyException e) {
			e.printStackTrace();
			rc = FXERR_PKI_KEY;
		}
		if(rc != FXERR_NO_ERROR)
			return setLastError(rc);

		return rc;
	}

	/* XAdESオブジェクトの追加 */
	private int addXadesObject(String id, Certificate cert, int fxsFlag) {
		int rc = FXERR_NO_ERROR;
		if(id == null)
			return setLastError(FXERR_INVALID_ARG);
		String objId = id + "-XAdES-Obj";
		String xadesId = id + "-XAdES-SignProp";
		DigestMethod dm = getDigestMethod();
		List<Transform> trForms = null;
//		byte[] hash = new byte[32];
		byte[] hash = null;
		try {
			// XML
			trForms = new ArrayList<Transform>();
			Transform c14n = getCanonicalMethod(fxsFlag);
			if(c14n == null)
				return getLastError();
			trForms.add(c14n);
			// Object生成
	        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			Document doc = dbf.newDocumentBuilder().newDocument();
			Element element = makeXadesObjectElement(doc, id, xadesId, cert, fxsFlag);
			// ハッシュ計算
			NodeList list = element.getElementsByTagNameNS(XADES_V132, "SignedProperties");
			if(list == null || list.getLength() <= 0)
				return setLastError(FXERR_XML_NOTFOUND);
			Element target = (Element)list.item(0);
			byte[] c14nBin = getC14N(target, fxsFlag);
			if(c14nBin == null)
				return getLastError();
			hash = getHash(c14nBin);
			if(hash == null)
				return getLastError();
			// Object追加
			XMLStructure content = new DOMStructure(element);
			XMLObject obj = sigFact_.newXMLObject(Collections.singletonList(content), objId, null, null);
			if(objs_ == null)
				objs_ = new ArrayList<XMLObject>();
			objs_.add(0, obj);
		} catch (Exception e) {
			e.printStackTrace();
			rc = FXERR_EXCEPTION;
		}
		if(rc != FXERR_NO_ERROR)
			return setLastError(rc);

		String refId = "#" + xadesId;
		String type = XADES_SIGN_PROP;
		Reference ref = sigFact_.newReference(refId, dm, trForms, type, null, hash);
		if(refs_ == null)
			refs_ = new ArrayList<Reference>();
		refs_.add(ref);
		return rc;
	}

	/* XAdESオブジェクト要素の生成 */
	private Element makeXadesObjectElement(Document doc, String id, String xadesId, Certificate cert, int fxsFlag) {
		Element content = null;
		Element root = doc.createElementNS(XADES_V132, "QualifyingProperties");
		root.setAttribute("Target", "#" + id);
		Element sp = doc.createElementNS(XADES_V132, "SignedProperties");
		sp.setAttribute("Id", xadesId);
		Element ssp = doc.createElementNS(XADES_V132, "SignedSignatureProperties");
		Element sc = makeSigningCertificate(doc, ssp, cert);
		ssp.appendChild(sc);
		if((fxsFlag & FXSF_NO_SIGN_TIME) == 0) {
			Element st = makeSigningTime(doc, ssp);
			ssp.appendChild(st);			
		}
		sp.appendChild(ssp);
		root.appendChild(sp);
		doc.appendChild(root);
		content = doc.getDocumentElement();

        return content;
	}
	
	/* XAdESオブジェクト要素の生成 */
	private Element makeSigningCertificate(Document doc, Element parent, Certificate cert) {
		Element st = null;
		try {
			st = doc.createElementNS(XADES_V132, "SigningCertificate");
			Element ct = doc.createElementNS(XADES_V132, "Cert");
			// CertDigest
			Element cd = doc.createElementNS(XADES_V132, "CertDigest");
			DigestMethod dm = getDigestMethod();
			Element dme = doc.createElementNS(XMLSignature.XMLNS, "DigestMethod");
			dme.setAttribute("Algorithm", dm.getAlgorithm());
			cd.appendChild(dme);
			Element dve = doc.createElementNS(XMLSignature.XMLNS, "DigestValue");
			byte[] certBin = cert.getEncoded();
			byte[] hash = getHash(certBin);
			String base64 = Base64.getEncoder().encodeToString(hash);
			Node hashText = doc.createTextNode(base64);
			dve.appendChild(hashText);
			cd.appendChild(dve);
			ct.appendChild(cd);
			// IssuerSerial
			Element is = doc.createElementNS(XADES_V132, "IssuerSerial");
			Element in = doc.createElementNS(XMLSignature.XMLNS, "X509IssuerName");
			X509Certificate x509cert = X509Certificate.getInstance(certBin);
			String issuer = x509cert.getIssuerDN().getName();
			Node issText = doc.createTextNode(issuer);
			in.appendChild(issText);
			is.appendChild(in);
			Element sn = doc.createElementNS(XMLSignature.XMLNS, "X509SerialNumber");
			BigInteger snum = x509cert.getSerialNumber();
			String serial = snum.toString();
			Node serText = doc.createTextNode(serial);
			sn.appendChild(serText);
			is.appendChild(sn);
			ct.appendChild(is);
			st.appendChild(ct);
		} catch (javax.security.cert.CertificateException e) {
			e.printStackTrace();
			setLastError(FXERR_PKI_CERT);
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
			setLastError(FXERR_PKI_CERT);
		}
        return st;
	}
	
	/* XAdESオブジェクト要素の生成 */
	private Element makeSigningTime(Document doc, Element parent) {
		Element st = null;
		st = doc.createElementNS(XADES_V132, "SigningTime");
		Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
		SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
		df.setTimeZone(cal.getTimeZone());
		String sigTime = df.format(cal.getTime());
		Node timeText = doc.createTextNode(sigTime);
		st.appendChild(timeText);
		return st;
	}
	
	/* --------------------------------------------------------------------------- */
	/* 署名タイムスタンプ処理 */

	/* 署名タイムスタンプを追加する */
	@Override
	public int addEsT(String tsUrl, String bUser, String bPswd, String id, String xpath)
	{
		int rc = FXVS_NO_SIGN;

		// Signature要素を探す
		NodeList nl = signDoc_.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
		if (nl.getLength() == 0)
		{
			// Signature要素が見つからない
            return setLastError(rc);
		}

		Node target = nl.item(0);	// 仮：最初の署名に署名タイムスタンプを付与する
		byte[] sigValue = getSignatureValue(target);
		if(sigValue == null)
			return setLastError(FXERR_GET_SIGVALUE);
		byte[] hash = getHash(sigValue);

		// nonceの生成
		byte[] nonce = new byte[8];
		new Random().nextBytes(nonce);

		// タイムスタンプリクエストの生成
		byte[] req = makeRequest(hash, nonce);
		if(req == null)
			setLastError(FXERR_EST_TSREQ);

		// タイムスタンプサーバ接続
		byte[] resp = httpConnect(tsUrl, req);
		if(resp == null)
			setLastError(FXERR_EST_CONNECT);

		// タイムスタンプレスポンスの解析（タイムスタンプトークン取得）
		byte[] tst = parseResponse(resp, nonce);
		if(tst == null)
			setLastError(FXERR_EST_TSRES);

		// タイムスタンプトークンの出力
		rc = addEstTst(target, tst);
		if(rc < 0)
			setLastError(rc);

		return FXERR_NO_ERROR;
	}

	/* バイナリ形式でのSignatureValueの取得 */
	private byte[] getSignatureValue(Node sign)
	{
		byte[] value = null;
		if(sign == null)
			return value;
		
		NodeList list = sign.getChildNodes();
		for (int i=0; i<list.getLength(); i++)
		{
			Node node = list.item(i);
			if(node.getNodeName() == "SignatureValue")
			{
				Node target = node.getFirstChild();
				String b64 = target.getNodeValue();
				if(b64 == null)
					return value;
				value = Base64.getMimeDecoder().decode(b64);
				break;
			}
		}
		return value;
	}

	/* TSTの埋め込み */
	private int addEstTst(Node sign, byte[] tst)
	{
		int rc = FXERR_NO_ERROR;
		if(sign == null)
			return FXERR_INVALID_ARG;

		return rc;
	}

	NodeList getNodesByPath(Node node, String path)
	{
		NodeList list = null;

		
//		Element elmt = (Element)node;
		
//		list = elmt.getElementsByTagName(path);
		return list;
	}
	
	/* --------------------------------------------------------------------------- */
	/* 検証処理 */

	/* 署名を検証する（仮） */
	@Override
	public int verifySign(int fxvFlag, String xpath) {
		// FXVS_VALID / FXVS_INVALID / FXVS_NO_SIGN
		int rc = FXVS_NO_SIGN;

		// Signature要素を探す
		NodeList nl = signDoc_.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
		if (nl.getLength() == 0)
		{
			// Signature要素が見つからない
            return rc;
		}

		for(int i=0; i<nl.getLength(); i++)
		{
			try {
				// 検証対象と鍵取得クラスを取得
				Node target = nl.item(i);
				DOMValidateContext valContext = new DOMValidateContext(new KeyValueKeySelector(), target);
				
				// 現在位置をセット(外部Detached用)
				String dir = rootDir_;
				if(dir == null)
					dir = ".";
				String cpath = new File(dir).getCanonicalPath();
				cpath = "file:///" + cpath.replace('\\', '/') + "/";
				valContext.setBaseURI(cpath);

				// XML から XMLSignature を非整列化する
				XMLSignature signature = sigFact_.unmarshalXMLSignature(valContext);

				// 検証実行
				boolean coreValidity = false;
				try {
					coreValidity = signature.validate(valContext);
				} catch(XMLSignatureException e) {
//					e.printStackTrace();					
				}

				if (coreValidity == false) {
					// 検証失敗
					boolean sigVerify = signature.getSignatureValue().validate(valContext);
					if(sigVerify == false) {
						rc = FXVS_INVALID;
					} else {
						// ToDo: 内部DetachedはおそらくIdが見つからないようだ。
						// Reference先をチェック
						/*
						Iterator<Reference> it = signature.getSignedInfo().getReferences().iterator();
						for (int j = 0; it.hasNext(); j++)
						{
							boolean refValid = (it.next()).validate(valContext);
							System.out.println(" Reference[" + j + "] validity status: " + refValid);
						}
						*/
						rc = FXVS_VALID;
					}
				} else {
					// 検証成功
					rc = FXVS_VALID;
				}
			} catch (IOException e) {
				e.printStackTrace();
				rc = FXVS_INVALID;
			} catch (XMLSignatureException e) {
				e.printStackTrace();
				rc = FXVS_INVALID;
			} catch (Exception e) {
				e.printStackTrace();
				rc = FXVS_INVALID;
			}
		}		
		
		return rc;
	}

    // ---------------------------------------------------------------------------
    // 検証用の鍵取得クラス（最もシンプルな実装）
	public static class KeyValueKeySelector extends KeySelector
	{
		@SuppressWarnings("unchecked")
		public KeySelectorResult select(
				KeyInfo keyInfo,
				KeySelector.Purpose purpose,
				AlgorithmMethod method,
				XMLCryptoContext context) throws KeySelectorException
		{
			List<XMLStructure> list = keyInfo.getContent();

			for (int i = 0; i < list.size(); i++)
			{
				XMLStructure xmlStructure = list.get(i);
				if (xmlStructure instanceof KeyValue)
				{
					PublicKey pubKey = null;
					try
					{
						// 公開鍵の取得
						pubKey = ((KeyValue)xmlStructure).getPublicKey();
					}
					catch (KeyException ke)
					{
						throw new KeySelectorException(ke);
					}
					// 署名アルゴリズムの確認
					if(pubKey.getAlgorithm().equalsIgnoreCase("RSA"))
						return new SimpleKeySelectorResult(pubKey);		// OK!!
				}
			}
			throw new KeySelectorException("No KeyValue element found!");
		}
	}

    // ---------------------------------------------------------------------------
    // 検証用の鍵戻しクラス（最もシンプルな実装）
	private static class SimpleKeySelectorResult implements KeySelectorResult
	{
		private PublicKey pubKey;

		SimpleKeySelectorResult(PublicKey pubKey)
		{
			this.pubKey = pubKey;
		}

		public Key getKey()
		{
			return pubKey;
		}
	}

	/* --------------------------------------------------------------------------- */
	/* 補助 */

	/* URIの基点となるルートディレクトリを指定 */
	@Override
	public void setRootDir(String rootDir) {
		rootDir_ = rootDir;
	}
	
	/* ハッシュ計算/署名計算時に使われるハッシュアルゴリズムを指定 */
	@Override
	public void setHashAlg(String hashAlg) {
		hashAlg_ = hashAlg;
	}

	/* --------------------------------------------------------------------------- */
	/* エラー処理 */

	private	int lastError_ = FXERR_NO_ERROR;				// 最後のエラー値を保持
	public int getLastError() { return lastError_; }		// 最後のエラー値を取得
	public void clearLastError() {							// 最後のエラー値をクリア
		lastError_ = FXERR_NO_ERROR;
	}
	private int setLastError(int fxerr) {					// エラー値セット(内部用)
		lastError_ = fxerr;
		return fxerr;
	}
	
	/* --------------------------------------------------------------------------- */
	/* 内部補助 */

	/* ルートディレクトリも考慮したパスを返す */
	private String getPath(String file) {
		String path = file;
		if(rootDir_ != null && file.charAt(0) != '/' && file.charAt(0) != '\\') {
			path = rootDir_ + file;
		}
		return path;
	}
	
	/* ファイル/文字列からのバイナリ取得 */
	private byte[] getBinary(String target, int fxaType) {
		byte[] bin = null;
		if(fxaType == FXAT_FILE_PATH) {
			// ファイルからの読み込み
			String path = getPath(target);
			File inFile = new File(path);
			FileInputStream fis = null;
			try {
				fis = new FileInputStream(inFile);
			} catch (FileNotFoundException e1) {
				e1.printStackTrace();
				setLastError(FXERR_FILE_NOTFOUND);
			}
			BufferedInputStream bis = new BufferedInputStream(fis);
			try {
				bin = new byte[bis.available()];
				bis.read(bin);
				bis.close();
			} catch (IOException e1) {
				e1.printStackTrace();
				setLastError(FXERR_FILE_READ);
			}
		} else if(fxaType == FXAT_XML_STRING || fxaType == FXAT_DATA_STRING) {
			try {
				bin = target.getBytes("UTF-8");
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
				setLastError(FXERR_EXCEPTION);
			}
		} else {
			setLastError(FXERR_INVALID_ARG);
		}
		return bin;
	}

	/* C14N正規化メソッド取得 */
	private CanonicalizationMethod getCanonicalMethod(int fxrFlag) {
		CanonicalizationMethod cm = null;
		try {
			if((fxrFlag & FXRF_TRANS_C14N_EX) != 0) {
				cm = sigFact_.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec)null);
			} else {
				cm = sigFact_.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec)null);
			}
		} catch (Exception e) {
			e.printStackTrace();
			setLastError(FXERR_PKI_INVALID_ALG);
		}				
		return cm;
	}

	/* 署名メソッド取得 */
	private SignatureMethod getSignatureMethod() {
		SignatureMethod sm = null;
		try {
			if(hashAlg_ == null || hashAlg_ == DigestMethod.SHA256) {
				sm = sigFact_.newSignatureMethod(RSA_SHA256, null);
//			} else if(hashAlg_ == DigestMethod.SHA384) {	// 未サポート
//				sm = sigFact_.newSignatureMethod(RSA_SHA384, null);				
			} else if(hashAlg_ == DigestMethod.SHA512) {
				sm = sigFact_.newSignatureMethod(RSA_SHA512, null);				
			} else if(hashAlg_ == DigestMethod.SHA1) {
				sm = sigFact_.newSignatureMethod(SignatureMethod.RSA_SHA1, null);	// 非推奨
			} else {
				setLastError(FXERR_PKI_UNK_ALG);
			}
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			setLastError(FXERR_PKI_UNK_ALG);
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
			setLastError(FXERR_PKI_INVALID_ALG);
		}				
		return sm;
	}

	/* ハッシュメソッド取得 */
	private DigestMethod getDigestMethod() {
		DigestMethod dm = null;
		try {
			if(hashAlg_ == null || hashAlg_ == DigestMethod.SHA256) {
				dm = sigFact_.newDigestMethod(DigestMethod.SHA256, null);
//			} else if(hashAlg_ == DigestMethod.SHA384) {	// 未サポート
//				dm = sigFact_.newDigestMethod(DigestMethod.SHA384, null);
			} else if(hashAlg_ == DigestMethod.SHA512) {
				dm = sigFact_.newDigestMethod(DigestMethod.SHA512, null);
			} else if(hashAlg_ == DigestMethod.SHA1) {
				dm = sigFact_.newDigestMethod(DigestMethod.SHA1, null);		// 非推奨
			} else {
				setLastError(FXERR_PKI_UNK_ALG);
			}
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			setLastError(FXERR_PKI_UNK_ALG);
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
			setLastError(FXERR_PKI_INVALID_ALG);
		}
		return dm;
	}
	
	/* ハッシュ計算 */
	private byte[] getHash(byte[] data) {
		byte[] hash = null;
		MessageDigest md = null;
		try {
			if(hashAlg_ == null || hashAlg_ == DigestMethod.SHA256 ) {
				md = MessageDigest.getInstance("SHA-256");
//			} else if(hashAlg_ == DigestMethod.SHA384) {	// 未サポート
//				md = MessageDigest.getInstance("SHA-384");
			} else if(hashAlg_ == DigestMethod.SHA512) {
				md = MessageDigest.getInstance("SHA-512");
			} else if(hashAlg_ == DigestMethod.SHA1) {
				md = MessageDigest.getInstance("SHA-1");
			} else {
				setLastError(FXERR_PKI_UNK_ALG);
				return hash;
			}
	        md.update(data);
	        hash = md.digest();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			setLastError(FXERR_PKI_UNK_ALG);
		}
        return hash;
	}
	
	/* ElementのC14N正規化処理 */
	private byte[] getC14N(Element elmt, int fxrFlag) {
		byte[] c14n = null;
		try {
			// Elementをバイナリへ変換
			ByteArrayOutputStream bs = new ByteArrayOutputStream();
			TransformerFactory tff = TransformerFactory.newInstance();
			Transformer tf = tff.newTransformer();
			tf.transform(new DOMSource(elmt), new StreamResult(bs));
			// C14N正規化
	    	ByteArrayInputStream inStream = new ByteArrayInputStream(bs.toByteArray());
			XMLSignatureFactory xsf = XMLSignatureFactory.getInstance("DOM");
	    	CanonicalizationMethod cm = xsf.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec)null);
	    	OctetStreamData rsltData = (OctetStreamData)cm.transform(new OctetStreamData(inStream), null);
	    	// 正規化済みバイナリの取得
	    	InputStream rsltStream = rsltData.getOctetStream();
	    	c14n = new byte[rsltStream.available()];
	    	rsltStream.read(c14n);
		} catch (IOException e) {
			e.printStackTrace();
			setLastError(FXERR_IO_EXCEPTION);
		} catch (Exception e) {
			e.printStackTrace();
			setLastError(FXERR_XML_C14N);
		}
		return c14n;
	}

	/* --------------------------------------------------------------------------- */
	/* タイムスタンプ補助 */

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
			byte[] hash,			// 20/32/64 バイト
			byte[] nonce			// 8 バイト
			)
	{
		byte[] req = null;

		// SHA-1 リクエスト情報定義
		byte[] sha1req = {
				0x30, 0x31,							// Request SEQUENCE (49バイト)
				0x02, 0x01, 0x01,					// Version INTEGER (1バイト) value: 1
				0x30, 0x1f,							// MessageImprint SEQUENCE (31バイト)
				0x30, 0x07,							// AlgorithmOID SEQUENCE (7バイト)
				0x06, 0x05,							// OID (5バイト)
				0x2b, 0x0e, 0x03, 0x02, 0x1a,		// OIDSHA1 value: 1.3.14.3.2.26
				0x04, 0x14,							// Hash OCTET STRING (20バイト)
				0x00, 0x00, 0x00, 0x00, 0x00,		// Placeholders for Hash (+18バイト)
				0x00, 0x00, 0x00, 0x00, 0x00,		// 10
				0x00, 0x00, 0x00, 0x00, 0x00,		// 15
				0x00, 0x00, 0x00, 0x00, 0x00,		// 20
				0x02, 0x08,							// Nonce INTEGER (8バイト)
				0x00, 0x00,	0x00, 0x00, 0x00,		// Placeholders for Nonce (+40バイト)
				0x00, 0x00, 0x00,					// 8
				0x01, 0x01,	(byte)0xff				// RequestCertificate BOOLEAN (1バイト) value: true
		};

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
	            if( nonce.length == 8 )
	            	System.arraycopy( nonce, 0, req, 88, nonce.length );	// 乱数値のセット
			} else if( hash.length == 32 ) {
				// SHA-256
				req = sha256req;
	            System.arraycopy( hash, 0, req, 22, hash.length );			// ハッシュ値のセット
	            if( nonce.length == 8 )
	            	System.arraycopy( nonce, 0, req, 56, nonce.length );	// 乱数値のセット
			} else if( hash.length == 20 ) {
				// SHA-1
				req = sha1req;
	            System.arraycopy( hash, 0, req, 18, hash.length );			// ハッシュ値のセット
	            if( nonce.length == 8 )
	            	System.arraycopy( nonce, 0, req, 40, nonce.length );	// 乱数値のセット
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
			byte[] send
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
