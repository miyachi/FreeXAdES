/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package jp.langedge.FreeXAdES;

import java.io.*;
import java.math.BigInteger;
import java.util.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;	// ��������ׂɃC���|�[�g
import java.text.SimpleDateFormat;

import javax.security.cert.X509Certificate;
import javax.xml.crypto.*;
import javax.xml.crypto.dom.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.*;
import javax.xml.crypto.dsig.keyinfo.*;
import javax.xml.crypto.dsig.spec.*;
import javax.xml.namespace.*;
import javax.xml.parsers.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.*;
import javax.xml.transform.stream.*;
import javax.xml.xpath.*;
import org.w3c.dom.*;				// Document�N���X���ɗ��p

/**
 * FreeXAdES : FreeXAdES main implement class.
 * @author miyachi
 *
 */
public class FreeXAdES implements IFreeXAdES {

	/** �v���C�x�[�g�v�f.
	 */
	private XMLSignatureFactory sigFact_ = null;			// XML�����t�@�N�g��
	private Document signDoc_ = null;						// ���C���h�L�������g
	private String hashAlg_ = null;							// �n�b�V������
	private List<Reference> refs_ = null;					// �Q��
	private List<XMLObject> objs_ = null;					// �I�u�W�F�N�g
	private String rootDir_ = null;							// �x�[�X�ɂȂ郋�[�g�f�B���N�g��
	
	/* --------------------------------------------------------------------------- */
	/* �R���X�g���N�^�� */
	
	/* �R���X�g���N�^ */
	public FreeXAdES() {
		clear();
        // XMLSignatureFactory��DOM�������擾����
		sigFact_ = XMLSignatureFactory.getInstance("DOM");
	}

	/* �t�@�C�i���C�Y */
	public void finalize () {
		clear();
		sigFact_ = null;
	}

	/* �N���A */
	private void clear() {
		clearLastError();
		signDoc_ = null;
		hashAlg_ = null;
		refs_ = null;
		objs_ = null;
		rootDir_ = null;
	}

	/* --------------------------------------------------------------------------- */
	/* ����XML�̃Z�b�g */
	
	/* ����XML���Z�b�g���� */
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
	
	/* ����XML�̓ǂݍ��� */
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
	/* ����XML�̎擾 */

	/* �����ς�XML���擾���� */
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

	/* �����ς�XML���t�@�C���ۑ����� */
	@Override
	public int saveXml(String path) {
		// XML�����������o�́B
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

	/* �����ς�XML�𕶎���Ŏ擾���� */
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
	/* �����ΏہiReference�j�̒ǉ� */

	/* Detached(�O��)�����Ώۂ̒ǉ� */
	@Override
	public int addDetached(String target, int fxaType, int fxrFlag) {
		int rc = FXERR_NO_ERROR;
		DigestMethod dm = getDigestMethod();
		List<Transform> trForms = null;
		byte[] hash = null;

		switch(fxaType) {
		case FXAT_FILE_PATH:
			// �O���t�@�C��
			int flagMask = FXRF_TRANS_C14N | FXRF_TRANS_C14N_EX;
			if((fxrFlag & flagMask) != 0) {
				// C14N/C14N_EX�̎w�肪������
				trForms = new ArrayList<Transform>();
				Transform c14n = getCanonicalMethod(fxrFlag);
				if(c14n == null)
					return getLastError();
				trForms.add(c14n);
			}
			break;
		case FXAT_XML_ID:
			// ID�Q�Ɓi���܂����삵�Ȃ��̂Ŏ��O��Id�v�f��T��C14N���K���ƃn�b�V���v�Z���Ă���j
			try {
				// ���O��ԂɈˑ����Ȃ��ׂ�XPath�Ō���
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
			// �n�b�V���v�Z�ς�
			ref = sigFact_.newReference(target, dm, trForms, null, null, hash);
		} else {
			// �n�b�V���v�Z�͏������ɍs��
			ref = sigFact_.newReference(target, dm, trForms, null, null);			
		}
		if(refs_ == null)
			refs_ = new ArrayList<Reference>();
		refs_.add(ref);
		return rc;
	}
	
	/* Enveloping(����)�����Ώۂ̒ǉ� */
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
					// Base64������
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
					// Base64�����Ȃ�
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

	/* Enveloped(����)�����Ώۂ̒ǉ� */
	@Override
	public int addEnveloped(String target, int fxaType, int fxrFlag, String xpath) {
		int rc = FXERR_NO_ERROR;
		DigestMethod dm = getDigestMethod();
		List<Transform> trForms = new ArrayList<Transform>();
		try {
			// Enveloped�w��
			Transform eped = sigFact_.newTransform(Transform.ENVELOPED, (TransformParameterSpec)null);
			trForms.add(eped);
			// C14N���K���w��
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
	/* �������� */

	/* ���������s���� */
	@Override
	public int execSign(String p12file, String p12pswd, int fxsFlag, String id, String xpath) {
		int rc = FXERR_NO_ERROR;

        String sigId = id;
        if(sigId == null)
        	sigId = "Signature1";

        if(refs_ == null)
			return setLastError(FXERR_NO_REFS);

		// PKCS#12�t�@�C������ؖ����Ɣ閧�����擾
		String path = getPath(p12file);
		KeyStore ks = null;
		String myAlias = null;
		Certificate cert = null;
		PublicKey pubKey = null;
		PrivateKey privKey = null;
		try {
			// PKCS#12�t�@�C���̊m�F
			ks = KeyStore.getInstance("PKCS12");
			FileInputStream fis;
			fis = new FileInputStream(path);
			ks.load(fis, p12pswd.toCharArray());
			for (Enumeration<String> e = ks.aliases(); e.hasMoreElements() ;)
			{
				String alias = e.nextElement();
				if(ks.getKey(alias, p12pswd.toCharArray()) != null)
				{
					myAlias = alias;	// PKCS#12�t�@�C���Ɋ܂܂�ŏ��ɔ閧�������ؖ�����alias��
					break;
				}
			}
			// �ؖ����ƌ��J���Ɣ閧���̎擾
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
			// XAdES�̃I�u�W�F�N�g�ƎQ�Ƃ�ǉ�
			rc = addXadesObject(sigId, cert, fxsFlag);
			if(rc != FXERR_NO_ERROR)
				return rc;
		}

		try {
			// �h�L�������g�̏���
			Node parent = null;
			if(signDoc_ == null) {
				// �V�����h�L�������g�𐶐�����iEnveloped/����Detached�ȊO�j
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
			
			// KeyValue������KeyInfo���쐬���ăZ�b�g
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

			// SignedInfo�𐶐�����
			CanonicalizationMethod cm = getCanonicalMethod(fxsFlag);
			if(cm == null)
				return getLastError();
			SignatureMethod sm = getSignatureMethod();
			if(sm == null)
				return getLastError();
			SignedInfo signedInfo = sigFact_.newSignedInfo(cm, sm, refs_);

			// Signature�v�f���쐬
			XMLSignature signature = sigFact_.newXMLSignature(signedInfo, keyInfo, objs_, sigId, null);

			// DOM�p���������Z�b�g
			DOMSignContext dsc = new DOMSignContext(privKey, parent);

			// ���݈ʒu���Z�b�g(�O��Detached�p)
			String dir = rootDir_;
			if(dir == null)
				dir = ".";
			String cpath = new File(dir).getCanonicalPath();
			cpath = "file:///" + cpath.replace('\\', '/') + "/";
			dsc.setBaseURI(cpath);
			
			// ����
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

	/* XAdES�I�u�W�F�N�g�̒ǉ� */
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
			// Object����
	        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			Document doc = dbf.newDocumentBuilder().newDocument();
			Element element = makeXadesObjectElement(doc, id, xadesId, cert, fxsFlag);
			// �n�b�V���v�Z
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
			// Object�ǉ�
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

	/* XAdES�I�u�W�F�N�g�v�f�̐��� */
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
	
	/* XAdES�I�u�W�F�N�g�v�f�̐��� */
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
	
	/* XAdES�I�u�W�F�N�g�v�f�̐��� */
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
	/* �����^�C���X�^���v���� */

	/* �����^�C���X�^���v��ǉ����� */
	@Override
	public int addEsT(String tsUrl, String bUser, String bPswd, String id, String xpath)
	{
		int rc = FXVS_NO_SIGN;

		// Signature�v�f��T��
		NodeList nl = signDoc_.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
		if (nl.getLength() == 0)
		{
			// Signature�v�f��������Ȃ�
            return setLastError(rc);
		}

		// �^�C���X�^���v�Ώۃn�b�V���l�̎擾
		Node target = nl.item(0);	// ���F�ŏ��̏����ɏ����^�C���X�^���v��t�^����
		byte[] sigValue = getSignatureValue(target);
		if(sigValue == null)
			return setLastError(FXERR_GET_SIGVALUE);
		byte[] hash = getHash(sigValue);

		// �^�C���X�^���v�g�[�N���̎擾
		FreeTimeStamp timestamp = new FreeTimeStamp();
		rc = timestamp.getFromServer(hash, tsUrl, bUser, bPswd);
		if(rc != 0)
			return setLastError(rc);
		byte[] tst = timestamp.getToken();
		
		// �^�C���X�^���v�g�[�N���̏o��
		rc = addEstTst(target, tst, id);
		if(rc < 0)
			setLastError(rc);

		return FXERR_NO_ERROR;
	}

	/* �o�C�i���`���ł�SignatureValue�̎擾 */
	private byte[] getSignatureValue(Node sign)
	{
		byte[] value = null;
		if(sign == null)
			return value;
		
		NodeList list = sign.getChildNodes();
		for (int i=0; i<list.getLength(); i++)
		{
			Node node = list.item(i);
			if("SignatureValue".equals(node.getNodeName()))
			{
				value = getC14N((Element) node, FXRF_TRANS_C14N);
				break;
			}
		}
		return value;
	}

	/* TST�̖��ߍ��� */
	private int addEstTst(Node sign, byte[] tst, String id)
	{
		int rc = FXERR_NO_ERROR;

		if(sign == null)
			return FXERR_INVALID_ARG;

		String path = "ds:Object/xsd:QualifyingProperties";
		NodeList list = getNodesByPath(sign, path);
		if(list == null || list.getLength() <= 0)
			return FXERR_EST_OBJECT;
		
		String path2 = path + "/xsd:UnsignedProperties";
		NodeList list2 = getNodesByPath(sign, path2);
		Node unsign = null;
		if(list2 == null || list2.getLength() <= 0) {
			Node qp = list.item(0);
			Element up = signDoc_.createElementNS(XADES_V132, "xsd:UnsignedProperties");
			up.setPrefix("");
			qp.appendChild(up);
			unsign = up;
		} else {
			unsign = list2.item(0);
		}
		
		String path3 = path2 + "/xsd:UnsignedSignatureProperties";
		NodeList list3 = getNodesByPath(sign, path3);
		Node usp = null;
		if(list3 == null || list3.getLength() <= 0) {
			Element usp2 = signDoc_.createElementNS(XADES_V132, "xsd:UnsignedSignatureProperties");
			usp2.setPrefix("");
			unsign.appendChild(usp2);
			usp = usp2;
		} else {
			usp = list3.item(0);
		}
		
		String path4 = path3 + "/xsd:SignatureTimeStamp";
		NodeList list4 = getNodesByPath(sign, path4);
		if(list4 != null && list4.getLength() > 0)
			return FXERR_EST_NODE;

		Element sts = signDoc_.createElementNS(XADES_V132, "xsd:SignatureTimeStamp");
		sts.setPrefix("");
		if(id != null)
			sts.setAttribute("Id", id);
		usp.appendChild(sts);
		
		Element ets = signDoc_.createElementNS(XADES_V132, "xsd:EncapsulatedTimeStamp");
		ets.setPrefix("");
		sts.appendChild(ets);

		String b64 = Base64.getMimeEncoder().encodeToString(tst);
		Node tstText = signDoc_.createTextNode(b64);
		ets.appendChild(tstText);

		return rc;
	}

	/* node�ʒu����XPath���擾 */
	private String getXPath(Node node, String xpath)
	{
		if(node == null || node.getLocalName() == null)
			return xpath;
		
		int count = 1;
		String name = node.getLocalName();
		Node prev = node.getPreviousSibling();
		while(prev != null && name != null) {
			if(name.equals(prev.getLocalName()))
				count++;
			prev = prev.getPreviousSibling();
		}
		String prefix = null;
		String uri = node.getNamespaceURI();
		if(uri != null) {
			if(XML_DSIG.equals(uri))
				prefix = "ds:";
			else if(XADES_V132.equals(uri))
				prefix = "xsd:";
			else if(XADES_V141.equals(uri))
				prefix = "xsd141:";
		}
		if(prefix != null)
			name = prefix + name;
		name = "/" + name;
		if(count > 1)
			name += "[" + count + "]";
		if(xpath == null)
			xpath = name;
		else
			xpath = name + xpath;

		return getXPath(node.getParentNode(), xpath);
	}
	
	private NodeList getNodesByPath(Node node, String path)
	{
		NodeList list = null;

		if(path.charAt(0) != '/') {
			String root = getXPath(node, null);
			path = root + "/" + path;
		}
        XPathFactory factory = XPathFactory.newInstance();
        XPath xpath = factory.newXPath();
        xpath.setNamespaceContext(new NamespaceContext() {
            public String getNamespaceURI(String prefix) {
              if (prefix == null)
                throw new IllegalArgumentException();
              else if ("ds".equals(prefix))
                  return XML_DSIG;
              else if ("xsd".equals(prefix))
                  return XADES_V132;
              else if ("xsd141".equals(prefix))
                  return XADES_V141;
              return null;
            }
            public String getPrefix(String namespaceURI) {
              if (namespaceURI == null)
                throw new IllegalArgumentException();
              else if (XML_DSIG.equals(namespaceURI))
                  return "ds";
              else if (XADES_V132.equals(namespaceURI))
                  return "xsd";
              else if (XADES_V141.equals(namespaceURI))
                  return "xsd141";
              return null;
            }
            public Iterator<String> getPrefixes(String namespaceURI) {
              if (namespaceURI == null)
                throw new IllegalArgumentException();
              else if (XML_DSIG.equals(namespaceURI))
                  return Arrays.asList("ds").iterator();
              else if (XADES_V132.equals(namespaceURI))
                  return Arrays.asList("xsd").iterator();
              else if (XADES_V141.equals(namespaceURI))
                  return Arrays.asList("xsd141").iterator();
              return null;
            }
        });
        try {
        	list = (NodeList)xpath.evaluate(path, signDoc_, XPathConstants.NODESET);
        	int num = list.getLength();
        	System.out.println( "DEBUG: num = " + num );
		} catch (XPathExpressionException e) {
			e.printStackTrace();
			list = null;
		}
		return list;
	}
	
	/* --------------------------------------------------------------------------- */
	/* ���؏��� */

	/* ���������؂���i���j */
	@Override
	public int verifySign(int fxvFlag, String xpath) {
		// FXVS_VALID / FXVS_INVALID / FXVS_NO_SIGN
		int rc = FXVS_NO_SIGN;

		// Signature�v�f��T��
		NodeList nl = signDoc_.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
		if (nl.getLength() == 0)
		{
			// Signature�v�f��������Ȃ�
            return rc;
		}

		for(int i=0; i<nl.getLength(); i++)
		{
			try {
				// ���ؑΏۂƌ��擾�N���X���擾
				Node target = nl.item(i);
				DOMValidateContext valContext = new DOMValidateContext(new KeyValueKeySelector(), target);
				
				// ���݈ʒu���Z�b�g(�O��Detached�p)
				String dir = rootDir_;
				if(dir == null)
					dir = ".";
				String cpath = new File(dir).getCanonicalPath();
				cpath = "file:///" + cpath.replace('\\', '/') + "/";
				valContext.setBaseURI(cpath);

				// XML ���� XMLSignature ��񐮗񉻂���
				XMLSignature signature = sigFact_.unmarshalXMLSignature(valContext);

				// ���؎��s
				boolean coreValidity = false;
				try {
					coreValidity = signature.validate(valContext);
				} catch(XMLSignatureException e) {
//					e.printStackTrace();					
				}

				if (coreValidity == false) {
					// ���؎��s
					boolean sigVerify = signature.getSignatureValue().validate(valContext);
					if(sigVerify == false) {
						rc = FXVS_INVALID;
					} else {
						// ToDo: ����Detached�͂����炭Id��������Ȃ��悤���B
						// Reference����`�F�b�N
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
					// ���ؐ���
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
    // ���ؗp�̌��擾�N���X�i�ł��V���v���Ȏ����j
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
						// ���J���̎擾
						pubKey = ((KeyValue)xmlStructure).getPublicKey();
					}
					catch (KeyException ke)
					{
						throw new KeySelectorException(ke);
					}
					// �����A���S���Y���̊m�F
					if(pubKey.getAlgorithm().equalsIgnoreCase("RSA"))
						return new SimpleKeySelectorResult(pubKey);		// OK!!
				}
			}
			throw new KeySelectorException("No KeyValue element found!");
		}
	}

    // ---------------------------------------------------------------------------
    // ���ؗp�̌��߂��N���X�i�ł��V���v���Ȏ����j
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
	/* �⏕ */

	/* URI�̊�_�ƂȂ郋�[�g�f�B���N�g�����w�� */
	@Override
	public void setRootDir(String rootDir) {
		rootDir_ = rootDir;
	}
	
	/* �n�b�V���v�Z/�����v�Z���Ɏg����n�b�V���A���S���Y�����w�� */
	@Override
	public void setHashAlg(String hashAlg) {
		hashAlg_ = hashAlg;
	}

	/* --------------------------------------------------------------------------- */
	/* �G���[���� */

	private	int lastError_ = FXERR_NO_ERROR;				// �Ō�̃G���[�l��ێ�
	public int getLastError() { return lastError_; }		// �Ō�̃G���[�l���擾
	public void clearLastError() {							// �Ō�̃G���[�l���N���A
		lastError_ = FXERR_NO_ERROR;
	}
	private int setLastError(int fxerr) {					// �G���[�l�Z�b�g(�����p)
		lastError_ = fxerr;
		return fxerr;
	}
	
	/* --------------------------------------------------------------------------- */
	/* �����⏕ */

	/* ���[�g�f�B���N�g�����l�������p�X��Ԃ� */
	private String getPath(String file) {
		String path = file;
		if(rootDir_ != null && file.charAt(0) != '/' && file.charAt(0) != '\\') {
			path = rootDir_ + file;
		}
		return path;
	}
	
	/* �t�@�C��/�����񂩂�̃o�C�i���擾 */
	private byte[] getBinary(String target, int fxaType) {
		byte[] bin = null;
		if(fxaType == FXAT_FILE_PATH) {
			// �t�@�C������̓ǂݍ���
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

	/* C14N���K�����\�b�h�擾 */
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

	/* �������\�b�h�擾 */
	private SignatureMethod getSignatureMethod() {
		SignatureMethod sm = null;
		try {
			if(hashAlg_ == null || DigestMethod.SHA256.equals(hashAlg_)) {
				sm = sigFact_.newSignatureMethod(RSA_SHA256, null);
//			} else if(DigestMethod.SHA384.equals(hashAlg_)) {	// ���T�|�[�g
//				sm = sigFact_.newSignatureMethod(RSA_SHA384, null);				
			} else if(DigestMethod.SHA512.equals(hashAlg_)) {
				sm = sigFact_.newSignatureMethod(RSA_SHA512, null);				
			} else if(DigestMethod.SHA1.equals(hashAlg_)) {
				sm = sigFact_.newSignatureMethod(SignatureMethod.RSA_SHA1, null);	// �񐄏�
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

	/* �n�b�V�����\�b�h�擾 */
	private DigestMethod getDigestMethod() {
		DigestMethod dm = null;
		try {
			if(hashAlg_ == null || DigestMethod.SHA256.equals(hashAlg_)) {
				dm = sigFact_.newDigestMethod(DigestMethod.SHA256, null);
//			} else if(DigestMethod.SHA384.equals(hashAlg_)) {	// ���T�|�[�g
//				dm = sigFact_.newDigestMethod(DigestMethod.SHA384, null);
			} else if(DigestMethod.SHA512.equals(hashAlg_)) {
				dm = sigFact_.newDigestMethod(DigestMethod.SHA512, null);
			} else if(DigestMethod.SHA1.equals(hashAlg_)) {
				dm = sigFact_.newDigestMethod(DigestMethod.SHA1, null);		// �񐄏�
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
	
	/* �n�b�V���v�Z */
	private byte[] getHash(byte[] data) {
		byte[] hash = null;
		MessageDigest md = null;
		try {
			if(hashAlg_ == null || DigestMethod.SHA256.equals(hashAlg_) ) {
				md = MessageDigest.getInstance("SHA-256");
//			} else if(DigestMethod.SHA384.equals(hashAlg_)) {	// ���T�|�[�g
//				md = MessageDigest.getInstance("SHA-384");
			} else if(DigestMethod.SHA512.equals(hashAlg_)) {
				md = MessageDigest.getInstance("SHA-512");
			} else if(DigestMethod.SHA1.equals(hashAlg_)) {
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
	
	/* Element��C14N���K������ */
	private byte[] getC14N(Element elmt, int fxrFlag) {
		byte[] c14n = null;
		try {
			// Element���o�C�i���֕ϊ�
			ByteArrayOutputStream bs = new ByteArrayOutputStream();
			TransformerFactory tff = TransformerFactory.newInstance();
			Transformer tf = tff.newTransformer();
			tf.transform(new DOMSource(elmt), new StreamResult(bs));
			// C14N���K��
	    	ByteArrayInputStream inStream = new ByteArrayInputStream(bs.toByteArray());
			XMLSignatureFactory xsf = XMLSignatureFactory.getInstance("DOM");
	    	CanonicalizationMethod cm = xsf.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec)null);
	    	OctetStreamData rsltData = (OctetStreamData)cm.transform(new OctetStreamData(inStream), null);
	    	// ���K���ς݃o�C�i���̎擾
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

}
