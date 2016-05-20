/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package jp.langedge.FreeXAdES;

import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;
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

import org.w3c.dom.*;				// Document�N���X���ɗ��p
import org.xml.sax.SAXException;
//import org.xml.sax.SAXException;

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
	
	/** �G���[�Ή�
	 */
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
		} catch (Exception e) {	// SAXException, ParserConfigurationException
			e.printStackTrace();
			rc = setLastError(FXERR_EXCEPTION);
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
		return null;		
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
		} catch (TransformerConfigurationException e) {
			e.printStackTrace();
			rc = FXERR_FILE_WRITE;
		} catch (TransformerException e) {
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
			xml = new String(utf8, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			setLastError(FXERR_EXCEPTION);
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
		try {
			switch(fxaType) {
			case FXAT_FILE_PATH:
				if((fxrFlag & FXRF_TRANS_C14N) != 0) {
					trForms = new ArrayList<Transform>();
					String canon = CanonicalizationMethod.INCLUSIVE;
					Transform tr = sigFact_.newCanonicalizationMethod(canon, (C14NMethodParameterSpec)null);
					trForms.add(tr);
				} else if((fxrFlag & FXRF_TRANS_C14N_EX) != 0) {
					trForms = new ArrayList<Transform>();
					String canon = CanonicalizationMethod.EXCLUSIVE;
					Transform tr = sigFact_.newCanonicalizationMethod(canon, (C14NMethodParameterSpec)null);
					trForms.add(tr);					
				}
				break;
			case FXAT_XML_ID:
				break;
			default:
				rc = FXERR_INVALID_ARG;
				break;
			}
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			rc = FXERR_PKI_UNK_ALG;
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
			rc = FXERR_PKI_INVALID_ALG;
		}
		if(rc != FXERR_NO_ERROR)
			return setLastError(rc);

		Reference ref = sigFact_.newReference(target, dm, trForms, null, null);
		if(refs_ == null) {
			refs_ = new ArrayList<Reference>();
		}
		refs_.add(ref);
		return rc;
	}

	/* Enveloping(����)�����Ώۂ̒ǉ� */
	@Override
	public int addEnveloping(String target, int fxaType, int fxrFlag) {
		int rc = FXERR_NO_ERROR;
		DigestMethod dm = getDigestMethod();
		List<Transform> trForms = null;
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		try {
			int flagMask = FXRF_TRANS_C14N | FXRF_TRANS_C14N_EX;
			if(fxaType == FXAT_XML_STRING || (fxrFlag & flagMask) != 0) {
				// XML
				if((fxrFlag & FXRF_TRANS_C14N_EX) != 0) {
					// C14N:EXCLUSIVE
					trForms = new ArrayList<Transform>();
					String canon = CanonicalizationMethod.EXCLUSIVE;
					Transform tr = sigFact_.newCanonicalizationMethod(canon, (C14NMethodParameterSpec)null);
					trForms.add(tr);
				} else {
					// C14N:INCLUSIVE
					trForms = new ArrayList<Transform>();
					String canon = CanonicalizationMethod.INCLUSIVE;
					Transform tr = sigFact_.newCanonicalizationMethod(canon, (C14NMethodParameterSpec)null);
					trForms.add(tr);					
				}
				byte[] xml = getBinary(target, fxaType);
				ByteArrayInputStream inStream = new ByteArrayInputStream(xml);
				Document doc = dbf.newDocumentBuilder().parse(inStream);
				Element element = doc.getDocumentElement();
				XMLStructure content = new DOMStructure(element);
				XMLObject obj = sigFact_.newXMLObject(Collections.singletonList(content), "MyObj", null, null);
				if(objs_ == null) {
					objs_ = new ArrayList<XMLObject>();
				}
				objs_.add(obj);
			} else {
				// DATA
				Document doc = dbf.newDocumentBuilder().newDocument();
				byte[] data = getBinary(target, fxaType);
				if((fxrFlag & FXRF_TRANS_BASE64) != 0) {
					// Base64������
					trForms = new ArrayList<Transform>();
					String canon = CanonicalizationMethod.INCLUSIVE;
					Transform tr = sigFact_.newCanonicalizationMethod(canon, (C14NMethodParameterSpec)null);
					trForms.add(tr);
					String base64 = Base64.getEncoder().encodeToString(data);
					Node text = doc.createTextNode(base64);
					XMLStructure content = new DOMStructure(text);
					String mimeType = "text/plain";
					String Encoding = "http://www.w3.org/2000/09/xmldsig#base64";
					XMLObject obj = sigFact_.newXMLObject(Collections.singletonList(content), "MyObj", mimeType, Encoding);
					if(objs_ == null) {
						objs_ = new ArrayList<XMLObject>();
					}
					objs_.add(obj);
				} else {
					// Base64�����Ȃ�
				}
			}
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			rc = FXERR_PKI_UNK_ALG;
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
			rc = FXERR_PKI_INVALID_ALG;
		} catch (SAXException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ParserConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if(rc != FXERR_NO_ERROR)
			return setLastError(rc);

		Reference ref = sigFact_.newReference("#MyObj", dm, trForms, null, null);
		if(refs_ == null) {
			refs_ = new ArrayList<Reference>();
		}
		refs_.add(ref);
		return rc;
	}

	/* Enveloped(����)�����Ώۂ̒ǉ� */
	@Override
	public int addEnveloped(String target, int fxaType, String xpath) {
		int rc = FXERR_NO_ERROR;
		DigestMethod dm = getDigestMethod();
		List<Transform> trForms = new ArrayList<Transform>();
		try {
			Transform trans = sigFact_.newTransform(Transform.ENVELOPED, (TransformParameterSpec)null);
			trForms.add(trans);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			rc = FXERR_PKI_UNK_ALG;
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
			rc = FXERR_PKI_INVALID_ALG;
		}
		Reference ref = sigFact_.newReference("", dm, trForms, null, null);
		if(refs_ == null) {
			refs_ = new ArrayList<Reference>();
		}
		refs_.add(ref);
		return rc;
	}

	/* --------------------------------------------------------------------------- */

	/* �n�b�V������ */
	private DigestMethod getDigestMethod() {
		DigestMethod dm = null;
		try {
			if(hashAlg_ == null || hashAlg_ == SIGN_RSA_SHA256) {
				dm = sigFact_.newDigestMethod(DigestMethod.SHA256, null);
			} else if(hashAlg_ == SIGN_RSA_SHA384) {
				dm = sigFact_.newDigestMethod(HASH_SHA384, null);
			} else if(hashAlg_ == SIGN_RSA_SHA512) {
				dm = sigFact_.newDigestMethod(DigestMethod.SHA512, null);
			} else if(hashAlg_ == SignatureMethod.RSA_SHA1) {
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
	
	/* --------------------------------------------------------------------------- */
	/* �������� */

	/* ���������s���� */
	@Override
	public int execSign(String p12file, String p12pswd, int fxsFlag, String id, String xpath) {
		int rc = FXERR_NO_ERROR;

		if(refs_ == null)
			return setLastError(FXERR_NO_REFS);

		if((fxsFlag & FXSF_NO_XADES_OBJ) != 0) {
			// XAdES�̃I�u�W�F�N�g�ƎQ�Ƃ�ǉ�
		}

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
			rc = FXERR_FILE_READ;
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
					}	
				}
			}
			
			// KeyValue������KeyInfo���쐬���ăZ�b�g
			KeyInfoFactory kif = sigFact_.getKeyInfoFactory();
			KeyValue keyValue = kif.newKeyValue(pubKey);
			X509Data certs = kif.newX509Data(Collections.singletonList(cert));
			List<XMLStructure> kis = new ArrayList<XMLStructure>();
			kis.add(keyValue);
			kis.add(certs);
			KeyInfo keyInfo = kif.newKeyInfo(kis, "MyKeyInfoId");

			// SignedInfo�𐶐�����
			CanonicalizationMethod cm = null;
			if((fxsFlag & FXRF_TRANS_C14N_EX) != 0) {
				cm = sigFact_.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec)null);
			} else {
				cm = sigFact_.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec)null);
			}
			SignatureMethod sm = null;
			if(hashAlg_ == null || hashAlg_ == SIGN_RSA_SHA256) {
				sm = sigFact_.newSignatureMethod(SIGN_RSA_SHA256, null);				
			} else if(hashAlg_ == SIGN_RSA_SHA384) {
				sm = sigFact_.newSignatureMethod(SIGN_RSA_SHA384, null);				
			} else if(hashAlg_ == SIGN_RSA_SHA512) {
				sm = sigFact_.newSignatureMethod(SIGN_RSA_SHA512, null);				
			} else if(hashAlg_ == SignatureMethod.RSA_SHA1) {
				sm = sigFact_.newSignatureMethod(SignatureMethod.RSA_SHA1, null);	// �񐄏�
			} else {
				return setLastError(FXERR_PKI_UNK_ALG);
			}
			SignedInfo signedInfo = sigFact_.newSignedInfo(cm, sm, refs_);

			// Signature�v�f���쐬
	        String sigId = id;
	        if(sigId == null)
	        	sigId = "Signature1";
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
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			rc = FXERR_PKI_UNK_ALG;
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
			rc = FXERR_PKI_INVALID_ALG;
		} catch (KeyException e) {
			e.printStackTrace();
			rc = FXERR_PKI_KEY;
		}
		if(rc != FXERR_NO_ERROR)
			return setLastError(rc);

		return rc;
	}

	/* --------------------------------------------------------------------------- */
	/* ���؏��� */

	/* ���������؂��� */
	@Override
	public byte[] verifySign(int fxvFlag, String xpath) {
		return null;
	}

	/* ���،���XML���珐�����،��ʃX�e�[�^�X���擾 */
	@Override
	public int getVerifiedStatus(byte[] verifiedXml) {
		int rc = FXERR_NO_ERROR;
		return rc;
	}

	/* ���،���XML����G���[���擾 */
	@Override
	public int[] getVerifiedErrors(byte[] verifiedXml) {
		return null;
	}

	/* URI�̊�_�ƂȂ郋�[�g�f�B���N�g�����w�� */
	@Override
	public void setRootDir(String rootDir) {
		rootDir_ = rootDir;
	}
	
	/* �n�b�V���v�Z/�����v�Z���Ɏg����n�b�V���A���S���Y�����w�� */
	public void setHashAlg(String hashAlg) {
		hashAlg_ = hashAlg;
	}

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

	/* --------------------------------------------------------------------------- */
}
