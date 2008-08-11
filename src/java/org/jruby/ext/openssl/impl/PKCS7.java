/***** BEGIN LICENSE BLOCK *****
 * Version: CPL 1.0/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Common Public
 * License Version 1.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.eclipse.org/legal/cpl-v10.html
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * Copyright (C) 2008 Ola Bini <ola.bini@gmail.com>
 * 
 * Alternatively, the contents of this file may be used under the terms of
 * either of the GNU General Public License Version 2 or later (the "GPL"),
 * or the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the CPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the CPL, the GPL or the LGPL.
 ***** END LICENSE BLOCK *****/
package org.jruby.ext.openssl.impl;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;
import java.util.Set;
import java.util.TimeZone;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/** c: PKCS7
 *
 * Basically equivalent of the ContentInfo structures in PKCS#7.
 *
 * @author <a href="mailto:ola.bini@gmail.com">Ola Bini</a>
 */
public class PKCS7 {
    // Used during processing
    private int state;

	/* content as defined by the type */
	/* all encryption/message digests are applied to the 'contents',
	 * leaving out the 'type' field. */

    private PKCS7Data data;

    public Object ctrl(int cmd, Object v, Object ignored) {
        return this.data.ctrl(cmd, v, ignored);
    }

    public void setDetached(int v) {
        ctrl(OP_SET_DETACHED_SIGNATURE, Integer.valueOf(v), null);
    }

    public int getDetached() {
        return ((Integer)ctrl(OP_GET_DETACHED_SIGNATURE, null, null)).intValue();
    }

    public boolean isDetached() {
        return isSigned() && getDetached() != 0;
    }

    private static void printDER(String moniker, DEREncodable object) {
        System.err.println(moniker + " " + object + "{" + object.getClass().getName() + "}");
    }

    private void initiateWith(Integer nid, DEREncodable content) {
        this.data = PKCS7Data.fromASN1(nid, content);
    }

    /**
     * ContentInfo ::= SEQUENCE {
     *   contentType ContentType,
     *   content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
     *
     * ContentType ::= OBJECT IDENTIFIER
     */
    public static PKCS7 fromASN1(DEREncodable obj) {
        int size = ((ASN1Sequence)obj).size();
        if(size == 0) {
            return new PKCS7();
        }

        DERObjectIdentifier contentType = (DERObjectIdentifier)(((ASN1Sequence)obj).getObjectAt(0));
        int nid = ASN1Registry.obj2nid(contentType);
        
        DEREncodable content = size == 1 ? (DEREncodable)null : ((ASN1Sequence)obj).getObjectAt(1);

        if(content != null && content instanceof DERTaggedObject && ((DERTaggedObject)content).getTagNo() == 0) {
            content = ((DERTaggedObject)content).getObject();
        }
        
        PKCS7 p7 = new PKCS7();
        p7.initiateWith(nid, content);
        return p7;
    }

    /* c: d2i_PKCS7_bio
     *
     */
    public static PKCS7 fromASN1(BIO bio) throws IOException {
        ASN1InputStream ais = new ASN1InputStream(BIO.asInputStream(bio));
        return fromASN1(ais.readObject());
    }

    public ASN1Encodable asASN1() {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        DERObjectIdentifier contentType = ASN1Registry.nid2obj(getType());
        vector.add(contentType);
        vector.add(data.asASN1());

        return new DERSequence(vector);
    }

    /* c: i2d_PKCS7
     *
     */
    public byte[] toASN1() throws IOException {
        return asASN1().getEncoded();
    }

    /* c: PKCS7_encrypt
     *
     */
    public static PKCS7 encrypt(List<X509Certificate> certs, byte[] in, Cipher cipher, int flags) {
        PKCS7 p7 = new PKCS7();

        p7.setType(ASN1Registry.NID_pkcs7_enveloped);

        try {
            p7.setCipher(cipher);

            for(X509Certificate x509 : certs) {
                p7.addRecipient(x509);
            }

            BIO p7bio = p7.dataInit(null);

            p7bio.crlfCopy(in, flags);
            p7bio.flush();
            p7.dataFinal(p7bio);

            return p7;
        } catch(IOException e) {
            throw new PKCS7Exception(F_PKCS7_ENCRYPT, R_PKCS7_DATAFINAL_ERROR, e.toString());
        }
    }

    /** c: PKCS7_set_type
     *
     */
    public void setType(int type) {
        switch(type) {
        case ASN1Registry.NID_pkcs7_signed:
            this.data = new PKCS7DataSigned();
            break;
        case ASN1Registry.NID_pkcs7_data:
            this.data = new PKCS7DataData();
            break;
        case ASN1Registry.NID_pkcs7_signedAndEnveloped:
            this.data = new PKCS7DataSignedAndEnveloped();
            break;
        case ASN1Registry.NID_pkcs7_enveloped:
            this.data = new PKCS7DataEnveloped();
            break;
        case ASN1Registry.NID_pkcs7_encrypted:
            this.data = new PKCS7DataEncrypted();
            break;
        case ASN1Registry.NID_pkcs7_digest:
            this.data = new PKCS7DataDigest();
            break;
        default:
            throw new PKCS7Exception(F_PKCS7_SET_TYPE,R_UNSUPPORTED_CONTENT_TYPE);
        }
    }

    /** c: PKCS7_set_cipher
     *
     */
    public void setCipher(Cipher cipher) {
        this.data.setCipher(cipher);
    }

    /** c: PKCS7_add_recipient
     *
     */
    public RecipInfo addRecipient(X509Certificate recip) {
        RecipInfo ri = new RecipInfo();
        ri.set(recip);
        addRecipientInfo(ri);
        return ri;
    }

    /** c: PKCS7_content_new
     *
     */
    public void contentNew(int nid) {
        PKCS7 ret = new PKCS7();
        ret.setType(nid);
        this.setContent(ret);
    }

    /** c: PKCS7_add_signer
     *
     */
    public void addSigner(SignerInfoWithPkey psi) {
        this.data.addSigner(psi);
    }

    /** c: PKCS7_add_certificate
     *
     */
    public void addCertificate(X509Certificate cert) {
        this.data.addCertificate(cert);
    }

    /** c: PKCS7_add_crl
     *
     */
    public void addCRL(X509CRL crl) {
        this.data.addCRL(crl);
    }

    /** c: PKCS7_add_recipient_info
     *
     */
    public void addRecipientInfo(RecipInfo ri) {
        this.data.addRecipientInfo(ri);
    }

    /** c: PKCS7_set_content
     *
     */
    public void setContent(PKCS7 p7) {
        this.data.setContent(p7);
    }
    
    /** c: PKCS7_get_signer_info
     *
     */
    public Set<SignerInfoWithPkey> getSignerInfo() {
        return this.data.getSignerInfo();
    }

    private final static int EVP_MAX_KEY_LENGTH = 32;
    private final static int EVP_MAX_IV_LENGTH = 16;
    private final static int EVP_MAX_BLOCK_LENGTH = 32;

    private final static byte[] PEM_STRING_PKCS7_START = "-----BEGIN PKCS7-----".getBytes();

    /** c: PEM_read_bio_PKCS7
     *
     */
    public static PKCS7 readPEM(BIO input) {
        try {
            byte[] buffer = new byte[SMIME.MAX_SMLEN];
            int read = -1;
            read = input.gets(buffer, SMIME.MAX_SMLEN);
            if(read > PEM_STRING_PKCS7_START.length) {
                byte[] tmp = new byte[PEM_STRING_PKCS7_START.length];
                System.arraycopy(buffer, 0, tmp, 0, tmp.length);
                if(Arrays.equals(PEM_STRING_PKCS7_START, tmp)) {
                    return fromASN1(BIO.base64Filter(input));
                } else {
                    return null;
                }
            } else {
                return null;
            }
        } catch(IOException e) {
            return null;
        }
    }

    /** c: stati PKCS7_bio_add_digest
     *
     */
    public BIO bioAddDigest(BIO pbio, AlgorithmIdentifier alg) {
        try {
            MessageDigest md = MessageDigest.getInstance(ASN1Registry.o2a(alg.getObjectId()));
            BIO btmp = BIO.mdFilter(md);
            if(pbio == null) {
                return btmp;
            } else {
                pbio.push(btmp);
                return pbio;
            }
        } catch(Exception e) {
            throw new PKCS7Exception(F_PKCS7_BIO_ADD_DIGEST, R_UNKNOWN_DIGEST_TYPE);
        }
    }

    /** c: PKCS7_dataInit
     *
     */
    public BIO dataInit(BIO bio) {
        Set<AlgorithmIdentifier> mdSk = null;
        ASN1OctetString os = null;
        int i = this.data.getType();
        state = S_HEADER;
        List<RecipInfo> rsk = null;
        AlgorithmIdentifier xalg = null;
        AlgorithmIdentifier xa = null;
        Cipher evpCipher = null;
        BIO out = null;
        BIO btmp = null;
        EncContent enc = null;

        switch(i) {
        case ASN1Registry.NID_pkcs7_signed:
            mdSk = getSign().getMdAlgs();
            os = getSign().getContents().getOctetString();
            break;
        case ASN1Registry.NID_pkcs7_signedAndEnveloped:
            rsk = getSignedAndEnveloped().getRecipientInfo();
            mdSk = getSignedAndEnveloped().getMdAlgs();
            enc = getSignedAndEnveloped().getEncData();
            xalg = getSignedAndEnveloped().getEncData().getAlgorithm();
            evpCipher = getSignedAndEnveloped().getEncData().getCipher();
            if(null == evpCipher) {
                throw new PKCS7Exception(F_PKCS7_DATAINIT, R_CIPHER_NOT_INITIALIZED);
            }
            break;
        case ASN1Registry.NID_pkcs7_enveloped:
            rsk = getEnveloped().getRecipientInfo();
            enc = getEnveloped().getEncData();
            xalg = getEnveloped().getEncData().getAlgorithm();
            evpCipher = getEnveloped().getEncData().getCipher();
            if(null == evpCipher) {
                throw new PKCS7Exception(F_PKCS7_DATAINIT, R_CIPHER_NOT_INITIALIZED);
            }
            break;
        case ASN1Registry.NID_pkcs7_digest:
            xa = getDigest().getMd();
            os = getDigest().getContents().getOctetString();
            break;
        default:
            throw new PKCS7Exception(F_PKCS7_DATAINIT, R_UNSUPPORTED_CONTENT_TYPE);
        }

        if(mdSk != null) {
            for(AlgorithmIdentifier ai : mdSk) {
                if((out = bioAddDigest(out, ai)) == null) {
                    return null;
                }
            }
        }

        if(xa != null && (out = bioAddDigest(out, xa)) == null) {
            return null;
        }


// 	if (evp_cipher != NULL)
// 		{

//             xalg->algorithm = OBJ_nid2obj(EVP_CIPHER_type(evp_cipher));
//             if (ivlen > 0) {
//                 if (xalg->parameter == NULL) 
//                     xalg->parameter=ASN1_TYPE_new();
//                 if(EVP_CIPHER_param_to_asn1(ctx, xalg->parameter) < 0)
//                     goto err;
//             }
// 		}
        if(evpCipher != null) {
            byte[] tmp;
            String algorithm = evpCipher.getAlgorithm();

            btmp = BIO.cipherFilter(evpCipher);

            int klen = -1;

            String algoBase = evpCipher.getAlgorithm();
            if(algoBase.indexOf('/') != -1) {
                algoBase = algoBase.split("/")[0];
            }

            try {
                KeyGenerator gen = KeyGenerator.getInstance(algoBase);
                gen.init(new SecureRandom());
                SecretKey key = gen.generateKey();
                klen = ((SecretKeySpec)key).getEncoded().length*8;
                evpCipher.init(Cipher.ENCRYPT_MODE, key);

                if(null != rsk) {
                    for(RecipInfo ri : rsk) {
                        PublicKey pkey = ri.getCert().getPublicKey();
                        Cipher cipher = Cipher.getInstance(pkey.getAlgorithm());
                        cipher.init(Cipher.ENCRYPT_MODE, pkey);
                        tmp = cipher.doFinal(((SecretKeySpec)key).getEncoded());
                        ri.setEncKey(new DEROctetString(tmp));
                    }
                }
            } catch(Exception e) {
                e.printStackTrace();
            }

            DERObjectIdentifier encAlgo = ASN1Registry.sym2oid(algorithm);
            if(encAlgo == null) {
                String name = algorithm;
                String block = "CBC";
                if(name.indexOf('/') != -1) {
                    String[] nameParts = name.split("/");
                    name = nameParts[0];
                    block = nameParts[1];
                }
                encAlgo = ASN1Registry.sym2oid(name + "-" + klen + "-" + block);
                if(null == encAlgo) {
                    throw new PKCS7Exception(-1, -1, "Couldn't find algorithm " + algorithm + ". Tried: " + (name + "-" + klen + "-" + block));
                }
            }

            enc.setAlgorithm(new AlgorithmIdentifier(encAlgo));

            if(out == null) {
                out = btmp;
            } else {
                out.push(btmp);
            }
            btmp = null;
        }

        if(bio == null) {
            if(isDetached()) {
                bio = BIO.nullSink();
            } else if(os != null && os.getOctets().length > 0) {
                bio = BIO.memBuf(os.getOctets());
            }
            if(bio == null) {
                bio = BIO.mem();
                bio.setMemEofReturn(0);
            }
        }
        out.push(bio);
        bio = null;
        return out;
    }

    /** c: static PKCS7_find_digest
     *
     */
    public BIO findDigest(MessageDigest[] pmd, BIO bio, int nid) {
        while(true) {
            bio = bio.findType(BIO.TYPE_MD);
            if(bio == null) {
                throw new PKCS7Exception(F_PKCS7_FIND_DIGEST, R_UNABLE_TO_FIND_MESSAGE_DIGEST);
            }
            pmd[0] = ((MessageDigestBIOFilter)bio).getMessageDigest();
            if(pmd[0] == null) {
                throw new PKCS7Exception(F_PKCS7_FIND_DIGEST, -1);
            }
            
            if(nid == ASN1Registry.sym2nid(pmd[0].getAlgorithm())) {
                return bio;
            }

            bio = bio.next();
        }
    }

    /** c: PKCS7_dataFinal
     *
     */
    public int dataFinal(BIO bio) { 
        Set<SignerInfoWithPkey> siSk = null;
        state = S_HEADER;
        BIO btmp;
        int bufLen;
        byte[] buf;
        MessageDigest mdc = null;
        MessageDigest ctx_tmp = null;
        ASN1Set sk;

        int i = this.data.getType();

        switch(i) {
        case ASN1Registry.NID_pkcs7_signedAndEnveloped:
            siSk = getSignedAndEnveloped().getSignerInfo();
            break;
        case ASN1Registry.NID_pkcs7_signed:
            siSk = getSignedAndEnveloped().getSignerInfo();
            break;
        case ASN1Registry.NID_pkcs7_digest:
            break;
        default:
            break;
        }

        if(siSk != null) {
            for(SignerInfoWithPkey si : siSk) {
                if(si.getPkey() == null) {
                    continue;
                }
                int j = ASN1Registry.obj2nid(si.getDigestAlgorithm().getObjectId());
                btmp = bio;
                MessageDigest[] _mdc = new MessageDigest[] {mdc};
                btmp = findDigest(_mdc, btmp, j);
                mdc = _mdc[0];
                if(btmp == null) {
                    return 0;
                }

                try {
                    ctx_tmp = (MessageDigest)mdc.clone();
                } catch(CloneNotSupportedException e) {
                    throw new RuntimeException(e);
                }
                
                sk = si.getAuthenticatedAttributes();

                Signature sign = null;

                try {
                    if(sk != null && sk.size() > 0) {
                        /* Add signing time if not already present */
                        if(null == si.getSignedAttribute(ASN1Registry.NID_pkcs9_signingTime)) {
                            DERUTCTime signTime = new DERUTCTime(Calendar.getInstance(TimeZone.getTimeZone("UTC")).getTime());
                            si.addSignedAttribute(ASN1Registry.NID_pkcs9_signingTime, signTime);
                        }

                        byte[] md_data = ctx_tmp.digest();
                        ASN1OctetString digest = new DEROctetString(md_data);
                        si.addSignedAttribute(ASN1Registry.NID_pkcs9_messageDigest, digest);

                        sk = si.getAuthenticatedAttributes();
                        sign = Signature.getInstance(ctx_tmp.getAlgorithm());
                        sign.initSign(si.getPkey());

                        byte[] abuf = sk.getEncoded();
                        sign.update(abuf);
                    }

                    if(sign != null) {
                        byte[] out = sign.sign();
                        si.setEncryptedDigest(new DEROctetString(out));
                    }
                } catch(Exception e) {
                    throw new PKCS7Exception(F_PKCS7_DATAFINAL,-1,e.toString());
                }
            }
        } else if(i == ASN1Registry.NID_pkcs7_digest) {
            int nid = ASN1Registry.obj2nid(getDigest().getMd().getObjectId());
            MessageDigest[] _mdc = new MessageDigest[] {mdc};
            bio = findDigest(_mdc, bio, nid);
            mdc = _mdc[0];
            byte[] md_data = mdc.digest();
            ASN1OctetString digest = new DEROctetString(md_data);
            getDigest().setDigest(digest);
        }

        if(!isDetached()) {
            btmp = bio.findType(BIO.TYPE_MEM);
            if(null == btmp) {
                throw new PKCS7Exception(F_PKCS7_DATAFINAL, R_UNABLE_TO_FIND_MEM_BIO);
            }
            buf = ((MemBIO)btmp).getMemCopy();

            switch(i) {
            case ASN1Registry.NID_pkcs7_signedAndEnveloped:
                getSignedAndEnveloped().getEncData().setEncData(new DEROctetString(buf));
                break;
            case ASN1Registry.NID_pkcs7_enveloped:
                getEnveloped().getEncData().setEncData(new DEROctetString(buf));
                break;
            case ASN1Registry.NID_pkcs7_signed:
                if(getSign().getContents().isData() && getDetached() != 0) {
                    getSign().getContents().setData(null);
                } else {
                    getSign().getContents().setData(new DEROctetString(buf));
                }
                break;
            case ASN1Registry.NID_pkcs7_digest:
                if(getDigest().getContents().isData() && getDetached() != 0) {
                    getDigest().getContents().setData(null);
                } else {
                    getDigest().getContents().setData(new DEROctetString(buf));
                }
                break;
            }
        }

        return 1;
    }

    @Override
    public String toString() {
        return "#<PKCS7 " + this.data + ">";
    }

    public static final int S_HEADER = 0;
    public static final int S_BODY = 1;
    public static final int S_TAIL = 2;

    public static final int OP_SET_DETACHED_SIGNATURE = 1;
    public static final int OP_GET_DETACHED_SIGNATURE = 2;

    /* S/MIME related flags */
    public static final int TEXT = 0x1;
    public static final int NOCERTS = 0x2;
    public static final int NOSIGS = 0x4;
    public static final int NOCHAIN = 0x8;
    public static final int NOINTERN = 0x10;
    public static final int NOVERIFY = 0x20;
    public static final int DETACHED = 0x40;
    public static final int BINARY = 0x80;
    public static final int NOATTR = 0x100;
    public static final int NOSMIMECAP = 0x200;
    public static final int NOOLDMIMETYPE = 0x400;
    public static final int CRLFEOL = 0x800;
    public static final int STREAM = 0x1000;
    public static final int NOCRL = 0x2000;

    /* Flags: for compatibility with older code */
    public static final int SMIME_TEXT = TEXT;
    public static final int SMIME_NOCERTS = NOCERTS;
    public static final int SMIME_NOSIGS = NOSIGS;
    public static final int SMIME_NOCHAIN = NOCHAIN;
    public static final int SMIME_NOINTERN = NOINTERN;
    public static final int SMIME_NOVERIFY = NOVERIFY;
    public static final int SMIME_DETACHED = DETACHED;
    public static final int SMIME_BINARY = BINARY;
    public static final int SMIME_NOATTR = NOATTR;

    /* Function codes. */
    public static final int F_B64_READ_PKCS7 = 120;
    public static final int F_B64_WRITE_PKCS7 = 121;
    public static final int F_PKCS7_ADD_ATTRIB_SMIMECAP = 118;
    public static final int F_PKCS7_ADD_CERTIFICATE = 100;
    public static final int F_PKCS7_ADD_CRL = 101;
    public static final int F_PKCS7_ADD_RECIPIENT_INFO = 102;
    public static final int F_PKCS7_ADD_SIGNER = 103;
    public static final int F_PKCS7_BIO_ADD_DIGEST = 125;
    public static final int F_PKCS7_CTRL = 104;
    public static final int F_PKCS7_DATADECODE = 112;
    public static final int F_PKCS7_DATAFINAL = 128;
    public static final int F_PKCS7_DATAINIT = 105;
    public static final int F_PKCS7_DATASIGN = 106;
    public static final int F_PKCS7_DATAVERIFY = 107;
    public static final int F_PKCS7_DECRYPT = 114;
    public static final int F_PKCS7_ENCRYPT = 115;
    public static final int F_PKCS7_FIND_DIGEST = 127;
    public static final int F_PKCS7_GET0_SIGNERS = 124;
    public static final int F_PKCS7_SET_CIPHER = 108;
    public static final int F_PKCS7_SET_CONTENT = 109;
    public static final int F_PKCS7_SET_DIGEST = 126;
    public static final int F_PKCS7_SET_TYPE = 110;
    public static final int F_PKCS7_SIGN = 116;
    public static final int F_PKCS7_SIGNATUREVERIFY = 113;
    public static final int F_PKCS7_SIMPLE_SMIMECAP = 119;
    public static final int F_PKCS7_VERIFY = 117;
    public static final int F_SMIME_READ_PKCS7 = 122;
    public static final int F_SMIME_TEXT = 123;

    /* Reason codes. */
    public static final int R_CERTIFICATE_VERIFY_ERROR = 117;
    public static final int R_CIPHER_HAS_NO_OBJECT_IDENTIFIER = 144;
    public static final int R_CIPHER_NOT_INITIALIZED = 116;
    public static final int R_CONTENT_AND_DATA_PRESENT = 118;
    public static final int R_DECODE_ERROR = 130;
    public static final int R_DECRYPTED_KEY_IS_WRONG_LENGTH = 100;
    public static final int R_DECRYPT_ERROR = 119;
    public static final int R_DIGEST_FAILURE = 101;
    public static final int R_ERROR_ADDING_RECIPIENT = 120;
    public static final int R_ERROR_SETTING_CIPHER = 121;
    public static final int R_INVALID_MIME_TYPE = 131;
    public static final int R_INVALID_NULL_POINTER = 143;
    public static final int R_MIME_NO_CONTENT_TYPE = 132;
    public static final int R_MIME_PARSE_ERROR = 133;
    public static final int R_MIME_SIG_PARSE_ERROR = 134;
    public static final int R_MISSING_CERIPEND_INFO = 103;
    public static final int R_NO_CONTENT = 122;
    public static final int R_NO_CONTENT_TYPE = 135;
    public static final int R_NO_MULTIPART_BODY_FAILURE = 136;
    public static final int R_NO_MULTIPART_BOUNDARY = 137;
    public static final int R_NO_RECIPIENT_MATCHES_CERTIFICATE = 115;
    public static final int R_NO_RECIPIENT_MATCHES_KEY = 146;
    public static final int R_NO_SIGNATURES_ON_DATA = 123;
    public static final int R_NO_SIGNERS = 142;
    public static final int R_NO_SIG_CONTENT_TYPE = 138;
    public static final int R_OPERATION_NOT_SUPPORTED_ON_THIS_TYPE = 104;
    public static final int R_PKCS7_ADD_SIGNATURE_ERROR = 124;
    public static final int R_PKCS7_DATAFINAL = 126;
    public static final int R_PKCS7_DATAFINAL_ERROR = 125;
    public static final int R_PKCS7_DATASIGN = 145;
    public static final int R_PKCS7_PARSE_ERROR = 139;
    public static final int R_PKCS7_SIG_PARSE_ERROR = 140;
    public static final int R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE = 127;
    public static final int R_SIGNATURE_FAILURE = 105;
    public static final int R_SIGNER_CERTIFICATE_NOT_FOUND = 128;
    public static final int R_SIG_INVALID_MIME_TYPE = 141;
    public static final int R_SMIME_TEXT_ERROR = 129;
    public static final int R_UNABLE_TO_FIND_CERTIFICATE = 106;
    public static final int R_UNABLE_TO_FIND_MEM_BIO = 107;
    public static final int R_UNABLE_TO_FIND_MESSAGE_DIGEST = 108;
    public static final int R_UNKNOWN_DIGEST_TYPE = 109;
    public static final int R_UNKNOWN_OPERATION = 110;
    public static final int R_UNSUPPORTED_CIPHER_TYPE = 111;
    public static final int R_UNSUPPORTED_CONTENT_TYPE = 112;
    public static final int R_WRONG_CONTENT_TYPE = 113;
    public static final int R_WRONG_PKCS7_TYPE = 114;

    public Envelope getEnveloped() {
        return this.data.getEnveloped();
    }

    public SignEnvelope getSignedAndEnveloped() {
        return this.data.getSignedAndEnveloped();
    }

    public Digest getDigest() {
        return this.data.getDigest();
    }

    public Encrypt getEncrypted() {
        return this.data.getEncrypted();
    }

    public ASN1Encodable getOther() {
        return this.data.getOther();
    }

    public void setSign(Signed sign) {
        this.data.setSign(sign);
    }

    public Signed getSign() {
        return this.data.getSign();
    }

    public void setData(ASN1OctetString data) {
        this.data.setData(data);
    }

    public ASN1OctetString getData() {
        return this.data.getData();
    }

    public boolean isSigned() {
        return this.data.isSigned();
    }

    public boolean isEncrypted() {
        return this.data.isEncrypted();
    }

    public boolean isEnveloped() {
        return this.data.isEnveloped();
    }

    public boolean isSignedAndEnveloped() {
        return this.data.isSignedAndEnveloped();
    }

    public boolean isData() {
        return this.data.isData();
    }

    public boolean isDigest() {
        return this.data.isDigest();
    }

    public boolean isOther() {
        return this.data.isOther();
    }

    public int getType() {
        return this.data.getType();
    }

    /* c: static PKCS7_get_octet_string
     *
     */
    public ASN1OctetString getOctetString() {
        if(isData()) {
            return getData();
        } else if(isOther() && getOther() != null && getOther() instanceof ASN1OctetString) {
            return (ASN1OctetString)getOther();
        }
        return null;
    }
}// PKCS7

