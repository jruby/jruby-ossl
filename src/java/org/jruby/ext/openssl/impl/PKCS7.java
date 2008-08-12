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
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.TimeZone;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509Name;
import org.jruby.ext.openssl.OpenSSLReal;
import org.jruby.ext.openssl.x509store.Name;
import org.jruby.ext.openssl.x509store.Store;

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

    /* c: PKCS7_add_signature
     *
     */
    public SignerInfoWithPkey addSignature(X509Certificate x509, PrivateKey pkey, MessageDigest dgst) {
        SignerInfoWithPkey si = new SignerInfoWithPkey();
        si.set(x509, pkey, dgst);
        addSigner(si);
        return si;
    }

    /* c: X509_find_by_issuer_and_serial
     *
     */
    public static X509Certificate findByIssuerAndSerial(Collection<X509Certificate> certs, X509Name issuer, BigInteger serial) {
        Name name = new Name(issuer);
        for(X509Certificate cert : certs) {
            if(name.isEqual(cert.getIssuerX500Principal()) && serial.equals(cert.getSerialNumber())) {
                return cert;
            }
        }
        return null;
    }


    /* c: PKCS7_get0_signers
     *
     */
    public List<X509Certificate> getSigners(Collection<X509Certificate> certs, List<SignerInfoWithPkey> sinfos, int flags) {
        List<X509Certificate> signers = new ArrayList<X509Certificate>();

        if(!isSigned()) {
            throw new PKCS7Exception(F_PKCS7_GET0_SIGNERS,R_WRONG_CONTENT_TYPE);
        }

        if(sinfos.size() == 0) {
            throw new PKCS7Exception(F_PKCS7_GET0_SIGNERS,R_NO_SIGNERS);
        }

        for(SignerInfoWithPkey si : sinfos) {
            IssuerAndSerialNumber ias = si.getIssuerAndSerialNumber();
            X509Certificate signer = null;
            if(certs != null) {
                signer = findByIssuerAndSerial(certs, ias.getName(), ias.getCertificateSerialNumber().getValue());
            }
            if(signer == null && (flags & NOINTERN) == 0 && getSign().getCert() != null) {
                signer = findByIssuerAndSerial(getSign().getCert(), ias.getName(), ias.getCertificateSerialNumber().getValue());
            }
            if(signer == null) {
                throw new PKCS7Exception(F_PKCS7_GET0_SIGNERS,R_SIGNER_CERTIFICATE_NOT_FOUND);
            }
            signers.add(signer);
        }
        return signers;
    }

    /* c: PKCS7_signatureVerify
     *
     */
    public void signatureVerify(BIO bio, SignerInfoWithPkey si, X509Certificate x509) {
        throw new UnsupportedOperationException("TODO: implement");
// 	ASN1_OCTET_STRING *os;
// 	EVP_MD_CTX mdc_tmp,*mdc;
// 	int ret=0,i;
// 	int md_type;
// 	STACK_OF(X509_ATTRIBUTE) *sk;
// 	BIO *btmp;
// 	EVP_PKEY *pkey;

// 	EVP_MD_CTX_init(&mdc_tmp);

// 	if (!PKCS7_type_is_signed(p7) && 
//         !PKCS7_type_is_signedAndEnveloped(p7)) {
// 		PKCS7err(PKCS7_F_PKCS7_SIGNATUREVERIFY,
//                  PKCS7_R_WRONG_PKCS7_TYPE);
// 		goto err;
// 	}

// 	md_type=OBJ_obj2nid(si->digest_alg->algorithm);

// 	btmp=bio;
// 	for (;;)
// 		{
//             if ((btmp == NULL) ||
//                 ((btmp=BIO_find_type(btmp,BIO_TYPE_MD)) == NULL))
//                 {
//                     PKCS7err(PKCS7_F_PKCS7_SIGNATUREVERIFY,
//                              PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST);
//                     goto err;
//                 }
//             BIO_get_md_ctx(btmp,&mdc);
//             if (mdc == NULL)
//                 {
//                     PKCS7err(PKCS7_F_PKCS7_SIGNATUREVERIFY,
//                              ERR_R_INTERNAL_ERROR);
//                     goto err;
//                 }
//             if (EVP_MD_CTX_type(mdc) == md_type)
//                 break;
//             /* Workaround for some broken clients that put the signature
//              * OID instead of the digest OID in digest_alg->algorithm
//              */
//             if (EVP_MD_pkey_type(EVP_MD_CTX_md(mdc)) == md_type)
//                 break;
//             btmp=BIO_next(btmp);
// 		}

// 	/* mdc is the digest ctx that we want, unless there are attributes,
// 	 * in which case the digest is the signed attributes */
// 	EVP_MD_CTX_copy_ex(&mdc_tmp,mdc);

// 	sk=si->auth_attr;
// 	if ((sk != NULL) && (sk_X509_ATTRIBUTE_num(sk) != 0))
// 		{
//             unsigned char md_dat[EVP_MAX_MD_SIZE], *abuf = NULL;
//             unsigned int md_len, alen;
//             ASN1_OCTET_STRING *message_digest;

//             EVP_DigestFinal_ex(&mdc_tmp,md_dat,&md_len);
//             message_digest=PKCS7_digest_from_attributes(sk);
//             if (!message_digest)
//                 {
//                     PKCS7err(PKCS7_F_PKCS7_SIGNATUREVERIFY,
//                              PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST);
//                     goto err;
//                 }
//             if ((message_digest->length != (int)md_len) ||
//                 (memcmp(message_digest->data,md_dat,md_len)))
//                 {
// #if 0
//                     {
//                         int ii;
//                         for (ii=0; ii<message_digest->length; ii++)
//                             printf("%02X",message_digest->data[ii]); printf(" sent\n");
//                         for (ii=0; ii<md_len; ii++) printf("%02X",md_dat[ii]); printf(" calc\n");
//                     }
// #endif
//                     PKCS7err(PKCS7_F_PKCS7_SIGNATUREVERIFY,
//                              PKCS7_R_DIGEST_FAILURE);
//                     ret= -1;
//                     goto err;
//                 }

//             EVP_VerifyInit_ex(&mdc_tmp,EVP_get_digestbynid(md_type), NULL);

//             alen = ASN1_item_i2d((ASN1_VALUE *)sk, &abuf,
//                                  ASN1_ITEM_rptr(PKCS7_ATTR_VERIFY));
//             EVP_VerifyUpdate(&mdc_tmp, abuf, alen);

//             OPENSSL_free(abuf);
// 		}

// 	os=si->enc_digest;
// 	pkey = X509_get_pubkey(x509);
// 	if (!pkey)
// 		{
//             ret = -1;
//             goto err;
// 		}
// #ifndef OPENSSL_NO_DSA
// 	if(pkey->type == EVP_PKEY_DSA) mdc_tmp.digest=EVP_dss1();
// #endif
// #ifndef OPENSSL_NO_ECDSA
// 	if (pkey->type == EVP_PKEY_EC) mdc_tmp.digest=EVP_ecdsa();
// #endif

// 	i=EVP_VerifyFinal(&mdc_tmp,os->data,os->length, pkey);
// 	EVP_PKEY_free(pkey);
// 	if (i <= 0)
// 		{
//             PKCS7err(PKCS7_F_PKCS7_SIGNATUREVERIFY,
//                      PKCS7_R_SIGNATURE_FAILURE);
//             ret= -1;
//             goto err;
// 		}
// 	else
// 		ret=1;
//  err:
// 	EVP_MD_CTX_cleanup(&mdc_tmp);
// 	return(ret);
        
    }

    /* c: PKCS7_verify
     *
     */
    public void verify(Collection<X509Certificate> certs, Store store, BIO indata, BIO out, int flags) {
        if(!isSigned()) {
            throw new PKCS7Exception(F_PKCS7_VERIFY, R_WRONG_CONTENT_TYPE);
        }

        if(getDetached() != 0 && indata == null) {
            throw new PKCS7Exception(F_PKCS7_VERIFY, R_NO_CONTENT);
        }

        List<SignerInfoWithPkey> sinfos = new ArrayList<SignerInfoWithPkey>(getSignerInfo());
        if(sinfos == null || sinfos.size() == 0) {
            throw new PKCS7Exception(F_PKCS7_VERIFY, R_NO_SIGNATURES_ON_DATA);
        }

        List<X509Certificate> signers = getSigners(certs, sinfos, flags);
        if(signers == null) {
            throw new NotVerifiedPKCS7Exception();
        }

// 	X509_STORE_CTX cert_ctx;
    
        /* Now verify the certificates */
        if((flags & NOVERIFY) == 0) {
            for(X509Certificate signer : signers) {
                throw new UnsupportedOperationException("TODO: implement");
// 		if (!(flags & PKCS7_NOCHAIN)) {
// 			if(!X509_STORE_CTX_init(&cert_ctx, store, signer,
// 							p7->d.sign->cert))
// 				{
// 				PKCS7err(PKCS7_F_PKCS7_VERIFY,ERR_R_X509_LIB);
// 				sk_X509_free(signers);
// 				return 0;
// 				}
// 			X509_STORE_CTX_set_purpose(&cert_ctx,
// 						X509_PURPOSE_SMIME_SIGN);
// 		} else if(!X509_STORE_CTX_init (&cert_ctx, store, signer, NULL)) {
// 			PKCS7err(PKCS7_F_PKCS7_VERIFY,ERR_R_X509_LIB);
// 			sk_X509_free(signers);
// 			return 0;
// 		}
// 		if (!(flags & PKCS7_NOCRL))
// 			X509_STORE_CTX_set0_crls(&cert_ctx, p7->d.sign->crl);
// 		i = X509_verify_cert(&cert_ctx);
// 		if (i <= 0) j = X509_STORE_CTX_get_error(&cert_ctx);
// 		X509_STORE_CTX_cleanup(&cert_ctx);
// 		if (i <= 0) {
// 			PKCS7err(PKCS7_F_PKCS7_VERIFY,PKCS7_R_CERTIFICATE_VERIFY_ERROR);
// 			ERR_add_error_data(2, "Verify error:",
// 					 X509_verify_cert_error_string(j));
// 			sk_X509_free(signers);
// 			return 0;
// 		}
// 		/* Check for revocation status here */
                
            }
        }

        BIO tmpin = indata;
        BIO p7bio = dataInit(tmpin);
        BIO tmpout = null;
        if((flags & TEXT) != 0) {
            tmpout = BIO.mem();
        } else {
            tmpout = out;
        }
        
        byte[] buf = new byte[4096];
        for(;;) {
            try {
                int i = p7bio.read(buf, 0, buf.length);
                if(i <= 0) {
                    break;
                }
                if(tmpout != null) {
                    tmpout.write(buf, 0, i);
                }
            } catch(IOException e) {
                throw new PKCS7Exception(F_PKCS7_VERIFY, -1, e);
            }
        }

        if((flags & TEXT) != 0) {
            new SMIME(Mime.DEFAULT).text(tmpout, out);
        }

        if((flags & NOSIGS) == 0) {
            for(int i=0; i<sinfos.size(); i++) {
                SignerInfoWithPkey si = sinfos.get(i);
                X509Certificate signer = signers.get(i);
                signatureVerify(p7bio, si, signer);
            }
        }

        if(tmpin == indata) {
            if(indata != null) {
                p7bio.pop();
            }
        }
    }

    /* c: PKCS7_sign
     *
     */
    public static PKCS7 sign(X509Certificate signcert, PrivateKey pkey, Collection<X509Certificate> certs, BIO data, int flags) {
        PKCS7 p7 = new PKCS7();
        p7.setType(ASN1Registry.NID_pkcs7_signed);
        p7.contentNew(ASN1Registry.NID_pkcs7_data);
        SignerInfoWithPkey si = p7.addSignature(signcert, pkey, EVP.sha1());
        if((flags & NOCERTS) == 0) {
            p7.addCertificate(signcert);
            if(certs != null) {
                for(X509Certificate c : certs) {
                    p7.addCertificate(c);
                }
            }
        }

        if((flags & NOATTR) == 0) {
            si.addSignedAttribute(ASN1Registry.NID_pkcs9_contentType, ASN1Registry.nid2obj(ASN1Registry.NID_pkcs7_data));
            if((flags & NOSMIMECAP) == 0) {
                ASN1EncodableVector smcap = new ASN1EncodableVector();
                smcap.add(new AlgorithmIdentifier(ASN1Registry.nid2obj(ASN1Registry.NID_des_ede3_cbc)));
                smcap.add(new AlgorithmIdentifier(ASN1Registry.nid2obj(ASN1Registry.NID_rc2_cbc), new DERInteger(128)));
                smcap.add(new AlgorithmIdentifier(ASN1Registry.nid2obj(ASN1Registry.NID_rc2_cbc), new DERInteger(64)));
                smcap.add(new AlgorithmIdentifier(ASN1Registry.nid2obj(ASN1Registry.NID_rc2_cbc), new DERInteger(40)));
                smcap.add(new AlgorithmIdentifier(ASN1Registry.nid2obj(ASN1Registry.NID_des_cbc)));
                si.addSignedAttribute(ASN1Registry.NID_SMIMECapabilities, new DERSequence(smcap));
            }
        }

        if((flags & STREAM) != 0) {
            return p7;
        }

        BIO p7bio = p7.dataInit(null);

        try {
            data.crlfCopy(p7bio, flags);
        } catch(IOException e) {
            throw new PKCS7Exception(F_PKCS7_SIGN, R_PKCS7_DATAFINAL_ERROR, e.toString());
        }

        if((flags & DETACHED) != 0) {
            p7.setDetached(1);
        }

        p7.dataFinal(p7bio);

        return p7;
    } 

    /* c: PKCS7_encrypt
     *
     */
    public static PKCS7 encrypt(Collection<X509Certificate> certs, byte[] in, Cipher cipher, int flags) {
        PKCS7 p7 = new PKCS7();

        p7.setType(ASN1Registry.NID_pkcs7_enveloped);

        try {
            p7.setCipher(cipher);

            for(X509Certificate x509 : certs) {
                p7.addRecipient(x509);
            }

            BIO p7bio = p7.dataInit(null);

            BIO.memBuf(in).crlfCopy(p7bio, flags);
            p7bio.flush();
            p7.dataFinal(p7bio);

            return p7;
        } catch(IOException e) {
            throw new PKCS7Exception(F_PKCS7_ENCRYPT, R_PKCS7_DATAFINAL_ERROR, e.toString());
        }
    }

    /* c: PKCS7_decrypt
     *
     */
    public void decrypt(PrivateKey pkey, X509Certificate cert, BIO data, int flags) {
        if(!isEnveloped()) {
            throw new PKCS7Exception(F_PKCS7_DECRYPT, R_WRONG_CONTENT_TYPE);
        }
        try {
            BIO tmpmem = dataDecode(pkey, null, cert);
            if((flags & TEXT) == TEXT) {
                BIO tmpbuf = BIO.buffered();
                BIO bread = tmpbuf.push(tmpmem);
                new SMIME(Mime.DEFAULT).text(bread, data);
            } else {
                int i;
                byte[] buf = new byte[4096];
                while((i = tmpmem.read(buf, 0, 4096)) > 0) {
                    data.write(buf, 0, i);
                }
            }
        } catch(IOException e) {
            throw new PKCS7Exception(F_PKCS7_DECRYPT, R_DECRYPT_ERROR, e.toString());
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
    public Collection<SignerInfoWithPkey> getSignerInfo() {
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
            MessageDigest md = EVP.getDigest(alg.getObjectId());
            BIO btmp = BIO.mdFilter(md);
            if(pbio == null) {
                return btmp;
            } else {
                pbio.push(btmp);
                return pbio;
            }
        } catch(Exception e) {
            throw new PKCS7Exception(F_PKCS7_BIO_ADD_DIGEST, R_UNKNOWN_DIGEST_TYPE, e);
        }
    }

    /** c: PKCS7_dataDecode
     *
     */
    public BIO dataDecode(PrivateKey pkey, BIO inBio, X509Certificate pcert) {
        BIO out = null;
        BIO btmp = null;
        BIO etmp = null;
        BIO bio = null;
        byte[] dataBody = null;
        Collection<AlgorithmIdentifier> mdSk = null;
        Collection<RecipInfo> rsk = null;
        AlgorithmIdentifier encAlg = null;
        AlgorithmIdentifier xalg = null;
        Cipher evpCipher = null;
        RecipInfo ri = null;

        int i = getType();
        state = S_HEADER;


        switch(i) {
        case ASN1Registry.NID_pkcs7_signed:
            dataBody = getSign().getContents().getOctetString().getOctets();
            mdSk = getSign().getMdAlgs();
            break;
        case ASN1Registry.NID_pkcs7_signedAndEnveloped:
            rsk = getSignedAndEnveloped().getRecipientInfo();
            mdSk = getSignedAndEnveloped().getMdAlgs();
            dataBody = getSignedAndEnveloped().getEncData().getEncData().getOctets();
            encAlg = getSignedAndEnveloped().getEncData().getAlgorithm();
            try {
                evpCipher = EVP.getCipher(encAlg.getObjectId());
            } catch(Exception e) {
                throw new PKCS7Exception(F_PKCS7_DATADECODE, R_UNSUPPORTED_CIPHER_TYPE);
            }
            xalg = getSignedAndEnveloped().getEncData().getAlgorithm();
            break;
        case ASN1Registry.NID_pkcs7_enveloped: 
            rsk = getEnveloped().getRecipientInfo();
            dataBody = getEnveloped().getEncData().getEncData().getOctets();
            encAlg = getEnveloped().getEncData().getAlgorithm();
            try {
                evpCipher = EVP.getCipher(encAlg.getObjectId());
            } catch(Exception e) {
                throw new PKCS7Exception(F_PKCS7_DATADECODE, R_UNSUPPORTED_CIPHER_TYPE);
            }
            xalg = getEnveloped().getEncData().getAlgorithm();
            break;
        default:
            throw new PKCS7Exception(F_PKCS7_DATADECODE, R_UNSUPPORTED_CONTENT_TYPE);
        }

        /* We will be checking the signature */
        if(mdSk != null) {
            for(AlgorithmIdentifier xa : mdSk) {
                try {
                    MessageDigest evpMd = EVP.getDigest(xa.getObjectId());
                    btmp = BIO.mdFilter(evpMd);
                    if(out == null) {
                        out = btmp;
                    } else {
                        out.push(btmp);
                    }
                    btmp = null;
                } catch(Exception e) {
                    throw new PKCS7Exception(F_PKCS7_DATADECODE, R_UNKNOWN_DIGEST_TYPE);
                }
            }
        }


        if(evpCipher != null) {

            /* It was encrypted, we need to decrypt the secret key
             * with the private key */

            /* Find the recipientInfo which matches the passed certificate
             * (if any)
             */
            if(pcert != null) {
                for(Iterator<RecipInfo> iter = rsk.iterator(); iter.hasNext();) {
                    ri = iter.next();
                    if(ri.compare(pcert)) {
                        break;
                    }
                    ri = null;
                }
                if(null == ri) {
                    throw new PKCS7Exception(F_PKCS7_DATADECODE, R_NO_RECIPIENT_MATCHES_CERTIFICATE);
                }
            }

            byte[] tmp = null;
            /* If we haven't got a certificate try each ri in turn */
            if(null == pcert) {
                for(Iterator<RecipInfo> iter = rsk.iterator(); iter.hasNext();) {
                    ri = iter.next();
                    try {
                        tmp = EVP.decrypt(ri.getEncKey().getOctets(), pkey);
                        if(tmp != null) {
                            break;
                        }
                    } catch(Exception e) {
                        tmp = null;
                    }
                    ri = null;
                }
                if(ri == null) {
                    throw new PKCS7Exception(F_PKCS7_DATADECODE, R_NO_RECIPIENT_MATCHES_KEY);
                }
            } else {
                try {
                    tmp = EVP.decrypt(ri.getEncKey().getOctets(), pkey);
                } catch(Exception e) {
                    throw new PKCS7Exception(F_PKCS7_DATADECODE, -1, e.toString());
                }
            }

            DEREncodable params = encAlg.getParameters();
            try {
                if(params != null && params instanceof ASN1OctetString) {
                    evpCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(tmp, evpCipher.getAlgorithm()), new IvParameterSpec(((ASN1OctetString)params).getOctets()));
                } else {
                    evpCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(tmp, evpCipher.getAlgorithm()));
                }
            } catch(Exception e) {
                throw new PKCS7Exception(F_PKCS7_DATADECODE, -1, e.toString());
            }

            etmp = BIO.cipherFilter(evpCipher);
            if(out == null) {
                out = etmp;
            } else {
                out.push(etmp);
            }
            etmp = null;
        }
        
        if(isDetached() || inBio != null) {
            bio = inBio;
        } else {
            if(dataBody != null && dataBody.length > 0) {
                bio = BIO.memBuf(dataBody);
            } else {
                bio = BIO.mem();
            }
        }
        out.push(bio);
        bio = null;
        return out;
    }

    /** c: PKCS7_dataInit
     *
     */
    public BIO dataInit(BIO bio) {
        Collection<AlgorithmIdentifier> mdSk = null;
        ASN1OctetString os = null;
        int i = this.data.getType();
        state = S_HEADER;
        Collection<RecipInfo> rsk = null;
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
            evpCipher = getSignedAndEnveloped().getEncData().getCipher();
            if(null == evpCipher) {
                throw new PKCS7Exception(F_PKCS7_DATAINIT, R_CIPHER_NOT_INITIALIZED);
            }
            break;
        case ASN1Registry.NID_pkcs7_enveloped:
            rsk = getEnveloped().getRecipientInfo();
            enc = getEnveloped().getEncData();
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
                KeyGenerator gen = KeyGenerator.getInstance(algoBase, OpenSSLReal.PROVIDER);
                gen.init(new SecureRandom());
                SecretKey key = gen.generateKey();
                klen = ((SecretKeySpec)key).getEncoded().length*8;
                evpCipher.init(Cipher.ENCRYPT_MODE, key);

                if(null != rsk) {
                    for(RecipInfo ri : rsk) {
                        PublicKey pkey = ri.getCert().getPublicKey();
                        Cipher cipher = Cipher.getInstance(pkey.getAlgorithm(), OpenSSLReal.PROVIDER);
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

            if(evpCipher.getIV() != null) {
                enc.setAlgorithm(new AlgorithmIdentifier(encAlgo, new DEROctetString(evpCipher.getIV())));
            } else {
                enc.setAlgorithm(new AlgorithmIdentifier(encAlgo));
            }

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
            
            if(nid == EVP.type(pmd[0])) {
                return bio;
            }

            bio = bio.next();
        }
    }

    /** c: PKCS7_dataFinal
     *
     */
    public int dataFinal(BIO bio) { 
        Collection<SignerInfoWithPkey> siSk = null;
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
            siSk = getSign().getSignerInfo();
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
                        sign = Signature.getInstance(EVP.signatureAlgorithm(ctx_tmp, si.getPkey()), OpenSSLReal.PROVIDER);
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

