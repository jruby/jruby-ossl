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
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.pkcs.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/** c: PKCS7
 *
 * Basically equivalent of the ContentInfo structures in PKCS#7.
 *
 * @author <a href="mailto:ola.bini@gmail.com">Ola Bini</a>
 */
public class PKCS7 {
    public static final int NID_pkcs7_data = 21;
    public static final int NID_pkcs7_signed = 22;
    public static final int NID_pkcs7_enveloped = 23;
    public static final int NID_pkcs7_signedAndEnveloped = 24;
    public static final int NID_pkcs7_digest = 25;
    public static final int NID_pkcs7_encrypted = 26;

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

    /* c: PKCS7_encrypt
     *
     */
    public static PKCS7 encrypt(List<X509Certificate> certs, byte[] in, Cipher cipher, int flags) {
        PKCS7 p7 = new PKCS7();

        p7.setType(NID_pkcs7_enveloped);

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
            // TODO: Handle correctly
        } catch(PKCS7Exception e) {
            // Equiv of err:
            // TODO: Handle different exceptions correctly here
        }
        return null;
    }

    /** c: PKCS7_set_type
     *
     */
    public void setType(int type) {
        switch(type) {
        case NID_pkcs7_signed:
            this.data = new PKCS7DataSigned();
            break;
        case NID_pkcs7_data:
            this.data = new PKCS7DataData();
            break;
        case NID_pkcs7_signedAndEnveloped:
            this.data = new PKCS7DataSignedAndEnveloped();
            break;
        case NID_pkcs7_enveloped:
            this.data = new PKCS7DataEnveloped();
            break;
        case NID_pkcs7_encrypted:
            this.data = new PKCS7DataEncrypted();
            break;
        case NID_pkcs7_digest:
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
    public void addSigner(SignerInfo psi) {
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
    public Set<SignerInfo> getSignerInfo() {
        return this.data.getSignerInfo();
    }

    private final static int EVP_MAX_KEY_LENGTH = 32;
    private final static int EVP_MAX_IV_LENGTH = 16;
    private final static int EVP_MAX_BLOCK_LENGTH = 32;


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
        Set<RecipInfo> rsk = null;
        AlgorithmIdentifier xalg = null;
        AlgorithmIdentifier xa = null;
        Cipher evpCipher = null;
        BIO out = null;
        BIO btmp = null;

        switch(i) {
        case NID_pkcs7_signed:
            mdSk = getSign().getMdAlgs();
            os = getSign().getContents().getOctetString();
            break;
        case NID_pkcs7_signedAndEnveloped:
            rsk = getSignedAndEnveloped().getRecipientInfo();
            mdSk = getSignedAndEnveloped().getMdAlgs();
            xalg = getSignedAndEnveloped().getEncData().getAlgorithm();
            evpCipher = getSignedAndEnveloped().getEncData().getCipher();
            if(null == evpCipher) {
                throw new PKCS7Exception(F_PKCS7_DATAINIT, R_CIPHER_NOT_INITIALIZED);
            }
            break;
        case NID_pkcs7_enveloped:
            rsk = getEnveloped().getRecipientInfo();
            xalg = getEnveloped().getEncData().getAlgorithm();
            evpCipher = getEnveloped().getEncData().getCipher();
            if(null == evpCipher) {
                throw new PKCS7Exception(F_PKCS7_DATAINIT, R_CIPHER_NOT_INITIALIZED);
            }
            break;
        case NID_pkcs7_digest:
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
            System.err.println("BLARG");
            int keylen, ivlen;
            int jj, max;
            byte[] tmp;
            
            btmp = BIO.cipherFilter(evpCipher);

            try {
                KeyGenerator gen = KeyGenerator.getInstance(evpCipher.getAlgorithm());
                gen.init(new SecureRandom());
                SecretKey key = gen.generateKey();
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

    /** c: PKCS7_dataFinal
     *
     */
    public void dataFinal(BIO bio) { 
// 	int ret=0;
// 	int i,j;
// 	BIO *btmp;
// 	BUF_MEM *buf_mem=NULL;
// 	BUF_MEM *buf=NULL;
// 	PKCS7_SIGNER_INFO *si;
// 	EVP_MD_CTX *mdc,ctx_tmp;
// 	STACK_OF(X509_ATTRIBUTE) *sk;
// 	STACK_OF(PKCS7_SIGNER_INFO) *si_sk=NULL;
// 	ASN1_OCTET_STRING *os=NULL;

// 	EVP_MD_CTX_init(&ctx_tmp);
// 	i=OBJ_obj2nid(p7->type);
// 	p7->state=PKCS7_S_HEADER;

// 	switch (i)
// 		{
//         case NID_pkcs7_signedAndEnveloped:
//             /* XXXXXXXXXXXXXXXX */
//             si_sk=p7->d.signed_and_enveloped->signer_info;
//             if (!(os=M_ASN1_OCTET_STRING_new()))
//                 {
//                     PKCS7err(PKCS7_F_PKCS7_DATAFINAL,ERR_R_MALLOC_FAILURE);
//                     goto err;
//                 }
//             p7->d.signed_and_enveloped->enc_data->enc_data=os;
//             break;
//         case NID_pkcs7_enveloped:
//             /* XXXXXXXXXXXXXXXX */
//             if (!(os=M_ASN1_OCTET_STRING_new()))
//                 {
//                     PKCS7err(PKCS7_F_PKCS7_DATAFINAL,ERR_R_MALLOC_FAILURE);
//                     goto err;
//                 }
//             p7->d.enveloped->enc_data->enc_data=os;
//             break;
//         case NID_pkcs7_signed:
//             si_sk=p7->d.sign->signer_info;
//             os=PKCS7_get_octet_string(p7->d.sign->contents);
//             /* If detached data then the content is excluded */
//             if(PKCS7_type_is_data(p7->d.sign->contents) && p7->detached) {
//                 M_ASN1_OCTET_STRING_free(os);
//                 p7->d.sign->contents->d.data = NULL;
//             }
//             break;

//         case NID_pkcs7_digest:
//             os=PKCS7_get_octet_string(p7->d.digest->contents);
//             /* If detached data then the content is excluded */
//             if(PKCS7_type_is_data(p7->d.digest->contents) && p7->detached)
//                 {
//                     M_ASN1_OCTET_STRING_free(os);
//                     p7->d.digest->contents->d.data = NULL;
//                 }
//             break;

// 		}

// 	if (si_sk != NULL)
// 		{
//             if ((buf=BUF_MEM_new()) == NULL)
//                 {
//                     PKCS7err(PKCS7_F_PKCS7_DATAFINAL,ERR_R_BIO_LIB);
//                     goto err;
//                 }
//             for (i=0; i<sk_PKCS7_SIGNER_INFO_num(si_sk); i++)
//                 {
//                     si=sk_PKCS7_SIGNER_INFO_value(si_sk,i);
//                     if (si->pkey == NULL) continue;

//                     j=OBJ_obj2nid(si->digest_alg->algorithm);

//                     btmp=bio;

//                     btmp = PKCS7_find_digest(&mdc, btmp, j);

//                     if (btmp == NULL)
//                         goto err;

//                     /* We now have the EVP_MD_CTX, lets do the
//                      * signing. */
//                     EVP_MD_CTX_copy_ex(&ctx_tmp,mdc);
//                     if (!BUF_MEM_grow_clean(buf,EVP_PKEY_size(si->pkey)))
//                         {
//                             PKCS7err(PKCS7_F_PKCS7_DATAFINAL,ERR_R_BIO_LIB);
//                             goto err;
//                         }

//                     sk=si->auth_attr;

//                     /* If there are attributes, we add the digest
//                      * attribute and only sign the attributes */
//                     if ((sk != NULL) && (sk_X509_ATTRIBUTE_num(sk) != 0))
//                         {
//                             unsigned char md_data[EVP_MAX_MD_SIZE], *abuf=NULL;
//                             unsigned int md_len, alen;
//                             ASN1_OCTET_STRING *digest;
//                             ASN1_UTCTIME *sign_time;
//                             const EVP_MD *md_tmp;

//                             /* Add signing time if not already present */
//                             if (!PKCS7_get_signed_attribute(si,
//                                                             NID_pkcs9_signingTime))
//                                 {
//                                     if (!(sign_time=X509_gmtime_adj(NULL,0)))
//                                         {
//                                             PKCS7err(PKCS7_F_PKCS7_DATAFINAL,
//                                                      ERR_R_MALLOC_FAILURE);
//                                             goto err;
//                                         }
//                                     PKCS7_add_signed_attribute(si,
//                                                                NID_pkcs9_signingTime,
//                                                                V_ASN1_UTCTIME,sign_time);
//                                 }

//                             /* Add digest */
//                             md_tmp=EVP_MD_CTX_md(&ctx_tmp);
//                             EVP_DigestFinal_ex(&ctx_tmp,md_data,&md_len);
//                             if (!(digest=M_ASN1_OCTET_STRING_new()))
//                                 {
//                                     PKCS7err(PKCS7_F_PKCS7_DATAFINAL,
//                                              ERR_R_MALLOC_FAILURE);
//                                     goto err;
//                                 }
//                             if (!M_ASN1_OCTET_STRING_set(digest,md_data,
//                                                          md_len))
//                                 {
//                                     PKCS7err(PKCS7_F_PKCS7_DATAFINAL,
//                                              ERR_R_MALLOC_FAILURE);
//                                     goto err;
//                                 }
//                             PKCS7_add_signed_attribute(si,
//                                                        NID_pkcs9_messageDigest,
//                                                        V_ASN1_OCTET_STRING,digest);

//                             /* Now sign the attributes */
//                             EVP_SignInit_ex(&ctx_tmp,md_tmp,NULL);
//                             alen = ASN1_item_i2d((ASN1_VALUE *)sk,&abuf,
//                                                  ASN1_ITEM_rptr(PKCS7_ATTR_SIGN));
//                             if(!abuf) goto err;
//                             EVP_SignUpdate(&ctx_tmp,abuf,alen);
//                             OPENSSL_free(abuf);
//                         }

// #ifndef OPENSSL_NO_DSA
//                     if (si->pkey->type == EVP_PKEY_DSA)
//                         ctx_tmp.digest=EVP_dss1();
// #endif
// #ifndef OPENSSL_NO_ECDSA
//                     if (si->pkey->type == EVP_PKEY_EC)
//                         ctx_tmp.digest=EVP_ecdsa();
// #endif

//                     if (!EVP_SignFinal(&ctx_tmp,(unsigned char *)buf->data,
//                                        (unsigned int *)&buf->length,si->pkey))
//                         {
//                             PKCS7err(PKCS7_F_PKCS7_DATAFINAL,ERR_R_EVP_LIB);
//                             goto err;
//                         }
//                     if (!ASN1_STRING_set(si->enc_digest,
//                                          (unsigned char *)buf->data,buf->length))
//                         {
//                             PKCS7err(PKCS7_F_PKCS7_DATAFINAL,ERR_R_ASN1_LIB);
//                             goto err;
//                         }
//                 }
// 		}
// 	else if (i == NID_pkcs7_digest)
// 		{
//             unsigned char md_data[EVP_MAX_MD_SIZE];
//             unsigned int md_len;
//             if (!PKCS7_find_digest(&mdc, bio,
//                                    OBJ_obj2nid(p7->d.digest->md->algorithm)))
//                 goto err;
//             EVP_DigestFinal_ex(mdc,md_data,&md_len);
//             M_ASN1_OCTET_STRING_set(p7->d.digest->digest, md_data, md_len);
// 		}

// 	if (!PKCS7_is_detached(p7))
// 		{
//             btmp=BIO_find_type(bio,BIO_TYPE_MEM);
//             if (btmp == NULL)
//                 {
//                     PKCS7err(PKCS7_F_PKCS7_DATAFINAL,PKCS7_R_UNABLE_TO_FIND_MEM_BIO);
//                     goto err;
//                 }
//             BIO_get_mem_ptr(btmp,&buf_mem);
//             /* Mark the BIO read only then we can use its copy of the data
//              * instead of making an extra copy.
//              */
//             BIO_set_flags(btmp, BIO_FLAGS_MEM_RDONLY);
//             BIO_set_mem_eof_return(btmp, 0);
//             os->data = (unsigned char *)buf_mem->data;
//             os->length = buf_mem->length;
// #if 0
//             M_ASN1_OCTET_STRING_set(os,
//                                     (unsigned char *)buf_mem->data,buf_mem->length);
// #endif
// 		}
// 	ret=1;
//  err:
// 	EVP_MD_CTX_cleanup(&ctx_tmp);
// 	if (buf != NULL) BUF_MEM_free(buf);
// 	return(ret);
       // TODO: implement
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

