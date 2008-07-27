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
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.crypto.Cipher;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

/** c: PKCS7
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
    public List<SignerInfo> getSignerInfo() {
        return this.data.getSignerInfo();
    }

    /** c: PKCS7_dataInit
     *
     */
    public BIO dataInit(Object val) {
        // TODO: implement
        return new BIO();
    }

    /** c: PKCS7_dataFinal
     *
     */
    public void dataFinal(BIO bio) {
        // TODO: implement
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

    public int getType() {
        return this.data.getType();
    }

}// PKCS7

