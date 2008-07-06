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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import java.security.cert.X509Certificate;
import javax.crypto.Cipher;
import java.util.List;
import org.bouncycastle.asn1.DEROctetString;

/** c: PKCS7
 *
 * @author <a href="mailto:ola.bini@gmail.com">Ola Bini</a>
 */
public class PKCS7 extends TypeDiscriminating {
    public static final int NID_pkcs7_signed = 22;
    public static final int NID_pkcs7_encrypted = 26;
    public static final int NID_pkcs7_enveloped = 23;
    public static final int NID_pkcs7_signedAndEnveloped = 24;
    public static final int NID_pkcs7_data = 21;
    public static final int NID_pkcs7_digest = 25;

    private String asn1;
    private int state; //used during processing
    private int detached;

	/* content as defined by the type */
	/* all encryption/message digests are applied to the 'contents',
	 * leaving out the 'type' field. */

    private String ptr;
    
    /* NID_pkcs7_data */
	private ASN1OctetString data;

    /* NID_pkcs7_signed */
    private Signed sign;

    /* NID_pkcs7_enveloped */
    private Envelope enveloped;

    /* NID_pkcs7_signedAndEnveloped */
    private SignEnvelope signedAndEnveloped;

    /* NID_pkcs7_digest */
    private Digest digest;
    
    /* NID_pkcs7_encrypted */
    private Encrypt encrypted;

    /* Anything else */
    private ASN1Encodable other;

    public Object ctrl(int cmd, Object v, Object ignored) {
        int ret = 0;
        switch(cmd) {
        case OP_SET_DETACHED_SIGNATURE:
            if(isSigned()) {
                ret = detached = ((Integer)v).intValue();
                if(ret != 0 && sign.contents.isData()) {
                    sign.contents.data = null;
                }
            } else {
                // TODO: ERR
                ret = 0;
            }
            break;
        case OP_GET_DETACHED_SIGNATURE:
            if(isSigned()) {
                if(sign == null || sign.contents.data == null) {
                    ret = 1;
                } else {
                    ret = 0;
                }
            } else {
                // TODO: ERR
                ret = 0;
            }

            break;
        default:
            // TODO: ERR
            ret = 0;
        }
        return Integer.valueOf(ret);
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
        } catch(PKCS7Exception e) {
            // Equiv of err:
            // TODO: Handle different exceptions correctly here
            return null;
        }
    }

    private void deleteOtherValues() {
        ptr = null;
        data = null;
        sign = null;
        enveloped = null;
        signedAndEnveloped = null;
        digest = null;
        encrypted = null;
        other = null;
    }

    /** c: PKCS7_set_type
     *
     */
    public void setType(int type) {
        this.type = type;
        deleteOtherValues();
        switch(type) {
        case NID_pkcs7_signed:
            this.sign = new Signed();
            this.sign.setVersion(1);
            break;
        case NID_pkcs7_data:
            this.data = new DEROctetString(new byte[0]);
            break;
        case NID_pkcs7_signedAndEnveloped:
            this.signedAndEnveloped = new SignEnvelope();
            this.signedAndEnveloped.setVersion(1);
            this.signedAndEnveloped.getEncData().setContentType(NID_pkcs7_data);
            break;
        case NID_pkcs7_enveloped:
            this.enveloped = new Envelope();
            this.enveloped.setVersion(0);
            this.enveloped.getEncData().setContentType(NID_pkcs7_data);
            break;
        case NID_pkcs7_encrypted:
            this.encrypted = new Encrypt();
            this.encrypted.setVersion(0);
            this.encrypted.getEncData().setContentType(NID_pkcs7_data);
            break;
        case NID_pkcs7_digest:
            this.digest = new Digest();
            this.digest.setVersion(0);
            break;
        default:
            throw new PKCS7Exception(F_PKCS7_SET_TYPE,R_UNSUPPORTED_CONTENT_TYPE);
        }
    }

    /** c: PKCS7_set_cipher
     *
     */
    public void setCipher(Cipher cipher) {
        // TODO: implement
    }

    /** c: PKCS7_add_recipient
     *
     */
    public void addRecipient(X509Certificate recip) {
        // TODO: implement
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

    public String getPtr() {
        return this.ptr;
    }

    public Envelope getEnveloped() {
        return this.enveloped;
    }

    public SignEnvelope getSignedAndEnveloped() {
        return this.signedAndEnveloped;
    }

    public Digest getDigest() {
        return this.digest;
    }

    public Encrypt getEncrypted() {
        return this.encrypted;
    }

    public ASN1Encodable getOther() {
        return this.other;
    }

    public void setSign(Signed sign) {
        this.sign = sign;
    }

    public Signed getSign() {
        return this.sign;
    }

    public void setData(ASN1OctetString data) {
        this.data = data;
    }

    public ASN1OctetString getData() {
        return this.data;
    }
}// PKCS7

