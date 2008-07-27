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

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREncodable;

/** PKCS7_SIGNER_INFO
 *
 * @author <a href="mailto:ola.bini@gmail.com">Ola Bini</a>
 */
public class SignerInfo {
    private List<Attribute> authAttr = new ArrayList<Attribute>();
    private List<Attribute> unauthAttr = new ArrayList<Attribute>();

    /**
     * Describe digestAlgorithm here.
     */
    private AlgorithmIdentifier digestAlgorithm;

    /**
     * Describe version here.
     */
    private int version;

    /**
     * Get the <code>DigestAlgorithm</code> value.
     *
     * @return a <code>AlgorithmIdentifier</code> value
     */
    public final AlgorithmIdentifier getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * Set the <code>DigestAlgorithm</code> value.
     *
     * @param newDigestAlgorithm The new DigestAlgorithm value.
     */
    public final void setDigestAlgorithm(final AlgorithmIdentifier newDigestAlgorithm) {
        this.digestAlgorithm = newDigestAlgorithm;
    }

    public List<Attribute> getAuthAttr() {
        return this.authAttr;
    }


    public List<Attribute> getUnauthAttr() {
        return this.unauthAttr;
    }

    /** c: PKCS7_add_signed_attribute
     *
     */
    public void addSignedAttribute(int nid, int atrtype, ASN1Encodable value) {
        addAttribute(authAttr, nid, atrtype, value);
    }

    /** c: PKCS7_add_attribute
     *
     */
    public void addAttribute(int nid, int atrtype, ASN1Encodable value) {
        addAttribute(unauthAttr, nid, atrtype, value);
    }


    /** c: static(pk7_doit.c) add_attribute
     *
     */
    private void addAttribute(List<Attribute> sk, int nid, int atrtype, ASN1Encodable value) {
        Attribute attr = Attribute.create(nid, atrtype, value);

        for(int i=0,j=sk.size(); i<j; i++) {
            if(sk.get(i).getType() == nid) {
                sk.set(i, attr);
                return;
            }
        }
        sk.add(attr);
    }

    /** c: PKCS7_get_signed_attribute
     *
     */
    public ASN1Encodable getSignedAttribute(int nid) {
        return getAttribute(authAttr, nid);
    }

    /** c: PKCS7_get_attribute
     *
     */
    public ASN1Encodable getAttribute(int nid) {
        return getAttribute(unauthAttr, nid);
    }


    /** c: static(pk7_doit.c) get_attribute
     *
     */
    private ASN1Encodable getAttribute(List<Attribute> sk, int nid) {
        for(int i=0,j=sk.size(); i<j; i++) {
            Attribute attr = sk.get(i);
            if(attr.getType() == nid) {
                if(!attr.isSingle() && attr.getSet().size() > 0) {
                    return attr.getSet().get(0);
                } else {
                    return null;
                }
            }
        }
        return null;
    }

    /**
     * Get the <code>Version</code> value.
     *
     * @return an <code>int</code> value
     */
    public final int getVersion() {
        return version;
    }

    /**
     * Set the <code>Version</code> value.
     *
     * @param newVersion The new Version value.
     */
    public final void setVersion(final int newVersion) {
        this.version = newVersion;
    }



    @Override
    public boolean equals(Object other) {
        boolean ret = this == other;
        if(!ret && (other instanceof SignerInfo)) {
            SignerInfo o = (SignerInfo)other;
            ret = 
                this.version == o.version &&
                (this.digestAlgorithm == null) ? o.digestAlgorithm == null : (this.digestAlgorithm.equals(o.digestAlgorithm)) &&
                this.authAttr.equals(o.authAttr) && 
                this.unauthAttr.equals(o.unauthAttr);
        }
        return ret;
    }

    @Override
    public int hashCode() {
        int ret = 33;
        ret = ret + 13 * version;
        ret = ret + (digestAlgorithm == null ? 0 : 13 * digestAlgorithm.hashCode());
        ret = ret + (authAttr == null ? 0 : 13 * authAttr.hashCode());
        ret = ret + (unauthAttr == null ? 0 : 13 * unauthAttr.hashCode());
        return ret;
    }

    @Override
    public String toString() {
        return "#<SignerInfo version="+version+" " + digestAlgorithm + " auth="+authAttr+" unauth="+unauthAttr+">";
    }

    /**
     * SignerInfo ::= SEQUENCE {
     *   version Version,
     *   issuerAndSerialNumber IssuerAndSerialNumber,
     *   digestAlgorithm DigestAlgorithmIdentifier,
     *   authenticatedAttributes [0] IMPLICIT Attributes OPTIONAL,
     *   digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
     *   encryptedDigest EncryptedDigest,
     *   unauthenticatedAttributes [1] IMPLICIT Attributes OPTIONAL }
     *
     * EncryptedDigest ::= OCTET STRING
     *
     */
    public static SignerInfo fromASN1(DEREncodable content) {
        return null;
    }

    /**
     * SET OF SignerInfo
     *
     */
    public static Set<SignerInfo> fromASN1Set(DEREncodable content) {
        ASN1Set set = (ASN1Set)content;
        Set<SignerInfo> result = new HashSet<SignerInfo>();
        for(Enumeration<?> e = set.getObjects(); e.hasMoreElements();) {
            result.add(fromASN1((DEREncodable)(e.nextElement())));
        }
        return result;
    }
}// SignerInfo
