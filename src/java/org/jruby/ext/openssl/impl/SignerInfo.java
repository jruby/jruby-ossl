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

import java.util.List;
import java.util.ArrayList;
import org.bouncycastle.asn1.ASN1Encodable;

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
    private String digestAlgorithm;

    /**
     * Get the <code>DigestAlgorithm</code> value.
     *
     * @return a <code>String</code> value
     */
    public final String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * Set the <code>DigestAlgorithm</code> value.
     *
     * @param newDigestAlgorithm The new DigestAlgorithm value.
     */
    public final void setDigestAlgorithm(final String newDigestAlgorithm) {
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


    /** c: add_attribute
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
}// SignerInfo
